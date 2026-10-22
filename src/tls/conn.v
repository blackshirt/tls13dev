// Copyright (c) 2026 blackshirt.
//
// conn.v is the public entry point of this TLS stack: dial() runs the TLS 1.3
// handshake and Conn exposes the protected stream over TCP — RFC 8446 §5 record
// framing, batched flights, reassembly of split records. The handshake core
// (tls.handshake's state_machine.v) stays transport-neutral; recordless QUIC (RFC 9001 §4) uses none.
module tls

import net
import sync
import time
import tls.handshake
import tls.pki
import tls.wire

// max_stored_session_tickets bounds the NewSessionTicket backlog kept on the
// handshake; resumption is unimplemented, so the queue is only diagnostic (RFC 8446 §4.6.1).
const max_stored_session_tickets = 32

// recv_buf_compact_threshold bounds the consumed prefix recv_buf may retain before
// its tail is shifted to the front, keeping compaction amortized O(1) per byte.
const recv_buf_compact_threshold = 16384

// recv_read_size is the number of bytes requested from the socket per read, sized
// to the largest plaintext record so a full record usually arrives in one read(2).
const recv_read_size = max_plaintext_record_len

// write_batch_threshold caps how much ciphertext Conn.write() accumulates before
// pushing it out, so a large write costs about one write(2) per 128 KiB.
const write_batch_threshold = 131072

// max_compat_ccs_records bounds the dummy ChangeCipherSpec records tolerated while
// awaiting a flight, so a peer cannot pin the handshake (RFC 8446 §5 / App. D.4).
const max_compat_ccs_records = 2

// Conn is a TLS 1.3 client connection over TCP, built only by dial(). read() and
// write() take separate mutexes; the lock order is always rlock → wlock.
@[noinit]
pub struct Conn {
mut:
	sock &net.TcpConn               // underlying TCP transport
	hs   handshake.RecordHandshaker // TLS handshake contract for the record adapter
	// The four RecordProtectors are the record layer's own state; the core never sees them.
	server_hs_cipher  RecordProtector // AEAD state for records the server sends under handshake keys
	client_hs_cipher  RecordProtector // AEAD state for records we send under handshake keys
	server_app_cipher RecordProtector // AEAD state for records the server sends under app keys
	client_app_cipher RecordProtector // AEAD state for records we send under app keys
	// session_tickets holds the NewSessionTicket backlog the core parses but does not keep (RFC 9001 §4.5).
	session_tickets   []handshake.NewSessionTicket
	post_hs_buf       []u8        // reassembly buffer for post-handshake messages (NewSessionTicket/KeyUpdate) split across records (RFC 8446 §5.2)
	recv_buf          []u8        // raw bytes read from the socket, framing not yet applied
	recv_pos          int         // start of unconsumed data in recv_buf (prefix is already parsed)
	read_scratch      []u8        // connection-lifetime scratch filled by sock.read in read_raw_record, so a record arriving in TCP pieces costs no allocation
	app_buf           []u8        // decrypted application bytes that didn't fit the caller's buffer
	app_pos           int         // start of undrained bytes in app_buf (mirrors recv_pos: draining advances the index instead of re-cloning the tail)
	closed            bool        // set once the connection is finished (close or fatal alert)
	close_notify_sent bool        // guards against sending close_notify twice
	sock_closed       bool        // set once sock.close() ran: `closed` alone cannot guard the fd, because handle_alert marks closed while leaving the socket open for close() to collect
	fatal_error       string      // non-empty once a fatal alert/error closed the connection; re-surfaced by read()
	rlock             &sync.Mutex // serializes read() and every read-cipher/recv_buf mutation; both locks are exclusive mutexes, not RwLock read sides, because each path rewrites AEAD sequence numbers
	wlock             &sync.Mutex // serializes write() and every write-cipher mutation
	negotiated_alpn   string      // server's ALPN pick — always one of Config.alpn (the handshake aborts otherwise), '' if none
	server_name       string      // SNI value sent and the name the certificate was checked against
	// Failure-alert plumbing, used only by send_failure_alert on a dead handshake.
	peer_terminated bool                        // set when the peer itself sent the alert: never alert back into a socket the peer already closed
	fail_alert      ?handshake.AlertDescription // adapter-classified alert; when unset, send_failure_alert falls back to the core's hs.failure_alert()
}

// dial connects to address (host:port), performs a TLS 1.3 handshake, and returns
// Conn. server_name falls back to the address host so SNI and hostname checks work.
pub fn dial(address string, config Config) !&Conn {
	// Prefer an explicit server_name; otherwise derive it from the dial address.
	server_name := if config.server_name.len > 0 {
		config.server_name
	} else {
		host_from_address(address)
	}

	// Open the TCP transport first: every later failure path must close it.
	mut sock := net.dial_tcp(address)!
	// Apply one bounded timeout to both directions (caller's value, else 30s).
	timeout := if config.timeout > 0 { config.timeout } else { 30 * time.second }
	sock.set_read_timeout(timeout)
	sock.set_write_timeout(timeout)

	// Trust anchors: an explicit root_cas wins, else the system bundle (skipped if verification is off).
	mut store := pki.new_trust_store()
	if roots := config.root_cas {
		store = roots
	} else if !config.insecure_skip_verify {
		// Fatal, but close the socket so a dial error leaks no fd.
		store = pki.system_root_cas() or {
			sock.close() or {}
			return err
		}
	}
	validator := pki.new_validator(store, config.insecure_skip_verify)
	// Apply the caller's RSA leaf-key floor only when it overrides the default.
	mut validator_mut := validator
	if config.min_rsa_bits > 0 {
		validator_mut.set_min_rsa_bits(config.min_rsa_bits)
	}

	mut hs := handshake.new_record_handshake(server_name, config.alpn, validator_mut) or {
		sock.close() or {}
		return err
	}

	mut conn := &Conn{
		sock:              sock
		hs:                hs
		session_tickets:   []handshake.NewSessionTicket{cap: 4}
		recv_buf:          []u8{cap: 2 * (max_ciphertext_record_len + record_header_len)} // one frame parsing, one arriving
		recv_pos:          0
		read_scratch:      []u8{len: recv_read_size}           // reused by every socket read for this connection
		app_buf:           []u8{cap: max_plaintext_record_len}                      // one full plaintext record
		app_pos:           0
		closed:            false
		close_notify_sent: false
		sock_closed:       false
		fatal_error:       ''
		rlock:             sync.new_mutex()
		wlock:             sync.new_mutex()
		negotiated_alpn:   ''
		server_name:       server_name
	}

	// On failure send the classified fatal alert (RFC 8446 §6), wipe secrets, close the socket.
	conn.do_handshake() or {
		conn.send_failure_alert()
		conn.wipe_on_failure()
		sock.close() or {}
		return err
	}
	// The ALPN pick is exposed only after the handshake proved it was offered (RFC 7301 §3.1).
	conn.negotiated_alpn = conn.hs.negotiated_alpn()
	return conn
}

// host_from_address extracts the host part of a dial address ("host:port" or
// "[ipv6]:port") so a bare address still supplies the SNI and verification name.
fn host_from_address(address string) string {
	// Bracketed form is an IPv6 literal: return the inner address, or the string unchanged.
	if address.starts_with('[') {
		end := address.index(']') or { return address }
		return address[1..end]
	}
	// host:port — split on the LAST colon so the port separator is removed.
	if colon := address.last_index(':') {
		return address[..colon]
	}
	// No colon at all: the entire string is already just a host (e.g. "localhost").
	return address
}

// do_handshake drives the full client flight over TCP: frame the ClientHello
// (+dummy CCS), then feed records into the core until it reports .connected (§5.1).
fn (mut c Conn) do_handshake() ! {
	ch := c.hs.create_client_hello()!
	c.write_records([new_record(.handshake, ch), change_cipher_spec()])!

	// The core's state machine is transport-neutral:
	// it has no concept of record framing.
	mut ccs_seen := 0
	for c.hs.state() != .connected {
		rec := c.read_raw_record()!

		match rec.content_type {
			.change_cipher_spec {
				// The peer's dummy CCS carries no meaning in TLS 1.3 — drop it (RFC 8446 §5).
				ccs_seen = validate_compat_ccs(rec.payload, ccs_seen) or {
					c.fail_alert = .unexpected_message
					return err
				}
				continue
			}
			.alert {
				// After ServerHello, RFC 8446 §6 requires alerts to be encrypted — reject a plaintext one.
				if c.hs.state() != .wait_server_hello {
					c.fail_alert = .unexpected_message
					return error('tls: unencrypted alert after ServerHello (unexpected_message)')
				}
				peer_alert := handshake.parse_alert(rec.payload)!
				// The peer terminated of its own accord: never alert back (RFC 8446 §6).
				c.peer_terminated = true
				return error('tls: received alert ${peer_alert.description} (level=${peer_alert.level})')
			}
			.handshake {
				// Plaintext handshake records are legal only while the ServerHello is outstanding (§5.1/§6).
				if c.hs.state() != .wait_server_hello {
					c.fail_alert = .unexpected_message
					return error('tls: unencrypted handshake record after ServerHello (unexpected_message)')
				}
				msgs := c.hs.receive(.initial, rec.payload)!
				// The record must have yielded exactly one complete message (§5.1).
				if c.hs.record_unconsumed_bytes(.initial) != 0 {
					c.fail_alert = .unexpected_message
					return error('tls: misframed ServerHello record: ${c.hs.record_unconsumed_bytes(.initial)} leftover byte(s) (unexpected_message)')
				}
				if msgs.len == 0 && c.hs.state() == .wait_server_hello {
					c.fail_alert = .unexpected_message
					return error('tls: incomplete ServerHello at record boundary (unexpected_message)')
				}
				if c.hs.state() == .wait_encrypted_extensions {
					// The core cached the handshake TrafficKeys; install this side's ciphers now.
					c.install_handshake_ciphers()!
				}
				// A retry ClientHello travels plaintext plus a fresh dummy CCS (App. D.4).
				for m in msgs {
					c.write_records([new_record(.handshake, m.msg()), change_cipher_spec()])!
				}
			}
			.application_data {
				// Everything under the server's handshake keys has outer type application_data (RFC 8446 §5.1/§5.2).
				if c.hs.state() == .start || c.hs.state() == .wait_server_hello {
					c.fail_alert = .unexpected_message
					return error('tls: unexpected encrypted record before ServerHello (unexpected_message)')
				}
				dec := c.server_hs_cipher.decrypt_record(rec)!
				// Inner-type routing is record-layer policy; the core has no ContentType concept.
				match dec.content_type {
					.handshake {
						msgs := c.hs.receive(.handshake, dec.plaintext)!
						for m in msgs {
							// The client's Finished travels under the client handshake keys (RFC 8446 §7.1).
							enc := c.client_hs_cipher.encrypt_record(.handshake, m.msg())!
							c.write_records([enc])!
						}
					}
					.alert {
						// RFC 8446 §6: the server may surface a fatal alert under the handshake keys.
						peer_alert := handshake.parse_alert(dec.plaintext)!
						if peer_alert.description == .close_notify {
							c.peer_terminated = true
							return error('tls: peer sent close_notify during handshake')
						}
						c.peer_terminated = true
						return error('tls: received alert ${peer_alert.description} during handshake')
					}
					else {
						// Only handshake and alert are legal here; anything else violates §5.6.
						c.fail_alert = .unexpected_message
						return error('tls: unexpected content type in handshake phase: ${dec.content_type}')
					}
				}
			}
			else {
				c.fail_alert = .unexpected_message
				return error('tls: unexpected record type ${rec.content_type} during handshake')
			}
		}
	}
	// The core verified the server Finished; install this adapter's post-handshake protection.
	c.install_application_ciphers()!
	// Nothing may protect or decrypt at the handshake level now, so the core may destroy its secrets (RFC 8446 §7.5).
	c.hs.on_handshake_confirmed()!
}

// ─── TCP transport: framing, write batching, dummy CCS ───
// validate_compat_ccs checks one dummy ChangeCipherSpec record and enforces max_compat_ccs_records.
fn validate_compat_ccs(payload []u8, seen int) !int {
	mut total := seen + 1
	if total > max_compat_ccs_records {
		return error('tls: too many change_cipher_spec records during handshake (unexpected_message)')
	}
	// Compliant peers send exactly the single byte 0x01 (App. D.4).
	if payload.len != 1 || payload[0] != 0x01 {
		return error('tls: malformed change_cipher_spec during handshake (must be the single byte 0x01)')
	}
	return total
}

// write_records serializes records into one buffer and pushes it in a single
// write(2), resuming from the first unwritten byte on a short write (RFC 8446 §5).
fn (mut c Conn) write_records(recs []Record) ! {
	if c.sock == unsafe { nil } {
		return error('tls: socket is nil')
	}
	if recs.len == 0 {
		return
	}
	mut total := 0
	for rec in recs {
		total += record_header_len + rec.payload.len
	}
	mut batched := []u8{cap: total}
	for rec in recs {
		rec.serialize_into(mut batched)
	}
	mut written := 0
	for written < batched.len {
		n := c.sock.write(batched[written..])!
		if n <= 0 {
			return error('tls: socket write made no progress (${written}/${batched.len} bytes)')
		}
		written += n
	}
}

// read_raw_record blocks until one complete TLS record (header + payload) is
// buffered, then parses it in place off recv_buf; TCP may split or coalesce records.
fn (mut c Conn) read_raw_record() !Record {
	// read_scratch is refilled in place, so a record arriving in TCP pieces costs no allocation.
	for {
		avail := c.recv_buf.len - c.recv_pos
		if avail >= record_header_len {
			// Peek the length field (offset 3) without consuming it; TCP can split records.
			payload_len := int(u16(c.recv_buf[c.recv_pos + 3]) << 8 | u16(c.recv_buf[c.recv_pos + 4]))
			if payload_len > max_ciphertext_record_len {
				return error('record: record length ${payload_len} exceeds maximum allowed ${max_ciphertext_record_len}')
			}
			total := record_header_len + payload_len
			if avail >= total {
				// Parse directly over the live recv_buf; read_bytes copies the payload out.
				mut r := wire.new_reader(c.recv_buf[c.recv_pos..c.recv_pos + total])
				c.recv_pos += total
				rec := parse_record(mut r)!
				c.compact_recv_buf()
				return rec
			}
		}
		if c.sock == unsafe { nil } {
			return error('tls: connection closed (no socket available to read further records)')
		}
		n := c.sock.read(mut c.read_scratch) or {
			return error('tls: connection closed while reading record: ${err}')
		}
		if n == 0 {
			return error('tls: connection closed while reading record')
		}
		c.recv_buf << c.read_scratch[..n]
	}
	return error('tls: unreachable')
}

// compact_recv_buf reclaims the already-consumed prefix of recv_buf, keeping its
// capacity when fully drained and shifting the tail down past the threshold.
fn (mut c Conn) compact_recv_buf() {
	if c.recv_pos == c.recv_buf.len {
		// Fully drained: clear() keeps the capacity for the next record.
		c.recv_buf.clear()
		c.recv_pos = 0
	} else if c.recv_pos >= recv_buf_compact_threshold {
		// Prefix over the bound: shift the live tail down once, keeping reclaim O(1) per byte.
		c.recv_buf = c.recv_buf[c.recv_pos..].clone()
		c.recv_pos = 0
	}
}

// record_protector_from_keys instantiates one direction's record protection from
// the core's cached TrafficKeys; sequence numbers restart at 0 per generation (§5.3).
fn record_protector_from_keys(suite handshake.CipherSuite, keys handshake.TrafficKeys) !RecordProtector {
	aead := handshake.new_aead_for_suite(suite, keys.key())!
	return new_record_protector(aead, keys.iv())!
}

// install_handshake_ciphers builds both handshake-key record states from the
// core's record_traffic_keys(.handshake); called once after the ServerHello is fed.
fn (mut c Conn) install_handshake_ciphers() ! {
	ck, sk := c.hs.record_traffic_keys(.handshake)!
	suite := c.hs.negotiated_cipher_suite()
	c.client_hs_cipher = record_protector_from_keys(suite, ck)!
	c.server_hs_cipher = record_protector_from_keys(suite, sk)!
}

// install_application_ciphers builds both application-key record states from the
// core's record_traffic_keys(.application); called once at .connected.
fn (mut c Conn) install_application_ciphers() ! {
	ck, sk := c.hs.record_traffic_keys(.application)!
	suite := c.hs.negotiated_cipher_suite()
	c.client_app_cipher = record_protector_from_keys(suite, ck)!
	c.server_app_cipher = record_protector_from_keys(suite, sk)!
}

// rekeyed_write_cipher rebuilds only the write-side application state after the
// core ratcheted the client secret (KeyUpdate); the read cipher is unchanged.
fn (mut c Conn) rekeyed_write_cipher() ! {
	ck, _ := c.hs.record_traffic_keys(.application)!
	c.client_app_cipher = record_protector_from_keys(c.hs.negotiated_cipher_suite(), ck)!
}

// rekeyed_read_cipher rebuilds only the read-side application state after the
// core ratcheted the server secret on receiving the peer's KeyUpdate.
fn (mut c Conn) rekeyed_read_cipher() ! {
	_, sk := c.hs.record_traffic_keys(.application)!
	c.server_app_cipher = record_protector_from_keys(c.hs.negotiated_cipher_suite(), sk)!
}

// handle_alert processes an alert received after the handshake. It marks the
// connection closed and returns 0 for a clean close_notify, else an error.
fn (mut c Conn) handle_alert(payload []u8) !int {
	// Any alert is terminal: mark closed before decoding, even a malformed body.
	c.closed = true
	// Peer termination is final: drop the app traffic secrets and the protectors' IVs (RFC 8446 §1.3.1/§7.5).
	c.hs.zeroize_app_secrets()
	wipe_record_protector(mut c.server_hs_cipher)
	wipe_record_protector(mut c.client_hs_cipher)
	wipe_record_protector(mut c.server_app_cipher)
	wipe_record_protector(mut c.client_app_cipher)
	peer_alert := handshake.parse_alert(payload) or {
		// A malformed alert body is fatal: pin a sticky error so later reads re-report it.
		c.fatal_error = 'tls: received malformed alert'
		return error(c.fatal_error)
	}
	// close_notify is the one clean-shutdown signal: return 0 like a normal EOF read.
	if peer_alert.description == .close_notify {
		return 0
	}
	// Every other description is fatal (RFC 8446 §6): surface the peer's code, sticky.
	c.fatal_error = 'tls: received alert ${peer_alert.description}'
	return error(c.fatal_error)
}

// read decrypts application data into buf. Returns bytes read (0 on clean close).
pub fn (mut c Conn) read(mut buf []u8) !int {
	// Serialize the whole read path: recv_buf, the read cipher and the sticky error.
	c.rlock.lock()
	defer {
		c.rlock.unlock()
	}
	if buf.len == 0 {
		return 0
	}
	// A fatal alert is sticky: report it on every later read, never 0.
	if c.fatal_error != '' {
		return error(c.fatal_error)
	}
	// Drain leftovers first so no plaintext is dropped or reordered.
	if c.app_buf.len > c.app_pos {
		n := copy(mut buf, c.app_buf[c.app_pos..])
		c.app_pos += n
		if c.app_pos == c.app_buf.len {
			c.app_buf.clear()
			c.app_pos = 0
		}
		return n
	}
	if c.closed {
		return 0
	}

	for {
		rec := c.read_raw_record()!
		match rec.content_type {
			.change_cipher_spec {
				// RFC 8446 §5: a CCS record is illegal once application keys are in use.
				return error('tls: received change_cipher_spec record after handshake (unexpected_message)')
			}
			.alert {
				// RFC 8446 §6: post-handshake alerts must be encrypted; a plaintext one is rejected.
				return error('tls: received unencrypted alert post-handshake (must be encrypted)')
			}
			.application_data {
				dec := c.server_app_cipher.decrypt_record(rec)!
				match dec.content_type {
					.application_data {
						if dec.plaintext.len == 0 {
							// Zero-length records are legal (padding only): keep looping.
							continue
						}
						n := copy(mut buf, dec.plaintext)
						if n < dec.plaintext.len {
							c.app_buf << dec.plaintext[n..]
						}
						return n
					}
					.alert {
						// Post-handshake alerts arrive encrypted as the inner type (RFC 8446 §5.1/§6).
						return c.handle_alert(dec.plaintext)
					}
					.handshake {
						// NewSessionTicket/KeyUpdate must not surface as application data.
						c.handle_post_handshake(dec.plaintext)!
						continue
					}
					else {
						return error('tls: unexpected inner content type ${dec.content_type}')
					}
				}
			}
			else {
				return error('tls: unexpected record type ${rec.content_type} after handshake')
			}
		}
	}
	return error('tls: unreachable')
}

// handle_post_handshake consumes NewSessionTicket and KeyUpdate messages from a
// decrypted post-handshake plaintext, reassembling fragments (RFC 8446 §5.2).
fn (mut c Conn) handle_post_handshake(data []u8) ! {
	c.post_hs_buf << data
	for {
		if c.post_hs_buf.len < 4 {
			return // header still incomplete; wait for the next record
		}
		mut r := wire.new_reader(c.post_hs_buf)
		msg_type, length := handshake.parse_handshake_header(mut r)!
		// A declared length beyond the core's bound is a violation, not a reason to allocate.
		if length > handshake.max_handshake_message_len {
			return error('tls: post-handshake message declares ${length} bytes, exceeds maximum ${handshake.max_handshake_message_len}')
		}
		if c.post_hs_buf.len < 4 + length {
			if c.post_hs_buf.len > 4 + handshake.max_handshake_message_len {
				return error('tls: post-handshake reassembly exceeds ${handshake.max_handshake_message_len} bytes without completing a message')
			}
			return // body still incomplete; wait for the next record
		}
		body := c.post_hs_buf[4..4 + length].clone()
		c.post_hs_buf = c.post_hs_buf[4 + length..].clone()
		match msg_type {
			.new_session_ticket {
				ticket := handshake.parse_new_session_ticket(body)!
				// Keep a bounded sample of the backlog; drop the overflow.
				if c.session_tickets.len < max_stored_session_tickets {
					c.session_tickets << ticket
				}
			}
			.key_update {
				// §4.6.3: a recipient always advances its read keys on receiving a KeyUpdate.
				request_update := handshake.parse_key_update(body)!
				c.hs.record_update_read_traffic_keys()!
				// The core ratcheted secrets only; swap in the new read cipher (seq restarts at 0, §5.3).
				c.rekeyed_read_cipher()!
				if request_update {
					c.send_key_update_response()!
				}
			}
			.certificate_request {
				// Client authentication: recognized, not answered by this client
			}
			else {
				// RFC 8446 §4.6: any other message is a fatal unexpected_message error
				return error('tls: unexpected post-handshake message ${msg_type} (unexpected_message)')
			}
		}
	}
}

// write encrypts and sends application data.
pub fn (mut c Conn) write(data []u8) !int {
	// Serialize against other writers and the read path's KeyUpdate response.
	c.wlock.lock()
	defer {
		c.wlock.unlock()
	}
	// Refuse to encrypt onto a finished connection.
	if c.closed {
		return error('tls: connection closed')
	}
	// Application keys exist only once connected.
	if c.hs.state() != .connected {
		return error('tls: handshake not complete')
	}
	// Chunk to max_plaintext_record_len (2^14): TLS forbids larger records (RFC 8446 §5.1).
	mut offset := 0
	mut batch := []Record{}
	mut batch_len := 0
	for offset < data.len {
		// §5.5: rekey one slot early so the KeyUpdate notice still fits under the old key.
		if c.client_app_cipher.seq_num >= record_seq_limit - 1 {
			// Flush the pending batch first: it must precede the KeyUpdate notice on the wire.
			c.write_records(batch)!
			batch = []Record{}
			batch_len = 0
			c.force_write_rekey()!
		}
		end := if data.len - offset > max_plaintext_record_len {
			offset + max_plaintext_record_len
		} else {
			data.len
		}
		chunk := data[offset..end]
		enc := c.client_app_cipher.encrypt_record(.application_data, chunk)!
		batch << enc
		batch_len += record_header_len + enc.payload.len
		// Ship at the batch bound or on the last chunk; coalescing never mixes generations.
		if batch_len >= write_batch_threshold || end == data.len {
			c.write_records(batch)!
			batch = []Record{}
			batch_len = 0
		}
		offset = end
	}
	return data.len
}

// send_key_update_response answers a KeyUpdate(update_requested): it sends the
// KeyUpdate under the current write keys and then ratchets them (§4.6.3).
fn (mut c Conn) send_key_update_response() ! {
	c.wlock.lock()
	defer {
		c.wlock.unlock()
	}
	msg := handshake.build_key_update(false)
	enc := c.client_app_cipher.encrypt_record(.handshake, msg)!
	c.write_records([enc])!
	c.hs.record_update_write_traffic_keys()!
	// Swap in the rebuilt write cipher before the next write() can reach it.
	c.rekeyed_write_cipher()!
}

// force_write_rekey fulfills the §5.5 sender-side record limit: announce a
// KeyUpdate with update_not_requested under the old write keys, then ratchet.
fn (mut c Conn) force_write_rekey() ! {
	msg := handshake.build_key_update(false)
	enc := c.client_app_cipher.encrypt_record(.handshake, msg)!
	c.write_records([enc])!
	c.hs.record_update_write_traffic_keys()!
	c.rekeyed_write_cipher()!
}

// close sends a close_notify alert and closes the underlying TCP connection.
pub fn (mut c Conn) close() ! {
	// Take the write lock only: a blocked reader is unblocked by closing the socket.
	c.wlock.lock()
	defer {
		c.wlock.unlock()
	}
	// Idempotent teardown: no second close_notify, no double socket close.
	if c.closed {
		c.close_socket()
		return
	}
	// Emit close_notify at most once, guarded separately from `closed`.
	if !c.close_notify_sent {
		c.close_notify_sent = true
		c.send_close_notify()
	}
	c.closed = true
	// Teardown is terminal: drop the app traffic secrets and the protectors' IVs (RFC 8446 §1.3.1/§7.5).
	c.hs.zeroize_app_secrets()
	wipe_record_protector(mut c.server_hs_cipher)
	wipe_record_protector(mut c.client_hs_cipher)
	wipe_record_protector(mut c.server_app_cipher)
	wipe_record_protector(mut c.client_app_cipher)
	c.close_socket()
}

// wipe_on_failure destroys every secret a failed handshake may have derived: the
// core's key-schedule material plus this adapter's record protectors.
fn (mut c Conn) wipe_on_failure() {
	c.hs.abort()
	wipe_record_protector(mut c.server_hs_cipher)
	wipe_record_protector(mut c.client_hs_cipher)
	wipe_record_protector(mut c.server_app_cipher)
	wipe_record_protector(mut c.client_app_cipher)
}

// send_failure_alert emits the fatal alert for a dead handshake (RFC 8446 §6),
// picking the encryption level from the ciphers actually installed.
fn (mut c Conn) send_failure_alert() {
	if c.peer_terminated {
		return
	}
	desc := c.fail_alert or { c.hs.failure_alert() }
	payload := handshake.new_alert(desc).encode()
	// A protector is initialized exactly when its IV is the full nonce base.
	if c.client_app_cipher.iv.len == aead_nonce_len {
		enc := c.client_app_cipher.encrypt_record(.alert, payload) or { return }
		c.write_records([enc]) or {}
		return
	}
	if c.client_hs_cipher.iv.len == aead_nonce_len {
		enc := c.client_hs_cipher.encrypt_record(.alert, payload) or { return }
		c.write_records([enc]) or {}
		return
	}
	c.write_records([new_record(.alert, payload)]) or {}
}

// close_socket closes the TCP transport exactly once; `closed` alone cannot be
// the once-guard, since handle_alert marks closed while leaving the socket open.
fn (mut c Conn) close_socket() {
	if c.sock == unsafe { nil } || c.sock_closed {
		return
	}
	c.sock.close() or {}
	c.sock_closed = true
}

// send_close_notify writes a close_notify alert, encrypted with the application
// keys (RFC 8446 §6.1/§A.4); a plaintext alert would violate §6, so send nothing.
fn (mut c Conn) send_close_notify() {
	if c.sock == unsafe { nil } {
		return
	}
	if c.hs.state() != .connected {
		return
	}
	notify := handshake.new_alert(.close_notify)
	enc := c.client_app_cipher.encrypt_record(.alert, notify.encode()) or {
		return
	}
	c.write_records([enc]) or {}
}

// negotiated_alpn returns the negotiated ALPN protocol, if any.
pub fn (c Conn) negotiated_alpn() string {
	return c.negotiated_alpn
}
