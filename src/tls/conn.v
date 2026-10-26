// Copyright (c) 2026 blackshirt.
//
// conn.v is the public entry point of this TLS stack: dial() runs the TLS 1.3
// handshake and Conn exposes the protected stream over TCP — RFC 8446 §5 record
// framing, batched flights, reassembly of split records. The handshake core
// (tls.handshake) stays transport-neutral; recordless QUIC (RFC 9001 §4) shares it.
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

// handshake_deadline_multiplier bounds the whole handshake at this multiple of the
// per-operation socket timeout: per-read timeouts alone cannot stop a slow-loris
// peer that dribbles valid bytes just under each timeout and stalls the flight forever.
const handshake_deadline_multiplier = 4

// max_server_name_len bounds the SNI/verification name at the DNS ceiling (RFC 1035
// §2.3.4), so a hostile or mistyped name cannot overflow the u16 SNI vector encoding.
const max_server_name_len = 253

// max_handshake_recv_buf_len caps unconsumed framed bytes during the handshake: one
// maximal ciphertext record plus one socket-read slack (a compliant server's flight
// is fully consumed before the next read). Post-handshake streaming coalesces freely,
// so the cap is enforced only while dial() is handshaking (deadline_ms != 0).
const max_handshake_recv_buf_len = 2 * max_ciphertext_record_len + record_header_len + recv_read_size

// max_handshake_flight_records bounds every record do_handshake consumes. A
// compliant flight stays far below it; a peer flooding state-neutral but
// decryptable records meets a deterministic cap instead of only the caller's
// wall-clock deadline (RFC 8446 §4 orders the flight; nothing legit repeats it).
const max_handshake_flight_records = 64

// epoch_ms is the module's epoch-ms clock, assembled from one time.now() snapshot;
// this V build has no time.millis() getter (unix_milli(i64) is a constructor).
fn epoch_ms() i64 {
	now := time.now()
	return now.unix() * 1000 + i64(now.nanosecond) / i64(time.millisecond)
}

// max_tolerated_records_per_read bounds the records one Conn.read() may skip
// without delivering data — zero-length padding and post-handshake messages are
// legal (RFC 8446 §5.2/§4.6), but a verified flood must not starve the caller.
// The cap mirrors Go crypto/tls maxUserRecords.
const max_tolerated_records_per_read = 100

// max_post_handshake_messages_per_record bounds the complete messages one
// handshake-inner-type record may deliver to handle_post_handshake: a maximal
// record packs ~3300 eight-byte KeyUpdate or ticket bodies, each costing a
// rekey (plus a KeyUpdate response write), so the bound fires before that work.
const max_post_handshake_messages_per_record = 1000

// Conn is a TLS 1.3 client connection over TCP, built only by dial(). read() and
// write() take separate mutexes; the lock order is always rlock → wlock.
@[noinit]
pub struct Conn {
mut:
	// Transport and transport-neutral handshake adapter.
	sock &net.TcpConn           // underlying TCP transport
	hs   handshake.TLSHandshake // TLS handshake contract for the record adapter

	// The four TLSProtections are the record layer's own state; the core never sees them.
	server_hsk_cipher TLSProtection // AEAD state for records the server sends under handshake keys
	client_hsk_cipher TLSProtection // AEAD state for records we send under handshake keys
	server_app_cipher TLSProtection // AEAD state for records the server sends under app keys
	client_app_cipher TLSProtection // AEAD state for records we send under app keys

	// session_tickets holds the NewSessionTicket backlog the core parses but does
	// not keep; exceeding it drops the ticket, never the connection (RFC 8446 §4.6.1).
	session_tickets []handshake.NewSessionTicket
	// Holds decrypted handshake bytes when a post-handshake message (e.g. a
	// NewSessionTicket) spans records; handle_post_handshake keeps the
	// incomplete tail for the next record (RFC 8446 §5.2).
	post_hsk_buf []u8
	// Set on processing a peer KeyUpdate, cleared by any delivered traffic: RFC
	// 8446 §4.5 forbids two in a row, so a second aborts before its rekey is
	// paid for — cutting rekey amplification at the first message.
	peer_key_update bool

	// Read-side buffers: socket bytes are framed into records, then decrypted
	// application bytes are delivered to callers.
	// Fixed-size, connection-lifetime staging buffer filled directly by each
	// sock.read in read_raw_record. Received bytes are appended to recv_buf before
	// it is reused, avoiding a fresh temporary allocation for every socket read.
	sock_buf []u8
	// TCP is a byte stream: a socket read may return part of a record or several
	// records. read_raw_record appends bytes here and parses one complete framed
	// record at a time, leaving any following record bytes for the next call.
	recv_buf []u8
	// Index of the first unread byte in recv_buf. Bytes before it belong to
	// records already parsed; advancing this index avoids shifting the remaining
	// bytes on every record. compact_recv_buf reclaims the prefix when appropriate.
	recv_pos int
	// Keeps the unread remainder of a decrypted application-data record when the
	// caller's read buffer is smaller than that record. Conn.read drains this
	// before reading/decrypting another record, preserving byte order.
	app_buf []u8
	// Index of the first undelivered plaintext byte in app_buf. Like recv_pos,
	// this lets partial reads advance without copying the remaining tail each time.
	app_pos int

	// Connection lifecycle and sticky read failure.
	// closed marks the terminal protocol state after a local close or peer alert.
	// Fatal alerts still surface through fatal_error rather than as clean EOF.
	closed bool
	// Set before attempting the local close_notify write, preventing retries if
	// that write fails or close() is called again.
	close_notify_sent bool
	// Tracks whether close_tcp_socket() has called sock.close(). This is separate
	// from `closed`, because handle_alert marks the protocol closed but leaves
	// the socket for close() to release.
	sock_closed bool
	// Sticky fatal read error; returned again on subsequent read() calls instead
	// of appearing as a clean EOF.
	fatal_error string

	// Serialize access to the read and write state; read() may acquire wlock
	// while handling a peer alert, so the global order is rlock then wlock.
	rlock &sync.Mutex // serializes read() and every read-cipher/recv_buf mutation; both locks are exclusive mutexes, not RwLock read sides, because each path rewrites AEAD sequence numbers
	wlock &sync.Mutex // serializes write() and every write-cipher mutation

	// Negotiated connection identity and protocol.
	negotiated_alpn string // server's ALPN pick — always one of HandshakeOptions.alpn (the handshake aborts otherwise), '' if none
	server_name     string // SNI value sent and the name the certificate was checked against

	// Failure-alert plumbing, used only by send_failure_alert on a dead handshake.
	// Suppresses a fatal-alert response when the peer has already terminated.
	peer_terminated bool
	fail_alert      ?handshake.AlertDescription // adapter-classified alert; when unset, send_failure_alert falls back to the core's hs.failure_alert()

	// Absolute monotonic-ms deadline bounding the whole handshake; 0 after dial
	// succeeds (and in @[noinit] defaults) so Conn.read() is never deadline-bound.
	deadline_ms i64
	// Per-operation socket timeout applied to both directions at dial. The
	// handshake loop shrinks the read side toward the deadline; dial restores
	// this value on success so Conn.read() keeps the caller's own bound.
	sock_timeout time.Duration
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
	// A name with stray whitespace would travel verbatim into SNI and into hostname
	// verification — reject it before the socket opens rather than dial ambiguously.
	if server_name != server_name.trim_space() {
		return error('tls: server name has stray whitespace')
	}
	if server_name.len > max_server_name_len {
		return error('tls: server name exceeds ${max_server_name_len} characters')
	}

	// Open the TCP transport first: every later failure path must close it.
	mut sock := net.dial_tcp(address)!
	// Apply one bounded timeout to both directions (caller's value, else 30s).
	timeout := if config.timeout > 0 { config.timeout } else { 30 * time.second }
	sock.set_read_timeout(timeout)
	sock.set_write_timeout(timeout)
	// Absolute bound for the whole handshake (see handshake_deadline_multiplier).
	// The socket timeout is ns-based, so it is converted to ms to match epoch_ms().
	deadline_ms := epoch_ms() + i64(timeout) * handshake_deadline_multiplier / i64(time.millisecond)

	handshake_options := config.hsk_options
	mut validator := if configured := handshake_options.validator {
		configured
	} else if config.insecure_skip_verify {
		// The named escape hatch: no roots are consulted, verification is skipped.
		pki.new_insecure_validator()
	} else {
		// Trust anchors: an explicit root_cas wins, else the system bundle.
		mut store := pki.new_trust_store()
		if roots := config.root_cas {
			store = roots
		} else {
			// Fatal, but close the socket so a dial error leaks no fd.
			store = pki.system_root_cas() or {
				sock.close() or {}
				return err
			}
		}
		pki.new_validator(store)
	}
	if config.min_rsa_bits > 0 {
		validator.set_min_rsa_bits(config.min_rsa_bits)
	}
	options := handshake.HandshakeOptions{
		alpn:                 handshake_options.alpn.clone()
		validator:            validator
		key_share_group:      handshake_options.key_share_group
		supported_groups:     handshake_options.supported_groups.clone()
		cipher_suites:        handshake_options.cipher_suites.clone()
		signature_algorithms: handshake_options.signature_algorithms.clone()
		legacy_session_id:    handshake_options.legacy_session_id.clone()
		random:               handshake_options.random.clone()
	}

	mut hs := handshake.new_tls_handshake(server_name, options) or {
		sock.close() or {}
		return err
	}

	mut conn := &Conn{
		sock:              sock
		hs:                hs
		session_tickets:   []handshake.NewSessionTicket{cap: 4}
		sock_buf:          []u8{len: recv_read_size} // reused by every socket read for this connection
		recv_buf:          []u8{cap: 2 * (max_ciphertext_record_len + record_header_len)} // one frame parsing, one arriving
		recv_pos:          0
		app_buf:           []u8{cap: max_plaintext_record_len} // one full plaintext record
		app_pos:           0
		closed:            false
		close_notify_sent: false
		sock_closed:       false
		fatal_error:       ''
		deadline_ms:       deadline_ms
		sock_timeout:      timeout
		rlock:             sync.new_mutex()
		wlock:             sync.new_mutex()
		negotiated_alpn:   ''
		server_name:       server_name
	}

	// The single handshake-phase teardown choke-point: every do_handshake() failure —
	// whether it pinned an alert via classify_failure or is an internal `!` surfacing the
	// core's default — funnels here to send the classified fatal alert (RFC 8446 §6),
	// destroy secrets, and close the socket. It stays a safety net even though the
	// classified sites already pinned fail_alert, so no future `return` path can leak material.
	conn.do_handshake() or {
		conn.send_failure_alert()
		conn.destroy_on_failure()
		sock.close() or {}
		return err
	}
	// The ALPN pick is exposed only after the handshake proved it was offered (RFC 7301 §3.1).
	conn.negotiated_alpn = conn.hs.negotiated_alpn()
	// Retire the handshake-only markers: the framing cap and deadline guard key
	// off deadline_ms, and steady-state reads must obey only the per-op timeout.
	conn.deadline_ms = 0
	// do_handshake shrinks the read timeout toward the handshake deadline; a
	// successful dial must hand the caller the full per-operation timeout again.
	sock.set_read_timeout(conn.sock_timeout)
	return conn
}

// do_handshake drives the full client flight over TCP: frame the ClientHello
// (+dummy CCS), then feed records into the core until it reports .connected (§5.1).
fn (mut c Conn) do_handshake() ! {
	ch := c.hs.create_client_hello()!
	// RFC 8446 §5.1: the initial ClientHello must fit exactly one record; an
	// oversized locally built one is our own fault, so abort before framing it.
	if ch.len > max_plaintext_record_len {
		return c.abort_connection(.internal_error, 'tls: ClientHello exceeds one record (${ch.len} > ${max_plaintext_record_len} bytes)')
	}
	c.write_records([new_record(.handshake, ch), change_cipher_spec()])!

	mut ccs_seen := 0
	mut flight_records := 0
	for c.hs.state() != .connected {
		// Cheap early check; the fill loop enforces the same deadline per read.
		remaining_ms := c.deadline_ms - epoch_ms()
		if remaining_ms <= 0 {
			return c.classify_failure(.unexpected_message, 'tls: handshake deadline exceeded (unexpected_message)')
		}
		// Shrink the per-read timeout to the deadline left, so the read itself
		// surfaces as the deadline error instead of racing a raw timeout.
		if remaining_ms * i64(time.millisecond) < i64(c.sock_timeout) {
			c.sock.set_read_timeout(remaining_ms * time.millisecond)
		}
		rec := c.read_raw_record()!
		flight_records++
		if flight_records > max_handshake_flight_records {
			return c.classify_failure(.unexpected_message, 'tls: too many records in the server flight (unexpected_message)')
		}

		match rec.content_type {
			.change_cipher_spec {
				// The peer's dummy CCS carries no meaning in TLS 1.3 — drop it (RFC 8446 §5).
				ccs_seen = validate_compat_ccs(rec.payload, ccs_seen) or {
					return c.classify_failure(.unexpected_message, err.msg())
				}
				continue
			}
			.alert {
				// After ServerHello, RFC 8446 §6 requires alerts to be encrypted — reject a plaintext one.
				if c.hs.state() != .wait_server_hello {
					return c.classify_failure(.unexpected_message, 'tls: unencrypted alert after ServerHello (unexpected_message)')
				}
				peer_alert := handshake.parse_alert(rec.payload) or {
					// A malformed alert record is a decode error, not our internal_error default.
					return c.classify_failure(.decode_error, 'tls: malformed alert record (decode_error): ${err.msg()}')
				}
				// The peer terminated of its own accord: never alert back (RFC 8446 §6).
				c.peer_terminated = true
				return error('tls: received alert ${peer_alert.description} (level=${peer_alert.level})')
			}
			.handshake {
				// Plaintext handshake records are legal only while the ServerHello is outstanding (§5.1/§6).
				if c.hs.state() != .wait_server_hello {
					return c.classify_failure(.unexpected_message, 'tls: unencrypted handshake record after ServerHello (unexpected_message)')
				}
				msgs := c.hs.receive_msgs_at_level(.initial, rec.payload)!
				// The record must have yielded exactly one complete message (§5.1).
				if c.hs.record_unconsumed_bytes(.initial) != 0 {
					return c.classify_failure(.unexpected_message, 'tls: misframed ServerHello record: ${c.hs.record_unconsumed_bytes(.initial)} leftover byte(s) (unexpected_message)')
				}
				if msgs.len == 0 && c.hs.state() == .wait_server_hello {
					return c.classify_failure(.unexpected_message, 'tls: incomplete ServerHello at record boundary (unexpected_message)')
				}
				if c.hs.available_secret_phases().handshake {
					// The core now holds both directions' handshake traffic secrets (and has
					// cached the record keys); install this side's ciphers. Keyed on real secret
					// availability rather than the .wait_encrypted_extensions state, so the
					// decision shares the core's single readiness query with the QUIC adapter.
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
					return c.classify_failure(.unexpected_message, 'tls: unexpected encrypted record before ServerHello (unexpected_message)')
				}
				dec := c.server_hsk_cipher.decrypt_record(rec) or {
					// Mirror the read() path's classification: a record that will not open under
					// the handshake keys is a TLS-integrity failure the peer caused, so it must
					// surface bad_record_mac/record_overflow, not the stale internal_error default.
					if err.msg().contains('sequence limit') {
						return c.classify_failure(.record_overflow, err.msg())
					}
					if err.msg().contains('AEAD decryption failed') {
						return c.classify_failure(.bad_record_mac, err.msg())
					}
					return c.classify_failure(.unexpected_message, err.msg())
				}
				// Inner-type routing is record-layer policy; the core has no ContentType concept.
				match dec.content_type {
					.handshake {
						// §5.1: handshake content must carry message bytes; an empty inner
						// payload advances no state and would only burn AEAD opens.
						if dec.plaintext.len == 0 {
							return c.classify_failure(.unexpected_message, 'tls: empty handshake record under handshake keys (unexpected_message)')
						}
						msgs := c.hs.receive_msgs_at_level(.handshake, dec.plaintext)!
						for m in msgs {
							// The client's Finished travels under the client handshake keys (RFC 8446 §7.1).
							enc := c.client_hsk_cipher.encrypt_record(.handshake, m.msg())!
							c.write_records([enc])!
						}
					}
					.alert {
						// RFC 8446 §6: the server may surface a fatal alert under the handshake keys.
						peer_alert := handshake.parse_alert(dec.plaintext) or {
							// A malformed encrypted alert body is a decode error, not the stale internal_error.
							return c.classify_failure(.decode_error, 'tls: malformed encrypted alert (decode_error): ${err.msg()}')
						}
						if peer_alert.description == .close_notify {
							c.peer_terminated = true
							return error('tls: peer sent close_notify during handshake')
						}
						c.peer_terminated = true
						return error('tls: received alert ${peer_alert.description} during handshake')
					}
					else {
						// Only handshake and alert are legal here; anything else violates §5.6.
						return c.classify_failure(.unexpected_message, 'tls: unexpected content type in handshake phase: ${dec.content_type}')
					}
				}
			}
			else {
				return c.classify_failure(.unexpected_message, 'tls: unexpected record type ${rec.content_type} during handshake')
			}
		}
	}
	// The core verified the server Finished; install this adapter's post-handshake protection.
	c.install_application_ciphers()!
	// §4.6.1 lets the server coalesce a NewSessionTicket behind its Finished; the
	// core's drain stops at .connected, so take (and scrub) its buffered bytes.
	coalesced := c.hs.take_buffered_handshake_bytes()
	if coalesced.len > 0 {
		// handle_post_handshake failures already abort_connection; don't re-alert.
		c.handle_post_handshake(coalesced)!
	}
	// Nothing may protect or decrypt at the handshake level now, so the core may destroy its secrets (RFC 8446 §7.5).
	c.hs.zeroize_traffic_secrets(.handshake)!
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

// write_records serializes records into one buffer and writes the full batch,
// continuing after short writes. It returns only after all bytes are sent or an
// error occurs, so callers do not need a partial byte count (RFC 8446 §5).
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
	// sock_buf is refilled in place, so a record arriving in TCP pieces costs no allocation.
	for {
		avail := c.recv_buf.len - c.recv_pos
		if avail >= record_header_len {
			// Peek the length field (offset 3) without consuming it; TCP can split records.
			payload_len := int(u16(c.recv_buf[c.recv_pos + 3]) << 8 | u16(c.recv_buf[c.recv_pos + 4]))
			if payload_len > max_ciphertext_record_len {
				c.fail_alert = .record_overflow
				return error('record: record length ${payload_len} exceeds maximum allowed ${max_ciphertext_record_len}')
			}
			total := record_header_len + payload_len
			if avail >= total {
				content_type_from_u8(c.recv_buf[c.recv_pos]) or {
					c.fail_alert = .unexpected_message
					return err
				}
				// Parse directly over the live recv_buf; read_bytes copies the payload out.
				mut r := wire.new_reader(c.recv_buf[c.recv_pos..c.recv_pos + total])
				c.recv_pos += total
				rec := read_record(mut r)!
				c.compact_recv_buf()
				return rec
			} else if c.deadline_ms != 0 && avail > max_handshake_recv_buf_len {
				// Handshake-phase only: dribbled bytes must not grow the framing
				// buffer without bound while no record completes.
				c.fail_alert = .unexpected_message
				return error('record: ${avail} unconsumed bytes exceed the handshake framing bound ${max_handshake_recv_buf_len}')
			}
		}
		if c.sock == unsafe { nil } {
			return error('tls: connection closed (no socket available to read further records)')
		}
		// The deadline must also bite inside an incomplete record: a slow-loris
		// dribble never completes one, so this fill loop is where the stall lives.
		// Cap each read at the time left; a read ending past it reports the deadline.
		mut read_wait_ms := i64(c.sock_timeout) / i64(time.millisecond)
		if c.deadline_ms != 0 {
			remaining_ms := c.deadline_ms - epoch_ms()
			if remaining_ms <= 0 {
				return c.classify_failure(.unexpected_message, 'tls: handshake deadline exceeded (unexpected_message)')
			}
			if remaining_ms < read_wait_ms {
				read_wait_ms = remaining_ms
				c.sock.set_read_timeout(read_wait_ms * time.millisecond)
			}
		}
		n := c.sock.read(mut c.sock_buf) or {
			if c.deadline_ms != 0 && epoch_ms() >= c.deadline_ms {
				return c.classify_failure(.unexpected_message, 'tls: handshake deadline exceeded (unexpected_message)')
			}
			return error('tls: connection closed while reading record: ${err}')
		}
		if n == 0 {
			return error('tls: connection closed while reading record')
		}
		c.recv_buf << c.sock_buf[..n]
	}
	// Every branch inside the loop returns or keeps looping; this fail-closed tail
	// exists only so no future edit can fall out of the loop unreturned.
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

// clear_app_buf zeroes then drops the staged-but-undelivered application
// plaintext, so freed buffer memory never retains decrypted bytes (§7.5 spirit).
fn (mut c Conn) clear_app_buf() {
	for i in 0 .. c.app_buf.len {
		c.app_buf[i] = 0
	}
	c.app_buf.clear()
	c.app_pos = 0
}

// tls_protection_from_keys instantiates one direction's record protection from
// the core's derived key and IV bytes; sequence numbers restart at 0 per generation (§5.3).
fn tls_protection_from_keys(suite handshake.CipherSuite, key []u8, iv []u8) !TLSProtection {
	aead := handshake.new_aead_for_suite(suite, key)!
	return new_tls_protection(aead, iv)!
}

// install_handshake_ciphers builds both handshake-key record states from the
// core's record_traffic_keys(.handshake); called once after the ServerHello is fed.
fn (mut c Conn) install_handshake_ciphers() ! {
	ck, civ, sk, siv := c.hs.record_traffic_keys(.handshake)!
	suite := c.hs.negotiated_cipher_suite()
	c.client_hsk_cipher = tls_protection_from_keys(suite, ck, civ)!
	c.server_hsk_cipher = tls_protection_from_keys(suite, sk, siv)!
}

// install_application_ciphers builds both application-key record states from the
// core's record_traffic_keys(.application); called once at .connected.
fn (mut c Conn) install_application_ciphers() ! {
	ck, civ, sk, siv := c.hs.record_traffic_keys(.application)!
	suite := c.hs.negotiated_cipher_suite()
	c.client_app_cipher = tls_protection_from_keys(suite, ck, civ)!
	c.server_app_cipher = tls_protection_from_keys(suite, sk, siv)!
}

// rekeyed_write_cipher rebuilds only the write-side application state after the
// core updated the client secret (KeyUpdate); the read cipher is unchanged.
fn (mut c Conn) rekeyed_write_cipher() ! {
	ck, civ, _, _ := c.hs.record_traffic_keys(.application)!
	c.client_app_cipher = tls_protection_from_keys(c.hs.negotiated_cipher_suite(), ck, civ)!
}

// rekeyed_read_cipher rebuilds only the read-side application state after the
// core updated the server secret on receiving the peer's KeyUpdate.
fn (mut c Conn) rekeyed_read_cipher() ! {
	_, _, sk, siv := c.hs.record_traffic_keys(.application)!
	c.server_app_cipher = tls_protection_from_keys(c.hs.negotiated_cipher_suite(), sk, siv)!
}

// handle_alert processes an alert received after the handshake. It marks the
// connection closed and returns 0 for a clean close_notify, else an error.
fn (mut c Conn) handle_alert(payload []u8) !int {
	// read() may hold rlock while a concurrent write() owns the write cipher.
	// Preserve the connection's rlock -> wlock order before wiping shared state.
	c.wlock.lock()
	defer {
		c.wlock.unlock()
	}
	// Any alert is terminal: mark closed before decoding, even a malformed body.
	c.closed = true
	// Peer termination is final: drop the app traffic secrets and the protectors' IVs (RFC 8446 §1.3.1/§7.5).
	c.destroy_on_close()!
	// Scrub undelivered plaintext still staged for the caller (same rlock side).
	c.clear_app_buf()
	for i in 0 .. c.post_hsk_buf.len {
		c.post_hsk_buf[i] = 0
	}
	c.post_hsk_buf = []u8{}
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
			c.clear_app_buf()
		}
		return n
	}
	if c.closed {
		return 0
	}

	mut tolerated_records := 0
	for {
		rec := c.read_raw_record() or {
			alert := c.fail_alert or { handshake.AlertDescription.decode_error }
			return c.abort_connection(alert, err.msg())
		}
		match rec.content_type {
			.change_cipher_spec {
				// RFC 8446 §5: a CCS record is illegal once application keys are in use.
				return c.abort_connection(.unexpected_message, 'tls: received change_cipher_spec record after handshake (unexpected_message)')
			}
			.alert {
				// RFC 8446 §6: post-handshake alerts must be encrypted; a plaintext one is rejected.
				return c.abort_connection(.unexpected_message, 'tls: received unencrypted alert post-handshake (must be encrypted)')
			}
			.application_data {
				mut dec := c.server_app_cipher.decrypt_record(rec) or {
					if err.msg().contains('sequence limit') {
						return c.abort_connection(.record_overflow, err.msg())
					}
					if err.msg().contains('AEAD decryption failed') {
						return c.abort_connection(.bad_record_mac, err.msg())
					}
					return c.abort_connection(.unexpected_message, err.msg())
				}
				match dec.content_type {
					.application_data {
						// Application traffic of any length breaks a KeyUpdate run (§4.5).
						c.peer_key_update = false
						if dec.plaintext.len == 0 {
							// Zero-length records are legal (padding only), but a verified flood
							// must not spin this loop forever (max_tolerated_records_per_read).
							tolerated_records++
							if tolerated_records > max_tolerated_records_per_read {
								return c.abort_connection(.unexpected_message, 'tls: too many skipped records in one read (unexpected_message)')
							}
							continue
						}
						n := copy(mut buf, dec.plaintext)
						if n < dec.plaintext.len {
							c.app_buf << dec.plaintext[n..]
						}
						// Scrub the decrypted staging copy the moment it is fully
						// delivered; the undelivered remainder is scrubbed when
						// app_buf drains (§7.5 spirit: no plaintext left in freed memory).
						for i in 0 .. dec.plaintext.len {
							dec.plaintext[i] = 0
						}
						return n
					}
					.alert {
						// Post-handshake alerts arrive encrypted as the inner type (RFC 8446 §5.1/§6).
						return c.handle_alert(dec.plaintext)
					}
					.handshake {
						// NewSessionTicket/KeyUpdate must not surface as application data, but a
						// record flood of them is the same starvation vector as empty padding.
						tolerated_records++
						if tolerated_records > max_tolerated_records_per_read {
							return c.abort_connection(.unexpected_message, 'tls: too many skipped records in one read (unexpected_message)')
						}
						c.handle_post_handshake(dec.plaintext)!
						continue
					}
					else {
						return c.abort_connection(.unexpected_message, 'tls: unexpected inner content type ${dec.content_type}')
					}
				}
			}
			else {
				return c.abort_connection(.unexpected_message, 'tls: unexpected record type ${rec.content_type} after handshake')
			}
		}
	}
	// The loop only exits through the explicit returns inside the match arms or an
	// error propagation; this fail-closed tail exists so no future path can fall out.
	return error('tls: unreachable')
}

// handle_post_handshake consumes NewSessionTicket and KeyUpdate messages from a
// decrypted post-handshake plaintext, reassembling fragments (RFC 8446 §5.2).
fn (mut c Conn) handle_post_handshake(data []u8) ! {
	// Check before appending so a hostile fragment cannot make the buffer exceed
	// the per-message cap, even transiently.
	max_buffered := record_header_len + handshake.max_handshake_message_len
	if data.len > max_buffered - c.post_hsk_buf.len {
		return c.abort_connection(.record_overflow, 'tls: post-handshake reassembly exceeds ${handshake.max_handshake_message_len} bytes without completing a message (record_overflow)')
	}
	c.post_hsk_buf << data
	mut messages_seen := 0
	for {
		msg := handshake.next_recordless_message(mut c.post_hsk_buf) or {
			return c.abort_connection(.decode_error, err.msg())
		}
		if msg.len == 0 {
			return // header or body still incomplete; wait for the next record
		}
		// Bound before the message is parsed, rekeyed, or answered, so the flood's
		// work is cut off at the cap rather than paid for one extra message.
		messages_seen++
		if messages_seen > max_post_handshake_messages_per_record {
			return c.abort_connection(.unexpected_message, 'tls: too many post-handshake messages in one record (unexpected_message)')
		}
		mut r := wire.new_reader(msg)
		msg_type, length := handshake.read_handshake_header(mut r) or {
			return c.abort_connection(.decode_error, err.msg())
		}
		body := r.read_bytes(length) or {
			return c.abort_connection(.decode_error, err.msg())
		}
		match msg_type {
			.new_session_ticket {
				ticket := handshake.parse_new_session_ticket(body) or {
					alert := if err.msg().contains('illegal_parameter') {
						handshake.AlertDescription.illegal_parameter
					} else {
						handshake.AlertDescription.decode_error
					}
					return c.abort_connection(alert, err.msg())
				}
				// Keep a bounded sample of the backlog; drop the overflow.
				if c.session_tickets.len < max_stored_session_tickets {
					c.session_tickets << ticket
				}
				// An accepted non-KeyUpdate message breaks the run (§4.5).
				c.peer_key_update = false
			}
			.key_update {
				// §4.5: "Clients and servers MUST NOT send more than one KeyUpdate
				// message in a row." Checked before parse and rekey so the violation is
				// terminal at zero derivation cost, not an endless HKDF-amplification loop.
				if c.peer_key_update {
					return c.abort_connection(.unexpected_message, 'tls: consecutive KeyUpdate from peer (unexpected_message)')
				}
				c.peer_key_update = true
				// §4.6.3: a recipient always advances its read keys on receiving a KeyUpdate.
				request_update := handshake.parse_key_update(body) or {
					alert := if body.len != 1 {
						handshake.AlertDescription.decode_error
					} else {
						handshake.AlertDescription.illegal_parameter
					}
					return c.abort_connection(alert, err.msg())
				}
				c.hs.record_update_read_traffic_keys() or {
					return c.abort_connection(.internal_error, err.msg())
				}
				// The core updated secrets only; swap in the new read cipher (seq restarts at 0, §5.3).
				c.rekeyed_read_cipher() or {
					return c.abort_connection(.internal_error, err.msg())
				}
				if request_update {
					c.send_key_update_response() or {
						return c.abort_connection(.internal_error, err.msg())
					}
				}
			}
			.certificate_request {
				// This client did not offer post_handshake_auth, so this request is forbidden.
				return c.abort_connection(.unexpected_message, 'tls: unexpected post-handshake CertificateRequest (unexpected_message)')
			}
			else {
				// RFC 8446 §4.6: any other message is a fatal unexpected_message error
				return c.abort_connection(.unexpected_message, 'tls: unexpected post-handshake message ${msg_type} (unexpected_message)')
			}
		}
	}
}

// abort_connection sends a best-effort fatal alert, destroys connection secrets,
// closes the socket, and makes the failure sticky for subsequent reads.
fn (mut c Conn) abort_connection(alert handshake.AlertDescription, message string) IError {
	c.wlock.lock()
	defer {
		c.wlock.unlock()
	}
	return c.abort_connection_locked(alert, message)
}

// abort_connection_locked terminates the connection while its write lock is
// already held, avoiding recursive locking from write() failure handling.
fn (mut c Conn) abort_connection_locked(alert handshake.AlertDescription, message string) IError {
	c.fail_alert = alert
	c.closed = true
	c.fatal_error = message
	c.send_failure_alert()
	c.destroy_on_failure()
	c.clear_app_buf()
	for i in 0 .. c.post_hsk_buf.len {
		c.post_hsk_buf[i] = 0
	}
	c.post_hsk_buf = []u8{}
	c.close_tcp_socket()
	return error(message)
}

// classify_failure records the alert the adapter must surface for a handshake-phase
// failure and returns the terminating error, so a call site cannot pin half of it.
// Unlike abort_connection, it deliberately does NOT tear down: every error
// propagates to dial()'s single teardown wrapper, which sends the pinned alert
// instead of the stale .internal_error fallback for an unset fail_alert.
fn (mut c Conn) classify_failure(alert handshake.AlertDescription, message string) IError {
	c.fail_alert = alert
	return error(message)
}

// write encrypts and sends application data.
@[direct_array_access]
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
	return c.write_application_data(data)
}

// write_application_data encrypts and sends application data while the caller
// holds wlock. Any failure is terminal because sequence numbers or stream bytes
// may already have advanced.
@[direct_array_access]
fn (mut c Conn) write_application_data(data []u8) !int {
	return c.write_application_data_inner(data) or {
		alert := if err.msg().contains('sequence limit') {
			handshake.AlertDescription.record_overflow
		} else {
			handshake.AlertDescription.internal_error
		}
		return c.abort_connection_locked(alert, 'tls: application write failed: ${err.msg()}')
	}
}

// write_application_data_inner performs record generation and socket writes.
// The caller holds wlock and owns terminal error handling.
@[direct_array_access]
fn (mut c Conn) write_application_data_inner(data []u8) !int {
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
// KeyUpdate under the current write keys and then updates them (§4.6.3).
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
// KeyUpdate with update_not_requested under the old write keys, then update them.
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
		c.close_tcp_socket()
		return
	}
	// Emit close_notify at most once, guarded separately from `closed`.
	if !c.close_notify_sent {
		c.close_notify_sent = true
		c.send_close_notify()
	}
	c.closed = true
	// Teardown is terminal: drop the app traffic secrets and the protectors' IVs (RFC 8446 §1.3.1/§7.5).
	c.destroy_on_close()!
	c.close_tcp_socket()
}

// wipe_protection_states zeroes this adapter's four record protectors; it is the
// single place the record layer's own key material is destroyed (RFC 8446 §7.5).
fn (mut c Conn) wipe_protection_states() {
	c.server_hsk_cipher.wipe()
	c.client_hsk_cipher.wipe()
	c.server_app_cipher.wipe()
	c.client_app_cipher.wipe()
}

// destroy_on_close is the terminal teardown for a closing connection: it drops the
// application traffic secrets once the handshake reached .connected (or the whole
// key schedule otherwise), then wipes this adapter's protectors, so no close path
// can clear one layer and forget the other (RFC 8446 §1.3.1/§7.5).
fn (mut c Conn) destroy_on_close() ! {
	if c.hs.state() == .connected {
		c.hs.zeroize_traffic_secrets(.application)!
	} else {
		c.hs.fail_and_zeroize_secrets()
	}
	c.wipe_protection_states()
}

// destroy_on_failure destroys every secret a failed handshake may have derived: the
// core's key-schedule material plus this adapter's record protectors. It runs after
// the fatal alert has been sent, so wiping the protectors cannot strand that alert.
fn (mut c Conn) destroy_on_failure() {
	c.hs.fail_and_zeroize_secrets()
	c.wipe_protection_states()
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
	if c.client_hsk_cipher.iv.len == aead_nonce_len {
		enc := c.client_hsk_cipher.encrypt_record(.alert, payload) or { return }
		c.write_records([enc]) or {}
		return
	}
	c.write_records([new_record(.alert, payload)]) or {}
}

// close_tcp_socket releases the TCP socket without sending TLS shutdown alerts.
// It is guarded separately because handle_alert marks closed but leaves it open.
fn (mut c Conn) close_tcp_socket() {
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

// Helpers
//

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
