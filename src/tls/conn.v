// Copyright (c) 2026 blackshirt.
//
// conn.v is the public entry point of this TLS stack: dial() opens a connection,
// runs the TLS 1.3 handshake (driving the handshake state machine, record layer,
// key schedule and PKI validation), and Conn exposes the protected stream via
// read/write/close. config.v holds the caller-facing options; dial_example.v shows
// the whole flow.
module tls

import net
import sync
import time

// max_stored_session_tickets bounds the NewSessionTicket backlog kept on the
// handshake. Resumption is unimplemented, so the queue is only diagnostic;
// without a cap a malicious server could stream tickets until the process
// exhausts memory (RFC 8446 §4.6.1 permits any number of tickets).
const max_stored_session_tickets = 32

// Conn is a TLS 1.3 client connection over TCP. The only way to build one is
// dial(), which supplies every field; @[noinit] prevents a half-initialized Conn.
//
// Concurrency: read() and write() are each guarded by their own mutex, so one
// goroutine may read while another writes (the Go crypto/tls model). The read
// path also mutates the write cipher when answering a KeyUpdate request, so that
// one write-side action takes wlock before touching client_app_cipher; the
// lock order is always rlock → wlock (close() follows the same order), which
// keeps the pair deadlock-free. Any other method is not safe to call
// concurrently with a close().
@[noinit]
pub struct Conn {
mut:
	sock              &net.TcpConn    // underlying TCP transport
	hs                ClientHandshake // handshake state machine, also holds the traffic keys
	recv_buf          []u8            // raw bytes read from the socket, framing not yet applied
	recv_pos          int             // start of unconsumed data in recv_buf (prefix is already parsed)
	read_scratch      []u8            // connection-lifetime scratch filled by sock.read in read_raw_record, so a record arriving in TCP pieces costs no allocation
	app_buf           []u8            // decrypted application bytes that didn't fit the caller's buffer
	app_pos           int             // start of undrained bytes in app_buf (mirrors recv_pos: draining advances the index instead of re-cloning the tail)
	closed            bool            // set once the connection is finished (close or fatal alert)
	close_notify_sent bool            // guards against sending close_notify twice
	fatal_error       string          // non-empty once a fatal alert/error closed the connection; re-surfaced by read()
	rlock             &sync.Mutex     // serializes read() and every read-cipher/recv_buf mutation; both locks are exclusive mutexes, not RwLock read sides, because each path rewrites AEAD sequence numbers
	wlock             &sync.Mutex     // serializes write() and every write-cipher mutation
	negotiated_alpn   string          // server's ALPN pick — always one of Config.alpn (the handshake aborts otherwise), '' if none
	server_name       string          // SNI value sent and the name the certificate was checked against
}

// dial connects to address (host:port), performs a TLS 1.3 handshake, and returns Conn.
// The server name falls back to the address host so SNI and certificate hostname
// verification still work when dialed by "host:port" alone.
pub fn dial(address string, config Config) !&Conn {
	// Prefer an explicit server_name; otherwise derive it from the dial address so
	// a bare "host:port" still supplies SNI and the hostname to verify against.
	server_name := if config.server_name.len > 0 {
		config.server_name
	} else {
		host_from_address(address)
	}

	// Open the TCP transport first: every later failure path must close the socket
	// it just acquired, so the handshake/validator steps below guard on `sock`.
	mut sock := net.dial_tcp(address)!
	// Apply one bounded timeout to both directions (caller's value, else 30s) so a
	// stalled peer cannot hang the handshake forever.
	timeout := if config.timeout > 0 { config.timeout } else { 30 * time.second }
	sock.set_read_timeout(timeout)
	sock.set_write_timeout(timeout)

	mut hs := new_client_handshake(server_name, config.alpn) or {
		sock.close() or {}
		return err
	}

	// Resolve trust anchors by precedence: an explicit root_cas wins, else the
	// process-wide cached system bundle is used — unless verification is skipped,
	// where an empty store is fine because the validator never consults it.
	mut store := new_trust_store()
	if roots := config.root_cas {
		store = roots
	} else if !config.insecure_skip_verify {
		// Loading the OS bundle can fail (missing file); that is fatal, but the
		// socket we already opened must be closed so a dial error leaks no fd.
		store = system_root_cas() or {
			sock.close() or {}
			return err
		}
	}
	validator := new_validator(store, config.insecure_skip_verify)

	mut conn := &Conn{
		sock:              sock
		hs:                hs
		recv_buf:          []u8{cap: 2 * (max_ciphertext_record_len + record_header_len)} // one frame parsing, one arriving
		recv_pos:          0
		read_scratch:      []u8{len: recv_read_size}           // reused by every socket read for this connection
		app_buf:           []u8{cap: max_plaintext_record_len}                      // one full plaintext record
		app_pos:           0
		closed:            false
		close_notify_sent: false
		fatal_error:       ''
		rlock:             sync.new_mutex()
		wlock:             sync.new_mutex()
		negotiated_alpn:   ''
		server_name:       server_name
	}

	// Run the full client flight; on failure close the socket (so an aborted
	// connection does not leak the fd) and propagate the error rather than
	// returning a half-connected Conn that would misbehave on read.
	conn.do_handshake(validator) or {
		sock.close() or {}
		return err
	}
	// Copy the ALPN pick onto the public field only now the handshake has proven
	// the server's choice was offered (RFC 7301 §3.1 check lives in the state machine).
	conn.negotiated_alpn = conn.hs.negotiated_alpn
	return conn
}

// host_from_address extracts the host part of a dial address ("host:port" or
// "[ipv6]:port") so a bare address can still supply the SNI name and hostname
// against which the peer certificate is verified.
fn host_from_address(address string) string {
	// Bracketed form is an IPv6 literal: return the inner address, or the string
	// unchanged when there is no closing ']' (it was not really bracketed).
	if address.starts_with('[') {
		end := address.index(']') or { return address }
		return address[1..end]
	}
	// host:port — split on the LAST colon so the port separator is removed while
	// any earlier structure in the string is preserved as part of the host.
	if colon := address.last_index(':') {
		return address[..colon]
	}
	// No colon at all: the entire string is already just a host (e.g. "localhost").
	return address
}

// do_handshake drives the full client flight over TCP: frame the ClientHello
// (+dummy CCS), then feed every incoming record into the state machine until it
// reports .connected. A loop, because the server flight can interleave dummy CCS
// records, plaintext alerts, or a whole HelloRetryRequest round trip at any
// point. Framing and serialization live in tcp_transport.v; the core only ever
// sees raw messages, so the encrypt/decrypt calls below are the record-layer
// bridge between the two.
fn (mut c Conn) do_handshake(validator Validator) ! {
	ch := c.hs.create_client_hello()!
	c.write_records([new_record(.handshake, ch), change_cipher_spec()])!

	mut ccs_seen := 0
	for c.hs.state != .connected {
		rec := c.read_raw_record()!

		match rec.content_type {
			.change_cipher_spec {
				// The peer's middlebox-compatibility dummy CCS carries no protocol
				// meaning in TLS 1.3 — accept and drop it (RFC 8446 §5), bounded by
				// validate_compat_ccs.
				ccs_seen = validate_compat_ccs(rec.payload, ccs_seen)!
				continue
			}
			.alert {
				// A plaintext alert is only plausible before the server installs
				// its handshake keys (a reject alert for our ClientHello). After
				// ServerHello, RFC 8446 §6 requires alerts to be encrypted: an
				// outer plaintext alert then is injected/unauthenticated and must
				// be rejected as unexpected_message, not acted on.
				if c.hs.state != .wait_server_hello {
					return error('tls: unencrypted alert after ServerHello (unexpected_message)')
				}
				peer_alert := parse_alert(rec.payload)!
				return error('tls: received alert ${peer_alert.description} (level=${peer_alert.level})')
			}
			.handshake {
				followups, sh := c.hs.process_server_hello(rec.payload)!
				if sh.is_hello_retry_req {
					// Frame the retry ClientHello and repeat the dummy CCS, exactly
					// as for the initial hello (App. D.4).
					mut out := []Record{}
					for m in followups {
						out << new_record(m.content_type, m.msg)
					}
					out << change_cipher_spec()
					c.write_records(out)!
					continue
				}
				// Normal ServerHello processed; wait for encrypted handshake records
			}
			.application_data {
				// Once the server installs its handshake keys, everything it sends —
				// including the rest of the flight — is wrapped with outer type
				// application_data; the true type is recovered from the inner
				// plaintext when decrypted (RFC 8446 §5.1/§5.2). Before the
				// ServerHello installs those keys no encrypted record can be
				// authentic, so an injected one must be rejected rather than fed
				// to a not-yet-initialized cipher state.
				if c.hs.state == .start || c.hs.state == .wait_server_hello {
					return error('tls: unexpected encrypted record before ServerHello (unexpected_message)')
				}
				c.hs.feed_encrypted_record(rec)!
				fins := c.hs.process_reassembled_messages(&validator)!
				if fins.len > 0 {
					// The only handshake-phase message the client sends once the server
					// keys are up is its Finished, which travels under the client
					// handshake keys (RFC 8446 §7.1). Installing the application ciphers
					// in the core did not touch this write cipher, so the record sequence
					// and nonce are byte-identical to the pre-refactor path.
					mut encs := []Record{}
					for m in fins {
						encs << c.hs.client_hs_cipher.encrypt_record(m.content_type, m.msg)!
					}
					c.write_records(encs)!
				}
			}
			else {
				return error('tls: unexpected record type ${rec.content_type} during handshake')
			}
		}
	}
}

// handle_alert processes an alert received after the handshake. It marks the
// connection closed and returns 0 for a clean close_notify, else an error.
fn (mut c Conn) handle_alert(payload []u8) !int {
	// Any alert is terminal for this direction, so mark closed before decoding —
	// even a malformed alert body must not leave the Conn looking usable.
	c.closed = true
	// Peer-initiated termination is as final as close(): drop the application
	// traffic secrets so captured application traffic cannot be decrypted later
	// by a memory compromise (RFC 8446 §1.3.1/§7.5). The triggering record was
	// already decrypted before this handler ran, so the read cipher is not needed.
	c.hs.zeroize_app_secrets()
	peer_alert := parse_alert(payload) or {
		// Malformed alert body is itself fatal: pin a sticky error so subsequent
		// read() calls re-report it rather than returning a clean EOF (0).
		c.fatal_error = 'tls: received malformed alert'
		return error(c.fatal_error)
	}
	// close_notify is the one clean-shutdown signal: return 0, the same value a
	// normal EOF read yields, so callers treat it as orderly end-of-stream.
	if peer_alert.description == .close_notify {
		return 0
	}
	// Every other description is fatal per RFC 8446 §6; surface the peer's code verbatim.
	// Pin it as sticky so a later read() cannot mistake the closed stream for
	// an orderly close_notify (returns the error, never 0).
	c.fatal_error = 'tls: received alert ${peer_alert.description}'
	return error(c.fatal_error)
}

// read decrypts application data into buf. Returns bytes read (0 on clean close).
pub fn (mut c Conn) read(mut buf []u8) !int {
	// Serialize the whole read path: recv_buf, the server read cipher and the
	// sticky error below are all read-modify state.
	c.rlock.lock()
	defer {
		c.rlock.unlock()
	}
	if buf.len == 0 {
		return 0
	}
	// A fatal alert (or malformed alert) is sticky: report it on every read after
	// the first, never 0, so a caller retrying after an error cannot mistake a
	// truncated stream for an orderly close_notify.
	if c.fatal_error != '' {
		return error(c.fatal_error)
	}
	// A decrypted record can hold more than the caller's buffer; leftovers are
	// drained first so no plaintext is dropped or reordered. app_pos indexes
	// the leftover instead of slicing a fresh clone per call, so draining one
	// record through a small caller buffer costs one memcpy per byte handed
	// over, not a quadratic cascade of tail copies.
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
				// RFC 8446 §5: once application keys are in use, a CCS record is
				// illegal and the receiver MUST abort with fatal unexpected_message.
				// Tolerating it post-handshake would let an off-path attacker
				// inject plaintext records the peer never agreed to receive.
				return error('tls: received change_cipher_spec record after handshake (unexpected_message)')
			}
			.alert {
				// RFC 8446 §6: alerts after handshake keys are established MUST be
				// encrypted; a plaintext outer alert here is illegal and rejected to
				// prevent plaintext alert injection.
				return error('tls: received unencrypted alert post-handshake (must be encrypted)')
			}
			.application_data {
				dec := c.hs.server_app_cipher.decrypt_record(rec)!
				match dec.content_type {
					.application_data {
						if dec.plaintext.len == 0 {
							// Zero-length records are legal (padding only) and carry no
							// data; keep looping until real bytes or an alert arrives.
							continue
						}
						n := copy(mut buf, dec.plaintext)
						if n < dec.plaintext.len {
							c.app_buf << dec.plaintext[n..]
						}
						return n
					}
					.alert {
						// Post-handshake alerts are encrypted, arriving as the inner
						// content type of an application_data record (RFC 8446 §5.1/§6).
						return c.handle_alert(dec.plaintext)
					}
					.handshake {
						// NewSessionTicket/KeyUpdate: asynchronous post-handshake
						// messages that must not surface as application data.
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
// decrypted post-handshake plaintext.
fn (mut c Conn) handle_post_handshake(data []u8) ! {
	// Loop while complete 4-byte-headered messages remain. Unlike the handshake
	// phase there is no reassembly buffer across records, so a message split over
	// two records surfaces as a truncation error — acceptable because these
	// messages are sent one-per-record in practice (§5.2 permits, not requires, splitting).
	mut buf := data.clone()
	for buf.len >= 4 {
		mut r := new_reader(buf)
		msg_type, length := parse_handshake_header(mut r)!
		if buf.len < 4 + length {
			return error('tls: truncated post-handshake message')
		}
		body := buf[4..4 + length].clone()
		buf = buf[4 + length..].clone()
		match msg_type {
			.new_session_ticket {
				ticket := parse_new_session_ticket(body)!
				// A server may stream NewSessionTicket messages endlessly; since
				// resumption is unimplemented the backlog is unusable anyway, so
				// keep a bounded sample and drop the overflow instead of letting
				// an unbounded allocation grow over a long-lived connection.
				if c.hs.session_tickets.len < max_stored_session_tickets {
					c.hs.session_tickets << ticket
				}
			}
			.key_update {
				// §4.6.3: a recipient always advances its read keys on receiving a
				// KeyUpdate; request_update only decides whether a response is owed.
				request_update := parse_key_update(body)!
				c.hs.update_read_traffic_keys()!
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
	if buf.len > 0 {
		return error('tls: truncated post-handshake message header (${buf.len} bytes)')
	}
}

// write encrypts and sends application data.
pub fn (mut c Conn) write(data []u8) !int {
	// Serialize against other writers and against the read path's KeyUpdate
	// response, both of which mutate client_app_cipher and its sequence number.
	c.wlock.lock()
	defer {
		c.wlock.unlock()
	}
	// Refuse to encrypt onto a finished connection: writing after close_notify
	// would hand the peer data it has already promised to stop reading.
	if c.closed {
		return error('tls: connection closed')
	}
	// Application keys exist only once connected; gate on the state machine rather
	// than trusting caller ordering.
	if c.hs.state != .connected {
		return error('tls: handshake not complete')
	}
	// Chunk to max_plaintext_record_len (2^14): TLS forbids larger plaintext
	// records (RFC 8446 §5.1), so one write() may emit many encrypted records.
	mut offset := 0
	mut batch := []Record{}
	mut batch_len := 0
	for offset < data.len {
		// §5.5 sender obligation: a key generation protects at most
		// record_seq_limit records, and the KeyUpdate that rotates it is itself
		// one more record encrypted under the old key. Triggering one slot early
		// reserves that final slot for the KeyUpdate notice: waiting until
		// seq_num actually reaches the limit would leave force_write_rekey unable
		// to encrypt its own notice, since encrypt_record's §5.5 guard rejects
		// seq_num >= record_seq_limit. Checking at every record boundary means
		// even a single write() spanning the limit rekeys instead of wearing out
		// the AEAD key.
		if c.hs.client_app_cipher.seq_num >= record_seq_limit - 1 {
			// Flush the pending batch first: the records below the limit were
			// encrypted under the current key and must precede its KeyUpdate
			// notice on the wire.
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
		enc := c.hs.client_app_cipher.encrypt_record(.application_data, chunk)!
		batch << enc
		batch_len += record_header_len + enc.payload.len
		// Ship at the batch bound or on the last chunk; every record in the
		// batch is already encrypted under its key generation, so coalescing
		// never reorders or mixes generations (see the flush above).
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
// KeyUpdate under the current (old) write keys and then ratchets them (§4.6.3).
// It owns wlock for the whole send-then-update so a concurrent write() can
// never interleave and reuse a key/nonce; defer guarantees release on error.
fn (mut c Conn) send_key_update_response() ! {
	c.wlock.lock()
	defer {
		c.wlock.unlock()
	}
	msg := build_key_update(false)
	enc := c.hs.client_app_cipher.encrypt_record(.handshake, msg)!
	c.write_records([enc])!
	c.hs.update_write_traffic_keys()!
}

// force_write_rekey fulfills the §5.5 sender-side record limit: announce a
// KeyUpdate with update_not_requested under the current (old) write keys, then
// ratchet — the same send-then-update ordering §4.6.3 requires of a KeyUpdate
// response, reusing the response-path primitives.
fn (mut c Conn) force_write_rekey() ! {
	msg := build_key_update(false)
	enc := c.hs.client_app_cipher.encrypt_record(.handshake, msg)!
	c.write_records([enc])!
	c.hs.update_write_traffic_keys()!
}

// close sends a close_notify alert and closes the underlying TCP connection.
pub fn (mut c Conn) close() ! {
	// Take the write lock so teardown cannot race a concurrent write()/KeyUpdate
	// response over the write cipher. rlock is deliberately not taken: a reader
	// may be blocked in a socket read, and close() must be able to unblock it by
	// closing the socket below rather than waiting for that reader.
	c.wlock.lock()
	defer {
		c.wlock.unlock()
	}
	// Idempotent teardown: a second close() must not re-send close_notify or
	// double-close the socket.
	if c.closed {
		if c.sock != unsafe { nil } {
			c.sock.close() or {}
		}
		return
	}
	// Emit close_notify at most once; guarded separately from `closed` so a failure
	// inside send_close_notify still leaves the connection closed below.
	if !c.close_notify_sent {
		c.close_notify_sent = true
		c.send_close_notify()
	}
	c.closed = true
	// Teardown is terminal: drop the application traffic secrets so a later memory
	// compromise cannot re-derive the record keys and decrypt captured traffic
	// (RFC 8446 §1.3.1/§7.5). send_close_notify above already used the live cipher,
	// so nothing still needs these secrets.
	c.hs.zeroize_app_secrets()

	// Best-effort socket close: errors are swallowed because we are already tearing
	// down and the caller has nothing left to act on.
	if c.sock != unsafe { nil } {
		c.sock.close() or {}
	}
}

// send_close_notify writes a close_notify alert, encrypted with the application
// keys once the handshake has completed (falling back to a plaintext record if
// encryption fails). RFC 8446 §6.1/§A.4: alerts after the server Finished MUST be
// encrypted; plaintext close_notify is only correct when keys are not yet up.
fn (mut c Conn) send_close_notify() {
	if c.sock == unsafe { nil } {
		return
	}
	notify := new_close_notify()
	plaintext_alert := alert_record(notify)
	if c.hs.state != .connected {
		c.write_records([plaintext_alert]) or {}
		return
	}
	enc := c.hs.client_app_cipher.encrypt_record(.alert, notify.encode()) or {
		c.write_records([plaintext_alert]) or {}
		return
	}
	c.write_records([enc]) or {}
}

// negotiated_alpn returns the negotiated ALPN protocol, if any.
pub fn (c Conn) negotiated_alpn() string {
	return c.negotiated_alpn
}
