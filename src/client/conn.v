// Copyright (c) 2026 blackshirt.
// SPDX-License-Identifier: MIT
//
// The client module is the public entry point of this TLS stack: dial() opens a
// connection, runs the TLS 1.3 handshake (driving handshake/pki/kdf), and Conn
// exposes the protected stream via read/write/close. config.v holds the
// caller-facing options; dial_example.v shows the whole flow.
module client

import net
import time
import handshake
import record
import wire
import pki

// recv_buf_compact_threshold bounds the consumed prefix recv_buf may retain
// before its unconsumed tail is shifted to the front, making compaction
// amortized O(1) per byte while keeping memory bounded.
const recv_buf_compact_threshold = 16384

// recv_read_size is the number of bytes requested from the socket per read.
const recv_read_size = 4096

// Conn is a TLS 1.3 client connection over TCP.
pub struct Conn {
mut:
	sock              &net.TcpConn = unsafe { nil } // underlying TCP transport
	hs                handshake.ClientHandshake // handshake state machine, also holds the traffic keys
	recv_buf          []u8                      // raw bytes read from the socket, framing not yet applied
	recv_pos          int                       // start of unconsumed data in recv_buf (prefix is already parsed)
	app_buf           []u8                      // decrypted application bytes that didn't fit the caller's buffer
	closed            bool                      // set once the connection is finished (close or fatal alert)
	close_notify_sent bool                      // guards against sending close_notify twice
pub mut:
	negotiated_alpn string // server's ALPN pick — always one of Config.alpn (the handshake aborts otherwise), '' if none
	server_name     string // SNI value sent and the name the certificate was checked against
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

	mut hs := handshake.new_client_handshake(server_name, config.alpn) or {
		sock.close() or {}
		return err
	}

	// Resolve trust anchors by precedence: an explicit root_cas wins, else the
	// system bundle is loaded — unless verification is skipped, where an empty
	// store is fine because the validator never consults it.
	mut store := pki.new_trust_store()
	if roots := config.root_cas {
		store = roots
	} else if !config.insecure_skip_verify {
		// Loading the OS bundle can fail (missing file); that is fatal, but the
		// socket we already opened must be closed so a dial error leaks no fd.
		store.load_system_ca_bundle() or {
			sock.close() or {}
			return err
		}
	}
	validator := pki.new_validator(store, config.insecure_skip_verify)

	mut conn := &Conn{
		sock:        sock
		hs:          hs
		recv_buf:    []u8{cap: record.max_ciphertext_record_len + record.record_header_len} // one full frame
		app_buf:     []u8{cap: record.max_plaintext_record_len}                           // one full plaintext record
		server_name: server_name
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

// do_handshake drives the full client flight: send ClientHello (+dummy CCS),
// then feed every incoming record into the state machine until it reports
// .connected. A loop, because the server flight can interleave dummy CCS records,
// alerts, or a whole HelloRetryRequest round trip at any point.
fn (mut c Conn) do_handshake(validator pki.Validator) ! {
	ch_recs, _ := c.hs.create_client_hello()!
	c.write_records(ch_recs)!

	for c.hs.state != .connected {
		rec := c.read_raw_record()!

		match rec.content_type {
			.change_cipher_spec {
				// The peer's middlebox-compatibility dummy CCS carries no protocol
				// meaning in TLS 1.3 — accept and drop it (RFC 8446 §5).
				continue
			}
			.alert {
				// Plausible only before server keys are installed (a reject alert for
				// our ClientHello); post-handshake alerts arrive encrypted as
				// application_data and are handled in read(), not here.
				a := record.parse_alert(rec.payload)!
				return error('tls: received alert ${a.description} (level=${a.level})')
			}
			.handshake {
				followups, sh := c.hs.process_server_hello(rec)!
				if sh.is_hello_retry_req {
					c.write_records(followups)!
					continue
				}
				// Normal ServerHello processed; wait for encrypted handshake records
			}
			.application_data {
				// Once the server installs its handshake keys, everything it sends —
				// including the rest of the flight — is wrapped with outer type
				// application_data; the true type is recovered from the inner
				// plaintext when decrypted (RFC 8446 §5.1/§5.2).
				c.hs.feed_encrypted_record(rec)!
				fins := c.hs.process_reassembled_messages(&validator)!
				if fins.len > 0 {
					c.write_records(fins)!
				}
			}
			else {
				return error('tls: unexpected record type ${rec.content_type} during handshake')
			}
		}
	}
}

// write_records serializes records and sends them to the peer in order; one
// socket write per record keeps record framing intact on the TCP stream.
fn (mut c Conn) write_records(recs []record.Record) ! {
	if c.sock == unsafe { nil } {
		return error('tls: socket is nil')
	}
	for rec in recs {
		bytes := rec.serialize()
		c.sock.write(bytes)!
	}
}

// read_raw_record blocks until one complete TLS record (header + full payload)
// has been buffered, then slices that frame off recv_buf and parses it. TCP may
// deliver a record in pieces or several glued together, so the frame is only
// consumed once its declared length is actually available.
fn (mut c Conn) read_raw_record() !record.Record {
	for {
		avail := c.recv_buf.len - c.recv_pos
		if avail >= record.record_header_len {
			// Peek the length field (2 bytes at offset 3) without consuming it; do
			// not parse until a whole frame is buffered, since TCP can split records.
			payload_len := int(u16(c.recv_buf[c.recv_pos + 3]) << 8 | u16(c.recv_buf[c.recv_pos + 4]))
			if payload_len > record.max_ciphertext_record_len {
				return error('record: record length ${payload_len} exceeds maximum allowed ${record.max_ciphertext_record_len}')
			}
			total := record.record_header_len + payload_len
			if avail >= total {
				frame := c.recv_buf[c.recv_pos..c.recv_pos + total].clone()
				c.recv_pos += total
				c.compact_recv_buf()
				mut r := wire.new_reader(frame)
				return record.parse_record(mut r)!
			}
		}
		if c.sock == unsafe { nil } {
			return error('tls: connection closed (no socket available to read further records)')
		}
		mut tmp := []u8{len: recv_read_size}
		n := c.sock.read(mut tmp) or {
			return error('tls: connection closed while reading record: ${err}')
		}
		if n == 0 {
			return error('tls: connection closed while reading record')
		}
		c.recv_buf << tmp[..n]
	}
	return error('tls: unreachable')
}

// compact_recv_buf reclaims the already-consumed prefix of recv_buf: a fully
// drained buffer keeps its capacity (clear retains cap), otherwise the tail is
// shifted to the front once the wasted prefix exceeds recv_buf_compact_threshold.
fn (mut c Conn) compact_recv_buf() {
	if c.recv_pos == c.recv_buf.len {
		// Fully drained: clear() drops the prefix but keeps capacity, so later reads
		// reuse the buffer and recv_pos resets to frame the next record at the front.
		c.recv_buf.clear()
		c.recv_pos = 0
	} else if c.recv_pos >= recv_buf_compact_threshold {
		// Consumed prefix exceeded the bound: shift the live tail down once,
		// amortizing reclaim to O(1) per byte while capping memory near the threshold.
		c.recv_buf = c.recv_buf[c.recv_pos..].clone()
		c.recv_pos = 0
	}
}

// handle_alert processes an alert received after the handshake. It marks the
// connection closed and returns 0 for a clean close_notify, else an error.
fn (mut c Conn) handle_alert(payload []u8) !int {
	// Any alert is terminal for this direction, so mark closed before decoding —
	// even a malformed alert body must not leave the Conn looking usable.
	c.closed = true
	a := record.parse_alert(payload)!
	// close_notify is the one clean-shutdown signal: return 0, the same value a
	// normal EOF read yields, so callers treat it as orderly end-of-stream.
	if a.description == .close_notify {
		return 0
	}
	// Every other description is fatal per RFC 8446 §6; surface the peer's code verbatim.
	return error('tls: received alert ${a.description}')
}

// read decrypts application data into buf. Returns bytes read (0 on clean close).
pub fn (mut c Conn) read(mut buf []u8) !int {
	if buf.len == 0 {
		return 0
	}
	// A decrypted record can hold more than the caller's buffer; leftovers are
	// drained first so no plaintext is dropped or reordered.
	if c.app_buf.len > 0 {
		n := copy(mut buf, c.app_buf)
		if n == c.app_buf.len {
			c.app_buf.clear()
		} else {
			c.app_buf = c.app_buf[n..].clone()
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
				continue
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
		mut r := wire.new_reader(buf)
		msg_type, length := handshake.parse_handshake_header(mut r)!
		if buf.len < 4 + length {
			return error('tls: truncated post-handshake message')
		}
		body := buf[4..4 + length].clone()
		buf = buf[4 + length..].clone()
		match msg_type {
			.new_session_ticket {
				ticket := handshake.parse_new_session_ticket(body)!
				c.hs.session_tickets << ticket
			}
			.key_update {
				// §4.6.3: a recipient always advances its read keys on receiving a
				// KeyUpdate; request_update only decides whether a response is owed.
				request_update := handshake.parse_key_update(body)!
				c.hs.update_read_traffic_keys()!
				if request_update {
					// §4.6.3: the response is protected under the current (old) write
					// keys; the sender updates only after the message has been sent.
					msg := handshake.build_key_update(false)
					enc := c.hs.client_app_cipher.encrypt_record(.handshake, msg)!
					c.write_records([enc])!
					c.hs.update_write_traffic_keys()!
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
	for offset < data.len {
		end := if data.len - offset > record.max_plaintext_record_len {
			offset + record.max_plaintext_record_len
		} else {
			data.len
		}
		chunk := data[offset..end]
		enc := c.hs.client_app_cipher.encrypt_record(.application_data, chunk)!
		c.write_records([enc])!
		offset = end
	}
	return data.len
}

// close sends a close_notify alert and closes the underlying TCP connection.
pub fn (mut c Conn) close() ! {
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
	plaintext_alert := record.alert_record(record.new_close_notify())
	if c.hs.state != .connected {
		c.write_records([plaintext_alert]) or {}
		return
	}
	enc := c.hs.client_app_cipher.encrypt_record(.alert, record.new_close_notify().encode()) or {
		c.write_records([plaintext_alert]) or {}
		return
	}
	c.write_records([enc]) or {}
}
