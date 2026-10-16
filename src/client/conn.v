// module client is the public entry point of this TLS stack: dial() opens a
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

// recv_buf_compact_threshold bounds how many already-consumed bytes may remain
// in recv_buf before its unconsumed tail is shifted to the front. Keeping the
// wasted prefix below this bound makes compaction amortized O(1) per byte while
// keeping memory usage bounded.
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
	server_name := if config.server_name.len > 0 {
		config.server_name
	} else {
		host_from_address(address)
	}

	mut sock := net.dial_tcp(address)!
	sock.set_read_timeout(30 * time.second)
	sock.set_write_timeout(30 * time.second)

	mut hs := handshake.new_client_handshake(server_name, config.alpn)!

	mut store := pki.new_trust_store()
	if roots := config.root_cas {
		store = roots
	} else if !config.insecure_skip_verify {
		store.load_system_ca_bundle()!
	}
	validator := pki.new_validator(store, config.insecure_skip_verify)

	mut conn := &Conn{
		sock:        sock
		hs:          hs
		recv_buf:    []u8{cap: record.max_ciphertext_record_len + record.record_header_len} // one full frame
		app_buf:     []u8{cap: record.max_plaintext_record_len}                           // one full plaintext record
		server_name: server_name
	}

	conn.do_handshake(validator)!
	conn.negotiated_alpn = conn.hs.negotiated_alpn
	return conn
}

// host_from_address extracts the host part of a dial address ("host:port" or
// "[ipv6]:port") so a bare address can still supply the SNI name and the
// hostname that the peer certificate is verified against.
fn host_from_address(address string) string {
	// Strip [ipv6]:port or host:port
	if address.starts_with('[') {
		end := address.index(']') or { return address }
		return address[1..end]
	}
	if colon := address.last_index(':') {
		return address[..colon]
	}
	return address
}

// do_handshake drives the full client flight: send ClientHello (+dummy CCS),
// then feed every incoming record into the handshake state machine until it
// reports .connected. A loop rather than straight-line code because the server
// flight can interleave dummy CCS records, alerts, or a whole HelloRetryRequest
// round trip at any point.
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
				// including the rest of the handshake flight — is wrapped with outer
				// type application_data, so "handshake" never appears again here;
				// the true type is recovered from the inner plaintext when decrypted
				// (RFC 8446 §5.1/§5.2).
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
	for rec in recs {
		bytes := rec.serialize()
		c.sock.write(bytes)!
	}
}

// read_raw_record blocks until one complete TLS record (header + full payload)
// has been buffered, then slices that frame off recv_buf and parses it. TCP may
// deliver a record in pieces or several records glued together, so the frame is
// only consumed once its declared length is actually available.
fn (mut c Conn) read_raw_record() !record.Record {
	for {
		avail := c.recv_buf.len - c.recv_pos
		if avail >= record.record_header_len {
			// Peek the length field (2 bytes at offset 3) without consuming it.
			// We must not parse until a whole header+payload frame is buffered:
			// TCP is a byte stream, so records can arrive split across reads.
			payload_len := int(u16(c.recv_buf[c.recv_pos + 3]) << 8 | u16(c.recv_buf[c.recv_pos + 4]))
			total := record.record_header_len + payload_len
			if avail >= total {
				frame := c.recv_buf[c.recv_pos..c.recv_pos + total].clone()
				c.recv_pos += total
				c.compact_recv_buf()
				mut r := wire.new_reader(frame)
				return record.parse_record(mut r)!
			}
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

// compact_recv_buf reclaims the already-consumed prefix of recv_buf. When the
// buffer is fully drained its capacity is retained (clear keeps cap); otherwise
// the unconsumed tail is shifted to the front once the wasted prefix exceeds
// recv_buf_compact_threshold. This avoids the O(n) re-slice clone that used to
// run on every record while keeping memory bounded.
fn (mut c Conn) compact_recv_buf() {
	if c.recv_pos == c.recv_buf.len {
		c.recv_buf.clear()
		c.recv_pos = 0
	} else if c.recv_pos >= recv_buf_compact_threshold {
		c.recv_buf = c.recv_buf[c.recv_pos..].clone()
		c.recv_pos = 0
	}
}

// handle_alert processes an alert received after the handshake. It marks the
// connection closed and returns 0 for a clean close_notify, or an error for any
// other alert.
fn (mut c Conn) handle_alert(payload []u8) !int {
	c.closed = true
	a := record.parse_alert(payload)!
	if a.description == .close_notify {
		return 0
	}
	return error('tls: received alert ${a.description}')
}

// read decrypts application data into buf. Returns bytes read (0 on clean close).
pub fn (mut c Conn) read(mut buf []u8) !int {
	if c.closed {
		return error('tls: connection closed')
	}
	// A decrypted record can hold more than the caller's buffer; leftovers from
	// the previous record are drained first so no plaintext is dropped or reordered.
	if c.app_buf.len > 0 {
		n := copy(mut buf, c.app_buf)
		c.app_buf = c.app_buf[n..].clone()
		return n
	}

	for {
		rec := c.read_raw_record()!
		match rec.content_type {
			.change_cipher_spec {
				continue
			}
			.alert {
				// Unencrypted alert: only possible before keys are installed; handled
				// directly since there is no inner content type to inspect.
				return c.handle_alert(rec.payload)
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
						// Post-handshake alerts are encrypted like everything else
						// (RFC 8446 §5.1/§6): the alert arrives as the inner content
						// type of an application_data record, not an outer .alert.
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

fn (mut c Conn) handle_post_handshake(data []u8) ! {
	// Loop while complete 4-byte-headered messages remain in this plaintext.
	// Unlike the handshake phase there is no reassembly buffer carried across
	// records, so a message split over two records would surface as a
	// 'truncated post-handshake message' error — acceptable because NewSessionTicket
	// and KeyUpdate are sent one-per-record in practice (RFC 8446 §5.2 permits
	// splitting, it does not require it).
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
				// KeyUpdate; the request_update flag only decides whether a response
				// is owed back to the sender.
				request_update := handshake.parse_key_update(body)!
				c.hs.update_read_traffic_keys()!
				if request_update {
					// RFC 8446 §4.6.3: the KeyUpdate response is protected under the
					// current (old) write keys; the sender switches to the next keys
					// only after the message has been sent.
					msg := handshake.build_key_update(false)
					enc := c.hs.client_app_cipher.encrypt_record(.handshake, msg)!
					c.write_records([enc])!
					c.hs.update_write_traffic_keys()!
				}
			}
			else {
				// Ignore unrecognized post-handshake messages
			}
		}
	}
}

// write encrypts and sends application data.
pub fn (mut c Conn) write(data []u8) !int {
	if c.closed {
		return error('tls: connection closed')
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
	if c.closed {
		c.sock.close() or {}
		return
	}
	if !c.close_notify_sent {
		c.close_notify_sent = true
		c.send_close_notify()
	}
	c.closed = true
	c.sock.close() or {}
}

// send_close_notify writes a close_notify alert, encrypted with the application
// keys once the handshake has completed (falling back to a plaintext record if
// encryption fails). RFC 8446 §6.1/§A.4: alerts after the server Finished MUST
// be encrypted; plaintext close_notify is only correct when keys are not yet up.
fn (mut c Conn) send_close_notify() {
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
