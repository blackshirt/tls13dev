// Copyright (c) 2026 blackshirt.
//
// client.v is the socket-owning QUIC facade. Where engine.v is a transport-agnostic
// handshake state machine that a caller must hand-drive over datagrams it owns, this
// file wraps it in a `quic.dial(address, Config)` that opens a UDP socket, runs the
// handshake loop to confirmation with a bounded deadline and a retransmit clock, and
// returns a `Conn` exposing the negotiated parameters. All wire logic still lives in
// the engine; this facade only moves bytes between the socket and the engine.
//
// It gives the caller a confirmed handshake, not a data plane: there are no streams,
// flow control, or congestion control (see QUIC.md §7). `serve()` keeps the pump
// running afterward so the engine can acknowledge and consume post-handshake traffic.
module quic

import net
import os
import time
import tls.handshake

// handshake_deadline_multiplier bounds the whole handshake at this multiple of
// Config.timeout, mirroring the tls record facade's dial deadline policy.
const handshake_deadline_multiplier = 4

// max_server_name_len bounds the SNI/verification name at the DNS ceiling
// (RFC 1035 §2.3.4), so a hostile or mistyped name cannot overflow the u16 SNI field.
const max_server_name_len = 253

// max_datagram_read is the largest UDP payload a single read can return; the facade
// reuses one buffer of this size for every datagram of the handshake.
const max_datagram_read = 65535

// debug_hex renders up to `limit` leading bytes of `data` as space-separated hex for
// the QUIC_DEBUG=1 handshake dump, so a rejected flight can be inspected offline.
fn debug_hex(data []u8, limit int) string {
	mut n := data.len
	if n > limit {
		n = limit
	}
	mut out := ''
	for i in 0 .. n {
		out += '${data[i]:02x} '
	}
	return out.trim_space()
}

// Conn is a confirmed QUIC connection owning a UDP socket and the handshake engine
// behind it. It mirrors tls.Conn's shape: dial once, read the negotiated parameters,
// then close (or keep the pump alive with serve).
pub struct Conn {
mut:
	engine       Engine        // transport-agnostic handshake state machine.
	sock         &net.UdpConn  // the socket this facade owns and must release.
	buf          []u8          // reused receive buffer for every datagram.
	deadline_ms  i64           // absolute handshake deadline in monotonic ms; 0 after confirmation.
	sock_timeout time.Duration // per-operation socket timeout the caller configured.
	server_name  string        // the SNI name the handshake was run under.
	debug        bool          // when true, dump each handshake datagram's size + head bytes (QUIC_DEBUG=1).
}

// dial connects to address (host:port), runs a full RFC 9001 handshake over a socket
// it owns, and returns a confirmed Conn. server_name falls back to the address host so
// SNI and hostname checks work. It blocks until HANDSHAKE_DONE or the deadline expires.
pub fn dial(address string, config Config) !&Conn {
	// Prefer an explicit server_name; otherwise derive it from the dial address.
	server_name := if config.server_name.len > 0 {
		config.server_name
	} else {
		host_from_address(address)
	}
	if server_name.len == 0 {
		return error('quic: empty server name')
	}
	// A name with stray whitespace would travel verbatim into SNI and into hostname
	// verification — reject it before the socket opens rather than dial ambiguously.
	if server_name != server_name.trim_space() {
		return error('quic: server name has stray whitespace')
	}
	if server_name.len > max_server_name_len {
		return error('quic: server name exceeds ${max_server_name_len} characters')
	}

	// Open the UDP transport first: every later failure path must close it.
	mut sock := net.dial_udp(address)!
	timeout := if config.timeout > 0 { config.timeout } else { 30 * time.second }
	sock.set_read_timeout(timeout)
	sock.set_write_timeout(timeout)
	// Absolute bound for the whole handshake (see handshake_deadline_multiplier).
	deadline_ms := mono_ms() + i64(timeout) * handshake_deadline_multiplier / i64(time.millisecond)

	mut eng := new_client_engine(server_name, config)!
	mut conn := &Conn{
		engine:       eng
		sock:         sock
		buf:          []u8{len: max_datagram_read}
		deadline_ms:  deadline_ms
		sock_timeout: timeout
		server_name:  server_name
		debug:        os.getenv('QUIC_DEBUG') == '1'
	}
	// On any handshake failure the socket is released before the error reaches the
	// caller, so a failed dial leaks no fd.
	conn.do_handshake() or {
		sock.close() or {}
		return err
	}
	return conn
}

// do_handshake drives the engine to confirmation over the socket: it sends the first
// flight, then reads one datagram at a time, feeding it back and writing whatever the
// engine returns. A read timeout advances the engine's retransmit clock instead of
// failing, so lossy paths still complete; the deadline bounds the whole loop.
fn (mut c Conn) do_handshake() ! {
	start := c.engine.start()!
	if c.debug {
		eprintln('[quic] first flight: ${start.len} bytes (first Initial datagram must pad to >=1200, RFC 9000 §14.1)')
		eprintln('[quic] first flight head: ${debug_hex(start, 48)}')
	}
	c.write_datagram(start)!
	for !c.engine.is_confirmed() {
		if mono_ms() >= c.deadline_ms {
			return error('quic: handshake deadline exceeded')
		}
		// Shrink the read timeout toward the deadline so a stalled peer cannot push
		// the handshake past its bound while a single recv() blocks.
		c.apply_read_timeout()
		mut timed_out := false
		n := c.read_into() or {
			msg := err.msg().to_lower()
			if msg.contains('timed out') || msg.contains('timeout') || msg.contains('eagain') || msg.contains('would block') || msg.contains('interrupted') {
				timed_out = true
				int(0)
			} else {
				// A reset/unreachable socket is terminal, not a retransmit trigger.
				return err
			}
		}
		if timed_out {
			// No datagram arrived: re-emit the outstanding flight if its probe timeout
			// elapsed (RFC 9000 §6.2.1). retransmit_expired is a no-op until then.
			rt := c.engine.retransmit_expired(mono_ms())!
			if c.debug {
				eprintln('[quic] read timed out; retransmit emitted ${rt.len} bytes')
			}
			if rt.len > 0 {
				c.write_datagram(rt)!
			}
			continue
		}
		if n == 0 {
			continue
		}
		out := c.engine.receive(c.buf[..n])!
		if c.debug {
			eprintln('[quic] recv ${n} bytes -> engine emitted ${out.len} bytes')
		}
		if out.len > 0 {
			c.write_datagram(out)!
		}
	}
	// The handshake is done: retire the deadline guard and restore the full
	// per-operation timeout so serve()/later reads obey only the caller's bound.
	c.deadline_ms = 0
	c.sock.set_read_timeout(c.sock_timeout)
}

// serve keeps the datagram pump running after confirmation so the engine can
// acknowledge packets and process the server's post-handshake traffic (which, with no
// application data plane, is the only reason to keep reading). It returns when
// idle_timeout elapses with no datagram, or once the peer closes the connection. A
// zero or negative idle_timeout waits indefinitely for the socket's own timeout.
pub fn (mut c Conn) serve(idle_timeout time.Duration) ! {
	if idle_timeout > 0 {
		c.sock.set_read_timeout(idle_timeout)
	}
	for {
		mut timed_out := false
		n := c.read_into() or {
			timed_out = true
			int(0)
		}
		if timed_out || n == 0 {
			return
		}
		// Post-handshake faults (a peer CONNECTION_CLOSE, or 1-RTT CRYPTO this engine
		// does not decode) end the pump rather than propagating: serve is liveness, not
		// a data path.
		out := c.engine.receive(c.buf[..n]) or {
			return
		}
		c.write_datagram(out)!
	}
}

// write_datagram sends one datagram in full or fails; a short UDP write means the
// payload exceeded the path MTU or the socket went bad.
fn (mut c Conn) write_datagram(data []u8) ! {
	if data.len == 0 {
		return
	}
	n := c.sock.write(data)!
	if n != data.len {
		return error('quic: sent ${n} of ${data.len} bytes in UDP datagram')
	}
}

// apply_read_timeout bounds the next socket read by the tightest of the caller's
// per-operation timeout, the time left before the handshake deadline, and the time
// until the engine's next probe timeout — so a lost outbound flight is retransmitted
// on the PTO cadence instead of waiting out the full socket timeout (§6.2.1).
fn (mut c Conn) apply_read_timeout() {
	mut wait_ms := i64(c.sock_timeout) / i64(time.millisecond)
	if c.deadline_ms > 0 {
		rem := c.deadline_ms - mono_ms()
		if rem < wait_ms {
			wait_ms = rem
		}
	}
	probe := c.engine.probe_wait_ms(mono_ms())
	if probe >= 0 && probe < wait_ms {
		wait_ms = probe
	}
	if wait_ms < 1 {
		wait_ms = 1 // never arm a zero/negative timeout that would spin the read loop
	}
	c.sock.set_read_timeout(wait_ms * time.millisecond)
}

// read_into reads one datagram into the reusable buffer and returns its length. It
// reduces net.UdpConn.read's (int, Addr) tuple to just the byte count, since a
// connected UDP socket's peer address is not consulted during the handshake.
fn (mut c Conn) read_into() !int {
	n, _ := c.sock.read(mut c.buf)!
	return n
}

// is_confirmed reports whether the handshake finished (HANDSHAKE_DONE processed).
pub fn (c &Conn) is_confirmed() bool {
	return c.engine.is_confirmed()
}

// state exposes the handshake state for polling.
pub fn (c &Conn) state() handshake.HandshakeState {
	return c.engine.state()
}

// negotiated_alpn returns the server's ALPN pick ('' if none).
pub fn (c &Conn) negotiated_alpn() string {
	return c.engine.negotiated_alpn()
}

// negotiated_cipher_suite returns the negotiated suite.
pub fn (c &Conn) negotiated_cipher_suite() handshake.CipherSuite {
	return c.engine.negotiated_cipher_suite()
}

// original_dcid returns the destination CID used in the first Initial packet.
pub fn (c &Conn) original_dcid() []u8 {
	return c.engine.original_dcid()
}

// source_cid returns this endpoint's source CID.
pub fn (c &Conn) source_cid() []u8 {
	return c.engine.source_cid()
}

// close seals a CONNECTION_CLOSE, sends it best-effort, and releases the socket.
// The seal is skipped when the engine has already lost its keys (an error path), so a
// close never fails just because the handshake did.
pub fn (mut c Conn) close() ! {
	closing := c.engine.close(0, 'handshake complete') or { []u8{} }
	if closing.len > 0 {
		c.write_datagram(closing) or {}
	}
	return c.sock.close()
}

// mono_ms returns a monotonic millisecond clock value, matching tls's deadline math.
fn mono_ms() i64 {
	return i64(time.sys_mono_now()) / i64(time.millisecond)
}

// host_from_address extracts the host part of a dial address ("host:port" or
// "[ipv6]:port") so a bare address still supplies the SNI and verification name.
fn host_from_address(address string) string {
	if address.starts_with('[') {
		end := address.index(']') or { return address }
		return address[1..end]
	}
	if colon := address.last_index(':') {
		return address[..colon]
	}
	return address
}
