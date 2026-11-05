// Copyright (c) 2026 blackshirt.
//
// TLS 1.3 connect example with pre-shared key (PSK) resumption support.
//
// Run:
//   v run src/example/psk_connect.v   (from repo root)
//
// Demonstrates the PSK resumption flow against cloudflare.com:443:
//   1. First connection without a PSK (certificate-authenticated handshake).
//   2. Collect any NewSessionTicket the server sends.
//   3. Build a PSK from the ticket (identity = ticket token, key = SHA-256 of token).
//   4. Reconnect offering the PSK in the pre_shared_key extension (§4.2.11).
//
// cloudflare.com does not know our PSK, so the second handshake is also
// certificate-authenticated — the PSK offer is carried harmlessly. Against a
// server that provisions the matching PSK key, the second handshake would be
// PSK-authenticated (§4.4.2) with no Certificate/CertificateVerify.
module main

import crypto.sha256
import time
import tls
import tls.handshake

// Initial PSK used on the first connection; cloudflare.com does not know it, so
// the first handshake is certificate-authenticated and the PSK offer is ignored.
const initial_psk_key = [u8(0x42)].repeat(32)
const initial_psk_identity = 'first-connection'.bytes()

fn build_psk_from_ticket(ticket handshake.NewSessionTicket) handshake.Psk {
	token := ticket.bytes() // opaque resumption token → PSK identity
	key := sha256.sum256(token) // derive PSK key material from the token
	return handshake.new_psk(token, key)
}

fn run() ! {
	// ── First connection: no PSK (or a dummy PSK the server ignores) ──
	cfg := tls.Config{
		server_name:          'cloudflare.com'
		insecure_skip_verify: false   // verify against the system trust store
		hsk_options:          handshake.HandshakeOptions{}
		root_cas:             none
		min_rsa_bits:         0
		psks:                 [handshake.new_psk(initial_psk_identity, initial_psk_key)]
		timeout:              30 * time.second
	}

	println('connecting to cloudflare.com:443 (first handshake, no PSK)...')
	t0 := time.now()
	mut conn := tls.dial('cloudflare.com:443', cfg)!
	elapsed1 := time.since(t0)
	println('connected; ALPN: ${conn.negotiated_alpn()}')
	println('first handshake took ${elapsed1.str()}')

	req := 'GET / HTTP/1.1\r\nhost: cloudflare.com\r\nconnection: close\r\n\r\n'.bytes()
	conn.write(req)! or { return err }
	mut buf := []u8{len: 8192}
	nr := conn.read(mut buf)! or { return err }
	println('received ${nr} bytes on first connection')

	// Collect session tickets the server sent (RFC 8446 §4.6.1). Extract the PSK
	// before close() wipes the ticket backlog.
	tickets := conn.session_tickets()
	println('session tickets received: ${tickets.len}')

	// Build the resumption PSK from the first ticket, or fall back to the
	// initial PSK if none was issued.
	resume_psk := if tickets.len > 0 {
		build_psk_from_ticket(tickets[0])
	} else {
		handshake.new_psk(initial_psk_identity, initial_psk_key)
	}
	if tickets.len > 0 {
		println('built PSK from ticket (lifetime=${tickets[0].lifetime()}s)')
	} else {
		println('no session ticket; reusing initial PSK for the second connection')
	}
	conn.close()! or { return err }

	cfg2 := tls.Config{
		server_name:          'cloudflare.com'
		insecure_skip_verify: false
		hsk_options:          handshake.HandshakeOptions{}
		root_cas:             none
		min_rsa_bits:         0
		psks:                 [resume_psk]
		timeout:              30 * time.second
	}

	println('connecting to cloudflare.com:443 (second handshake with PSK offer)...')
	t2 := time.now()
	mut conn2 := tls.dial('cloudflare.com:443', cfg2)!
	elapsed2 := time.since(t2)
	println('connected; ALPN: ${conn2.negotiated_alpn()}')
	println('second handshake took ${elapsed2.str()}')

	req2 := 'GET / HTTP/1.1\r\nhost: cloudflare.com\r\nconnection: close\r\n\r\n'.bytes()
	conn2.write(req2)! or { return err }
	mut buf2 := []u8{len: 8192}
	nr2 := conn2.read(mut buf2)! or { return err }
	println('received ${nr2} bytes on second connection')

	conn2.close()! or { return err }

	// The PSK is immutable once constructed; reuse it on as many connections
	// as the server accepts.
	println('PSK identity for reuse: ${resume_psk.identity().bytestr()}')
	println('=== Timing summary ===')
	println('First handshake (no PSK):  ${elapsed1.str()}')
	println('Second handshake (with PSK): ${elapsed2.str()}')
	if elapsed2.milliseconds() < elapsed1.milliseconds() {
		diff := elapsed1.milliseconds() - elapsed2.milliseconds()
		println('PSK handshake was ${diff} ms faster')
	} else {
		diff := elapsed2.milliseconds() - elapsed1.milliseconds()
		println('PSK handshake was ${diff} ms slower')
	}
}

fn main() {
	run() or {
		println('example failed: ${err.msg()}')
	}
}
