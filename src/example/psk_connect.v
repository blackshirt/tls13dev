// Copyright (c) 2026 blackshirt.
//
// TLS 1.3 connect example with RFC 8446 §7.2 PSK resumption.
//
// Run:
//   v run src/example/psk_connect.v   (from repo root)
//
// Two connections to cloudflare.com:443:
//   1. First handshake offers an external PSK identity the server has never
//      seen; Cloudflare declines and completes a certificate handshake, then
//      pushes one or more NewSessionTickets after .connected (§4.6.1).
//   2. Derive resumption PSKs from those tickets with the §7.2 chain
//      (HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce))
//      via Conn.resumption_psks(), and offer them on the second dial. The
//      server picks one, echoes its index in ServerHello.pre_shared_key, and
//      the second flight shortens to ClientHello / ServerHello /
//      EncryptedExtensions / Finished with no Certificate or CertificateVerify.
module main

import time
import tls
import tls.handshake

// External PSK material for the first handshake only. The identity is one
// cloudflare.com has never issued, so the server declines the pre_shared_key
// extension and falls back to certificate authentication while still
// exercising the §4.2.11 wire encoding.
const first_psk_key = [u8(0x42)].repeat(32)
const first_psk_identity = 'example-external-first'.bytes()

fn run() ! {
	// ── First connection: certificate handshake, collect tickets ──
	cfg := tls.Config{
		server_name:          'cloudflare.com'
		insecure_skip_verify: false
		hsk_options:          handshake.HandshakeOptions{}
		root_cas:             none
		min_rsa_bits:         0
		psks:                 [handshake.new_psk(first_psk_identity, first_psk_key)!]
		timeout:              30 * time.second
	}

	println('connecting to cloudflare.com:443 (first handshake, external PSK offer)...')
	t0 := time.now()
	mut conn := tls.dial('cloudflare.com:443', cfg)!
	elapsed1 := time.since(t0)
	println('connected; ALPN: "${conn.negotiated_alpn()}"')
	println('first handshake took ${elapsed1.str()}')

	req := 'GET / HTTP/1.1\r\nhost: cloudflare.com\r\nconnection: close\r\n\r\n'.bytes()
	conn.write(req)! or { return err }
	mut buf := []u8{len: 8192}
	nr := conn.read(mut buf)! or { return err }
	println('received ${nr} bytes on first connection')

	// Derive resumption PSKs BEFORE close(): Conn.close() runs
	// zeroize_traffic_secrets(), which retires the Resumption Master Secret the
	// §7.2 chain needs. session_tickets() itself is diagnostic — the raw
	// tokens are opaque to us; the derived Psk is what carries the key.
	resume_psks := conn.resumption_psks()!
	println('resumption PSKs derived: ${resume_psks.len}')
	if resume_psks.len > 0 {
		first := conn.session_tickets()[0]
		println('first ticket lifetime=${first.lifetime()}s, PSK identity size=${resume_psks[0].identity().len} bytes')
	}
	conn.close()! or { return err }

	if resume_psks.len == 0 {
		println('no tickets issued by the server; skipping the resumption attempt')
		return
	}

	// ── Second connection: offer the resumption PSKs ──
	cfg2 := tls.Config{
		server_name:          'cloudflare.com'
		insecure_skip_verify: false
		hsk_options:          handshake.HandshakeOptions{}
		root_cas:             none
		min_rsa_bits:         0
		psks:                 resume_psks
		timeout:              30 * time.second
	}

	println('connecting to cloudflare.com:443 (second handshake, resumption PSK offer)...')
	t2 := time.now()
	mut conn2 := tls.dial('cloudflare.com:443', cfg2)!
	elapsed2 := time.since(t2)
	println('connected; ALPN: "${conn2.negotiated_alpn()}"')
	println('second handshake took ${elapsed2.str()}')

	// The stack reports the ServerHello pre_shared_key index directly, so no
	// timing inference is needed: none means every offer was declined and the
	// peer ran a full certificate handshake; an int means resumption fired.
	if idx := conn2.negotiated_psk_index() {
		println('resumed via PSK index ${idx}')
	} else {
		println('PSK offer declined; full certificate handshake')
	}
	req2 := 'GET / HTTP/1.1\r\nhost: cloudflare.com\r\nconnection: close\r\n\r\n'.bytes()
	conn2.write(req2)! or { return err }
	mut buf2 := []u8{len: 8192}
	nr2 := conn2.read(mut buf2)! or { return err }
	println('received ${nr2} bytes on second connection')

	new_tickets := conn2.resumption_psks()!
	println('second-connection tickets issued: ${new_tickets.len}')

	conn2.close()! or { return err }

	println('=== Timing summary ===')
	println('First handshake  (external PSK offer, cert auth): ${elapsed1.str()}')
	println('Second handshake (resumption PSK offer):          ${elapsed2.str()}')
	if elapsed2.milliseconds() < elapsed1.milliseconds() {
		diff := elapsed1.milliseconds() - elapsed2.milliseconds()
		println('handshake saved ${diff} ms')
	} else {
		diff := elapsed2.milliseconds() - elapsed1.milliseconds()
		println('handshake cost ${diff} ms extra (network jitter or the peer re-ran the cert flight)')
	}
}

fn main() {
	run() or {
		println('example failed: ${err.msg()}')
	}
}
