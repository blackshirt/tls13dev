// Copyright (c) 2026 blackshirt.
//
// Runs a QUIC TLS handshake against cloudflare-quic.com:443 and prints the
// negotiated ALPN and cipher suite. Run with
// `v run src/example/quic_dial_example.v`.
//
// Set QUIC_DEBUG=1 to trace the handshake on stderr (the plaintext ClientHello,
// datagram sizes, and first-flight bytes):
// `QUIC_DEBUG=1 v run src/example/quic_dial_example.v`.
//
// quic.dial owns the socket and drives the handshake to confirmation internally, so
// the caller no longer hand-pumps datagrams through the engine. It still stops at a
// confirmed handshake: there are no streams, flow control, or loss recovery yet.
module main

import tls.handshake
import tls.quic

const server_name = 'cloudflare-quic.com'
const server_address = '${server_name}:443'

fn main() {
	run() or {
		eprintln('QUIC dial failed: ${err}')
		exit(1)
	}
}

fn run() ! {
	mut conn := quic.dial(server_address, quic.Config{
		hsk_options: handshake.HandshakeOptions{
			alpn: ['h3']
		}
	})!
	defer {
		conn.close() or { eprintln('QUIC close failed: ${err}') }
	}

	println('QUIC handshake confirmed with ${server_name}')
	println('ALPN: ${conn.negotiated_alpn()}')
	println('Cipher suite: ${conn.negotiated_cipher_suite()}')
}
