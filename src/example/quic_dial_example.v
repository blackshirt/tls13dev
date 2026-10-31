// Copyright (c) 2026 blackshirt.
//
// Attempts a QUIC TLS handshake with test.privateoctopus.com:4433. Run with
// `v run src/example/quic_dial_example.v`.
//
// quic.dial owns the socket and drives the handshake to confirmation internally, so
// the caller no longer hand-pumps datagrams through the engine. It still stops at a
// confirmed handshake: there are no streams, flow control, or loss recovery yet.
module main

import tls.handshake
import tls.quic

const server_name = 'test.privateoctopus.com'
const server_address = '${server_name}:4433'

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
