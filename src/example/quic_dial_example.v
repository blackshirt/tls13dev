// Copyright (c) 2026 blackshirt.
//
// Attempts a QUIC TLS handshake with test.privateoctopus.com:4433. Run with
// `v run src/example/quic_dial_example.v`.
//
// This demonstrates the current handshake engine, not a complete QUIC client:
// it does not yet implement streams, flow control, or loss recovery.
module main

import net
import time
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
	mut socket := net.dial_udp(server_address)!
	defer {
		socket.close() or { eprintln('UDP socket close failed: ${err}') }
	}
	socket.set_read_timeout(10 * time.second)

	mut engine := quic.new_client_engine(server_name, quic.Config{
		hsk_options: handshake.HandshakeOptions{
			alpn: ['h3']
		}
	})!
	initial := engine.start()!
	send_datagram(mut socket, initial)!

	mut buf := []u8{len: 65535}
	for !engine.confirmed() {
		n, _ := socket.read(mut buf)!
		if n == 0 {
			continue
		}
		outbound := engine.receive(buf[..n])!
		if outbound.len > 0 {
			send_datagram(mut socket, outbound)!
		}
	}

	println('QUIC handshake confirmed with ${server_name}')
	println('ALPN: ${engine.negotiated_alpn()}')
	println('Cipher suite: ${engine.negotiated_cipher_suite()}')

	close_datagram := engine.close(0, 'handshake complete')!
	send_datagram(mut socket, close_datagram)!
}

fn send_datagram(mut socket net.UdpConn, datagram []u8) ! {
	n := socket.write(datagram)!
	if n != datagram.len {
		return error('sent ${n} of ${datagram.len} bytes in UDP datagram')
	}
}
