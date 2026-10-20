// Copyright (c) 2026 blackshirt.
//
// The smallest useful tls client: connect, send one HTTPS GET, print the
// response, close cleanly. Run with `v run src/example/simple_example.v`.
//
// For a fuller demo (CLI arguments, flags, HTTP status/header parsing, and
// chunked-body decoding) see dial_example.v beside this file.
module main

import tls

fn main() {
	host := 'example.com'

	// dial() does the whole TLS 1.3 handshake and verifies the server's
	// certificate against the system trust store. server_name drives both SNI
	// and the hostname check, so it must match the certificate.
	mut conn := tls.dial('${host}:443', server_name: host)!

	// Write the HTTP request over the encrypted tunnel. The library moves bytes,
	// not HTTP — we frame the request ourselves. `Connection: close` lets the
	// server end the connection once the body is complete.
	conn.write('GET / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n'.bytes())!

	// read() returns one record's worth at a time and 0 once the server has sent
	// its close_notify, so loop until then and collect the pieces.
	mut response := []u8{}
	mut buf := []u8{len: 4096}
	for {
		n := conn.read(mut buf)!
		if n == 0 {
			break
		}
		response << buf[..n]
	}
	print(response.bytestr())

	// Send close_notify and close the socket.
	conn.close()!
}
