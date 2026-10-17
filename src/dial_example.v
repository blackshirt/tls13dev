// Copyright (c) 2026 blackshirt.
// SPDX-License-Identifier: MIT
//
// Minimal end-to-end demo of the client API: TLS 1.3 handshake → plaintext HTTP
// request/response → orderly close_notify. Run with `v run src/dial_example.v`.
module main

import client

fn main() {
	// server_name drives both SNI and certificate hostname verification, so it
	// must match the host in the dial address (or a name in the server's cert SANs).
	cfg := client.Config{
		server_name:          'testserver.host'
		alpn:                 ['http/1.1']
		insecure_skip_verify: false
	}
	mut conn := client.dial('tls-v1-3.testserver.host:443', cfg) or {
		eprintln('dial failed: ${err}')
		exit(1)
	}
	defer {
		conn.close() or {}
	}
	req := 'GET /tls/client-hello HTTP/1.1\r\nHost: tls-v1-3.testserver.host\r\nConnection: close\r\n\r\n'.bytes()
	conn.write(req) or {
		eprintln('write failed: ${err}')
		exit(1)
	}
	// A single read() returns at most one record's worth; a real client would
	// loop until the HTTP response is complete (Connection: close ends it here).
	mut buf := []u8{len: 8192}
	n := conn.read(mut buf) or {
		eprintln('read failed: ${err}')
		exit(1)
	}
	println(buf[..n].bytestr())
	println('ALPN: ${conn.negotiated_alpn}')
}
