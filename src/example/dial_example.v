// Copyright (c) 2026 blackshirt.
//
// Minimal end-to-end demo of the tls API: TLS 1.3 handshake → plaintext HTTP
// request/response → orderly close_notify. Run with `v run src/example/dial_example.v`.
module main

import tls

fn main() {
	// Config is a @[params] struct, so dial() accepts its fields as trailing named
	// arguments — no need to build a Config or mutate immutable fields. server_name
	// drives both SNI and certificate hostname verification, so it must match the
	// dial host (or a name in the server's cert SANs); omitted fields (root_cas,
	// timeout, insecure_skip_verify) fall back to the defaults declared on Config.
	mut conn := tls.dial('tls-v1-3.testserver.host:443',
		server_name: 'testserver.host'
		alpn:        ['http/1.1']
	) or {
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
	println('ALPN: ${conn.negotiated_alpn()}')
}
