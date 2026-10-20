// Copyright (c) 2026 blackshirt.
//
// The simplest client that supplies its own trust store: build a TrustStore
// (here, the host's system bundle loaded explicitly — swap in add_pem() to pin
// a private CA) and pass it as Config.root_cas. Run with
// `v run src/example/trust_store_example.v`.
//
// For the absolute minimal client (no root_cas) see simple_example.v; for a
// fuller demo (CLI args, HTTP parsing, chunked bodies) see dial_example.v.
module main

import tls
import tls.pki

fn main() {
	host := 'example.com'

	// Build the trust store dial() will anchor the server's chain to. Passing
	// root_cas replaces the default (system) trust set entirely — it does not add
	// to it — so everything the chain must reach has to be in here.
	mut store := pki.new_trust_store()
	n := store.load_system_ca_bundle()!
	eprintln('trusting ${n} system root certificate(s)')
	// To pin a private CA instead, read its PEM bundle and add it:
	//   store.add_pem(os.read_file('ca.pem')!)!

	mut conn := tls.dial('${host}:443',
		server_name: host
		root_cas:    store
	)!

	conn.write('GET / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n'.bytes())!

	// read() returns 0 once the server sends close_notify, ending the loop.
	mut response := []u8{}
	mut buf := []u8{len: 4096}
	for {
		k := conn.read(mut buf)!
		if k == 0 {
			break
		}
		response << buf[..k]
	}
	print(response.bytestr())

	conn.close()!
}
