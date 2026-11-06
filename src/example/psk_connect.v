// Copyright (c) 2026 blackshirt.
//
// TLS 1.3 connect example with RFC 8446 §7.2 PSK resumption, backed by a file
// ticket store so resumption state survives across runs.
//
// Run:
//   v run src/example/psk_connect.v   (from repo root)
//
// Two connections to cloudflare.com:443:
//   1. First handshake offers an external PSK identity the server has never
//      seen; Cloudflare declines and completes a certificate handshake, then
//      pushes one or more NewSessionTickets after .connected (§4.6.1). Each
//      accepted ticket is write-through to the file store together with the §7.2
//      PSK derived from this session's resumption master secret.
//   2. The second dial draws its resumption PSKs from the same store — dial()
//      appends store.resumption_psks() to the ClientHello's pre_shared_key list
//      — so no in-memory PSK plumbing is needed between the two flights. The
//      server picks one, echoes its index, and the second flight shortens to
//      ClientHello / ServerHello / EncryptedExtensions / Finished. After
//      resumption the used PSK is burned (§8.6: single-use).
//
// The store lives in tickets.bin under a temp dir and is not wiped at the end,
// so a later run can resume on tickets this run persisted.
module main

import os
import time
import tls
import tls.handshake

// External PSK material for the first handshake only. The identity is one
// cloudflare.com has never issued, so the server declines the pre_shared_key
// extension and falls back to certificate authentication while still
// exercising the §4.2.11 wire encoding.
const first_psk_key = [u8(0x42)].repeat(32)
const first_psk_identity = 'example-external-first'.bytes()

// ticket_dir holds tickets.bin, the persisted resumption state. A fixed path
// lets the store outlive this process; the next run reopens it.
const ticket_dir = os.join_path(os.temp_dir(), 'tls_psk_connect')

fn run() ! {
	// One store for the whole run: it outlives both connections, so tickets
	// accepted on the first are available to seed the second, and everything
	// survives in tickets.bin for the next run.
	mut store := tls.new_file_ticket_store(ticket_dir)! or { return err }

	// ── First connection: certificate handshake, tickets flow into the store ──
	cfg := tls.Config{
		server_name:          'cloudflare.com'
		insecure_skip_verify: false
		hsk_options:          handshake.HandshakeOptions{}
		root_cas:             none
		min_rsa_bits:         0
		psks:                 [handshake.new_psk(first_psk_identity, first_psk_key)!]
		session_ticket_store: tls.SessionTicketStore(store)
		timeout:              30 * time.second
	}

	println('connecting to cloudflare.com:443 (first handshake, external PSK offer)...')
	t0 := time.now()
	mut conn := tls.dial('cloudflare.com:443', cfg)! or { return err }
	elapsed1 := time.since(t0)
	println('connected; ALPN: "${conn.negotiated_alpn()}"')
	println('first handshake took ${elapsed1.str()}')

	req := 'GET / HTTP/1.1\r\nhost: cloudflare.com\r\nconnection: close\r\n\r\n'.bytes()
	conn.write(req)! or { return err }
	mut buf := []u8{len: 8192}
	nr := conn.read(mut buf)! or { return err }
	println('received ${nr} bytes on first connection')

	// The store write-throughd each accepted ticket during the handshake, so its
	// PSKs survive conn.close() (which zeroizes the traffic secrets this
	// example's in-memory derivation would otherwise need).
	mut persisted := store.resumption_psks()
	println('tickets received: ${conn.session_tickets().len}; resumption PSKs persisted: ${persisted.len}')

	conn.close()! or { return err }
	// dial() appends store.resumption_psks() to cfg2.psks automatically, so no
	// caller-supplied psks are needed here.
	cfg2 := tls.Config{
		server_name:          'cloudflare.com'
		insecure_skip_verify: false
		hsk_options:          handshake.HandshakeOptions{}
		root_cas:             none
		min_rsa_bits:         0
		session_ticket_store: tls.SessionTicketStore(store)
		timeout:              30 * time.second
	}

	// Mirror dial()'s second-flight offer so negotiated_psk_index() maps onto a
	// real identity we can burn (§8.6: a resumed PSK is single-use).
	mut offered := [][]u8{}
	for p in store.resumption_psks() {
		if p.identity() in offered {
			continue
		}
		offered << p.identity().clone()
	}

	println('connecting to cloudflare.com:443 (second handshake, store-seeded resumption offer)...')
	t2 := time.now()
	mut conn2 := tls.dial('cloudflare.com:443', cfg2)! or { return err }
	elapsed2 := time.since(t2)
	println('connected; ALPN: "${conn2.negotiated_alpn()}"')
	println('second handshake took ${elapsed2.str()}')

	// The stack reports the ServerHello pre_shared_key index directly, so no
	// timing inference is needed: none means every offer was declined and the
	// peer ran a full certificate handshake; an int means resumption fired.
	if idx := conn2.negotiated_psk_index() {
		println('resumed via PSK index ${idx}')
		store.consume(offered[int(idx)])
	} else {
		println('PSK offer declined; full certificate handshake')
	}
	req2 := 'GET / HTTP/1.1\r\nhost: cloudflare.com\r\nconnection: close\r\n\r\n'.bytes()
	conn2.write(req2)! or { return err }
	mut buf2 := []u8{len: 8192}
	nr2 := conn2.read(mut buf2)! or { return err }
	println('received ${nr2} bytes on second connection')

	// Tickets accepted on the resumed connection are write-through too.
	mut refreshed := store.resumption_psks()
	println('resumption PSKs persisted after the second connection: ${refreshed.len}')

	conn2.close()! or { return err }

	println('=== Timing summary ===')
	println('First handshake  (external PSK offer, cert auth): ${elapsed1.str()}')
	println('Second handshake (store-seeded resumption offer): ${elapsed2.str()}')
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
