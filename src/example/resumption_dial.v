// Copyright (c) 2026 blackshirt.
//
// Dedicated example: resume a TLS 1.3 session using tickets persisted to the
// file ticket store by a previous run.
//
// The store lives in tickets.bin under a temp dir and is not wiped at the end,
// so a later run can resume on tickets this run persisted. The store is
// encrypted at rest with a stable 32-byte AES-256-GCM key kept in store.key
// next to tickets.bin; generated on first use so cross-run encrypted resumption
// works.
//
// Run:
//   v run src/example/resumption_dial.v   (from repo root)
//
// Flow:
//   1. Reopen the file store at <temp>/tls_resumption_dial — tickets.bin holds
//      whatever tickets + §7.2 PSKs an earlier run persisted there.
//   2. On a first run the store is empty, so the example offers an external PSK
//      identity the server has never seen. The server declines it (§4.2.11),
//      completes a certificate handshake, and pushes NewSessionTickets
//      (§4.6.1). Those tickets + their §7.2 PSKs are persisted to tickets.bin
//      before close(), so the store is populated for the next run.
//   3. On a later run dial() automatically seeds Conn's backlog from
//      store.tickets() and appends store.resumption_psks() to the ClientHello's
//      pre_shared_key list (§4.6.1/§4.2.11), so resumption fires with no
//      caller-side PSK plumbing.
//   4. If the server accepted one of the stored PSKs, negotiated_psk_index()
//      reports it; the example burns that pair with store.consume() (§8.6: a
//      resumption PSK is single-use) so a later run cannot re-offer it.
//   5. Tickets accepted on this connection are write-through to the store too,
//      so resumption state refreshes across runs.
//
// A first run against cloudflare.com:443 may not resume (Cloudflare may decline
// to issue resumable tickets), but it will populate tickets.bin whenever it
// issues them. A later run then offers them automatically.
module main

import crypto
import crypto.rand
import os
import time
import tls
import tls.handshake

// External PSK material offered only when the store is empty, to prompt the
// server into issuing resumable NewSessionTickets (§4.6.1). cloudflare.com has
// never issued this identity, so it declines the pre_shared_key extension and
// falls back to certificate authentication while still exercising §4.2.11.
const first_psk_key = [u8(0x42)].repeat(32)
const first_psk_identity = 'example-external-first'.bytes()

const ticket_dir = os.join_path(os.temp_dir(), 'tls_resumption_dial')
const server = 'cloudflare.com:443'

fn run() ! {
	// Reopen the file store: tickets written by any earlier run load here.
	// Encrypted at rest with a stable 32-byte AES-256-GCM key kept in
	// store.key next to tickets.bin; generated on first use so cross-run
	// encrypted resumption works.
	key_path := os.join_path(ticket_dir, 'store.key')
	key := os.read_bytes(key_path) or {
		os.mkdir_all(ticket_dir, mode: 0o700) or { return err }
		mut generated := crypto.rand.bytes(32)! or { return err }
		os.write_bytes(key_path, generated)! or { return err }
		os.chmod(key_path, 0o600) or { return err }
		generated
	}
	mut store := tls.new_encrypted_file_ticket_store(ticket_dir, key)! or { return err }
	persisted := store.resumption_psks()
	println('store loaded; persisted resumption PSKs: ${persisted.len}')

	// When the store is empty, offer an external PSK so the server is prompted
	// to decline it and issue resumable tickets. A populated store already
	// offers its resumption PSKs through dial() automatically (§4.6.1), and
	// dial() appends them after any caller-supplied PSKs (§4.2.11 ordering).
	mut psks := []handshake.Psk{}
	if persisted.len == 0 {
		psks = [handshake.new_psk(first_psk_identity, first_psk_key)!]
	}

	cfg := tls.Config{
		server_name:          'cloudflare.com'
		insecure_skip_verify: false
		hsk_options:          handshake.HandshakeOptions{}
		root_cas:             none
		min_rsa_bits:         0
		psks:                 psks
		session_ticket_store: tls.SessionTicketStore(store)
		timeout:              30 * time.second
	}

	println('connecting to ${server} (resumption dial, store-seeded offer)...')
	t0 := time.now()
	mut conn := tls.dial(server, cfg)! or { return err }
	elapsed := time.since(t0)
	println('connected; ALPN: "${conn.negotiated_alpn()}"')
	println('handshake took ${elapsed.str()}')

	if idx := conn.negotiated_psk_index() {
		// dial() already burned the resumed pair via store.consume() (§8.6),
		// so there is nothing more for the caller to do here.
		println('resumed via PSK index ${idx}')
	} else {
		println('no resumption; full certificate handshake (store empty or peer declined)')
	}

	req := 'GET / HTTP/1.1\r\nhost: cloudflare.com\r\nconnection: close\r\n\r\n'.bytes()
	conn.write(req)! or { return err }
	mut buf := []u8{len: 8192}
	nr := conn.read(mut buf)! or { return err }
	println('received ${nr} bytes')

	// Persist each accepted ticket to the store before close() zeroizes the
	// traffic secrets. Conn.resumption_psks() derives the §7.2 PSK for every
	// backlog ticket; store.put() write-throughs the pair so the next dial can
	// resume. The post-handshake path in dial() does the same when the
	// resumption master secret is already available; this is the safety net.
	mut tickets := conn.session_tickets()
	mut conn_psks := conn.resumption_psks() or { return err }
	mut stored := 0
	for i in 0 .. tickets.len {
		store.put(tickets[i], conn_psks[i]) or { continue }
		stored += 1
	}
	println('resumption PSKs persisted after this dial: ${stored}')

	conn.close()! or { return err }
}

fn main() {
	run() or {
		println('example failed: ${err.msg()}')
	}
}
