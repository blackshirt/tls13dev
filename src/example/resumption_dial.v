// Copyright (c) 2026 blackshirt.
//
// Dedicated example: resume a TLS 1.3 session using tickets persisted to the
// file ticket store by a previous run.
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
//      (§4.6.1). dial() write-throughs each accepted ticket with its §7.2 PSK
//      to tickets.bin, so the store is populated for the next run.
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
	mut store := tls.new_file_ticket_store(ticket_dir)! or { return err }
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
		// Mirror dial()'s offer so the reported index maps to a real identity,
		// then burn the pair (§8.6 single-use) so it is not re-offered later.
		mut offered := [][]u8{}
		for p in store.resumption_psks() {
			if p.identity() in offered {
				continue
			}
			offered << p.identity().clone()
		}
		println('resumed via PSK index ${idx}')
		store.consume(offered[int(idx)])
	} else {
		println('no resumption; full certificate handshake (store empty or peer declined)')
	}

	req := 'GET / HTTP/1.1\r\nhost: cloudflare.com\r\nconnection: close\r\n\r\n'.bytes()
	conn.write(req)! or { return err }
	mut buf := []u8{len: 8192}
	nr := conn.read(mut buf)! or { return err }
	println('received ${nr} bytes')

	// Tickets accepted this run are write-through too, refreshing the store.
	refreshed := store.resumption_psks()
	println('resumption PSKs persisted after this dial: ${refreshed.len}')

	conn.close()! or { return err }
}

fn main() {
	run() or {
		println('example failed: ${err.msg()}')
	}
}
