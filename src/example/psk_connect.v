// Copyright (c) 2026 blackshirt.
//
// TLS 1.3 connect example with RFC 8446 §7.2 PSK resumption, backed by a file
// ticket store so resumption state survives across runs.
//
// Run:
//   v run src/example/psk_connect.v   (from repo root)
//
// Flow:
//   1. Open the encrypted file ticket store at <temp>/tls_psk_connect —
//      tickets.bin holds whatever tickets + §7.2 PSKs an earlier run persisted.
//   2. Build a single Config whose session_ticket_store is that store, then
//      dial once. dial() seeds Conn's backlog from store.tickets() and appends
//      store.resumption_psks() to the ClientHello's pre_shared_key list
//      (§4.6.1/§4.2.11), so resumption fires with no caller-side PSK plumbing.
//   3. If Cloudflare rejects the stored PSK binder (decrypt_error — ticket
//      nonce/age stale after a process restart), fall back to a plain
//      certificate handshake without store seeding, then persist the fresh
//      tickets + §7.2 PSKs to the store for the next run.
//   4. If the server accepted a stored PSK, negotiated_psk_index() reports it
//      and dial() already burned that pair via store.consume() (§8.6).
//   5. Tickets accepted on this connection are write-through to the store too,
//      refreshing resumption state across runs.
//
// A first run against cloudflare.com:443 may not resume (Cloudflare may decline
// to issue resumable tickets), but it will populate tickets.bin whenever it
// issues them. A later run then offers them automatically.
//
// The store is encrypted at rest with a stable 32-byte AES-256-GCM key kept in
// store.key next to tickets.bin; the key is generated on first use and reused
// thereafter, so cross-run encrypted resumption works.
module main

import crypto
import crypto.rand
import os
import time
import tls
import tls.handshake

// ticket_dir holds tickets.bin and store.key, the persisted resumption state.
// A fixed path lets the store outlive this process; the next run reopens it.
const ticket_dir = os.join_path(os.temp_dir(), 'tls_psk_connect')

// new_store_key loads the stored AES-256-GCM key from store.key, generating and
// persisting it on first use so the encrypted store can reopen tickets.bin
// across runs.
fn new_store_key(dir string) ![]u8 {
	key_path := os.join_path(dir, 'store.key')
	return os.read_bytes(key_path) or {
		os.mkdir_all(dir, mode: 0o700) or { return err }
		mut generated := crypto.rand.bytes(32)! or { return err }
		os.write_bytes(key_path, generated)! or { return err }
		os.chmod(key_path, 0o600) or { return err }
		generated
	}
}

fn run() ! {
	// Open the encrypted store; tickets written by any earlier run load here.
	key := new_store_key(ticket_dir)! or { return err }
	mut store := tls.new_encrypted_file_ticket_store(ticket_dir, key)! or { return err }
	persisted := store.resumption_psks()
	println('store loaded; persisted resumption PSKs: ${persisted.len}')

	// Single dial: load from persisted store, then dial. dial() seeds the
	// ClientHello from store.resumption_psks() automatically (§4.6.1). The
	// external PSK is offered only when the store is empty, to prompt the
	// server into issuing resumable tickets (§4.6.1).
	mut psks := []handshake.Psk{}
	if persisted.len == 0 {
		psks = [handshake.new_psk('example-external-first'.bytes(), [u8(0x42)].repeat(32))!]
	}
	t0 := time.now()
	mut conn := tls.dial('cloudflare.com:443', tls.Config{
		server_name:          'cloudflare.com'
		insecure_skip_verify: false
		hsk_options:          handshake.HandshakeOptions{}
		root_cas:             none
		min_rsa_bits:         0
		psks:                 psks
		session_ticket_store: tls.SessionTicketStore(store)
		timeout:              30 * time.second
	}) or {
		// Stale stored tickets: the server rejected the PSK binder
		// (decrypt_error — ticket nonce/age stale across the process restart).
		// Fall back to a plain certificate handshake without store seeding so
		// the stale PSKs are not re-offered, then persist fresh tickets to the
		// store for the next run.
		println('stored PSK binder rejected by server; falling back to certificate handshake...')
		mut fallback_psks := []handshake.Psk{}
		fallback_psks = [handshake.new_psk('example-external-first'.bytes(), [u8(0x42)].repeat(32))!]
		mut fresh_conn := tls.dial('cloudflare.com:443', tls.Config{
			server_name:          'cloudflare.com'
			insecure_skip_verify: false
			hsk_options:          handshake.HandshakeOptions{}
			root_cas:             none
			min_rsa_bits:         0
			psks:                 fallback_psks
			timeout:              30 * time.second
		}) or { return err }
		// Persist fresh tickets + §7.2 PSKs before close() zeroizes secrets.
		mut tickets := fresh_conn.session_tickets()
		mut fresh_psks := fresh_conn.resumption_psks() or { return err }
		mut stored := 0
		for i in 0 .. tickets.len {
			store.put(tickets[i], fresh_psks[i]) or { continue }
			stored += 1
		}
		println('cert handshake; new tickets persisted: ${stored}')
		fresh_conn
	}
	elapsed := time.since(t0)

	println('connected; ALPN: "${conn.negotiated_alpn()}"')
	println('handshake took ${elapsed.str()}')

	if idx := conn.negotiated_psk_index() {
		// dial() already burned the resumed pair via store.consume() (§8.6),
		// so there is nothing more for the caller to do here.
		println('resumed via PSK index ${idx}')
	} else {
		println('full certificate handshake (store empty or peer declined)')
	}

	req := 'GET / HTTP/1.1\r\nhost: cloudflare.com\r\nconnection: close\r\n\r\n'.bytes()
	conn.write(req)! or { return err }
	mut buf := []u8{len: 8192}
	nr := conn.read(mut buf)! or { return err }
	println('received ${nr} bytes')

	// Tickets accepted this run are write-through too, refreshing the store.
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
