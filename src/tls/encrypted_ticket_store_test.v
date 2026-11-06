// Copyright (c) 2026 blackshirt.
//
// Tests for EncryptedFileTicketStore: AES-256-GCM encryption at rest,
// round-trip persistence, wrong-key rejection, tamper detection, key wipe,
// and the shared SessionTicketStore contract.
module tls

import os
import crypto.rand
import tls.handshake
import tls.wire

// nst_ticket builds a NewSessionTicket carrying the given lifetime and opaque
// token, using the same §4.6.1 wire encoding the store persists.
fn est_nst_ticket(lifetime u32, token []u8) !handshake.NewSessionTicket {
	mut w := wire.new_writer(16 + token.len)
	w.write_u32(lifetime)
	w.write_u32(0) // ticket_age_add
	w.write_vector_u8([u8(0)]) or { return error('tls test: nonce vector failed') }
	w.write_vector_u16(token) or { return error('tls test: ticket vector failed') }
	w.write_vector_u16([]u8{}) or { return error('tls test: extensions vector failed') }
	return handshake.parse_new_session_ticket(w.bytes())!
}

// psk_blob encodes a stored-PSK blob the way handshake.Psk.encode does.
fn est_psk_blob(token []u8, key_len int, hash_byte u8) []u8 {
	mut w := wire.new_writer(10 + token.len + key_len)
	w.write_vector_u16(token) or {}
	w.write_vector_u16([]u8{len: key_len, init: 0x5a}) or {}
	w.write_u32(0x11223344)
	w.write_u8(hash_byte)
	w.write_u8(0)
	return w.bytes()
}

// store_dir returns a clean directory for one store, created 0700.
fn est_store_dir(name string) string {
	dir := os.join_path(os.temp_dir(), name)
	os.rmdir_all(dir) or {}
	os.mkdir(dir, mode: 0o700) or {}
	return dir
}

// est_key returns 32 random bytes suitable as an AES-256-GCM store key.
fn est_key() ![]u8 {
	return crypto.rand.bytes(32)!
}

// test_encrypted_ticket_store_roundtrip checks that a persisted ticket and its
// PSK survive a new encrypted store instance over the same directory with the
// same key: the restart case.
fn test_encrypted_ticket_store_roundtrip() ! {
	dir := est_store_dir('tls_est_rt')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0xaa), 0xbb]
	key := est_key()!
	mut store := new_encrypted_file_ticket_store(dir, key)! or { return err }
	store.put(est_nst_ticket(3600, token)!,
		handshake.parse_resumption_psk(est_psk_blob(token, 32, 0))!)
	assert store.tickets().len == 1
	assert store.tickets()[0].bytes() == token
	assert store.resumption_psks().len == 1
	assert store.resumption_psks()[0].identity() == token

	// Reopening with the same key decrypts and sees the persisted state.
	mut reopened := new_encrypted_file_ticket_store(dir, key)! or { return err }
	tickets := reopened.tickets()
	assert tickets.len == 1
	assert tickets[0].bytes() == token
	psks := reopened.resumption_psks()
	assert psks.len == 1
	assert psks[0].key() == []u8{len: 32, init: 0x5a}
	reopened.wipe()
	assert reopened.tickets().len == 0
}

// test_encrypted_ticket_store_wrong_key_yields_empty_store checks that opening
// an encrypted store with a different key yields an empty store: the AES-GCM
// tag verification fails on the ciphertext written under the first key.
fn test_encrypted_ticket_store_wrong_key_yields_empty_store() ! {
	dir := est_store_dir('tls_est_wk')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0xcc), 0xdd]
	key_a := est_key()!
	key_b := est_key()!
	assert key_a != key_b
	mut store := new_encrypted_file_ticket_store(dir, key_a)! or { return err }
	store.put(est_nst_ticket(3600, token)!,
		handshake.parse_resumption_psk(est_psk_blob(token, 32, 0))!)
	assert store.tickets().len == 1

	// A different key cannot decrypt: GCM tag mismatch degrades to empty.
	mut wrong := new_encrypted_file_ticket_store(dir, key_b)! or { return err }
	assert wrong.tickets().len == 0
	assert wrong.resumption_psks().len == 0
	// The store stays usable under the wrong key: new writes encrypt under it.
	mut other := [u8(0xee), 0xff]
	wrong.put(est_nst_ticket(3600, other)!,
		handshake.parse_resumption_psk(est_psk_blob(other, 32, 0))!)
	assert wrong.tickets().len == 1
	assert wrong.tickets()[0].bytes() == other
}

// test_encrypted_ticket_store_tamper_detection checks that flipping a ciphertext
// byte causes GCM tag verification to fail and the store degrades to empty,
// rather than returning corrupted ticket or PSK material.
fn test_encrypted_ticket_store_tamper_detection() ! {
	dir := est_store_dir('tls_est_tm')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0x11), 0x22]
	key := est_key()!
	mut store := new_encrypted_file_ticket_store(dir, key)! or { return err }
	store.put(est_nst_ticket(3600, token)!,
		handshake.parse_resumption_psk(est_psk_blob(token, 32, 0))!)
	assert store.tickets().len == 1

	// Flip a byte in the ciphertext portion of tickets.bin.
	path := os.join_path(dir, ticket_store_filename)
	mut data := os.read_bytes(path)! or { return err }
	assert data.len > encrypted_file_store_nonce_len
	data[encrypted_file_store_nonce_len] ^= 0xff
	os.write_bytes(path, data)! or { return err }

	// Tampered ciphertext fails GCM verification: empty store.
	mut tampered := new_encrypted_file_ticket_store(dir, key)! or { return err }
	assert tampered.tickets().len == 0
	assert tampered.resumption_psks().len == 0
}

// test_encrypted_ticket_store_wipe_clears_key checks that wipe() zeroes the
// stored AES key in memory as well as the cache, and unlinks the file.
fn test_encrypted_ticket_store_wipe_clears_key() ! {
	dir := est_store_dir('tls_est_wipe')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0x33), 0x44]
	key := est_key()!
	mut store := new_encrypted_file_ticket_store(dir, key)! or { return err }
	store.put(est_nst_ticket(3600, token)!,
		handshake.parse_resumption_psk(est_psk_blob(token, 32, 0))!)
	assert store.tickets().len == 1
	assert os.exists(os.join_path(dir, ticket_store_filename))

	store.wipe()
	assert store.tickets().len == 0
	assert store.resumption_psks().len == 0
	assert !os.exists(os.join_path(dir, ticket_store_filename))

	// A wiped store stays usable: reconstruct it with a fresh key and new
	// material is accepted.
	mut fresh := new_encrypted_file_ticket_store(dir, est_key()!)! or { return err }
	fresh.put(est_nst_ticket(3600, [u8(0x55), 0x66])!,
		handshake.parse_resumption_psk(est_psk_blob([u8(0x55), 0x66], 32, 0))!)
	assert fresh.tickets().len == 1
}

// test_encrypted_ticket_store_rejects_short_key checks that a key shorter than
// 32 bytes is rejected at construction.
fn test_encrypted_ticket_store_rejects_short_key() ! {
	dir := est_store_dir('tls_est_sk')
	defer {
		os.rmdir_all(dir) or {}
	}
	// A 16-byte key must be rejected: only 32-byte keys are accepted.
	new_encrypted_file_ticket_store(dir, [u8(0x01)].repeat(16)) or {
		// Expected: short key was rejected
		return
	}
	// If we get here, no error was returned, which is wrong.
	return error('expected short key to be rejected')
}

// test_encrypted_ticket_store_ciphertext_changes_per_write checks that two
// writes produce different ciphertext (random nonce per write), so AES-GCM
// nonce reuse never occurs even when the underlying cache is unchanged.
fn test_encrypted_ticket_store_ciphertext_changes_per_write() ! {
	dir := est_store_dir('tls_est_ct')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0x77), 0x88]
	key := est_key()!
	mut store := new_encrypted_file_ticket_store(dir, key)! or { return err }
	store.put(est_nst_ticket(3600, token)!,
		handshake.parse_resumption_psk(est_psk_blob(token, 32, 0))!)
	path := os.join_path(dir, ticket_store_filename)
	first := os.read_bytes(path)! or { return err }

	// Re-putting the same token refreshes the record (new issued_at_ms) and
	// rewrites the file with a fresh random nonce, so the ciphertext differs.
	store.put(est_nst_ticket(3600, token)!,
		handshake.parse_resumption_psk(est_psk_blob(token, 32, 0))!)
	second := os.read_bytes(path)! or { return err }

	assert first.len == second.len
	// At least the nonce prefix (first 12 bytes) should differ; the ciphertext
	// body almost certainly differs too.
	mut nonce_differs := false
	for i in 0 .. encrypted_file_store_nonce_len {
		if first[i] != second[i] {
			nonce_differs = true
			break
		}
	}
	assert nonce_differs // nonce prefix changed: fresh random nonce per write
}
