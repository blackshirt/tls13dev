// Copyright (c) 2026 blackshirt.
//
// Tests for the ticket stores: the FileTicketStore file round-trip and its
// expiry, reissue, bound-pair, single-use, merge and corrupt-input behaviour,
// the AES-256-GCM encrypted file backend's at-rest protection and key-rotation
// detection, and the in-memory backend's share of the same SessionTicketStore
// contract dial() drives.
module tls

import os
import time
import crypto.rand
import crypto
import tls.handshake
import tls.wire

// nst_ticket builds a NewSessionTicket carrying the given lifetime and opaque
// token, using the same §4.6.1 wire encoding the store persists.
fn nst_ticket(lifetime u32, token []u8) !handshake.NewSessionTicket {
	mut w := wire.new_writer(16 + token.len)
	w.write_u32(lifetime)
	w.write_u32(0) // ticket_age_add
	w.write_vector_u8([u8(0)]) or { return error('tls test: nonce vector failed') }
	w.write_vector_u16(token) or { return error('tls test: ticket vector failed') }
	w.write_vector_u16([]u8{}) or { return error('tls test: extensions vector failed') }
	return handshake.parse_new_session_ticket(w.bytes())!
}

// psk_blob encodes a stored-PSK blob the way handshake.Psk.encode does, so the
// tests can also write deliberately malformed ones.
fn psk_blob(token []u8, key_len int, hash_byte u8) []u8 {
	return psk_blob_age(token, key_len, hash_byte, 0x11223344)
}

// psk_blob_age is psk_blob with an explicit obfuscated_ticket_age, so a test
// can pin the age arithmetic the store performs on the way out.
fn psk_blob_age(token []u8, key_len int, hash_byte u8, age u32) []u8 {
	mut w := wire.new_writer(10 + token.len + key_len)
	w.write_vector_u16(token) or {}
	w.write_vector_u16([]u8{len: key_len, init: 0x5a}) or {}
	w.write_u32(age)
	w.write_u8(hash_byte)
	w.write_u8(0)
	return w.bytes()
}

// psk_blob_rejected reports whether parse_resumption_psk refuses `blob` with an
// error naming `want`. It is a helper rather than an `or {}` block so that a
// blob wrongly accepted fails the test instead of skipping the check.
fn psk_blob_rejected(blob []u8, want string) bool {
	_ := handshake.parse_resumption_psk(blob) or {
		return err.msg().contains(want)
	}
	return false
}

// blob_age reads the u32 obfuscated_ticket_age out of a Psk.encode blob: the
// field follows the two length-prefixed vectors, so its offset is the identity
// and key fields plus their four prefix bytes. The age itself is private to
// tls.handshake, which is why a store test decodes it instead of reading it.
fn blob_age(blob []u8, token_len int, key_len int) u32 {
	off := 2 + token_len + 2 + key_len
	return (u32(blob[off]) << 24) | (u32(blob[off + 1]) << 16) | (u32(blob[off + 2]) << 8) | u32(blob[off + 3])
}

// write_store_file lays out the store file by hand — magic, version, count and
// one record — so tests can feed the loader exact (or exact-wrong) bytes.
fn write_store_file(dir string, ticket_body []u8, blob []u8) ! {
	mut w := wire.new_writer(32 + ticket_body.len + blob.len)
	w.write_bytes(ticket_store_magic.bytes())
	w.write_u8(ticket_store_version)
	w.write_u16(1)
	w.write_u64(u64(time.utc().unix_milli()))
	w.write_vector_u16(ticket_body) or {}
	w.write_vector_u16(blob) or {}
	os.write_bytes(os.join_path(dir, ticket_store_filename), w.bytes())!
}

// store_dir returns a clean directory for one store, so tests never share or
// inherit a tickets.bin from an earlier run. It is created 0700 rather than at
// os.mkdir's 0777 default, because a store refuses a group- or world-writable
// directory and umask 0 would otherwise leave every one of these tests failing.
fn store_dir(name string) string {
	dir := os.join_path(os.temp_dir(), name)
	os.rmdir_all(dir) or {}
	os.mkdir(dir, mode: 0o700) or {}
	return dir
}

// est_key returns 32 random bytes suitable as an AES-256-GCM store key.
fn est_key() ![]u8 {
	return crypto.rand.bytes(32)!
}

// test_file_ticket_store_roundtrip checks that a persisted ticket and its PSK
// survive a new store instance over the same directory: the restart case.
fn test_file_ticket_store_roundtrip() ! {
	dir := store_dir('tls_tstore_rt')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0xaa), 0xbb]
	mut store := new_file_ticket_store(dir)!
	store.put(nst_ticket(3600, token)!, handshake.parse_resumption_psk(psk_blob(token, 32, 0))!)
	assert store.tickets().len == 1

	mut reopened := new_file_ticket_store(dir)!
	tickets := reopened.tickets()
	assert tickets.len == 1
	assert tickets[0].lifetime() == 3600
	assert tickets[0].bytes() == token
	// The PSK is what makes the persisted ticket resumable, so it must come back
	// with its key bytes intact (§7.2).
	psks := reopened.resumption_psks()
	assert psks.len == 1
	assert psks[0].identity() == token
	assert psks[0].key() == []u8{len: 32, init: 0x5a}
	// Wiping the reopened store scrubs the key the file handed out.
	reopened.wipe()
	assert reopened.resumption_psks().len == 0
}

// test_file_ticket_store_new_creates_missing_dir checks that a store can be
// pointed at a path that does not exist yet.
fn test_file_ticket_store_new_creates_missing_dir() ! {
	base := store_dir('tls_tstore_mk')
	dir := os.join_path(base, 'nested')
	defer {
		os.rmdir_all(base) or {}
	}
	assert !os.exists(dir)
	_ := new_file_ticket_store(dir)!
	assert os.is_dir(dir)
}

// store_dir_refused reports whether new_file_ticket_store refuses `dir` with an
// error naming `want`. It is a helper rather than an `or {}` block so that a
// directory wrongly accepted fails the test instead of skipping the check.
fn store_dir_refused(dir string, want string) bool {
	_ := new_file_ticket_store(dir) or {
		return err.msg().contains(want)
	}
	return false
}

// test_file_ticket_store_rejects_open_directory pins the constructor's shared-path
// guard: a directory anyone but the owner may write to is not a place to put key
// material, since whoever owns it can replace tickets.bin and read what this
// process persists.
fn test_file_ticket_store_rejects_open_directory() ! {
	dir := store_dir('tls_tstore_open')
	defer {
		os.chmod(dir, 0o700) or {}
		os.rmdir_all(dir) or {}
	}
	$if !windows {
		// chmod, unlike mkdir's mode argument, is not filtered through the process
		// umask, so this open mode is reproducible wherever the test runs.
		os.chmod(dir, 0o777) or {}
		assert store_dir_refused(dir, 'group- or world-writable')
		// The same path becomes usable again once it is private.
		os.chmod(dir, 0o700) or {}
		_ := new_file_ticket_store(dir)!
	}
}

// test_file_ticket_store_rejects_file_path checks that the path a store is asked
// for has to be a directory: an existing file there is reported, not silently
// replaced by a tickets.bin beside it.
fn test_file_ticket_store_rejects_file_path() ! {
	dir := store_dir('tls_tstore_file')
	defer {
		os.rmdir_all(dir) or {}
	}
	path := os.join_path(dir, 'not_a_directory')
	os.write_file(path, 'x')!
	assert store_dir_refused(path, 'cannot create ticket store directory')
}

// test_file_ticket_store_expired_dropped checks that a ticket whose lifetime
// elapsed is dropped from tickets() and resumption_psks(), scrubbed and rewritten
// away rather than merely hidden. A §4.6.1 lifetime of 0, which put() refuses, is
// dropped the same way once it arrives through a file.
fn test_file_ticket_store_expired_dropped() ! {
	dir := store_dir('tls_tstore_exp')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0x01), 0x02]
	mut store := new_file_ticket_store(dir)!
	store.put(nst_ticket(10, token)!, handshake.parse_resumption_psk(psk_blob(token, 32, 0))!)
	// Age the record past its lifetime by hand: a 10-second ticket issued an
	// hour ago, written back so the file carries the stale timestamp too.
	mut aged := store.read_file()
	aged[0].issued_at_ms -= i64(3600) * 1000
	store.cache = aged
	store.write_file()

	assert store.tickets().len == 0
	assert store.resumption_psks().len == 0
	assert store.read_file().len == 0 // expiry was persisted, not merely filtered

	// A lifetime of 0 means the server forbade resumption with that ticket, and only
	// a peer's file can hand one over, since put() refuses it. The load path accepts
	// it, so the read path must delete it rather than just hide it.
	write_store_file(dir, nst_ticket(0, token)!.encode(), psk_blob(token, 32, 0))!
	mut reloaded := new_file_ticket_store(dir)!
	assert reloaded.read_file().len == 1
	assert reloaded.tickets().len == 0
	assert reloaded.read_file().len == 0
}

// test_file_ticket_store_psks_age checks the §4.6.1 age arithmetic end to end
// through the store: a record aged by hand is still offered, and its encoded
// PSK blob carries the elapsed milliseconds folded into ticket_age_add (mod
// 2^32), so a day-old ticket does not present itself as freshly minted. The
// age field itself is module-private to tls.handshake, so the assertion reads
// it out of the serialized blob the store emits.
fn test_file_ticket_store_psks_age() ! {
	dir := store_dir('tls_tstore_age')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0x21), 0x22]
	mut store := new_file_ticket_store(dir)!
	store.put(nst_ticket(86400, token)!, handshake.parse_resumption_psk(psk_blob_age(token, 32, 0, 1000))!)
	mut aged := store.read_file()
	aged[0].issued_at_ms -= i64(60000)
	store.cache = aged
	store.write_file()

	psks := store.resumption_psks()
	assert psks.len == 1
	age := blob_age(psks[0].encode(), token.len, 32)
	assert age >= u32(1000 + 60000) && age <= u32(1000 + 60005)
	// The held time comes from the record's own timestamp, so ageing the
	// timestamp another minute advances the reported age with it.
	mut older := store.read_file()
	older[0].issued_at_ms -= i64(60000)
	store.cache = older
	store.write_file()
	assert blob_age(store.resumption_psks()[0].encode(), token.len, 32) >= u32(1000 + 120000)
	// Reads hand out aged copies; the persisted PSK keeps its issue-time age.
	assert blob_age(store.read_file()[0].psk.encode(), token.len, 32) == u32(1000)
}

// test_ticket_is_live_expiry_rules covers the expiry edges a wall-clock fixture
// cannot reach: lifetime 0, an expired ticket and a rewound clock, and the split
// between truly expiring (prune_expired deletes) and merely hiding (the reads do).
fn test_ticket_is_live_expiry_rules() ! {
	ticket := nst_ticket(3600, [u8(0x7f), 0x7e])!
	zero := nst_ticket(0, [u8(0x7f), 0x7e])!
	issued := time.utc().unix_milli()
	assert ticket_is_live(ticket, issued, issued)
	assert ticket_is_live(ticket, issued, issued + i64(3599) * 1000)
	assert !ticket_is_live(ticket, issued, issued + i64(3600) * 1000)
	assert !ticket_is_live(zero, issued, issued) // §4.6.1: lifetime 0 disallows resumption
	assert !ticket_is_live(ticket, issued, issued - 1) // clock behind the issue time
	// A clock behind the record makes a ticket unofferable, not expired: only the
	// server's own lifetime may destroy it.
	assert !ticket_expired(ticket, issued, issued - 1)
	assert !ticket_expired(ticket, issued, issued + i64(3599) * 1000)
	assert ticket_expired(ticket, issued, issued + i64(3600) * 1000)
	assert ticket_expired(zero, issued, issued)
}

// test_file_ticket_store_reissue_refreshes_in_place checks that reissuing the
// same opaque token replaces the old record instead of taking a second slot.
fn test_file_ticket_store_reissue_refreshes_in_place() ! {
	dir := store_dir('tls_tstore_reissue')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0xcc), 0xdd]
	mut store := new_file_ticket_store(dir)!
	store.put(nst_ticket(3600, token)!, handshake.parse_resumption_psk(psk_blob(token, 32, 0))!)
	store.put(nst_ticket(7200, token)!, handshake.parse_resumption_psk(psk_blob(token, 48, 1))!)

	tickets := store.tickets()
	assert tickets.len == 1
	assert tickets[0].lifetime() == 7200
	psks := store.resumption_psks()
	assert psks.len == 1
	assert psks[0].key().len == 48 // the refreshed key, not the first one
	assert store.read_file().len == 1
}

// test_file_ticket_store_survives_borrower_wipe checks that the tickets a store
// hands out are its borrower's to destroy, and that a ticket the borrower owns
// is not what the store kept: Conn's teardown wipes every backlog ticket in place
// (§7.5), so shared buffers would zero the cache and the next rewrite would
// persist empty tokens.
fn test_file_ticket_store_survives_borrower_wipe() ! {
	dir := store_dir('tls_tstore_alias')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0xa1), 0xa2, 0xa3]
	next := [u8(0xb1), 0xb2]
	psk := handshake.parse_resumption_psk(psk_blob(token, 32, 0))!
	mut store := new_file_ticket_store(dir)!
	store.put(nst_ticket(3600, token)!, psk)

	mut borrowed := store.tickets()
	assert borrowed.len == 1
	borrowed[0].wipe() // what Conn.destroy_all() does to each backlog entry
	assert store.tickets()[0].bytes() == token
	store.write_file()
	assert store.read_file()[0].ticket.bytes() == token

	// The other direction: put() must survive the caller wiping the ticket it
	// handed over when that connection closes.
	mut issued := nst_ticket(3600, next)!
	store.put(issued, handshake.parse_resumption_psk(psk_blob(next, 32, 0))!)
	issued.wipe()
	assert store.tickets().len == 2
	assert store.tickets()[1].bytes() == next
	store.write_file()
	assert store.read_file()[1].ticket.bytes() == next
}

// test_file_ticket_store_future_dated_record_is_hidden checks that a record
// dated ahead of the clock — an NTP correction, or a clock glitch — is hidden by
// both reads but never pruned: deleting it would turn a time adjustment into lost
// tickets, and it becomes usable again once the clock catches up.
fn test_file_ticket_store_future_dated_record_is_hidden() ! {
	dir := store_dir('tls_tstore_future')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0xc1), 0xc2]
	mut store := new_file_ticket_store(dir)!
	store.put(nst_ticket(3600, token)!, handshake.parse_resumption_psk(psk_blob(token, 32, 0))!)
	mut ahead := store.read_file()
	ahead[0].issued_at_ms += i64(120000)
	store.cache = ahead
	store.write_file()

	assert store.tickets().len == 0
	assert store.resumption_psks().len == 0
	assert store.read_file().len == 1 // hidden, not destroyed

	mut caught := store.read_file()
	caught[0].issued_at_ms = now_ms_or_zero() - i64(1000)
	store.cache = caught
	assert store.tickets()[0].bytes() == token
	assert blob_age(store.resumption_psks()[0].encode(), token.len, 32) >= u32(1000)
}

// test_file_ticket_store_bounds_cache checks the cache and the file both stop
// at max_stored_session_tickets, keeping the earliest records.
fn test_file_ticket_store_bounds_cache() ! {
	dir := store_dir('tls_tstore_bound')
	defer {
		os.rmdir_all(dir) or {}
	}
	mut store := new_file_ticket_store(dir)!
	for i in 0 .. max_stored_session_tickets + 8 {
		token := [u8(i), 0x5a]
		store.put(nst_ticket(3600, token)!, handshake.parse_resumption_psk(psk_blob(token, 32, 0))!)
	}
	assert store.tickets().len == max_stored_session_tickets
	assert store.resumption_psks().len == max_stored_session_tickets
	assert store.read_file().len == max_stored_session_tickets
	assert store.tickets()[0].bytes() == [u8(0), 0x5a]
}

// test_ticket_stores_reject_mismatched_pair pins the §7.2 bound-pair guard every
// entry point shares: a PSK whose identity is not the ticket it arrived with can
// never be offered as binder material for that ticket again, so put() and the
// loader both refuse it instead of keeping a record no read could match.
fn test_ticket_stores_reject_mismatched_pair() ! {
	dir := store_dir('tls_tstore_pair')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0x01), 0x02]
	foreign := [u8(0x03), 0x04]
	mismatched := handshake.parse_resumption_psk(psk_blob(foreign, 32, 0))!
	mut store := new_file_ticket_store(dir)!
	store.put(nst_ticket(3600, token)!, mismatched)
	assert store.tickets().len == 0
	assert store.resumption_psks().len == 0
	assert store.read_file().len == 0 // refused before anything was persisted

	mut mem := new_in_memory_ticket_store()
	mem.put(nst_ticket(3600, token)!, mismatched)
	assert mem.tickets().len == 0
	assert mem.resumption_psks().len == 0
	// Only the identity below changes, so the guard rather than some other
	// rejection is what emptied the store above.
	store.put(nst_ticket(3600, token)!, handshake.parse_resumption_psk(psk_blob(token, 32, 0))!)
	assert store.tickets().len == 1
	assert store.read_file().len == 1
	// The loader applies the same rule, so a hand-edited file cannot smuggle an
	// unbindable pair into a later resumption offer either.
	write_store_file(dir, nst_ticket(3600, token)!.encode(), psk_blob(foreign, 32, 0))!
	mut reloaded := new_file_ticket_store(dir)!
	assert reloaded.read_file().len == 0
	assert reloaded.tickets().len == 0
	assert reloaded.resumption_psks().len == 0
}

// test_file_ticket_store_consume_burns_used_ticket covers the §8.6 duty dial()
// owes after resuming: the record it resumed on must leave the store in memory
// and on disk, or a restart would offer a PSK the peer has already seen used.
fn test_file_ticket_store_consume_burns_used_ticket() ! {
	dir := store_dir('tls_tstore_consume')
	defer {
		os.rmdir_all(dir) or {}
	}
	used := [u8(0xe1), 0xe2]
	spare := [u8(0xf1), 0xf2]
	mut store := new_file_ticket_store(dir)!
	store.put(nst_ticket(3600, used)!, handshake.parse_resumption_psk(psk_blob(used, 32, 0))!)
	store.put(nst_ticket(3600, spare)!, handshake.parse_resumption_psk(psk_blob(spare, 32, 0))!)
	assert store.read_file().len == 2

	store.consume(used) or {}
	assert store.tickets().len == 1
	assert store.tickets()[0].bytes() == spare
	assert store.resumption_psks()[0].identity() == spare
	assert store.read_file().len == 1 // the burn was persisted, not just cached
	assert store.read_file()[0].ticket.bytes() == spare
	// A restarted process must not offer the burned PSK back either.
	mut reopened := new_file_ticket_store(dir)!
	assert reopened.resumption_psks().len == 1
	assert reopened.resumption_psks()[0].identity() == spare
	// An identity the store never held — a caller's external PSK — burns nothing.
	reopened.consume([u8(0xfe), 0xff]) or {}
	assert reopened.tickets().len == 1
}

// test_file_ticket_store_merge_keeps_peer_records covers the lost-update case a
// whole-file rewrite has: another process persisted a record this store never
// loaded, so write_file folds the file back in first. A token both copies hold
// keeps this store's fresher version.
fn test_file_ticket_store_merge_keeps_peer_records() ! {
	dir := store_dir('tls_tstore_merge')
	defer {
		os.rmdir_all(dir) or {}
	}
	mine := [u8(0x62), 0x63]
	theirs := [u8(0x60), 0x61]
	later := [u8(0x64), 0x65]
	mut store := new_file_ticket_store(dir)!
	store.put(nst_ticket(3600, mine)!, handshake.parse_resumption_psk(psk_blob(mine, 32, 0))!)
	// A peer rewrites tickets.bin with only its own record while this store holds
	// `mine`; the next write must not drop the peer's.
	write_store_file(dir, nst_ticket(3600, theirs)!.encode(), psk_blob(theirs, 32, 0))!
	store.put(nst_ticket(7200, mine)!, handshake.parse_resumption_psk(psk_blob(mine, 48, 1))!)
	records := store.read_file()
	assert records.len == 2
	assert records[0].ticket.bytes() == mine
	assert records[0].psk.key().len == 48 // this store's refreshed copy won its own token
	assert records[1].ticket.bytes() == theirs
	// The merged record is resumable, so its PSK came through the peer's file.
	assert store.resumption_psks().len == 2
	// A stale peer copy of a token this store already holds cannot overwrite it.
	write_store_file(dir, nst_ticket(1200, mine)!.encode(), psk_blob(mine, 32, 0))!
	store.put(nst_ticket(3600, later)!, handshake.parse_resumption_psk(psk_blob(later, 32, 0))!)
	assert store.tickets()[0].lifetime() == 7200
	assert store.read_file().len == 3
}

// test_file_ticket_store_header_count_matches_records pins the whole-file header
// count to what was actually serialized, so a reader never waits for records that
// are not there. The count is read out of the raw bytes rather than through the
// loader, which stops it from agreeing with itself.
fn test_file_ticket_store_header_count_matches_records() ! {
	dir := store_dir('tls_tstore_count')
	defer {
		os.rmdir_all(dir) or {}
	}
	a := [u8(0x70), 0x71]
	b := [u8(0x72), 0x73]
	c := [u8(0x74), 0x75]
	mut store := new_file_ticket_store(dir)!
	store.put(nst_ticket(3600, a)!, handshake.parse_resumption_psk(psk_blob(a, 32, 0))!)
	store.put(nst_ticket(3600, b)!, handshake.parse_resumption_psk(psk_blob(b, 32, 0))!)
	store.put(nst_ticket(3600, c)!, handshake.parse_resumption_psk(psk_blob(c, 32, 0))!)
	path := os.join_path(dir, ticket_store_filename)
	raw := os.read_bytes(path)!
	assert raw.len > ticket_store_header_len
	assert raw[..ticket_store_magic.len].bytestr() == ticket_store_magic
	assert raw[ticket_store_magic.len] == ticket_store_version
	count := (u16(raw[ticket_store_magic.len + 1]) << 8) | u16(raw[ticket_store_magic.len + 2])
	assert count == u16(3)

	store.consume(b) or {}
	burned := os.read_bytes(path)!
	count2 := (u16(burned[ticket_store_magic.len + 1]) << 8) | u16(burned[ticket_store_magic.len + 2])
	assert count2 == u16(2)
	assert store.read_file().len == 2
	assert store.tickets()[0].bytes() == a
	assert store.tickets()[1].bytes() == c
}

// test_file_ticket_store_oversized_file_is_ignored bounds the damage a planted
// tickets.bin can do: past what this writer could itself produce the file is not
// a ticket store, so it is never read into memory or parsed, and the store still
// persists normally afterwards.
fn test_file_ticket_store_oversized_file_is_ignored() ! {
	dir := store_dir('tls_tstore_size')
	defer {
		os.rmdir_all(dir) or {}
	}
	path := os.join_path(dir, ticket_store_filename)
	mut big := []u8{cap: ticket_store_max_file_len + 1}
	big << ticket_store_magic.bytes()
	big << ticket_store_version
	big << u8(0)
	big << []u8{len: ticket_store_max_file_len + 1 - big.len}
	os.write_bytes(path, big)!
	mut store := new_file_ticket_store(dir)!
	assert store.read_file().len == 0
	assert store.tickets().len == 0
	// The oversized file cannot wedge the store: its own write replaces it.
	token := [u8(0x8a), 0x8b]
	store.put(nst_ticket(3600, token)!, handshake.parse_resumption_psk(psk_blob(token, 32, 0))!)
	assert store.read_file().len == 1
	assert store.tickets()[0].bytes() == token
}

// test_file_ticket_store_rejects_foreign_file checks that a file this build did
// not write — an older layout, or plain garbage — yields an empty store, and
// that the store can still persist afterwards.
fn test_file_ticket_store_rejects_foreign_file() ! {
	dir := store_dir('tls_tstore_foreign')
	defer {
		os.rmdir_all(dir) or {}
	}
	path := os.join_path(dir, ticket_store_filename)
	body := nst_ticket(3600, [u8(0x11), 0x22])!.encode()
	mut legacy := []u8{} // pre-magic framing: u16 length + wire body, no header
	legacy << u8(body.len >> 8)
	legacy << u8(body.len & 0xff)
	legacy << body
	os.write_bytes(path, legacy)!

	mut store := new_file_ticket_store(dir)!
	assert store.tickets().len == 0
	assert store.resumption_psks().len == 0
	os.write_file(path, 'garbage')!
	assert store.read_file().len == 0
	token := [u8(0x33), 0x34]
	store.put(nst_ticket(3600, token)!, handshake.parse_resumption_psk(psk_blob(token, 32, 0))!)
	records := store.read_file()
	assert records.len == 1
	assert records[0].ticket.bytes() == token
	assert records[0].psk.key().len == 32
}

// test_file_ticket_store_rejects_bad_psk_blob checks that a record whose PSK
// half is malformed never reaches the handshake: parse_resumption_psk screens
// the §7.1 key floors on the way in, and the loader skips such a record.
fn test_file_ticket_store_rejects_bad_psk_blob() ! {
	dir := store_dir('tls_tstore_badpsk')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0x77), 0x78]
	// A 16-byte key is under the 32-byte §7.1 floor, so the decoder must refuse it.
	assert psk_blob_rejected(psk_blob(token, 16, 0), 'stored PSK key')
	write_store_file(dir, nst_ticket(3600, token)!.encode(), psk_blob(token, 16, 0))!
	mut store := new_file_ticket_store(dir)!
	assert store.tickets().len == 0
	assert store.resumption_psks().len == 0
	write_store_file(dir, nst_ticket(3600, token)!.encode(), psk_blob(token, 32, 0))!
	assert store.read_file().len == 1
}

// test_file_ticket_store_wipe_clears_file checks the §7.5 teardown path: cache
// and file are both emptied, the file's name is unlinked rather than left behind
// as a zero-length record, and the store stays usable.
fn test_file_ticket_store_wipe_clears_file() ! {
	dir := store_dir('tls_tstore_wipe')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0x44), 0x45]
	mut store := new_file_ticket_store(dir)!
	store.put(nst_ticket(3600, token)!, handshake.parse_resumption_psk(psk_blob(token, 32, 0))!)
	assert store.tickets().len == 1

	store.wipe()
	assert store.tickets().len == 0
	assert store.resumption_psks().len == 0
	assert store.read_file().len == 0
	assert !os.exists(os.join_path(dir, ticket_store_filename)) // unlink, not truncate
	next := [u8(0x55), 0x56]
	store.put(nst_ticket(3600, next)!, handshake.parse_resumption_psk(psk_blob(next, 32, 0))!)
	assert store.read_file().len == 1
}

// test_in_memory_ticket_store_expiry_and_age covers the half of the shared
// store behaviour that is not file-specific: an expired pair disappears from both
// reads and frees its slot, a §4.6.1 lifetime-0 pair never gets in at all, and
// the age advanced on the way out never compounds (reads hand out copies).
fn test_in_memory_ticket_store_expiry_and_age() ! {
	token := [u8(0x99), 0x9a]
	psk := handshake.parse_resumption_psk(psk_blob_age(token, 32, 0, 1000))!
	mut store := new_in_memory_ticket_store()
	store.put(nst_ticket(3600, token)!, psk)
	// §4.6.1: a lifetime of 0 means the server disallows resumption with that
	// ticket, so put() refuses it outright — with its own PSK, so what is refused
	// here is the lifetime rather than the §7.2 pair binding.
	zero_token := [u8(0x9b), 0x9c]
	store.put(nst_ticket(0, zero_token)!, handshake.parse_resumption_psk(psk_blob(zero_token, 32, 0))!)
	assert store.tickets().len == 1
	assert store.cache.len == 1
	assert store.resumption_psks().len == 1

	age := blob_age(store.resumption_psks()[0].encode(), token.len, 32)
	assert age >= u32(1000) && age <= u32(1005)
	// The age is advanced per read and never compounds: a second read of a
	// freshly issued ticket still reports the near-issue age, not double it.
	assert blob_age(store.resumption_psks()[0].encode(), token.len, 32) <= u32(1005)
	// The record's own issue time drives the age: moving it back 2 seconds moves
	// the reported age with it.
	store.cache[0].issued_at_ms -= i64(2000)
	assert blob_age(store.resumption_psks()[0].encode(), token.len, 32) >= u32(3000)

	// Age the surviving record past its lifetime: both reads go empty, and the
	// slot frees for the next put().
	store.cache[0].issued_at_ms -= i64(3600) * 1000
	assert store.resumption_psks().len == 0
	assert store.tickets().len == 0
	assert store.cache.len == 0
	store.put(nst_ticket(3600, token)!, psk)
	assert store.tickets().len == 1
}

// test_in_memory_ticket_store_reissue_refreshes_slot checks that the in-memory
// backend refreshes a reissued token in place like FileTicketStore does, instead
// of letting one repeated token consume bounded slots.
fn test_in_memory_ticket_store_reissue_refreshes_slot() ! {
	token := [u8(0xd1), 0xd2]
	mut store := new_in_memory_ticket_store()
	store.put(nst_ticket(3600, token)!, handshake.parse_resumption_psk(psk_blob(token, 32, 0))!)
	store.put(nst_ticket(7200, token)!, handshake.parse_resumption_psk(psk_blob(token, 48, 1))!)
	assert store.tickets().len == 1
	assert store.tickets()[0].lifetime() == 7200
	assert store.resumption_psks()[0].key().len == 48
	assert store.cache.len == 1
}

// test_in_memory_ticket_store_consume_burns_pair checks the §8.6 single-use burn
// for the in-memory backend: the pair is wiped and all three parallel slices
// shrink together, so index i is still one record afterwards. Distinct key
// lengths make a burn that dropped the wrong record visible.
fn test_in_memory_ticket_store_consume_burns_pair() ! {
	first := [u8(0xe5), 0xe6]
	second := [u8(0xe7), 0xe8]
	third := [u8(0xe9), 0xea]
	mut store := new_in_memory_ticket_store()
	store.put(nst_ticket(3600, first)!, handshake.parse_resumption_psk(psk_blob(first, 32, 0))!)
	store.put(nst_ticket(3600, second)!, handshake.parse_resumption_psk(psk_blob(second, 48, 1))!)
	store.put(nst_ticket(3600, third)!, handshake.parse_resumption_psk(psk_blob(third, 64, 0))!)
	assert store.tickets().len == 3

	store.consume(second) or {}
	assert store.tickets().len == 2
	assert store.cache.len == 2
	assert store.tickets()[0].bytes() == first
	assert store.tickets()[1].bytes() == third
	psks := store.resumption_psks()
	assert psks.len == 2
	assert psks[0].key().len == 32
	assert psks[1].key().len == 64 // each PSK still belongs to its own ticket
	// An identity the store never held changes nothing.
	store.consume([u8(0xfe), 0xff]) or {}
	assert store.tickets().len == 2
	assert store.cache.len == 2
}

// test_in_memory_ticket_store_roundtrip checks that an in-memory store keeps its
// records across a reconstructed instance is not applicable (in-memory state does
// not survive reconstruction); instead it checks put/read/consume/wipe directly.
fn test_in_memory_ticket_store_roundtrip() ! {
	token := [u8(0x99), 0x9a]
	psk := handshake.parse_resumption_psk(psk_blob(token, 32, 0))!
	mut store := new_in_memory_ticket_store()
	store.put(nst_ticket(3600, token)!, psk)
	assert store.tickets().len == 1
	assert store.resumption_psks()[0].identity() == token
	store.consume(token) or {}
	assert store.tickets().len == 0
}

// test_encrypted_ticket_store_roundtrip checks that a persisted ticket and its
// PSK survive a new encrypted store instance over the same directory with the
// same key: the restart case.
fn test_encrypted_ticket_store_roundtrip() ! {
	dir := store_dir('tls_est_rt')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0xaa), 0xbb]
	key := est_key()!
	mut store := new_encrypted_file_ticket_store(dir, key)! or { return err }
	store.put(nst_ticket(3600, token)!,
		handshake.parse_resumption_psk(psk_blob(token, 32, 0))!) or { return err }
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
	dir := store_dir('tls_est_wk')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0xcc), 0xdd]
	key_a := est_key()!
	key_b := est_key()!
	assert key_a != key_b
	mut store := new_encrypted_file_ticket_store(dir, key_a)! or { return err }
	store.put(nst_ticket(3600, token)!,
		handshake.parse_resumption_psk(psk_blob(token, 32, 0))!) or { return err }
	assert store.tickets().len == 1

	// A different key cannot decrypt: GCM tag mismatch degrades to empty.
	mut wrong := new_encrypted_file_ticket_store(dir, key_b)! or { return err }
	assert wrong.tickets().len == 0
	assert wrong.resumption_psks().len == 0
	// The store stays usable under the wrong key: new writes encrypt under it.
	mut other := [u8(0xee), 0xff]
	wrong.put(nst_ticket(3600, other)!,
		handshake.parse_resumption_psk(psk_blob(other, 32, 0))!) or { return err }
	assert wrong.tickets().len == 1
	assert wrong.tickets()[0].bytes() == other
}

// test_encrypted_ticket_store_tamper_detection checks that flipping a ciphertext
// byte causes GCM tag verification to fail and the store degrades to empty,
// rather than returning corrupted ticket or PSK material.
fn test_encrypted_ticket_store_tamper_detection() ! {
	dir := store_dir('tls_est_tm')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0x11), 0x22]
	key := est_key()!
	mut store := new_encrypted_file_ticket_store(dir, key)! or { return err }
	store.put(nst_ticket(3600, token)!,
		handshake.parse_resumption_psk(psk_blob(token, 32, 0))!) or { return err }
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
	dir := store_dir('tls_est_wipe')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0x33), 0x44]
	key := est_key()!
	mut store := new_encrypted_file_ticket_store(dir, key)! or { return err }
	store.put(nst_ticket(3600, token)!,
		handshake.parse_resumption_psk(psk_blob(token, 32, 0))!) or { return err }
	assert store.tickets().len == 1
	assert os.exists(os.join_path(dir, ticket_store_filename))

	store.wipe()
	assert store.tickets().len == 0
	assert store.resumption_psks().len == 0
	assert !os.exists(os.join_path(dir, ticket_store_filename))

	// A wiped store stays usable: reconstruct it with a fresh key and new
	// material is accepted.
	mut fresh := new_encrypted_file_ticket_store(dir, est_key()!)! or { return err }
	fresh.put(nst_ticket(3600, [u8(0x55), 0x66])!,
		handshake.parse_resumption_psk(psk_blob([u8(0x55), 0x66], 32, 0))!) or { return err }
	assert fresh.tickets().len == 1
}

// test_encrypted_ticket_store_rejects_short_key checks that a key shorter than
// 32 bytes is rejected at construction.
fn test_encrypted_ticket_store_rejects_short_key() ! {
	dir := store_dir('tls_est_sk')
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
	dir := store_dir('tls_est_ct')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0x77), 0x88]
	key := est_key()!
	mut store := new_encrypted_file_ticket_store(dir, key)! or { return err }
	store.put(nst_ticket(3600, token)!,
		handshake.parse_resumption_psk(psk_blob(token, 32, 0))!) or { return err }
	path := os.join_path(dir, ticket_store_filename)
	first := os.read_bytes(path)! or { return err }

	// Re-putting the same token refreshes the record (new issued_at_ms) and
	// rewrites the file with a fresh random nonce, so the ciphertext differs.
	store.put(nst_ticket(3600, token)!,
		handshake.parse_resumption_psk(psk_blob(token, 32, 0))!) or { return err }
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

// test_encrypted_ticket_store_key_was_rejected checks that opening a store with
// a wrong key sets key_was_rejected(), so callers can detect that all persisted
// tickets were lost to key rotation rather than simply being absent.
fn test_encrypted_ticket_store_key_was_rejected() ! {
	dir := store_dir('tls_est_kwr')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0xdd), 0xee]
	key_a := est_key()!
	key_b := est_key()!
	assert key_a != key_b

	// Write one ticket under key_a.
	mut store := new_encrypted_file_ticket_store(dir, key_a)! or { return err }
	store.put(nst_ticket(3600, token)!,
		handshake.parse_resumption_psk(psk_blob(token, 32, 0))!) or { return err }
	assert store.tickets().len == 1
	assert !store.key_was_rejected()

	// Reopen with a different key: decryption fails, store is empty, and the
	// flag tells the caller exactly why.
	mut wrong := new_encrypted_file_ticket_store(dir, key_b)! or { return err }
	assert wrong.tickets().len == 0
	assert wrong.resumption_psks().len == 0
	assert wrong.key_was_rejected()

	// An absent tickets.bin does not set the flag.
	dir2 := store_dir('tls_est_kwr_empty')
	defer {
		os.rmdir_all(dir2) or {}
	}
	mut fresh := new_encrypted_file_ticket_store(dir2, est_key()!)! or { return err }
	assert fresh.tickets().len == 0
	assert !fresh.key_was_rejected()
}

// test_stores_satisfy_ticket_store_seam pins both backends to the
// SessionTicketStore seam dial() uses: FileTicketStore is the one a caller puts
// in Config.session_ticket_store, and the module-internal in-memory backend must
// satisfy the same contract — read, written through, burned after use, and wiped.
fn test_stores_satisfy_ticket_store_seam() ! {
	dir := store_dir('tls_tstore_seam')
	defer {
		os.rmdir_all(dir) or {}
	}
	token := [u8(0x66), 0x67]
	psk := handshake.parse_resumption_psk(psk_blob(token, 32, 0))!
	mut file_backend := SessionTicketStore(new_file_ticket_store(dir)!)
	assert file_backend.tickets().len == 0
	assert file_backend.resumption_psks().len == 0
	file_backend.put(nst_ticket(3600, token)!, psk)
	assert file_backend.tickets().len == 1
	assert file_backend.resumption_psks().len == 1
	file_backend.consume(token) or {} // §8.6: the resumed pair is gone, not just unread
	assert file_backend.tickets().len == 0
	assert file_backend.resumption_psks().len == 0
	file_backend.put(nst_ticket(3600, token)!, psk)
	assert file_backend.tickets().len == 1 // a burn leaves the store usable
	file_backend.wipe()
	assert file_backend.tickets().len == 0

	mut mem_backend := SessionTicketStore(new_in_memory_ticket_store())
	mem_backend.put(nst_ticket(3600, token)!, psk)
	assert mem_backend.tickets().len == 1
	assert mem_backend.resumption_psks()[0].key().len == 32
	mem_backend.consume([u8(0xfe), 0xff]) or {} // an unknown identity burns nothing
	assert mem_backend.tickets().len == 1
	mem_backend.consume(token) or {}
	assert mem_backend.tickets().len == 0
	mem_backend.wipe()
	assert mem_backend.resumption_psks().len == 0

	// Config is immutable by design, so the seam enters through a literal exactly
	// as an external caller passes it: at construction, never by assignment.
	config := Config{
		server_name:          'example.com'
		session_ticket_store: SessionTicketStore(new_file_ticket_store(dir)!)
	}
	assert config.session_ticket_store != none
}
