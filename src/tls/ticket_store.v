// Copyright (c) 2026 blackshirt.
//
// ticket_store.v owns the SessionTicketStore seam and its file backend
// (RFC 8446 §4.6.1). A store durably claims ticket/PSK pairs before dial()
// offers them, and takes back every new ticket a connection accepts.
//
// FileTicketStore is a single opaque type with two modes chosen at
// construction:
//   - plain (new_file_ticket_store): writes the serialized cache to tickets.bin
//     raw, protected only by directory/file permissions.
//   - encrypted (new_encrypted_file_ticket_store): wraps the same serialized
//     bytes in AES-256-GCM with a fresh random nonce per write, so on-disk key
//     material is protected by a caller-supplied 32-byte key.
//
// InMemoryTicketStore is a module-internal plain-text in-memory backend used
// by tests; it shares the SessionTicketStore seam and has no encrypted mode
// because it dies with the process.
//
// Both stores keep one cache []FileTicketRecord. Encryption only touches the
// serialization boundary (write_file/persist_cache and read_file), so the
// in-memory cache layout is identical in both modes.
@[has_globals]
module tls

import crypto.aes
import crypto
import os
import os.filelock
import sync
import time
import tls.handshake
import tls.wire

// max_stored_session_tickets bounds how many tickets a store may hold, out of
// the many a server may push. Put() returns an error when this cap is reached.
const max_stored_session_tickets = 32

// ticket_store_filename is the on-disk name of the persisted store file
// (tickets.bin) shared by plain and encrypted modes.
const ticket_store_filename = 'tickets.bin'

// temp_file_suffix is appended to the store path (with the writing process's
// pid in front) to form the temp name that write_file renames into place.
const temp_file_suffix = '.tmp'

// ticket_store_magic tags the store file so a foreign or truncated file is
// never parsed as tickets.
const ticket_store_magic = 'TLS13TSK'

// ticket_store_version bumps when the record layout changes; version 3 added
// the stored resumption PSK, without which a restarted process could not bind
// a ticket it had saved (§7.2).
const ticket_store_version = u8(3)

// ticket_record_header_len is the fixed part of one record: u64 issued_at_ms
// plus the two u16 length prefixes around the ticket and PSK bodies.
const ticket_record_header_len = 12

// ticket_store_header_len is the whole-file framing ahead of the records:
// magic + version byte + u16 count.
const ticket_store_header_len = 11

// ticket_record_body_max_len is the largest body a record's u16 length prefix
// can carry. A ticket or PSK blob past it is skipped whole instead of
// truncating the records behind it.
const ticket_record_body_max_len = 0xffff

// ticket_store_max_file_len bounds what read_file will even look at. Past this
// size the file could not have been written by this code and is not parsed.
const ticket_store_max_file_len = 8 * 1024 * 1024

// encrypted_file_store_key_len is the AES-256 key length required to
// construct an encrypted store. Exactly 32 bytes; shorter or longer keys are
// rejected at construction.
const encrypted_file_store_key_len = 32

// encrypted_file_store_nonce_len is the per-write nonce length prepended to
// every ciphertext so it can be recovered on read. AES-GCM uses 12-byte
// nonces.
const encrypted_file_store_nonce_len = 12

__global ticket_store_process_mutex sync.Mutex

$if windows {
	#include <windows.h>
	fn C._commit(fd int) int
	fn C.MoveFileExW(&u16, &u16, u32) bool
} $else {
	fn C.fsync(fd int) int
	fn C.open(&char, int, ...int) int
	fn C.close(fd int) int
}

const movefile_replace_existing = u32(0x1)
const movefile_write_through = u32(0x8)

// TicketStoreLock owns both locks needed by a file-store transaction. The
// process mutex is required because POSIX record locks do not serialize threads
// in one process; the persistent sidecar lock serializes independent processes.
@[noinit]
struct TicketStoreLock {
mut:
	file_lock      filelock.FileLock
	process_locked bool
}

// acquire_ticket_store_lock locks the process mutex and the persistent sidecar
fn acquire_ticket_store_lock(path string) !TicketStoreLock {
	ticket_store_process_mutex.lock()
	lock_path := '${path}.lock'
	mut lock_file := os.open_file(lock_path, 'a', 0o600) or {
		ticket_store_process_mutex.unlock()
		return error('tls: cannot open ticket store lock: ${err.msg()}')
	}
	lock_file.close()
	os.chmod(lock_path, 0o600) or {
		ticket_store_process_mutex.unlock()
		return error('tls: cannot secure ticket store lock: ${err.msg()}')
	}
	mut store_lock := filelock.new_file(lock_path, filelock.LockOptions{
		mode: .exclusive
	})
	store_lock.acquire() or {
		ticket_store_process_mutex.unlock()
		return error('tls: cannot acquire ticket store lock: ${err.msg()}')
	}
	return TicketStoreLock{
		file_lock:      store_lock
		process_locked: true
	}
}

fn (mut guard TicketStoreLock) release() {
	guard.file_lock.release()
	if guard.process_locked {
		guard.process_locked = false
		ticket_store_process_mutex.unlock()
	}
}

fn identity_is_excluded(identity []u8, excluded [][]u8) bool {
	for item in excluded {
		if item == identity {
			return true
		}
	}
	return false
}

// wipe_ticket_snapshot scrubs every ticket and PSK in the snapshot, then
fn wipe_ticket_snapshot(mut snapshot TicketStoreSnapshot) {
	for i in 0 .. snapshot.tickets.len {
		snapshot.tickets[i].wipe()
	}
	for i in 0 .. snapshot.psks.len {
		snapshot.psks[i].wipe()
	}
	snapshot.tickets = []handshake.NewSessionTicket{}
	snapshot.psks = []handshake.Psk{}
}

// sync_file_descriptor flushes the OS buffers for `fd` to disk, so a
fn sync_file_descriptor(fd int) ! {
	$if windows {
		if C._commit(fd) != 0 {
			return error('tls: failed to sync ticket store file')
		}
	} $else {
		if C.fsync(fd) != 0 {
			return error('tls: failed to sync ticket store file')
		}
	}
}

// sync_store_directory flushes the OS buffers for the directory containing
fn sync_store_directory(path string) ! {
	$if !windows {
		dir := os.dir(path)
		fd := C.open(&char(dir.str), 0)
		if fd == -1 {
			return error('tls: cannot open ticket store directory for sync')
		}
		defer {
			C.close(fd)
		}
		if C.fsync(fd) != 0 {
			return error('tls: failed to sync ticket store directory')
		}
	}
}

// SessionTicketStore is a source and sink for session tickets and the
// resumption PSKs derived from them. tickets() and resumption_psks() hand back
// what is still live, aged by the hold time (§4.6.1); put() is the
// write-through side.
//
// File stores serialize mutations across processes. claim_for_resumption()
// atomically removes every stored PSK it returns, so a failed handshake may
// consume tickets; this avoids re-offering a ticket after a process crash.
// wipe() is the owner's scrub (§7.5); Conn never calls wipe().
pub interface SessionTicketStore {
mut:
	tickets() []handshake.NewSessionTicket
	resumption_psks() []handshake.Psk
	claim_for_resumption(excluded [][]u8, limit int) !TicketStoreSnapshot
	put(ticket handshake.NewSessionTicket, psk handshake.Psk) !
	consume(identity []u8) !
	wipe()
}

// TicketStoreSnapshot contains matching copies of tickets and aged PSKs
// claimed for one ClientHello.
@[noinit]
struct TicketStoreSnapshot {
mut:
	tickets []handshake.NewSessionTicket
	psks    []handshake.Psk
}

// FileTicketStore is the file-backed SessionTicketStore: it atomically claims
// persisted ticket/PSK pairs for a dial, write-throughs tickets accepted during
// a connection, and drops expired records.
//
// @[noinit] keeps a bare FileTicketStore{} from existing with a garbage cache
// slice; a long-lived store must not be built inline in Config{}.
//
// Mode is chosen at construction: key == none means plain bytes to tickets.bin;
// key == 32 bytes means AES-256-GCM encryption with a fresh nonce per write.
// key_was_rejected is set (encrypted mode only) when the existing tickets.bin
// cannot be decrypted with the supplied key.
@[noinit]
struct FileTicketStore {
mut:
	path              string
	key               ?[]u8 // 32-byte AES key when encrypted; none when plain; wiped by wipe(); never written to disk
	cache             []FileTicketRecord
	key_was_rejected  bool
	file_was_rejected bool
}

// new_file_ticket_store creates a plain FileTicketStore over `dir` (mode 0700).
// It loads any existing tickets.bin so tickets() and resumption_psks() see
// persisted state from the first call. A missing file is an empty store; an
// unreadable, oversized, or invalid existing file is marked rejected, and
// mutations fail closed rather than replacing it.
pub fn new_file_ticket_store(dir string) !FileTicketStore {
	os.mkdir_all(dir, mode: 0o700) or {
		return error('tls: cannot create ticket store directory ${dir}: ${err.msg()}')
	}
	$if !windows {
		// Guard shared paths such as /tmp so key material is not world-readable.
		info := os.stat(dir) or {
			return error('tls: cannot inspect ticket store directory ${dir}: ${err.msg()}')
		}
		if info.mode & 0o077 != 0 {
			return error('tls: ticket store directory ${dir} is group- or world-writable')
		}
	} $else {
		// Windows mode bits do not map to Unix permissions; probe writability instead.
		probe := os.join_path(dir, '.tls_ticket_store_probe')
		os.write_bytes(probe, []u8{}) or {
			return error('tls: cannot write to ticket store directory ${dir}')
		}
		os.rm(probe) or {}
	}
	mut s := FileTicketStore{
		path:  os.join_path(dir, ticket_store_filename)
		key:   none
		cache: []FileTicketRecord{}
	}
	mut guard := acquire_ticket_store_lock(s.path)!
	defer {
		guard.release()
	}
	s.reload_cache()
	return s
}

// new_encrypted_file_ticket_store creates an encrypted FileTicketStore over `dir`
// (mode 0700) using `key` as the 32-byte AES-256-GCM key. It scans any existing
// tickets.bin (decrypting it) so tickets() and resumption_psks() see persisted
// state from the first call. A file that fails to decrypt yields an empty store
// and sets key_was_rejected; mutations and resumption claims then fail closed
// so the unreadable file is never overwritten with an empty cache.
pub fn new_encrypted_file_ticket_store(dir string, key []u8) !FileTicketStore {
	if key.len != encrypted_file_store_key_len {
		return error('tls: encrypted ticket store key must be exactly ${encrypted_file_store_key_len} bytes, got ${key.len}')
	}
	os.mkdir_all(dir, mode: 0o700) or {
		return error('tls: cannot create ticket store directory ${dir}: ${err.msg()}')
	}
	$if !windows {
		info := os.stat(dir) or {
			return error('tls: cannot inspect ticket store directory ${dir}: ${err.msg()}')
		}
		if info.mode & 0o077 != 0 {
			return error('tls: ticket store directory ${dir} is group- or world-writable')
		}
	} $else {
		probe := os.join_path(dir, '.tls_ticket_store_probe')
		os.write_bytes(probe, []u8{}) or {
			return error('tls: cannot write to ticket store directory ${dir}')
		}
		os.rm(probe) or {}
	}
	mut s := FileTicketStore{
		path:  os.join_path(dir, ticket_store_filename)
		key:   key.clone()
		cache: []FileTicketRecord{}
	}
	mut guard := acquire_ticket_store_lock(s.path)!
	defer {
		guard.release()
	}
	s.reload_cache()
	return s
}

// tickets returns the persisted tickets that may still be used, ready to seed
// Conn's backlog: expired records are pruned and rewritten away, future-dated
// records are hidden but kept. Each ticket is a copy so the borrower's teardown
// cannot scrub what the store holds.
pub fn (mut s FileTicketStore) tickets() []handshake.NewSessionTicket {
	// Drop any records whose lifetime has elapsed, then collect live tickets
	// as copies so the caller can wipe them without touching the cache.
	s.prune_expired()
	now := now_ms_or_zero()
	mut out := []handshake.NewSessionTicket{cap: s.cache.len}
	for r in s.cache {
		if ticket_is_live(r.ticket, r.issued_at_ms, now) {
			out << r.ticket.clone()
		}
	}
	return out
}

// resumption_psks returns the PSKs of the records that may still be used, with
// obfuscated ages advanced by the hold time (§4.6.1). Callers get copies so the
// cache keeps its own ages.
pub fn (mut s FileTicketStore) resumption_psks() []handshake.Psk {
	// Drop expired records, then hand out aged PSK copies for each live record.
	s.prune_expired()
	now := now_ms_or_zero()
	mut out := []handshake.Psk{cap: s.cache.len}
	for r in s.cache {
		if ticket_is_live(r.ticket, r.issued_at_ms, now) {
			out << r.psk.clone_aged(now - r.issued_at_ms)
		}
	}
	return out
}

// claim_for_resumption reloads the latest persisted state and atomically burns
// every eligible stored PSK it returns. A ticket is never re-offered after a
// crash or by another process, at the cost of losing claimed tickets when the
// handshake fails or the server declines them.
pub fn (mut s FileTicketStore) claim_for_resumption(excluded [][]u8, limit int) !TicketStoreSnapshot {
	mut guard := acquire_ticket_store_lock(s.path)!
	defer {
		guard.release()
	}
	s.reload_cache()
	if s.key_was_rejected {
		return error('tls: cannot claim tickets: encrypted ticket store key was rejected')
	}
	if s.file_was_rejected {
		return error('tls: cannot claim tickets: ticket store file was rejected')
	}
	pruned := prune_expired_records(mut s.cache, now_ms_or_zero())
	mut snapshot := TicketStoreSnapshot{
		tickets: []handshake.NewSessionTicket{cap: s.cache.len}
		psks:    []handshake.Psk{cap: s.cache.len}
	}
	mut kept := []FileTicketRecord{cap: s.cache.len}
	now := now_ms_or_zero()
	for mut record in s.cache {
		if snapshot.psks.len < limit && ticket_is_live(record.ticket, record.issued_at_ms, now)
			&& !identity_is_excluded(record.psk.identity(), excluded) {
			snapshot.tickets << record.ticket.clone()
			snapshot.psks << record.psk.clone_aged(now - record.issued_at_ms)
			record.wipe_record()
		} else {
			kept << record
		}
	}
	if snapshot.psks.len > 0 || pruned {
		s.cache = kept
		s.persist_cache() or {
			wipe_ticket_snapshot(mut snapshot)
			s.reload_cache()
			return err
		}
	} else {
		s.cache = kept
	}
	return snapshot
}

// key_was_rejected reports whether the existing tickets.bin could not be
// decrypted with the supplied key (encrypted mode only).
pub fn (s FileTicketStore) key_was_rejected() bool {
	return s.key_was_rejected
}

// file_was_rejected reports whether an existing tickets.bin was unreadable,
// oversized, malformed, or from an unsupported format version.
pub fn (s FileTicketStore) file_was_rejected() bool {
	return s.file_was_rejected
}

// put persists a server-issued ticket with the §7.2 PSK derived for it,
// replacing any earlier record carrying the same token (§4.6.1 allows a server
// to reissue one). Returns an error on a full store or a write/disk failure;
// an inconsistent pair, a lifetime-0 ticket, or an unroundtrippable PSK is
// silently refused — the ticket stays in Conn's backlog only.
pub fn (mut s FileTicketStore) put(ticket handshake.NewSessionTicket, psk handshake.Psk) ! {
	// A record is a bound pair: §7.2 makes the PSK identity the ticket bytes, so a
	// mismatched pair is refused rather than kept as an offer no server can
	// reproduce and no read can match again.
	if psk.identity() != ticket.bytes() {
		return
	}
	// A lifetime of 0 means the server forbade resumption with this ticket, so it
	// is refused at the door instead of taking a slot the next read prunes.
	if ticket.lifetime() == 0 {
		return
	}
	mut guard := acquire_ticket_store_lock(s.path)!
	defer {
		guard.release()
	}
	// Always base a mutation on the latest committed file, never this process's
	// potentially stale cache.
	s.reload_cache()
	if s.key_was_rejected {
		return error('tls: cannot write ticket store: encrypted ticket store key was rejected')
	}
	if s.file_was_rejected {
		return error('tls: cannot write ticket store: ticket store file was rejected')
	}
	prune_expired_records(mut s.cache, now_ms_or_zero())
	now_ms := now_ms_or_zero()
	// The store must own what it keeps: Conn wipes its backlog at teardown (§7.5),
	// so copy both the ticket and the PSK straight into the record. The PSK goes
	// through its own codec, which also validates it the way the file loader will.
	held_psk := handshake.parse_resumption_psk(psk.encode()) or { return }
	// Re-issuing a known token refreshes it in place instead of taking a second slot.
	for i in 0 .. s.cache.len {
		if s.cache[i].ticket.bytes() == ticket.bytes() {
			s.cache[i].wipe_record()
			s.cache[i] = FileTicketRecord{
				issued_at_ms: now_ms
				ticket:       ticket.clone()
				psk:          held_psk
			}
			s.persist_cache() or {
				s.reload_cache()
				return err
			}
			return
		}
	}
	if s.cache.len >= max_stored_session_tickets {
		return error('tls: ticket store full: ${max_stored_session_tickets} tickets stored')
	}
	s.cache << FileTicketRecord{
		issued_at_ms: now_ms
		ticket:       ticket.clone()
		psk:          held_psk
	}
	s.persist_cache() or {
		s.reload_cache()
		return err
	}
}

// consume burns the record whose §7.2 PSK carries `identity`, once a connection
// has resumed on it (§8.6: a resumption PSK is single-use, and offering it twice
// lets a peer link the two connections). Unknown identities change nothing, so a
// caller-supplied external PSK cannot reach stored material.
pub fn (mut s FileTicketStore) consume(identity []u8) ! {
	mut guard := acquire_ticket_store_lock(s.path)!
	defer {
		guard.release()
	}
	s.reload_cache()
	if s.key_was_rejected {
		return error('tls: cannot consume ticket: encrypted ticket store key was rejected')
	}
	if s.file_was_rejected {
		return error('tls: cannot consume ticket: ticket store file was rejected')
	}
	pruned := prune_expired_records(mut s.cache, now_ms_or_zero())
	mut target := -1
	for i in 0 .. s.cache.len {
		if s.cache[i].psk.identity() == identity {
			target = i
			break // only the first match; put() keeps tokens unique
		}
	}
	if target < 0 {
		if pruned {
			s.persist_cache() or {
				s.reload_cache()
				return err
			}
		}
		return
	}
	// Scrub before dropping, then persist the burn so a restart cannot re-offer
	// a PSK the peer has already seen used.
	s.cache[target].wipe_record()
	mut kept := []FileTicketRecord{cap: s.cache.len - 1}
	for i in 0 .. s.cache.len {
		if i != target {
			kept << s.cache[i]
		}
	}
	s.cache = kept
	s.persist_cache() or {
		s.reload_cache()
		return err
	}
}

// wipe drops every cached record, scrubs them in memory, wipes the stored AES
// key when the store is encrypted, then overwrites the store file with random
// bytes before unlinking it (§7.5). Conn never calls it — a close must not
// delete the tickets it just persisted — so this is the owner's teardown.
pub fn (mut s FileTicketStore) wipe() {
	mut guard := acquire_ticket_store_lock(s.path) or {
		for i in 0 .. s.cache.len {
			s.cache[i].wipe_record()
		}
		s.cache = []FileTicketRecord{}
		if s.key != none {
			zero_bytes(mut s.key!)
			s.key = none
		}
		return
	}
	defer {
		guard.release()
	}
	// Scrub every cached record's ticket and PSK before releasing them.
	for i in 0 .. s.cache.len {
		s.cache[i].wipe_record()
	}
	s.cache = []FileTicketRecord{}
	// Zero the in-memory AES key (encrypted mode only) and then shred the file.
	if s.key != none {
		zero_bytes(mut s.key!)
		s.key = none
	}
	shred_file(s.path)
}

// shred_file overwrites `path` with random bytes before unlinking it, so
// previously persisted key material is not recoverable from freed blocks.
// Best-effort: on copy-on-write or wear-leveling filesystems blocks may remain
// elsewhere; keep the store on tmpfs or an encrypted volume when that matters.
fn shred_file(path string) {
	info := os.stat(path) or { return }
	if info.size == 0 {
		os.rm(path) or {}
		return
	}
	mut junk := []u8{len: int(info.size)}
	junk = crypto.rand.bytes(int(info.size)) or { junk }
	os.write_bytes(path, junk) or {}
	os.rm(path) or {}
}

// prune_expired drops records whose ticket_lifetime has truly elapsed, scrubbing
// their secrets and persisting expiry so it survives a restart. Records dated
// ahead of the clock are hidden by the reads but never pruned here: a clock
// glitch must not turn into lost tickets.
fn (mut s FileTicketStore) prune_expired() {
	mut guard := acquire_ticket_store_lock(s.path) or { return }
	defer {
		guard.release()
	}
	s.reload_cache()
	if s.key_was_rejected || s.file_was_rejected {
		return
	}
	if prune_expired_records(mut s.cache, now_ms_or_zero()) {
		s.persist_cache() or {
			s.reload_cache()
		}
	}
}

// prune_expired_records removes stale cache entries and reports whether the
// caller must persist the resulting state.
fn prune_expired_records(mut cache []FileTicketRecord, now_ms i64) bool {
	mut dropped := false
	mut alive := []FileTicketRecord{cap: cache.len}
	for r in cache {
		if ticket_expired(r.ticket, r.issued_at_ms, now_ms) {
			dropped = true
		} else {
			alive << r
		}
	}
	if dropped {
		for i in 0 .. cache.len {
			if ticket_expired(cache[i].ticket, cache[i].issued_at_ms, now_ms) {
				cache[i].wipe_record()
			}
		}
		cache = alive.clone()
	}
	return dropped
}

// enc_payload wraps `plaintext` in AES-256-GCM and returns `nonce || ciphertext`
// with a fresh random nonce per call, so two identical caches never encrypt
// alike. Returns empty bytes on encryption failure.
fn enc_payload(key []u8, plaintext []u8) []u8 {
	// Build the AEAD from the 32-byte key.
	mut aead := aes.new_aes_gcm(key) or { return []u8{} }
	// Fresh random nonce per write so identical plaintexts never encrypt alike.
	mut nonce := crypto.rand.bytes(encrypted_file_store_nonce_len) or { return []u8{} }
	// Encrypt with the nonce as associated data.
	ciphertext := aead.encrypt(plaintext, nonce, []u8{}) or { return []u8{} }
	mut payload := []u8{cap: encrypted_file_store_nonce_len + ciphertext.len}
	payload << nonce
	payload << ciphertext
	return payload
}

// dec_payload splits `nonce || ciphertext` from `data` and decrypts it with the
// given key. Returns empty bytes on failure (wrong key, truncated or tampered
// ciphertext), which callers treat as an empty store.
fn dec_payload(key []u8, data []u8) []u8 {
	// Need at least a nonce prefix to attempt decryption.
	if data.len < encrypted_file_store_nonce_len {
		return []u8{} // not even a nonce: not a store we wrote
	}
	nonce := data[..encrypted_file_store_nonce_len].clone()
	ciphertext := data[encrypted_file_store_nonce_len..].clone()
	// Build AEAD from the key; GCM tag verification rejects wrong/tampered keys.
	mut aead := aes.new_aes_gcm(key) or { return []u8{} }
	plaintext := aead.decrypt(ciphertext, nonce, []u8{}) or { return []u8{} }
	return plaintext
}

// InMemoryTicketStore keeps tickets and their PSKs in one bounded plain-text
// cache, bounded and expired exactly as FileTicketStore does. It is module-
// internal: in-process resumption goes through Conn.resumption_psks(), so the
// public Config.session_ticket_store seam only needs the file backend.
//
// Unlike the file store there is no encrypted mode: an in-memory store dies
// with the process and shares its address space, so per-record encryption adds
// complexity without meaningful security. Methods stay pub because the
// SessionTicketStore interface requires it.
@[noinit]
struct InMemoryTicketStore {
mut:
	cache []FileTicketRecord
}

// new_in_memory_ticket_store creates a plain in-memory store bounded at
// max_stored_session_tickets.
pub fn new_in_memory_ticket_store() InMemoryTicketStore {
	return InMemoryTicketStore{
		cache: []FileTicketRecord{cap: max_stored_session_tickets}
	}
}

// put stores a ticket with its resumption PSK, pruning first so expired pairs
// cannot hold bounded slots, refreshing a reissued token in place instead of
// taking a second slot. Returns an error if the store is full; an inconsistent
// pair or lifetime-0 ticket is silently refused.
pub fn (mut s InMemoryTicketStore) put(ticket handshake.NewSessionTicket, psk handshake.Psk) ! {
	// Reject mismatched pairs and lifetime-0 tickets outright.
	if psk.identity() != ticket.bytes() || ticket.lifetime() == 0 {
		return
	}
	// Drop expired records before writing so they cannot occupy bounded slots.
	s.prune_expired()
	held_psk := handshake.parse_resumption_psk(psk.encode()) or { return }
	now_ms := now_ms_or_zero()
	// Refresh a known token in place rather than consuming another slot.
	for i in 0 .. s.cache.len {
		if s.cache[i].ticket.bytes() == ticket.bytes() {
			s.cache[i].wipe_record()
			s.cache[i] = FileTicketRecord{
				issued_at_ms: now_ms
				ticket:       ticket.clone()
				psk:          held_psk
			}
			return
		}
	}
	// Error out if the cache is already at capacity.
	if s.cache.len >= max_stored_session_tickets {
		return error('tls: ticket store full: ${max_stored_session_tickets} tickets stored')
	}
	s.cache << FileTicketRecord{
		issued_at_ms: now_ms
		ticket:       ticket.clone()
		psk:          held_psk
	}
}

// consume burns the pair whose PSK carries `identity`, once a connection has
// resumed on it (§8.6). Unknown identities change nothing; the cache stays one
// record per slot.
pub fn (mut s InMemoryTicketStore) consume(identity []u8) ! {
	// Find the record whose PSK carries this identity.
	mut target := -1
	for i in 0 .. s.cache.len {
		if s.cache[i].psk.identity() == identity {
			target = i
			break
		}
	}
	if target < 0 {
		return
	}
	// Scrub the burned record before dropping it.
	s.cache[target].wipe_record()
	mut kept := []FileTicketRecord{cap: s.cache.len - 1}
	for i in 0 .. s.cache.len {
		if i != target {
			kept << s.cache[i]
		}
	}
	s.cache = kept
}

// claim_for_resumption removes each returned PSK from the in-memory cache
// before the caller can offer it, matching FileTicketStore's single-use rule.
pub fn (mut s InMemoryTicketStore) claim_for_resumption(excluded [][]u8, limit int) !TicketStoreSnapshot {
	s.prune_expired()
	now := now_ms_or_zero()
	mut snapshot := TicketStoreSnapshot{
		tickets: []handshake.NewSessionTicket{cap: s.cache.len}
		psks:    []handshake.Psk{cap: s.cache.len}
	}
	mut kept := []FileTicketRecord{cap: s.cache.len}
	for mut record in s.cache {
		if snapshot.psks.len < limit && ticket_is_live(record.ticket, record.issued_at_ms, now)
			&& !identity_is_excluded(record.psk.identity(), excluded) {
			snapshot.tickets << record.ticket.clone()
			snapshot.psks << record.psk.clone_aged(now - record.issued_at_ms)
			record.wipe_record()
		} else {
			kept << record
		}
	}
	s.cache = kept
	return snapshot
}

// tickets returns the stored tickets that may still be used, ready to seed
// Conn's backlog, each as a copy the borrower may wipe freely.
pub fn (mut s InMemoryTicketStore) tickets() []handshake.NewSessionTicket {
	// Prune expired records, then return copies of live tickets.
	s.prune_expired()
	now := now_ms_or_zero()
	mut out := []handshake.NewSessionTicket{cap: s.cache.len}
	for r in s.cache {
		if ticket_is_live(r.ticket, r.issued_at_ms, now) {
			out << r.ticket.clone()
		}
	}
	return out
}

// resumption_psks returns the PSKs that may still be used, with ages advanced
// by the hold time (§4.6.1). Callers get copies so the recorded ages cannot be
// rewritten.
pub fn (mut s InMemoryTicketStore) resumption_psks() []handshake.Psk {
	// Prune expired records, then return aged copies of live PSKs.
	s.prune_expired()
	now := now_ms_or_zero()
	mut out := []handshake.Psk{cap: s.cache.len}
	for r in s.cache {
		if ticket_is_live(r.ticket, r.issued_at_ms, now) {
			out << r.psk.clone_aged(now - r.issued_at_ms)
		}
	}
	return out
}

// wipe scrubs every stored ticket and PSK and clears the cache. Conn does not
// call it; the caller decides when material should go (§7.5).
pub fn (mut s InMemoryTicketStore) wipe() {
	// Scrub every cached record's ticket and PSK.
	for i in 0 .. s.cache.len {
		s.cache[i].wipe_record()
	}
	s.cache = []FileTicketRecord{}
}

// prune_expired drops pairs whose ticket_lifetime has truly elapsed, scrubbing
// their secrets; future-dated records stay hidden but present.
fn (mut s InMemoryTicketStore) prune_expired() {
	now := now_ms_or_zero()
	mut dropped := false
	mut alive := []FileTicketRecord{cap: s.cache.len}
	// Collect non-expired records; mark whether any were dropped.
	for r in s.cache {
		if ticket_expired(r.ticket, r.issued_at_ms, now) {
			dropped = true
			continue
		}
		alive << r
	}
	if dropped {
		// Scrub secrets of expired records before discarding them.
		for i in 0 .. s.cache.len {
			if ticket_expired(s.cache[i].ticket, s.cache[i].issued_at_ms, now) {
				s.cache[i].wipe_record()
			}
		}
		s.cache = alive
	}
}

// FileTicketRecord is one persisted ticket, the §7.2 PSK derived for it, and the
// wall-clock issue time that makes expiry survive a restart. Callers reach the
// material through tickets() and resumption_psks(), never through a record.
@[noinit]
struct FileTicketRecord {
mut:
	issued_at_ms i64
	ticket       handshake.NewSessionTicket
	psk          handshake.Psk
}

// wipe_record scrubs the ticket token and the PSK key the record holds; both
// delegate to the handshake wipe methods which use a read-back checksum barrier
// so the zeroing pass is not eliminated as a dead store.
fn (mut r FileTicketRecord) wipe_record() {
	// Scrub the ticket token and the PSK key this record holds.
	r.ticket.wipe()
	r.psk.wipe()
	r.issued_at_ms = 0
}

// read_file decodes the store file. Plain mode parses raw bytes; encrypted mode
// decrypts the nonce || ciphertext wrapper first. Invalid input returns an
// empty cache while setting a rejection flag so no mutation can overwrite it.
fn (mut s FileTicketStore) reload_cache() {
	for i in 0 .. s.cache.len {
		s.cache[i].wipe_record()
	}
	s.cache = s.read_file()
}

fn (mut s FileTicketStore) read_file() []FileTicketRecord {
	// Bound the read before allocating: os.read_bytes takes the whole file, so
	// anything past what this writer could produce is not a ticket store.
	s.key_was_rejected = false
	s.file_was_rejected = false
	if !os.exists(s.path) {
		return []FileTicketRecord{}
	}
	info := os.stat(s.path) or {
		s.file_was_rejected = true
		return []FileTicketRecord{}
	}
	if info.size > ticket_store_max_file_len {
		s.file_was_rejected = true
		return []FileTicketRecord{}
	}
	data := os.read_bytes(s.path) or {
		s.file_was_rejected = true
		return []FileTicketRecord{}
	}
	if s.key != none {
		// Decrypt nonce || ciphertext wrapper; mark key rejected on failure.
		plaintext := dec_payload(s.key!, data)
		if plaintext.len == 0 && data.len > 0 {
			s.key_was_rejected = true
			return []FileTicketRecord{}
		}
		records := parse_store_bytes(plaintext) or {
			s.file_was_rejected = true
			return []FileTicketRecord{}
		}
		return records
	}
	records := parse_store_bytes(data) or {
		s.file_was_rejected = true
		return []FileTicketRecord{}
	}
	return records
}

// parse_store_bytes decodes magic + version + count + records into
// FileTicketRecords, rejecting unbound ticket/PSK pairs and oversized bodies.
// A corrupt or foreign file is rejected as a whole; accepting a partial prefix
// could silently discard later resumable tickets on the next write.
fn parse_store_bytes(data []u8) ![]FileTicketRecord {
	mut out := []FileTicketRecord{}
	mut valid := false
	defer {
		if !valid {
			for i in 0 .. out.len {
				out[i].wipe_record()
			}
		}
	}
	if data.len < ticket_store_header_len {
		return error('tls: truncated ticket store header')
	}
	if data[..ticket_store_magic.len].bytestr() != ticket_store_magic {
		return error('tls: unrecognized ticket store magic')
	}
	mut r := wire.new_reader(data[ticket_store_magic.len..])
	version := r.read_u8()!
	if version != ticket_store_version {
		return error('tls: unsupported ticket store version')
	}
	count := int(r.read_u16()!)
	if count > max_stored_session_tickets {
		return error('tls: ticket store record count exceeds limit')
	}
	for _ in 0 .. count {
		// Stop if there are not enough bytes left for one record header.
		if r.remaining() < ticket_record_header_len {
			return error('tls: truncated ticket store record header')
		}
		issued_at_ms := i64(r.read_u64()!)
		if issued_at_ms < 0 {
			return error('tls: invalid negative ticket store issue time')
		}
		ticket_len := int(r.read_u16()!)
		if ticket_len <= 0 || ticket_len > handshake.max_handshake_message_len || r.remaining() < ticket_len {
			return error('tls: invalid ticket store ticket length')
		}
		ticket_bytes := r.read_bytes(ticket_len)!
		psk_len := int(r.read_u16()!)
		if psk_len <= 0 || psk_len > handshake.max_handshake_message_len || r.remaining() < psk_len {
			return error('tls: invalid ticket store PSK length')
		}
		psk_bytes := r.read_bytes(psk_len)!
		ticket := handshake.parse_new_session_ticket(ticket_bytes) or {
			return error('tls: invalid ticket store ticket record: ${err.msg()}')
		}
		psk := handshake.parse_resumption_psk(psk_bytes) or {
			return error('tls: invalid ticket store PSK record: ${err.msg()}')
		}
		// A file that separates a ticket from its own PSK is not one this store
		// wrote; skip it rather than keeping an unbindable pair.
		if psk.identity() != ticket.bytes() {
			return error('tls: ticket store ticket and PSK identities do not match')
		}
		for existing in out {
			if existing.psk.identity() == psk.identity() {
				return error('tls: duplicate identity in ticket store')
			}
		}
		out << FileTicketRecord{
			issued_at_ms: issued_at_ms
			ticket:       ticket
			psk:          psk
		}
	}
	if r.remaining() != 0 {
		return error('tls: trailing bytes in ticket store file')
	}
	valid = true
	return out
}

// write_file persists the current cache. Production mutations reload the latest
// disk state under lock before changing the cache; this helper is also used by
// focused format tests that prepare a cache directly.
fn (mut s FileTicketStore) write_file() ! {
	mut guard := acquire_ticket_store_lock(s.path)!
	defer {
		guard.release()
	}
	s.persist_cache()!
}

// serialize_cache serializes the cache through magic / version / count framing,
// skipping oversized bodies so the header count stays honest.
fn serialize_cache(cache []FileTicketRecord) []u8 {
	// Allocate room for framing plus worst-case record bodies.
	mut body := wire.new_writer(cache.len * (ticket_record_header_len + 128))
	mut persisted := 0
	for r in cache {
		encoded_ticket := r.ticket.encode()
		encoded_psk := r.psk.encode()
		if encoded_ticket.len > ticket_record_body_max_len {
			continue
		}
		if encoded_psk.len > ticket_record_body_max_len {
			continue
		}
		body.write_u64(u64(r.issued_at_ms))
		body.write_vector_u16(encoded_ticket) or {}
		body.write_vector_u16(encoded_psk) or {}
		persisted += 1
	}
	encoded := body.bytes()
	// Write magic, version, and the real count of persisted records.
	mut w := wire.new_writer(ticket_store_header_len + encoded.len)
	w.write_bytes(ticket_store_magic.bytes())
	w.write_u8(ticket_store_version)
	w.write_u16(u16(persisted))
	w.write_bytes(encoded)
	return w.bytes()
}

// persist_cache serializes the cache, optionally encrypts it, and commits it
// through a private same-directory temp file. File and directory syncs make a
// successful return durable across a process or machine restart.
fn (s FileTicketStore) persist_cache() ! {
	mut out := serialize_cache(s.cache)
	if s.key != none {
		// Encrypted mode: wrap serialized bytes as nonce || ciphertext.
		payload := enc_payload(s.key!, out)
		if payload.len == 0 {
			return error('tls: failed to encrypt ticket store cache')
		}
		out = payload.clone()
	}
	tmp_path := '${s.path}.${os.getpid()}${temp_file_suffix}'
	os.rm(tmp_path) or {}
	defer {
		os.rm(tmp_path) or {}
	}
	mut tmp := os.open_file(tmp_path, 'w', 0o600)!
	defer {
		tmp.close()
	}
	written := tmp.write(out)!
	if written != out.len {
		return error('tls: incomplete write to ticket store temporary file')
	}
	tmp.flush()
	os.chmod(tmp_path, 0o600) or { return err }
	sync_file_descriptor(tmp.fd)!
	tmp.close()
	$if windows {
		source := tmp_path.to_wide()
		destination := s.path.to_wide()
		flags := movefile_replace_existing | movefile_write_through
		if !C.MoveFileExW(source, destination, flags) {
			return error('tls: cannot atomically replace ticket store file')
		}
	} $else {
		os.rename(tmp_path, s.path)!
	}
	sync_store_directory(s.path)!
}

// now_ms_or_zero is the shared clock, clamped to 0 when the system clock is
// unusable so age arithmetic never trusts a broken clock.
fn now_ms_or_zero() i64 {
	ms := time.utc().unix_milli()
	// Clamp negative/unusable clock readings to zero.
	return if ms < 0 { 0 } else { ms }
}

// ticket_expired reports whether a ticket may no longer be used for resumption:
// lifetime 0 disallows it outright; otherwise its lifetime has elapsed since the
// recorded issue time. A future-dated record is not expired here — the clock
// moved, not the ticket.
fn ticket_expired(ticket handshake.NewSessionTicket, issued_at_ms i64, now_ms i64) bool {
	lifetime := ticket.lifetime()
	if lifetime == 0 {
		return true
	}
	// A clock behind the record is not expiry; only elapsed lifetime destroys.
	if now_ms < issued_at_ms {
		return false
	}
	return now_ms - issued_at_ms >= i64(lifetime) * 1000
}

// ticket_is_live reports whether a ticket may be offered right now: its lifetime
// has not elapsed and the clock is not behind its issue time, since a hold time
// the client cannot have observed would make the §4.6.1 age arithmetic a guess.
fn ticket_is_live(ticket handshake.NewSessionTicket, issued_at_ms i64, now_ms i64) bool {
	return now_ms >= issued_at_ms && !ticket_expired(ticket, issued_at_ms, now_ms)
}
