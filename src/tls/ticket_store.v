// Copyright (c) 2026 blackshirt.
//
// ticket_store.v owns the SessionTicketStore seam and its file backend
// (RFC 8446 §4.6.1). A store seeds dial() with tickets / resumption PSKs and
// takes back every ticket a connection accepts.
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
module tls

import crypto.aes
import crypto
import os
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

// SessionTicketStore is a source and sink for session tickets and the
// resumption PSKs derived from them. tickets() and resumption_psks() hand back
// what is still live, aged by the hold time (§4.6.1); put() is the
// write-through side.
//
// Concurrency: not thread-safe. One store instance per directory per process.
// wipe() is the owner's scrub (§7.5); consume() is the single-use burn owed
// after resuming on a ticket (§8.6). Conn never calls wipe().
pub interface SessionTicketStore {
mut:
	tickets() []handshake.NewSessionTicket
	resumption_psks() []handshake.Psk
	put(ticket handshake.NewSessionTicket, psk handshake.Psk) !
	consume(identity []u8) !
	wipe()
}

// FileTicketStore is the file-backed SessionTicketStore: it seeds a dial from
// persisted tickets and their PSKs, write-throughs tickets accepted during a
// connection, and drops expired records at load.
//
// @[noinit] keeps a bare FileTicketStore{} from existing with a garbage cache
// slice; a long-lived store must not be built inline in Config{}.
//
// Mode is chosen at construction: key == none means plain bytes to tickets.bin;
// key == 32 bytes means AES-256-GCM encryption with a fresh nonce per write.
// key_was_rejected is set (encrypted mode only) when the existing tickets.bin
// cannot be decrypted with the supplied key.
@[noinit]
pub struct FileTicketStore {
mut:
	path             string
	key              ?[]u8 // 32-byte AES key when encrypted; none when plain; wiped by wipe(); never written to disk
	cache            []FileTicketRecord
	key_was_rejected bool
}

// new_file_ticket_store creates a plain FileTicketStore over `dir` (mode 0700).
// It loads any existing tickets.bin so tickets() and resumption_psks() see
// persisted state from the first call. Fails only when `dir` cannot be created,
// is not a directory, or is writable by others; an unreadable store file yields
// an empty store.
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
	s.cache = s.read_file()
	return s
}

// new_encrypted_file_ticket_store creates an encrypted FileTicketStore over `dir`
// (mode 0700) using `key` as the 32-byte AES-256-GCM key. It scans any existing
// tickets.bin (decrypting it) so tickets() and resumption_psks() see persisted
// state from the first call. A file that fails to decrypt yields an empty store
// and sets key_was_rejected — a dial is never blocked by a bad tickets.bin.
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
	s.cache = s.read_file()
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

// key_was_rejected reports whether the existing tickets.bin could not be
// decrypted with the supplied key (encrypted mode only).
pub fn (s FileTicketStore) key_was_rejected() bool {
	return s.key_was_rejected
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
	// Prune before writing so a store that was only ever read cannot rewrite
	// expired records back onto disk alongside the new one.
	s.prune_expired()
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
			s.write_file()!
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
	s.write_file()!
}

// consume burns the record whose §7.2 PSK carries `identity`, once a connection
// has resumed on it (§8.6: a resumption PSK is single-use, and offering it twice
// lets a peer link the two connections). Unknown identities change nothing, so a
// caller-supplied external PSK cannot reach stored material.
pub fn (mut s FileTicketStore) consume(identity []u8) ! {
	// Fold in what peers persisted so the burn cannot come back on a later merge.
	s.merge_disk_state()
	mut target := -1
	for i in 0 .. s.cache.len {
		if s.cache[i].psk.identity() == identity {
			target = i
			break // only the first match; put() keeps tokens unique
		}
	}
	if target < 0 {
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
	s.persist_cache()!
}

// wipe drops every cached record, scrubs them in memory, wipes the stored AES
// key when the store is encrypted, then overwrites the store file with random
// bytes before unlinking it (§7.5). Conn never calls it — a close must not
// delete the tickets it just persisted — so this is the owner's teardown.
pub fn (mut s FileTicketStore) wipe() {
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
		// Scrub the secrets of expired records before discarding them.
		for i in 0 .. s.cache.len {
			if ticket_expired(s.cache[i].ticket, s.cache[i].issued_at_ms, now) {
				s.cache[i].wipe_record()
			}
		}
		s.cache = alive
		s.write_file() or {}
	}
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
fn new_in_memory_ticket_store() InMemoryTicketStore {
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
// decrypts the nonce || ciphertext wrapper first. Degrades to empty on any bad
// input; sets key_was_rejected only when a non-empty file fails to decrypt
// (wrong key or tampered ciphertext), so callers can tell key rotation from an
// empty store.
fn (mut s FileTicketStore) read_file() []FileTicketRecord {
	// Bound the read before allocating: os.read_bytes takes the whole file, so
	// anything past what this writer could produce is not a ticket store.
	info := os.stat(s.path) or { return []FileTicketRecord{} }
	if info.size > ticket_store_max_file_len {
		return []FileTicketRecord{}
	}
	data := os.read_bytes(s.path) or { return []FileTicketRecord{} }
	if s.key != none {
		// Decrypt nonce || ciphertext wrapper; mark key rejected on failure.
		plaintext := dec_payload(s.key!, data)
		if plaintext.len == 0 && data.len > 0 {
			s.key_was_rejected = true
		}
		return parse_store_bytes(plaintext)
	}
	return parse_store_bytes(data)
}

// parse_store_bytes decodes magic + version + count + records into
// FileTicketRecords, rejecting unbound ticket/PSK pairs and oversized bodies.
// A corrupt or foreign file degrades to empty rather than failing the dial.
fn parse_store_bytes(data []u8) []FileTicketRecord {
	mut out := []FileTicketRecord{}
	if data.len < ticket_store_header_len {
		return out
	}
	if data[..ticket_store_magic.len].bytestr() != ticket_store_magic {
		return out
	}
	mut r := wire.new_reader(data[ticket_store_magic.len..])
	version := r.read_u8() or { return out }
	if version != ticket_store_version {
		return out
	}
	count := int(r.read_u16() or { return out })
	for _ in 0 .. count {
		// Stop if there are not enough bytes left for one record header.
		if r.remaining() < ticket_record_header_len {
			break
		}
		issued_at_ms := i64(r.read_u64() or { break })
		ticket_len := int(r.read_u16() or { break })
		if ticket_len <= 0 || ticket_len > handshake.max_handshake_message_len || r.remaining() < ticket_len {
			break
		}
		ticket_bytes := r.read_bytes(ticket_len) or { break }
		psk_len := int(r.read_u16() or { break })
		if psk_len <= 0 || psk_len > handshake.max_handshake_message_len || r.remaining() < psk_len {
			break
		}
		psk_bytes := r.read_bytes(psk_len) or { break }
		ticket := handshake.parse_new_session_ticket(ticket_bytes) or { continue }
		psk := handshake.parse_resumption_psk(psk_bytes) or { continue }
		// A file that separates a ticket from its own PSK is not one this store
		// wrote; skip it rather than keeping an unbindable pair.
		if psk.identity() != ticket.bytes() {
			continue
		}
		if out.len >= max_stored_session_tickets {
			break // keep the oldest records; put() refuses the rest
		}
		out << FileTicketRecord{
			issued_at_ms: issued_at_ms
			ticket:       ticket
			psk:          psk
		}
	}
	return out
}

// write_file merges what peers persisted, then writes exactly the result so a
// whole-file rewrite cannot lose their tickets. The cache stays authoritative.
fn (mut s FileTicketStore) write_file() ! {
	// Fold in peer-persisted records before rewriting.
	s.merge_disk_state()
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

// persist_cache serializes the cache, optionally encrypts it, and writes via a
// 0600 temp file and atomic rename so a torn copy never shadows the live store.
// consume() calls this directly because folding in a peer's file would
// resurrect the record it just burned.
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
	// The pid keeps two processes writing the same store from sharing one temp
	// name, which would rename an interleaved stream into place.
	tmp_path := '${s.path}.${os.getpid()}${temp_file_suffix}'
	os.rm(tmp_path) or {}
	os.write_bytes(tmp_path, out) or { return err }
	// Chmod to 0600 before the rename adopts the file.
	os.chmod(tmp_path, 0o600) or { return err }
	// Windows rename fails when the target exists; unlink first to persist.
	$if windows {
		os.rm(s.path) or {}
	}
	os.rename(tmp_path, s.path) or { return err }
}

// merge_disk_state folds in records another process persisted since this cache
// was loaded, so a whole-file rewrite cannot lose their tickets. A token this
// cache already holds keeps this cache's fresher copy.
fn (mut s FileTicketStore) merge_disk_state() {
	// Read current disk state (decrypting if encrypted mode).
	disk := s.read_file()
	now := now_ms_or_zero()
	for r in disk {
		if s.cache.len >= max_stored_session_tickets {
			break // this cache's own tickets keep priority
		}
		if ticket_expired(r.ticket, r.issued_at_ms, now) {
			continue
		}
		// Skip tokens this cache already holds.
		mut known := false
		for c in s.cache {
			if c.ticket.bytes() == r.ticket.bytes() {
				known = true
				break
			}
		}
		if !known {
			s.cache << r
		}
	}
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
