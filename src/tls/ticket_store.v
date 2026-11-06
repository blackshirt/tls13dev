// Copyright (c) 2026 blackshirt.
//
// ticket_store.v owns the SessionTicketStore seam and its two backends (RFC 8446
// §4.6.1): a store supplies dial() with the tickets to seed Conn's backlog and
// the resumption PSKs to offer in the ClientHello, and takes back every ticket
// the connection accepts.
//
// put() receives a pair, not a ticket. The key is HKDF-Expand-Label of the
// issuing session's resumption master secret (§7.2), so only
// handshake.HandshakeCore can produce it and only while that session is alive;
// a store that kept the ticket bytes alone could never bind a later resumption.
//
// FileTicketStore writes the pairs to tickets.bin. That file is key material, so
// new_file_ticket_store creates its directory 0700 and every file it writes is
// chmodded 0600 before the rename. Its record layout is described by the
// ticket_store_* and ticket_record_* constants.
//
// Declarations are ordered: the constants, the seam and the public file backend
// that answers it, the module-internal in-memory backend, then private helpers.
module tls

import os
import time
import tls.handshake
import tls.wire

// max_stored_session_tickets bounds how many tickets a store may hold, out of
// the many a server may push.
const max_stored_session_tickets = 32

// ticket_store_filename is the filename for the persisted ticket store.
const ticket_store_filename = 'tickets.bin'

// temp_file_suffix is the tail of the temp name write_file renames from, with the
// writing process's pid in front of it so two stores cannot collide on one name.
const temp_file_suffix = '.tmp'

// ticket_store_magic tags the store file so a foreign or truncated file is
// never parsed as tickets.
const ticket_store_magic = 'TLS13TSK'

// ticket_store_version bumps when the record layout changes; version 3 added the
// stored resumption PSK, without which a restarted process could not bind a
// ticket it had saved (§7.2).
const ticket_store_version = u8(3)

// ticket_record_header_len is the fixed part of one record: u64 issued_at_ms
// plus the two u16 length prefixes around the ticket and the PSK blob.
const ticket_record_header_len = 12

// ticket_store_header_len is the whole-file framing ahead of the records:
// magic + version byte + u16 count.
const ticket_store_header_len = 11

// ticket_record_body_max_len is the largest body a record's u16 length prefix
// can carry. A ticket or PSK blob past it cannot be persisted, so write_file
// skips that record whole rather than truncating the records behind it.
const ticket_record_body_max_len = 0xffff

// ticket_store_max_file_len bounds what read_file will even look at. The file is
// read whole, and the largest one this writer could produce is the framing plus
// every slot at its maximum record, so a bigger file was not written by this
// code and is not parsed. Rounded up from that ceiling on purpose.
const ticket_store_max_file_len = 8 * 1024 * 1024

// SessionTicketStore is a source and sink for session tickets and the resumption
// PSKs derived from them. tickets() and resumption_psks() hand back what is still
// live, aged by the hold time (§4.6.1); put() is the write-through side.
//
// Concurrency: a store is not thread-safe. One store instance must be used from a
// single thread, and one directory should have one live store per process. The
// merge_disk_state() fold-in at write time mitigates lost updates between two
// processes sharing a directory, but it is not a distributed lock — two live
// stores over the same tickets.bin can overwrite each other's records.
//
// A store outlives the connection that filled it: Conn never calls wipe(), since
// teardown runs on every close and would otherwise delete the tickets it just
// persisted. wipe() is the owner's scrub (§7.5), and consume() is the narrower
// burn a connection owes after it resumes on a ticket (§8.6).
pub interface SessionTicketStore {
mut:
	tickets() []handshake.NewSessionTicket
	resumption_psks() []handshake.Psk
	put(ticket handshake.NewSessionTicket, psk handshake.Psk) !
	consume(identity []u8)
	wipe()
}

// FileTicketStore is the file-backed SessionTicketStore: it seeds a dial from
// persisted tickets and their PSKs, write-throughs both for tickets accepted
// during a connection, and drops expired records at load. @[noinit] keeps a bare
// FileTicketStore{} from existing with a garbage cache slice, which every read
// and write would then free or scrub. Cache state lives with the store value, so
// a long-lived store must not be built inline in Config{}.
@[noinit]
pub struct FileTicketStore {
mut:
	path  string
	cache []FileTicketRecord
}

// new_file_ticket_store creates a FileTicketStore over `dir` with mode 0700,
// scanning any existing tickets.bin so tickets() and resumption_psks() see
// persisted state from the first call. An existing directory is the normal case,
// not an error: os.mkdir would fail EEXIST there, so this uses mkdir_all. It
// fails only when `dir` cannot be created, is not a directory, or is writable by
// others; an unreadable store file yields an empty store.
pub fn new_file_ticket_store(dir string) !FileTicketStore {
	os.mkdir_all(dir, mode: 0o700) or {
		return error('tls: cannot create ticket store directory ${dir}: ${err.msg()}')
	}
	$if !windows {
		// On a shared path such as /tmp, whoever creates the directory first would
		// otherwise receive our key material. A directory this call just made gets at
		// most 0700, because the requested mode still passes through the umask, so this
		// can only reject a directory someone else set up to be group/world-writable.
		info := os.stat(dir) or {
			return error('tls: cannot inspect ticket store directory ${dir}: ${err.msg()}')
		}
		if info.mode & 0o077 != 0 {
			return error('tls: ticket store directory ${dir} is group- or world-writable')
		}
	} $else {
		// On Windows, mode bits don't map to Unix permissions. Verify the directory is
		// at least writable by creating and deleting a probe file.
		probe := os.join_path(dir, '.tls_ticket_store_probe')
		os.write_bytes(probe, []u8{}) or {
			return error('tls: cannot write to ticket store directory ${dir}')
		}
		os.rm(probe) or {}
	}
	mut s := FileTicketStore{
		path:  os.join_path(dir, ticket_store_filename)
		cache: []FileTicketRecord{}
	}
	s.cache = s.read_file()
	return s
}

// tickets returns the persisted tickets that may still be used, ready to seed
// Conn's backlog: records whose lifetime elapsed are dropped and rewritten away,
// records the clock cannot date yet are hidden but kept. Each ticket is a copy,
// so the borrower's teardown cannot scrub what the store holds.
pub fn (mut s FileTicketStore) tickets() []handshake.NewSessionTicket {
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

// resumption_psks returns the PSKs of the records that may still be used, their
// obfuscated ages advanced by the time the file says each ticket was held
// (§4.6.1) — the reason this store exists. Callers get copies, so the cache keeps
// its own ages.
pub fn (mut s FileTicketStore) resumption_psks() []handshake.Psk {
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

// put persists a server-issued ticket with the §7.2 PSK derived for it,
// replacing an earlier record carrying the same token (§4.6.1 allows a server
// to reissue one). Returns an error on a full store or a write/disk failure;
// an unusable or inconsistent pair, a lifetime of 0, or an unroundtrippable
// PSK is silent by design — the ticket stays in Conn's backlog only.
pub fn (mut s FileTicketStore) put(ticket handshake.NewSessionTicket, psk handshake.Psk) ! {
	// A record is a bound pair: §7.2 makes the PSK identity the ticket bytes, so a
	// pair that disagrees is refused rather than kept as an offer no server can
	// reproduce and no read can match again.
	if psk.identity() != ticket.bytes() {
		return
	}
	// §4.6.1: a lifetime of 0 means the server forbade resumption with this ticket,
	// so it is refused at the door instead of taking a slot the next read prunes.
	if ticket.lifetime() == 0 {
		return
	}
	// Prune before writing, so a store that was only ever read (or never read at
	// all) cannot rewrite expired records back onto disk alongside the new one.
	s.prune_expired()
	now_ms := now_ms_or_zero()
	// The store must own what it keeps: Conn wipes its backlog at teardown (§7.5)
	// and hands the PSK over as a temporary, so both are copied straight into the
	// record here — the PSK through its own codec, which also validates it the way
	// the file loader will.
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

// consume burns the record whose §7.2 PSK carries this identity, once a
// connection has resumed on it (§8.6: a resumption PSK is single-use, and
// offering it twice lets a peer link the two connections). Unknown identities
// change nothing, so a caller-supplied external PSK cannot reach stored material.
pub fn (mut s FileTicketStore) consume(identity []u8) {
	// A peer's file is folded in first, so this rewrite cannot lose a ticket
	// another process just persisted, and the burn cannot come back on a later merge.
	s.merge_disk_state()
	mut target := -1
	for i in 0 .. s.cache.len {
		if s.cache[i].psk.identity() == identity {
			target = i
			break // only the first match, and put() keeps tokens unique
		}
	}
	if target < 0 {
		return
	}
	// Scrub before dropping it, as prune_expired does, then persist the burn: a
	// store that only forgot in memory would hand the same PSK back after a restart.
	s.cache[target].wipe_record()
	mut kept := []FileTicketRecord{cap: s.cache.len - 1}
	for i in 0 .. s.cache.len {
		if i != target {
			kept << s.cache[i]
		}
	}
	s.cache = kept
	s.persist_cache() or {}
}

// wipe drops every cached record and unlinks the store file (§7.5). Conn does not
// call it — a close must not delete the tickets it just persisted — so this is
// the owner's teardown. unlink rather than a zero-length write: a symlink planted
// at tickets.bin would take the write, and os.rm removes the name itself. Bytes
// already on disk are not zeroed, so a scrubbed store is released, not erased.
pub fn (mut s FileTicketStore) wipe() {
	for i in 0 .. s.cache.len {
		s.cache[i].wipe_record()
	}
	s.cache = []FileTicketRecord{}
	os.rm(s.path) or {}
}

// InMemoryTicketStore keeps tickets and their PSKs in three parallel slices,
// bounded and expired exactly as FileTicketStore does. It is module-internal:
// in-process resumption goes through Conn.resumption_psks(), so the public
// Config.session_ticket_store seam only needs the file backend. Its methods stay
// pub because the interface they satisfy requires it.
@[noinit]
struct InMemoryTicketStore {
mut:
	tickets   []handshake.NewSessionTicket
	psks      []handshake.Psk
	issued_at []i64 // per-record issue time, feeding the §4.6.1 age arithmetic
}

// new_in_memory_ticket_store creates a store bounded at max_stored_session_tickets.
fn new_in_memory_ticket_store() InMemoryTicketStore {
	return InMemoryTicketStore{
		tickets:   []handshake.NewSessionTicket{cap: max_stored_session_tickets}
		psks:      []handshake.Psk{cap: max_stored_session_tickets}
		issued_at: []i64{cap: max_stored_session_tickets}
	}
}

// put stores a ticket with its resumption PSK, pruning first so expired pairs
// cannot hold the bounded slots, refreshing a reissued token in place as
// FileTicketStore does, and dropping the pair if the store is full. Never fails:
// a rejected or inconsistent pair stays in Conn's backlog only.
pub fn (mut s InMemoryTicketStore) put(ticket handshake.NewSessionTicket, psk handshake.Psk) ! {
	// Same bound-pair and §4.6.1 lifetime rules as FileTicketStore.put.
	if psk.identity() != ticket.bytes() || ticket.lifetime() == 0 {
		return
	}
	s.prune_expired()
	// Owned copies, for the same reasons FileTicketStore.put states.
	held_psk := handshake.parse_resumption_psk(psk.encode()) or { return }
	now_ms := now_ms_or_zero()
	for i in 0 .. s.tickets.len {
		if s.tickets[i].bytes() == ticket.bytes() {
			s.tickets[i].wipe()
			s.psks[i].wipe()
			s.tickets[i] = ticket.clone()
			s.psks[i] = held_psk
			s.issued_at[i] = now_ms
			return
		}
	}
	if s.tickets.len >= max_stored_session_tickets {
		return
	}
	s.tickets << ticket.clone()
	s.psks << held_psk
	s.issued_at << now_ms
}

// consume burns the pair whose PSK carries this identity, once a connection has
// resumed on it (§8.6). Unknown identities change nothing. The three slices are
// rebuilt together so they keep one record per index.
pub fn (mut s InMemoryTicketStore) consume(identity []u8) {
	mut target := -1
	for i in 0 .. s.psks.len {
		if s.psks[i].identity() == identity {
			target = i
			break // only the first match, and put() keeps tokens unique
		}
	}
	if target < 0 {
		return
	}
	s.tickets[target].wipe()
	s.psks[target].wipe()
	mut kept_tickets := []handshake.NewSessionTicket{cap: s.tickets.len - 1}
	mut kept_psks := []handshake.Psk{cap: s.psks.len - 1}
	mut kept_at := []i64{cap: s.issued_at.len - 1}
	for i in 0 .. s.tickets.len {
		if i == target {
			continue
		}
		kept_tickets << s.tickets[i]
		kept_psks << s.psks[i]
		kept_at << s.issued_at[i]
	}
	s.tickets = kept_tickets
	s.psks = kept_psks
	s.issued_at = kept_at
}

// tickets returns the stored tickets that may still be used, ready to seed Conn's
// backlog, each as a copy the borrower may wipe freely.
pub fn (mut s InMemoryTicketStore) tickets() []handshake.NewSessionTicket {
	s.prune_expired()
	now := now_ms_or_zero()
	mut out := []handshake.NewSessionTicket{cap: s.tickets.len}
	for i, t in s.tickets {
		if ticket_is_live(t, s.issued_at[i], now) {
			out << t.clone()
		}
	}
	return out
}

// resumption_psks returns the PSKs that may still be used, with their ages
// advanced by the hold time (§4.6.1, applied by handshake.Psk.clone_aged).
// dial() appends these to Config.psks; callers get copies, so the recorded ages
// cannot be rewritten.
pub fn (mut s InMemoryTicketStore) resumption_psks() []handshake.Psk {
	s.prune_expired()
	now := now_ms_or_zero()
	mut out := []handshake.Psk{cap: s.psks.len}
	for i, p in s.psks {
		if ticket_is_live(s.tickets[i], s.issued_at[i], now) {
			out << p.clone_aged(now - s.issued_at[i])
		}
	}
	return out
}

// wipe scrubs every stored ticket and PSK and clears all three slices. Conn
// does not call it: the caller decides when persisted material should go (§7.5).
pub fn (mut s InMemoryTicketStore) wipe() {
	for i in 0 .. s.tickets.len {
		s.tickets[i].wipe()
	}
	for i in 0 .. s.psks.len {
		s.psks[i].wipe()
	}
	s.tickets.clear()
	s.psks.clear()
	s.issued_at.clear()
}

// prune_expired drops every pair whose ticket_lifetime has truly elapsed
// (§4.6.1), scrubbing the removed material; pairs merely ahead of the clock are
// left in place for the reads to hide. The three slices stay the same length, so
// index i is one record across all of them.
fn (mut s InMemoryTicketStore) prune_expired() {
	now := now_ms_or_zero()
	mut dropped := false
	mut tickets := []handshake.NewSessionTicket{cap: s.tickets.len}
	mut psks := []handshake.Psk{cap: s.psks.len}
	mut issued_at := []i64{cap: s.issued_at.len}
	for i, t in s.tickets {
		if ticket_expired(t, s.issued_at[i], now) {
			dropped = true
			continue
		}
		tickets << t
		psks << s.psks[i]
		issued_at << s.issued_at[i]
	}
	if dropped {
		for i in 0 .. s.tickets.len {
			if ticket_expired(s.tickets[i], s.issued_at[i], now) {
				s.tickets[i].wipe()
				s.psks[i].wipe()
			}
		}
		s.tickets = tickets
		s.psks = psks
		s.issued_at = issued_at
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

// prune_expired drops records whose ticket_lifetime has truly elapsed, scrubbing
// their secrets and rewriting so expiry is persisted rather than re-decided per
// read. A record dated ahead of the clock is left on disk: hiding it is the read
// path's job, and deleting it would turn a clock glitch into lost tickets.
fn (mut s FileTicketStore) prune_expired() {
	now := now_ms_or_zero()
	mut dropped := false
	mut alive := []FileTicketRecord{cap: s.cache.len}
	for r in s.cache {
		if ticket_expired(r.ticket, r.issued_at_ms, now) {
			dropped = true
			continue
		}
		alive << r
	}
		if dropped {
			for i in 0 .. s.cache.len {
				if ticket_expired(s.cache[i].ticket, s.cache[i].issued_at_ms, now) {
					s.cache[i].wipe_record()
				}
			}
			s.cache = alive
			s.write_file() or {}
		}
}

// wipe_record scrubs the ticket token and the PSK key the record holds.
fn (mut r FileTicketRecord) wipe_record() {
	r.ticket.wipe()
	r.psk.wipe()
	r.issued_at_ms = 0
}

// read_file decodes the store file. A missing file, one larger than this writer
// could produce, a foreign magic or version, a corrupt record tail or a pair
// §7.2 cannot bind yields an empty store or what was parsed so far, never an
// error: the store degrades to empty rather than failing the dial that consults it.
fn (s FileTicketStore) read_file() []FileTicketRecord {
	// Bounded before the read, because os.read_bytes takes the whole file into
	// memory at once: past ticket_store_max_file_len it is not a ticket store,
	// whoever wrote it.
	info := os.stat(s.path) or { return []FileTicketRecord{} }
	if info.size > ticket_store_max_file_len {
		return []FileTicketRecord{}
	}
	data := os.read_bytes(s.path) or { return []FileTicketRecord{} }
	return parse_store_bytes(data)
}

// parse_store_bytes decodes the store file framing (magic + version + u16 count
// + records) into records. All rejection rules mirror put()'s invariants: a file
// that separates a ticket from its own PSK, or carries an unroundtrippable PSK,
// never reaches the cache. Both FileTicketStore and EncryptedFileTicketStore
// share this loader so a wrong magic, version, or corrupt record always degrades
// to empty rather than failing the dial that consults it.
fn parse_store_bytes(data []u8) []FileTicketRecord {
	mut out := []FileTicketRecord{}
	if data.len < ticket_store_header_len {
		return out // absent, empty, or an older layout: start clean
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
		if r.remaining() < ticket_record_header_len {
			break
		}
		issued_at_ms := i64(r.read_u64() or { break })
		// Both bodies are the u16-prefixed vectors the encoder wrote; a short or
		// empty one ends the valid stream rather than being trusted as a ticket.
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
		// The bound pair is the loader's invariant as much as put()'s: a file that
		// separates a ticket from its own PSK is not one this store wrote, and no
		// server can reproduce such an offer, so it never reaches the cache.
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

// write_file merges what peers persisted, then writes exactly the result, so a
// whole-file rewrite cannot lose their tickets. Returns an error on write/disk
// failure; the cache stays authoritative here.
fn (mut s FileTicketStore) write_file() ! {
	s.merge_disk_state()
	s.persist_cache()!
}

// serialize_cache serializes exactly this cache through the on-disk framing:
// magic + version byte + u16 count + records. Counting records as they are
// serialized keeps the header honest: a body too large for its u16 prefix is
// skipped whole instead of truncating the records behind it. Both
// FileTicketStore.persist_cache and EncryptedFileTicketStore.persist_cache use
// this so the serialized bytes are identical before any encryption is applied.
fn serialize_cache(cache []FileTicketRecord) []u8 {
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
	mut w := wire.new_writer(ticket_store_header_len + encoded.len)
	w.write_bytes(ticket_store_magic.bytes())
	w.write_u8(ticket_store_version)
	w.write_u16(u16(persisted))
	w.write_bytes(encoded)
	return w.bytes()
}

// persist_cache serializes exactly this cache through a 0600 temp file and a
// rename, so a torn or stale copy never shadows the live store. Returns an error
// on write/disk failure. consume() calls this directly, because folding in a
// peer's file would resurrect the record it just burned.
fn (s FileTicketStore) persist_cache() ! {
	out := serialize_cache(s.cache)
	// The pid keeps two processes writing the same store from sharing one temp
	// name, which would rename an interleaved stream into place. It cannot tell two
	// stores in one process apart, so a directory should have one live store per
	// process — the same reason its cache must not be built inline in Config{}.
	tmp_path := '${s.path}.${os.getpid()}${temp_file_suffix}'
	// The name is still predictable, so it may be a symlink planted by another
	// process and write_bytes would follow it: os.rm unlinks it first.
	os.rm(tmp_path) or {}
	os.write_bytes(tmp_path, out) or { return err }
	// Created under the process umask, so tighten it to 0600 before the rename
	// adopts it; the store directory's 0700 mode already hides it meanwhile.
	os.chmod(tmp_path, 0o600) or { return err }
	// POSIX rename(2) replaces an existing file atomically, but the CRT
	// _wrename os.rename calls on Windows fails when the target exists, so unlink
	// there and accept a brief window with no store file rather than never
	// persisting a second ticket.
	$if windows {
		os.rm(s.path) or {}
	}
	os.rename(tmp_path, s.path) or { return err }
}

// merge_disk_state folds in records another process persisted since this cache
// was loaded, so a whole-file rewrite cannot lose their tickets. A token this
// cache holds keeps this cache's copy, the one put() just refreshed; read_file
// already screened the bound pair, so only expiry can disqualify a record here.
fn (mut s FileTicketStore) merge_disk_state() {
	disk := s.read_file()
	now := now_ms_or_zero()
	for r in disk {
		if s.cache.len >= max_stored_session_tickets {
			break // this cache's own tickets keep priority; the rest stay on their disk
		}
		if ticket_expired(r.ticket, r.issued_at_ms, now) {
			continue
		}
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

// now_ms_or_zero is the stores' shared clock, clamped to 0 when the system clock
// is unusable: the age arithmetic then adds nothing and ticket_is_live treats a
// dated record as expired rather than trusting a broken clock.
fn now_ms_or_zero() i64 {
	ms := time.utc().unix_milli()
	return if ms < 0 { 0 } else { ms }
}

// ticket_expired reports a ticket the server no longer allows resumption with
// (§4.6.1): lifetime 0 disallows it outright, and otherwise its lifetime has
// elapsed since the recorded issue time. A record dated ahead of the clock is
// not expired — the clock moved, not the ticket — so it is never destroyed here.
fn ticket_expired(ticket handshake.NewSessionTicket, issued_at_ms i64, now_ms i64) bool {
	lifetime := ticket.lifetime()
	if lifetime == 0 {
		return true
	}
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
