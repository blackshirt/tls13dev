// Copyright (c) 2026 blackshirt.
//
// SessionTicketStore seam and its file backend (RFC 8446 §4.6.1). A store seeds
// dial() with tickets / resumption PSKs and takes back every ticket a connection
// accepts. FileTicketStore is a single opaque type with two modes chosen at
// construction: plain (new_file_ticket_store, bytes to tickets.bin raw) or
// encrypted (new_encrypted_file_ticket_store, AES-256-GCM with a fresh nonce per
// write). The serialized cache layout is identical in both modes; encryption only
// wraps those bytes. An in-memory plain-text backend (InMemoryTicketStore) is kept
// module-internal for tests.
module tls

import crypto.aes
import crypto
import os
import time
import tls.handshake
import tls.wire

const max_stored_session_tickets = 32
const ticket_store_filename = 'tickets.bin'
const temp_file_suffix = '.tmp'
const ticket_store_magic = 'TLS13TSK'
const ticket_store_version = u8(3)
const ticket_record_header_len = 12
const ticket_store_header_len = 11
const ticket_record_body_max_len = 0xffff
const ticket_store_max_file_len = 8 * 1024 * 1024
const encrypted_file_store_key_len = 32
const encrypted_file_store_nonce_len = 12

pub interface SessionTicketStore {
mut:
	tickets() []handshake.NewSessionTicket
	resumption_psks() []handshake.Psk
	put(ticket handshake.NewSessionTicket, psk handshake.Psk) !
	consume(identity []u8) !
	wipe()
}

@[noinit]
pub struct FileTicketStore {
mut:
	path  string
	key   ?[]u8 // 32-byte AES key when encrypted; none when plain; wiped by wipe(); never written to disk
	cache []FileTicketRecord
	// set when the existing tickets.bin cannot be decrypted with the supplied key
	key_was_rejected bool
}

// Plain file-backed store over `dir` (mode 0700). Loads any existing tickets.bin
// on construction; a missing/unreadable file yields an empty store.
pub fn new_file_ticket_store(dir string) !FileTicketStore {
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
		key:   none
		cache: []FileTicketRecord{}
	}
	s.cache = s.read_file()
	return s
}

// Encrypted file-backed store over `dir` with 32-byte AES-256-GCM `key`. A file
// that fails to decrypt yields an empty store and sets key_was_rejected.
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

pub fn (s FileTicketStore) key_was_rejected() bool {
	return s.key_was_rejected
}

// Persists a (ticket, PSK) pair, replacing any earlier record with the same token.
// A mismatched pair or lifetime-0 ticket is silently refused; a full store errors.
pub fn (mut s FileTicketStore) put(ticket handshake.NewSessionTicket, psk handshake.Psk) ! {
	if psk.identity() != ticket.bytes() {
		return
	}
	if ticket.lifetime() == 0 {
		return
	}
	s.prune_expired()
	now_ms := now_ms_or_zero()
	held_psk := handshake.parse_resumption_psk(psk.encode()) or { return }
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

// Burns the record whose PSK carries `identity` (single-use, §8.6). Unknown
// identities change nothing.
pub fn (mut s FileTicketStore) consume(identity []u8) ! {
	s.merge_disk_state()
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

// Scrubs every record, wipes the AES key (encrypted mode), then shreds and
// unlinks the store file. Owner's teardown (§7.5); Conn never calls it.
pub fn (mut s FileTicketStore) wipe() {
	for i in 0 .. s.cache.len {
		s.cache[i].wipe_record()
	}
	s.cache = []FileTicketRecord{}
	if s.key != none {
		zero_bytes(mut s.key!)
		s.key = none
	}
	shred_file(s.path)
}

// Overwrites `path` with random bytes before unlinking it.
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

// Drops expired records, scrubbing their secrets and persisting expiry.
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

// Wraps `plaintext` in AES-256-GCM as `nonce || ciphertext` with a fresh nonce.
// Empty bytes on failure.
fn enc_payload(key []u8, plaintext []u8) []u8 {
	mut aead := aes.new_aes_gcm(key) or { return []u8{} }
	mut nonce := crypto.rand.bytes(encrypted_file_store_nonce_len) or { return []u8{} }
	ciphertext := aead.encrypt(plaintext, nonce, []u8{}) or { return []u8{} }
	mut payload := []u8{cap: encrypted_file_store_nonce_len + ciphertext.len}
	payload << nonce
	payload << ciphertext
	return payload
}

// Splits `nonce || ciphertext` from `data` and decrypts. Empty bytes on failure.
fn dec_payload(key []u8, data []u8) []u8 {
	if data.len < encrypted_file_store_nonce_len {
		return []u8{}
	}
	nonce := data[..encrypted_file_store_nonce_len].clone()
	ciphertext := data[encrypted_file_store_nonce_len..].clone()
	mut aead := aes.new_aes_gcm(key) or { return []u8{} }
	plaintext := aead.decrypt(ciphertext, nonce, []u8{}) or { return []u8{} }
	return plaintext
}

// In-memory plain-text store. No encrypted mode: it dies with the process and
// shares the process address space, so per-record encryption adds no real
// security. Module-internal; tests exercise it through the SessionTicketStore seam.
@[noinit]
struct InMemoryTicketStore {
mut:
	cache []FileTicketRecord
}

fn new_in_memory_ticket_store() InMemoryTicketStore {
	return InMemoryTicketStore{
		cache: []FileTicketRecord{cap: max_stored_session_tickets}
	}
}

pub fn (mut s InMemoryTicketStore) put(ticket handshake.NewSessionTicket, psk handshake.Psk) ! {
	if psk.identity() != ticket.bytes() || ticket.lifetime() == 0 {
		return
	}
	s.prune_expired()
	held_psk := handshake.parse_resumption_psk(psk.encode()) or { return }
	now_ms := now_ms_or_zero()
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
	if s.cache.len >= max_stored_session_tickets {
		return error('tls: ticket store full: ${max_stored_session_tickets} tickets stored')
	}
	s.cache << FileTicketRecord{
		issued_at_ms: now_ms
		ticket:       ticket.clone()
		psk:          held_psk
	}
}

pub fn (mut s InMemoryTicketStore) consume(identity []u8) ! {
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
	s.cache[target].wipe_record()
	mut kept := []FileTicketRecord{cap: s.cache.len - 1}
	for i in 0 .. s.cache.len {
		if i != target {
			kept << s.cache[i]
		}
	}
	s.cache = kept
}

pub fn (mut s InMemoryTicketStore) tickets() []handshake.NewSessionTicket {
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

pub fn (mut s InMemoryTicketStore) resumption_psks() []handshake.Psk {
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

pub fn (mut s InMemoryTicketStore) wipe() {
	for i in 0 .. s.cache.len {
		s.cache[i].wipe_record()
	}
	s.cache = []FileTicketRecord{}
}

// Drops expired records, scrubbing their secrets. Future-dated records stay.
fn (mut s InMemoryTicketStore) prune_expired() {
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
	}
}

@[noinit]
struct FileTicketRecord {
mut:
	issued_at_ms i64
	ticket       handshake.NewSessionTicket
	psk          handshake.Psk
}

fn (mut r FileTicketRecord) wipe_record() {
	r.ticket.wipe()
	r.psk.wipe()
	r.issued_at_ms = 0
}

// Decodes the store file. Plain mode parses raw bytes; encrypted mode decrypts
// first. Degrades to empty on any bad input; sets key_was_rejected only when a
// non-empty file fails to decrypt (wrong key / tampered).
fn (mut s FileTicketStore) read_file() []FileTicketRecord {
	info := os.stat(s.path) or { return []FileTicketRecord{} }
	if info.size > ticket_store_max_file_len {
		return []FileTicketRecord{}
	}
	data := os.read_bytes(s.path) or { return []FileTicketRecord{} }
	if s.key != none {
		plaintext := dec_payload(s.key!, data)
		if plaintext.len == 0 && data.len > 0 {
			s.key_was_rejected = true
		}
		return parse_store_bytes(plaintext)
	}
	return parse_store_bytes(data)
}

// Decodes magic + version + count + records into FileTicketRecords, rejecting
// unbound pairs and oversized bodies.
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
		if psk.identity() != ticket.bytes() {
			continue
		}
		if out.len >= max_stored_session_tickets {
			break
		}
		out << FileTicketRecord{
			issued_at_ms: issued_at_ms
			ticket:       ticket
			psk:          psk
		}
	}
	return out
}

fn (mut s FileTicketStore) write_file() ! {
	s.merge_disk_state()
	s.persist_cache()!
}

// Serializes cache through magic/version/count framing; oversized bodies skipped.
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

// Serializes, optionally encrypts, writes via 0600 temp file + atomic rename.
fn (s FileTicketStore) persist_cache() ! {
	mut out := serialize_cache(s.cache)
	if s.key != none {
		payload := enc_payload(s.key!, out)
		if payload.len == 0 {
			return error('tls: failed to encrypt ticket store cache')
		}
		out = payload.clone()
	}
	tmp_path := '${s.path}.${os.getpid()}${temp_file_suffix}'
	os.rm(tmp_path) or {}
	os.write_bytes(tmp_path, out) or { return err }
	os.chmod(tmp_path, 0o600) or { return err }
	$if windows {
		os.rm(s.path) or {}
	}
	os.rename(tmp_path, s.path) or { return err }
}

// Folds in disk-persisted records this cache doesn't already hold.
fn (mut s FileTicketStore) merge_disk_state() {
	disk := s.read_file()
	now := now_ms_or_zero()
	for r in disk {
		if s.cache.len >= max_stored_session_tickets {
			break
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

fn now_ms_or_zero() i64 {
	ms := time.utc().unix_milli()
	return if ms < 0 { 0 } else { ms }
}

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

fn ticket_is_live(ticket handshake.NewSessionTicket, issued_at_ms i64, now_ms i64) bool {
	return now_ms >= issued_at_ms && !ticket_expired(ticket, issued_at_ms, now_ms)
}
