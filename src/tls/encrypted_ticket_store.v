// Copyright (c) 2026 blackshirt.
//
// encrypted_ticket_store.v adds EncryptedFileTicketStore, an AES-256-GCM
// encrypted variant of FileTicketStore (RFC 8446 §4.6.1 / §7.5). The serialized
// ticket + PSK cache is encrypted before it ever touches tickets.bin, so the
// on-disk key material is protected by the caller-supplied key rather than by
// filesystem permissions alone.
//
// Each write uses a fresh random 12-byte nonce that is prepended to the
// ciphertext, so two writes of the same cache never produce identical ciphertext
// and AES-GCM nonce reuse is avoided. The plaintext cache lives only in memory;
// the key is wiped by wipe() and never written to disk.
//
// Usage:
//   key := crypto.rand.bytes(32)! // or any 32 bytes of high-entropy material
//   mut store := tls.new_encrypted_file_ticket_store(dir, key)!
//
// Module `tls`: EncryptedFileTicketStore satisfies the same SessionTicketStore
// seam as FileTicketStore and can be passed to Config.session_ticket_store.
module tls

import crypto.aes
import crypto.cipher
import crypto.rand
import os
import tls.handshake

// encrypted_file_store_key_len is the AES-256 key length required to construct
// an EncryptedFileTicketStore. Exactly 32 bytes of high-entropy key material.
// A shorter key is rejected outright; a longer key is rejected so the caller
// cannot mistake a truncated derivation for full strength.
const encrypted_file_store_key_len = 32

// encrypted_file_store_nonce_len is the per-write nonce length, prepended to
// every ciphertext so it can be recovered on read. AES-GCM uses 12-byte nonces.
const encrypted_file_store_nonce_len = 12

// EncryptedFileTicketStore is a SessionTicketStore that encrypts the serialized
// cache with AES-256-GCM before writing tickets.bin and decrypts after reading.
// The AES key is held in memory for the store's life and wiped by wipe(); it is
// never written to disk. Each write uses a fresh random nonce, so identical
// caches never produce identical ciphertext.
//
// Concurrency: not thread-safe. One store per directory per process; see the
// SessionTicketStore seam for the shared concurrency contract.
//
// @[noinit] keeps a bare value from existing with a garbage cache slice or an
// uninitialized AEAD, which every read and write would otherwise corrupt.
@[noinit]
pub struct EncryptedFileTicketStore {
mut:
	path   string
	key    []u8 // 32-byte AES-256 key, wiped by wipe(); never written to disk
	aead   cipher.AEAD
	cache  []FileTicketRecord
}

// new_encrypted_file_ticket_store creates an EncryptedFileTicketStore over `dir`
// with mode 0700, using `key` as the 32-byte AES-256-GCM key. It scans any
// existing tickets.bin (decrypting it) so tickets() and resumption_psks() see
// persisted state from the first call. Fails when `dir` cannot be created, is
// not a directory, is writable by others, `key` is not exactly 32 bytes, or the
// existing file cannot be decrypted with `key` (wrong key or corrupt file yields
// an empty store, not an error, so a dial is never blocked by a bad tickets.bin).
pub fn new_encrypted_file_ticket_store(dir string, key []u8) !EncryptedFileTicketStore {
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
		// On Windows, mode bits don't map to Unix permissions. Verify the directory is
		// at least writable by creating and deleting a probe file.
		probe := os.join_path(dir, '.tls_ticket_store_probe')
		os.write_bytes(probe, []u8{}) or {
			return error('tls: cannot write to ticket store directory ${dir}')
		}
		os.rm(probe) or {}
	}
	mut aead := aes.new_aes_gcm(key)!
	mut s := EncryptedFileTicketStore{
		path:  os.join_path(dir, ticket_store_filename)
		key:   key.clone()
		aead:  aead
		cache: []FileTicketRecord{}
	}
	s.cache = s.read_file()
	return s
}

// tickets returns the persisted tickets that may still be used, decrypted from
// tickets.bin and aged by the hold time (§4.6.1). Each ticket is a copy, so the
// borrower's teardown cannot scrub what the store holds.
pub fn (mut s EncryptedFileTicketStore) tickets() []handshake.NewSessionTicket {
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

// resumption_psks returns the PSKs of the records that may still be used,
// decrypted from tickets.bin, with obfuscated ages advanced by the hold time
// (§4.6.1). Callers get copies, so the recorded ages cannot be rewritten.
pub fn (mut s EncryptedFileTicketStore) resumption_psks() []handshake.Psk {
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

// put persists an encrypted copy of the ticket/PSK pair to tickets.bin,
// replacing an earlier record carrying the same token (§4.6.1 allows a server
// to reissue one). Returns an error on a full store or a write/disk failure;
// an unusable or inconsistent pair, a lifetime of 0, or an unroundtrippable
// PSK is silent by design — the ticket stays in Conn's backlog only.
pub fn (mut s EncryptedFileTicketStore) put(ticket handshake.NewSessionTicket, psk handshake.Psk) ! {
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
	s.prune_expired()
	now_ms := now_ms_or_zero()
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

// consume burns the decrypted record whose PSK carries this identity, then
// re-encrypts and persists the burn (§8.6: a resumption PSK is single-use).
// Unknown identities change nothing, so a caller-supplied external PSK cannot
// reach stored material.
pub fn (mut s EncryptedFileTicketStore) consume(identity []u8) {
	// A peer's file is folded in first, so this rewrite cannot lose a ticket
	// another process just persisted, and the burn cannot come back on a later
	// restart.
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
	// Scrub before dropping it, then persist the burn: a store that only forgot
	// in memory would hand the same PSK back after a restart.
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

// wipe scrubs every cached ticket/PSK, wipes the stored AES key, and unlinks
// the store file (§7.5). Conn does not call it — a close must not delete the
// tickets it just persisted — so this is the owner's scrub. unlink rather than
// a zero-length write: a symlink planted at tickets.bin would take the write,
// and os.rm removes the name itself. The AES key is zeroed in memory; bytes
// already on disk are not zeroed, so a scrubbed store is released, not erased.
pub fn (mut s EncryptedFileTicketStore) wipe() {
	for i in 0 .. s.cache.len {
		s.cache[i].wipe_record()
	}
	s.cache = []FileTicketRecord{}
	for i in 0 .. s.key.len {
		s.key[i] = 0
	}
	s.key = []u8{}
	os.rm(s.path) or {}
}

// prune_expired drops records whose ticket_lifetime has truly elapsed (§4.6.1),
// scrubbing their secrets and rewriting so expiry is persisted rather than
// re-decided per read. A record dated ahead of the clock is left on disk:
// hiding it is the read path's job, and deleting it would turn a clock glitch
// into lost tickets.
fn (mut s EncryptedFileTicketStore) prune_expired() {
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

// read_file reads the encrypted store file, splits the per-write nonce from the
// ciphertext, decrypts with AES-256-GCM, and parses the plaintext format through
// parse_store_bytes. A missing file, one shorter than a nonce, a wrong key
// (tag mismatch), a tampered ciphertext, foreign magic/version, or corrupt
// records all degrade to an empty store — the store never fails a dial.
fn (s EncryptedFileTicketStore) read_file() []FileTicketRecord {
	info := os.stat(s.path) or { return []FileTicketRecord{} }
	if info.size > ticket_store_max_file_len {
		return []FileTicketRecord{}
	}
	data := os.read_bytes(s.path) or { return []FileTicketRecord{} }
	if data.len < encrypted_file_store_nonce_len {
		return []FileTicketRecord{} // not even a nonce: not a store we wrote
	}
	nonce := data[..encrypted_file_store_nonce_len].clone()
	ciphertext := data[encrypted_file_store_nonce_len..].clone()
	// AES-GCM tag verification rejects wrong keys, truncated ciphertext, and
	// tampered ciphertext alike: decryption failure degrades to an empty store.
	plaintext := s.aead.decrypt(ciphertext, nonce, []u8{}) or { return []FileTicketRecord{} }
	return parse_store_bytes(plaintext)
}

// write_file merges what peers persisted (decrypting their file first), then
// re-encrypts and writes exactly the result, so a whole-file rewrite cannot lose
// their tickets. Returns an error on write/disk failure; the cache stays authoritative here.
fn (mut s EncryptedFileTicketStore) write_file() ! {
	s.merge_disk_state()
	s.persist_cache()!
}

// persist_cache serializes the cache, encrypts it with a fresh random nonce, and
// writes nonce || ciphertext through a 0600 temp file and atomic rename. Returns
// an error on write/encryption failure; the cache stays authoritative and the next
// write retries.
fn (s EncryptedFileTicketStore) persist_cache() ! {
	out := serialize_cache(s.cache)
	mut nonce := rand.bytes(encrypted_file_store_nonce_len) or { return err }
	ciphertext := s.aead.encrypt(out, nonce, []u8{}) or { return err }
	mut payload := []u8{cap: encrypted_file_store_nonce_len + ciphertext.len}
	payload << nonce
	payload << ciphertext
	// The pid keeps two processes writing the same store from sharing one temp
	// name, which would rename an interleaved stream into place.
	tmp_path := '${s.path}.${os.getpid()}${temp_file_suffix}'
	// The name is still predictable, so it may be a symlink planted by another
	// process and write_bytes would follow it: os.rm unlinks it first.
	os.rm(tmp_path) or {}
	os.write_bytes(tmp_path, payload) or { return err }
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

// merge_disk_state folds in decrypted records another process persisted since
// this cache was loaded, so a whole-file rewrite cannot lose their tickets. A
// token this cache holds keeps this cache's copy (the one put() just refreshed);
//
// read_file already screened the bound pair, so only expiry can disqualify a
// record here.
fn (mut s EncryptedFileTicketStore) merge_disk_state() {
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
