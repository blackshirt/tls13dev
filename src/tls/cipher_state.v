// Copyright (c) 2026 blackshirt.
//
// cipher_state.v carries one direction's AEAD key, IV, and sequence number across the
// handshake→application key transition, building each record nonce per §5.3 and
// enforcing the record limit that forces a KeyUpdate.
module tls

import crypto.cipher
import tls.handshake

// aead_nonce_len is the fixed 12-byte AEAD nonce size for every TLS 1.3 cipher
// suite (AES-GCM and ChaCha20-Poly1305, RFC 8446 §5.3 / RFC 8439 §2.8). The
// canonical value now lives in tls.handshake (the key schedule derives the nonce
// base to it); this local alias keeps the single source of truth while letting
// the record layer's `${aead_nonce_len}` messages interpolate by local name.
const aead_nonce_len = handshake.aead_nonce_len

// nonce_seq_offset is where the 64-bit sequence number lands in the nonce: the
// trailing 8 bytes, leaving the leading bytes of the IV untouched when XORed
// (RFC 8446 §5.3 left-pads the sequence number with 4 zero bytes).
const nonce_seq_offset = aead_nonce_len - 8

// record_seq_limit bounds how many records one key generation may carry in a
// direction. RFC 8446 §5.5 sets the tightest AEAD-internal bound (AES-GCM) at
// 2^24.5 records: senders MUST initiate a KeyUpdate before exceeding it and
// receivers MUST abort when it is exceeded. This is the round power-of-two
// lower bound, applied uniformly to every suite — ChaCha20-Poly1305 would
// tolerate 2^36.5, but one conservative bound avoids per-suite special cases.
const record_seq_limit = u64(1 << 24)

// RecordProtector manages encryption, decryption, sequence numbers, and nonces
// for one direction of a TLS 1.3 connection (RFC 8446 §5.2 & §5.3).
// Each record's nonce is derived from a static per-direction value plus the
// sequence number, so no per-record IV is ever transmitted.
struct RecordProtector {
mut:
	aead    cipher.AEAD // AEAD primitive for this direction (AES-GCM or ChaCha20-Poly1305)
	iv      []u8        // 12-byte nonce base from the key schedule ("iv" label), not a per-record IV
	seq_num u64         // record counter for this direction; implicitly part of every nonce
}

// new_record_protector initializes a per-direction record protector at seq 0
// (the first record under each key uses sequence number 0). The IV must be the
// suite's full nonce base — aead_nonce_len bytes.
fn new_record_protector(aead cipher.AEAD, iv []u8) !RecordProtector {
	if iv.len != aead_nonce_len {
		return error('record: IV length must be ${aead_nonce_len} bytes, got ${iv.len}')
	}
	return RecordProtector{
		aead:    aead
		iv:      iv.clone()
		seq_num: 0
	}
}

// compute_nonce derives the 12-byte AEAD nonce, nonce = XOR(padded seq_num, iv)
// (RFC 8446 §5.3). XORing a strictly increasing counter keeps the nonce unique
// under a fixed key without ever transmitting it, which AES-GCM and
// ChaCha20-Poly1305 both require; the sequence number occupies only the low 64
// bits, so the first 4 bytes of the IV are left untouched.
fn (s &RecordProtector) compute_nonce(seq u64) []u8 {
	mut nonce := s.iv.clone()
	for i in 0 .. 8 {
		shift := (7 - i) * 8
		nonce[nonce_seq_offset + i] ^= u8((seq >> shift) & 0xff)
	}
	return nonce
}

// record_aad builds the 5-byte Additional Authenticated Data for a TLS 1.3
// record: ContentType, legacy_version, and the ciphertext length (RFC 8446 §5.2).
fn record_aad(content_type ContentType, version u16, length int) []u8 {
	return [
		u8(content_type),
		u8(version >> 8),
		u8(version & 0xff),
		u8(length >> 8),
		u8(length & 0xff),
	]
}

// encrypt_record encrypts a plaintext payload into an encrypted Record (§5.2).
// The outer ContentType is always application_data (23): TLS 1.3 hides the real
// message type so observers cannot fingerprint handshake or alert traffic.
fn (mut s RecordProtector) encrypt_record(inner_type ContentType, plaintext []u8) !Record {
	// Fail closed on an uninitialized/partial cipher state: without this the
	// nonce computation below indexes a zero-length IV (panic) or calls a nil
	// AEAD interface. No legitimate path reaches here before the handshake
	// installs the keys, so refusing is the only safe answer.
	if s.iv.len != aead_nonce_len {
		return error('record: record protector not initialized (IV length ${s.iv.len}, expected ${aead_nonce_len})')
	}
	if s.seq_num >= record_seq_limit {
		// RFC 8446 §5.5: rekeying is mandatory before this bound; reaching the
		// backstop means the caller skipped its KeyUpdate obligation. Refusing
		// is the only safe option — continuing would reuse nonces under a worn
		// key, breaking GCM's uniqueness requirement.
		return error('record: sequence limit reached; rekey required (§5.5)')
	}
	if plaintext.len > max_plaintext_record_len {
		return error('record: plaintext length ${plaintext.len} exceeds maximum allowed ${max_plaintext_record_len}')
	}

	// TLSInnerPlaintext = plaintext || inner_content_type
	mut inner_plaintext := []u8{cap: plaintext.len + 1}
	inner_plaintext << plaintext
	inner_plaintext << u8(inner_type)

	// The 5-byte outer header is not encrypted, so it is bound into the AEAD tag
	// as AAD to prove its length/content-type bytes were not tampered with (§5.2).
	aad := record_aad(.application_data, legacy_record_version, inner_plaintext.len + s.aead.overhead())
	nonce := s.compute_nonce(s.seq_num)
	ciphertext := s.aead.encrypt(inner_plaintext, nonce, aad)!
	s.seq_num++

	return Record{
		content_type:   .application_data
		legacy_version: legacy_record_version
		payload:        ciphertext
	}
}

// DecryptedRecord holds the extracted inner content type and plaintext.
struct DecryptedRecord {
mut:
	content_type ContentType // true inner type, recovered from the trailing byte of plaintext
	plaintext    []u8        // decrypted payload with padding and the inner type byte stripped
}

// decrypt_record decrypts an encrypted Record, verifies the AEAD tag, and
// extracts the true inner ContentType and plaintext (RFC 8446 §5.2).
fn (mut s RecordProtector) decrypt_record(rec Record) !DecryptedRecord {
	// Fail closed on an uninitialized/partial cipher state (no handshake keys
	// installed yet): the nonce computation below would index a zero-length IV
	// and panic, and the AEAD interface would be nil. An encrypted record
	// arriving before the keys exist is a protocol violation, never a panic.
	if s.iv.len != aead_nonce_len {
		return error('record: record protector not initialized (IV length ${s.iv.len}, expected ${aead_nonce_len})')
	}
	if s.seq_num >= record_seq_limit {
		// Receive-side twin of the §5.5 bound: a peer that sent more than the
		// limit without rekeying is non-compliant, and processing further
		// records under a worn key risks an AEAD-fitness break. Fatal per §5.5
		// (record_overflow), matching the sender-side backstop above.
		return error('record: sequence limit reached; rekey required (§5.5)')
	}
	if rec.content_type != .application_data {
		return error('record: encrypted record must have outer content type application_data (23), got ${rec.content_type}')
	}

	aad := record_aad(rec.content_type, rec.legacy_version, rec.payload.len)
	nonce := s.compute_nonce(s.seq_num)
	inner_plaintext := s.aead.decrypt(rec.payload, nonce, aad) or {
		return error('record: AEAD decryption failed: ${err.msg()}')
	}

	// Increment only on success: a failed tag check means the record is
	// untrusted, and a bad_record_mac is fatal anyway (RFC 8446 §6), so advancing
	// would desync the nonce base for any further use.
	s.seq_num++

	// TLSInnerPlaintext is content || content_type || zero-padding (§5.2), so the
	// type byte is not the last byte: it sits just before a run of 0x00 padding
	// the sender may add to hide plaintext lengths. Receivers must discard it;
	// an all-zero result carries no type byte and is a fatal decode error.
	// The empty case (a tag-only record) must be rejected before `len - 1`, so
	// malformed input stays an error and never an integer-underflow panic.
	if inner_plaintext.len == 0 {
		return error('record: malformed inner plaintext (no content type byte)')
	}
	mut end := inner_plaintext.len - 1
	for end >= 0 && inner_plaintext[end] == 0 {
		end--
	}
	if end < 0 {
		return error('record: malformed inner plaintext (only zero padding found)')
	}

	inner_type := content_type_from_u8(inner_plaintext[end])!
	if inner_type == .invalid {
		return error('record: invalid inner content type (unexpected_message)')
	}
	plaintext := inner_plaintext[..end].clone()
	if plaintext.len > max_plaintext_record_len {
		return error('record: decrypted plaintext length ${plaintext.len} exceeds maximum allowed ${max_plaintext_record_len} (record_overflow)')
	}

	return DecryptedRecord{
		content_type: inner_type
		plaintext:    plaintext
	}
}

// wipe_record_protector zeroes a record protector's IV in place and resets the
// sequence number, so a discarded or failed connection leaves no nonce base
// from which record nonces under the dead key could be reconstructed. It is
// called from the handshake-failure and close paths alongside the core's
// secret wipes; the AEAD handle is dropped with the struct, matching the
// best-effort bar of handshake.wipe_traffic_keys (vlib cipher objects expose
// no in-place key wipe).
fn wipe_record_protector(mut s RecordProtector) {
	for i in 0 .. s.iv.len {
		s.iv[i] = 0
	}
	s.iv = []u8{}
	s.seq_num = 0
}
