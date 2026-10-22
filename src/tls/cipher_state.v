// Copyright (c) 2026 blackshirt.
//
// cipher_state.v carries one direction's AEAD key, IV, and sequence number across
// the handshake→application key transition, building each record nonce per §5.3
// and enforcing the record limit that forces a KeyUpdate.
module tls

import crypto.cipher
import tls.handshake

// aead_nonce_len is the fixed 12-byte AEAD nonce size for every TLS 1.3 cipher
// suite (RFC 8446 §5.3 / RFC 8439 §2.8); the canonical value lives in tls.handshake.
const aead_nonce_len = handshake.aead_nonce_len

// nonce_seq_offset is where the 64-bit sequence number lands in the nonce: the
// trailing 8 bytes, leaving the leading IV bytes untouched (RFC 8446 §5.3).
const nonce_seq_offset = aead_nonce_len - 8

// record_seq_limit bounds how many records one key generation may carry in a
// direction; RFC 8446 §5.5 requires a KeyUpdate before the 2^24.5 AEAD bound.
const record_seq_limit = u64(1 << 24)

// RecordProtector manages encryption, decryption, sequence numbers, and nonces
// for one direction of a TLS 1.3 connection (RFC 8446 §5.2 & §5.3).
struct RecordProtector {
mut:
	aead    cipher.AEAD // AEAD primitive for this direction (AES-GCM or ChaCha20-Poly1305)
	iv      []u8        // 12-byte nonce base from the key schedule ("iv" label), not a per-record IV
	seq_num u64         // record counter for this direction; implicitly part of every nonce
}

// new_record_protector initializes a per-direction record protector at seq 0; the
// IV must be the suite's full nonce base (aead_nonce_len bytes).
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
// (RFC 8446 §5.3): a strictly increasing counter keeps it unique without being sent.
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

// encrypt_record encrypts a plaintext payload into an encrypted Record (§5.2);
// the outer ContentType is always application_data (23), hiding the real type.
fn (mut s RecordProtector) encrypt_record(inner_type ContentType, plaintext []u8) !Record {
	// Fail closed: an uninitialized cipher would index a zero-length IV or call a nil AEAD.
	if s.iv.len != aead_nonce_len {
		return error('record: record protector not initialized (IV length ${s.iv.len}, expected ${aead_nonce_len})')
	}
	if s.seq_num >= record_seq_limit {
		// RFC 8446 §5.5: rekeying is mandatory before this bound — refuse rather than reuse nonces.
		return error('record: sequence limit reached; rekey required (§5.5)')
	}
	if plaintext.len > max_plaintext_record_len {
		return error('record: plaintext length ${plaintext.len} exceeds maximum allowed ${max_plaintext_record_len}')
	}

	// TLSInnerPlaintext = plaintext || inner_content_type
	mut inner_plaintext := []u8{cap: plaintext.len + 1}
	inner_plaintext << plaintext
	inner_plaintext << u8(inner_type)

	// The 5-byte outer header is bound in as AAD to prove it was not tampered with (§5.2).
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
	// Fail closed: an uninitialized cipher would index a zero-length IV or call a nil AEAD.
	if s.iv.len != aead_nonce_len {
		return error('record: record protector not initialized (IV length ${s.iv.len}, expected ${aead_nonce_len})')
	}
	if s.seq_num >= record_seq_limit {
		// §5.5: a peer that exceeded the limit without rekeying is non-compliant (record_overflow).
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

	// Increment only on success: a bad tag is fatal anyway (RFC 8446 §6).
	s.seq_num++

	// The type byte sits just before any 0x00 padding; an all-zero result is a fatal decode error (§5.2).
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

// wipe_record_protector zeroes a record protector's IV in place and resets its
// sequence number, so a dead connection leaves no nonce base behind.
fn wipe_record_protector(mut s RecordProtector) {
	for i in 0 .. s.iv.len {
		s.iv[i] = 0
	}
	s.iv = []u8{}
	s.seq_num = 0
}
