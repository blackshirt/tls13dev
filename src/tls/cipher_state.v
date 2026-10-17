// Copyright (c) 2026 blackshirt.
//
// cipher_state.v carries one direction's AEAD key, IV, and sequence number across the
// handshake→application key transition, building each record nonce per §5.3 and
// enforcing the record limit that forces a KeyUpdate.
module tls

import crypto.cipher

// aead_nonce_len is the fixed 12-byte AEAD nonce size for every TLS 1.3 cipher
// suite (AES-GCM and ChaCha20-Poly1305, RFC 8446 §5.3 / RFC 8439 §2.8).
const aead_nonce_len = 12

// nonce_seq_offset is where the 64-bit sequence number lands in the nonce: the
// trailing 8 bytes, leaving the leading bytes of the IV untouched when XORed
// (RFC 8446 §5.3 left-pads the sequence number with 4 zero bytes).
const nonce_seq_offset = aead_nonce_len - 8

// RecordCipherState manages encryption, decryption, sequence numbers, and nonces
// for one direction of a TLS 1.3 connection (RFC 8446 §5.2 & §5.3).
// Each record's nonce is derived from a static per-direction value plus the
// sequence number, so no per-record IV is ever transmitted.
struct RecordCipherState {
mut:
	aead    cipher.AEAD // AEAD primitive for this direction (AES-GCM or ChaCha20-Poly1305)
	iv      []u8        // 12-byte nonce base from the key schedule ("iv" label), not a per-record IV
	seq_num u64         // record counter for this direction; implicitly part of every nonce
}

// new_record_cipher_state initializes a per-direction cipher state at seq 0
// (the first record under each key uses sequence number 0). The IV must be the
// suite's full nonce base — aead_nonce_len bytes.
fn new_record_cipher_state(aead cipher.AEAD, iv []u8) !RecordCipherState {
	if iv.len != aead_nonce_len {
		return error('record: IV length must be ${aead_nonce_len} bytes, got ${iv.len}')
	}
	return RecordCipherState{
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
fn (s &RecordCipherState) compute_nonce(seq u64) []u8 {
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
fn (mut s RecordCipherState) encrypt_record(inner_type ContentType, plaintext []u8) !Record {
	if s.seq_num == max_u64 {
		// RFC 8446 §5.5: a direction must rekey before 2^64-1 records; continuing
		// would reuse a nonce under the same key.
		return error('record: sequence number overflow; connection must close')
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
fn (mut s RecordCipherState) decrypt_record(rec Record) !DecryptedRecord {
	if s.seq_num == max_u64 {
		// Same nonce-uniqueness bound as encrypt_record (RFC 8446 §5.5).
		return error('record: sequence number overflow; connection must close')
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
