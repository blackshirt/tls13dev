module record

import crypto.cipher

// aead_nonce_len is the fixed 12-byte AEAD nonce size for every TLS 1.3 cipher
// suite (AES-GCM and ChaCha20-Poly1305, RFC 8446 §5.3 / RFC 8439 §2.1).
pub const aead_nonce_len = 12

// nonce_seq_offset: the 64-bit sequence number occupies the trailing 8 bytes of
// the nonce; the leading bytes keep the IV untouched when XORing (RFC 8446 §5.3
// left-pads the sequence number with 4 zero bytes, which XOR to nothing).
const nonce_seq_offset = aead_nonce_len - 8

// RecordCipherState manages encryption, decryption, sequence numbers, and nonces
// for one direction of a TLS 1.3 connection (RFC 8446 §5.2 & §5.3).
// TLS 1.3 uses a single unique nonce per record derived from a static per-direction
// value plus the sequence number, so the state only needs the AEAD, the nonce base
// ("write IV"), and a counter — no per-record IV is ever transmitted.
pub struct RecordCipherState {
pub mut:
	aead    cipher.AEAD // AEAD primitive for this direction (AES-GCM or ChaCha20-Poly1305)
	iv      []u8        // 12-byte nonce base from the key schedule (HKDF-Expand-Label "iv"), NOT a per-record IV
	seq_num u64         // record counter for this direction; implicitly part of every nonce
}

// new_record_cipher_state initializes a per-direction cipher state at seq 0
// (the first record of each key always uses sequence number 0). The IV must be
// the suite's full nonce base — see aead_nonce_len above.
pub fn new_record_cipher_state(aead cipher.AEAD, iv []u8) !RecordCipherState {
	if iv.len != aead_nonce_len {
		return error('record: IV length must be ${aead_nonce_len} bytes, got ${iv.len}')
	}
	return RecordCipherState{
		aead:    aead
		iv:      iv.clone()
		seq_num: 0
	}
}

// compute_nonce derives the 12-byte AEAD nonce per RFC 8446 §5.3:
//
//	nonce = XOR(seq_num padded to 12 bytes, write_iv)
//
// Why XOR with a sequence number instead of a transmitted random IV:
// - AES-GCM/ChaCha20-Poly1305 fail catastrophically on nonce reuse under the same
//   key; since seq_num strictly increments per record, the derived nonce is
//   guaranteed unique without ever sending it on the wire.
// - The seq number occupies only the low 64 bits, so the loop XORs into nonce[4..12]
//   and leaves the first 4 bytes of the IV untouched (the leading zero-padding of
//   the 12-byte big-endian sequence number XORs to nothing).
fn (s &RecordCipherState) compute_nonce(seq u64) []u8 {
	mut nonce := s.iv.clone()
	// Walk the 64-bit sequence number big-endian: byte 0 is its most-significant
	// byte, landing at nonce[4] where the zero-padded prefix ends.
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

// encrypt_record encrypts a plaintext payload and produces an encrypted Record (RFC 8446 §5.2).
// The outer ContentType on the wire is always application_data (23): TLS 1.3
// deliberately hides the real message type so passive observers cannot fingerprint
// handshake or alert traffic from record headers.
pub fn (mut s RecordCipherState) encrypt_record(inner_type ContentType, plaintext []u8) !Record {
	if s.seq_num == max_u64 {
		// RFC 8446 §5.5: a direction must rekey before 2^64-1 records are sent;
		// continuing past this point would reuse a nonce under the same key.
		return error('record: sequence number overflow; connection must close')
	}
	if plaintext.len > max_plaintext_record_len {
		return error('record: plaintext length ${plaintext.len} exceeds maximum allowed ${max_plaintext_record_len}')
	}

	// 1. Construct TLSInnerPlaintext: plaintext || inner_content_type
	mut inner_plaintext := []u8{cap: plaintext.len + 1}
	inner_plaintext << plaintext
	inner_plaintext << u8(inner_type)

	// 2. Prepare Additional Authenticated Data (AAD): 5-byte outer record header.
	// The header is not encrypted, so it is bound into the AEAD tag to prove the
	// outer length/content-type bytes were not tampered with in transit (RFC 8446 §5.2).
	// The length here is the ciphertext size: inner plaintext plus the AEAD tag overhead.
	aad := record_aad(.application_data, legacy_record_version, inner_plaintext.len + s.aead.overhead())

	// 3. Compute Nonce
	nonce := s.compute_nonce(s.seq_num)

	// 4. Encrypt with AEAD
	ciphertext := s.aead.encrypt(inner_plaintext, nonce, aad)!

	// 5. Increment sequence number
	s.seq_num++

	return Record{
		content_type:   .application_data
		legacy_version: legacy_record_version
		payload:        ciphertext
	}
}

// DecryptedRecord holds the extracted inner content type and plaintext.
pub struct DecryptedRecord {
pub:
	content_type ContentType // true inner type, recovered from the trailing byte of plaintext
	plaintext    []u8        // decrypted payload with the padding and inner type byte stripped
}

// decrypt_record decrypts an encrypted Record, verifies the AEAD tag,
// and extracts the true inner ContentType and plaintext (RFC 8446 §5.2).
pub fn (mut s RecordCipherState) decrypt_record(rec Record) !DecryptedRecord {
	if s.seq_num == max_u64 {
		// Same nonce-uniqueness bound as encrypt_record (RFC 8446 §5.5): decrypting
		// past 2^64-1 records would replay a nonce under this read key.
		return error('record: sequence number overflow; connection must close')
	}
	if rec.content_type != .application_data {
		return error('record: encrypted record must have outer content type application_data (23), got ${rec.content_type}')
	}

	// 1. Prepare AAD from record header
	aad := record_aad(rec.content_type, rec.legacy_version, rec.payload.len)

	// 2. Compute Nonce
	nonce := s.compute_nonce(s.seq_num)

	// 3. Decrypt with AEAD
	inner_plaintext := s.aead.decrypt(rec.payload, nonce, aad) or {
		return error('record: AEAD decryption failed: ${err.msg()}')
	}

	// 4. Increment sequence number on successful decryption only: a failed tag check
	// means the nonce/record is untrusted, and per RFC 8446 §6 a bad_record_mac is
	// fatal anyway — advancing would desync the nonce base for any further use.
	s.seq_num++

	// 5. Strip trailing padding zeros to locate the inner ContentType.
	// TLSInnerPlaintext is content || content_type || zero-padding (RFC 8446 §5.2),
	// so the type byte is NOT the last byte — it sits just before a run of 0x00
	// padding that the sender may add to hide plaintext lengths. Receivers must
	// tolerate and discard it; an all-zero result carries no type byte and is a
	// fatal decode error.
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
