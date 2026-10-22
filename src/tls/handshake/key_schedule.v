// Copyright (c) 2026 blackshirt.
//
// key_schedule.v runs the RFC 8446 §7.1 HKDF-Extract/Expand ladder over the
// (EC)DHE and traffic-secret stages, deriving every handshake and application key.
module handshake

import crypto.hmac
import crypto.sha256
import crypto.sha512

// HashAlgorithm specifies the hash function used by the negotiated cipher suite.
// Pub because hkdf_expand_label needs it, and a QUIC engine names the suite's hash to expand the RFC 9001 §5.1 labels.
pub enum HashAlgorithm {
	sha256
	sha384
}

// hash_len returns the digest length in bytes.
fn (h HashAlgorithm) hash_len() int {
	return match h {
		.sha256 { 32 }
		.sha384 { 48 }
	}
}

// compute_hash calculates the hash of data.
fn (h HashAlgorithm) compute_hash(data []u8) []u8 {
	return match h {
		.sha256 { sha256.sum256(data) }
		.sha384 { sha512.sum384(data) }
	}
}

// HMAC block sizes in bytes (RFC 2104), which must match the underlying hash.
const sha256_block_size = 64
const sha384_block_size = 128

// compute_hmac calculates the HMAC of data using key.
fn (h HashAlgorithm) compute_hmac(key []u8, data []u8) []u8 {
	return match h {
		.sha256 { hmac.new(key, data, sha256.sum256, sha256_block_size) }
		.sha384 { hmac.new(key, data, sha512.sum384, sha384_block_size) }
	}
}

// hkdf_extract implements HKDF-Extract(salt, ikm) (RFC 5869 §2.2).
// An empty salt means a string of Hash.length zeros, the RFC 5869 default.
fn hkdf_extract(hash HashAlgorithm, salt []u8, ikm []u8) []u8 {
	effective_salt := if salt.len == 0 { []u8{len: hash.hash_len()} } else { salt }
	return hash.compute_hmac(effective_salt, ikm)
}

// hkdf_expand implements HKDF-Expand(prk, info, length) (RFC 5869 §2.3), producing
// T(1) || T(2) || … where T(i) = HMAC(PRK, T(i-1) || info || i).
fn hkdf_expand(hash HashAlgorithm, prk []u8, info []u8, length int) ![]u8 {
	hash_len := hash.hash_len()
	// At most 255 blocks are reachable (one byte of counter); more would repeat a block (RFC 5869 §2.3).
	if length > 255 * hash_len {
		return error('handshake: HKDF-Expand requested length ${length} exceeds maximum (${255 * hash_len})')
	}
	mut out := []u8{cap: length}
	mut prev := []u8{} // T(0) is the empty string, so the first round has no prior block
	mut counter := u8(1) // blocks are indexed from 1; appended to every HMAC input

	for out.len < length {
		// T(i) = HMAC(PRK, T(i-1) || info || i): each round is unique to its index.
		mut step_input := []u8{cap: prev.len + info.len + 1}
		step_input << prev
		step_input << info
		step_input << counter

		prev = hash.compute_hmac(prk, step_input)
		// Append only the bytes still required, landing `out` on exactly `length`.
		needed := length - out.len
		to_copy := if needed < prev.len { needed } else { prev.len }
		out << prev[..to_copy]
		counter++
	}
	return out
}

// hkdf_expand_label implements HKDF-Expand-Label (RFC 8446 §7.1), prefixing the
// label with "tls13 "; pub for the RFC 9001 §5.1 quic key/iv/hp derivations.
pub fn hkdf_expand_label(hash HashAlgorithm, secret []u8, label string, context []u8, length int) ![]u8 {
	full_label := 'tls13 ' + label
	if full_label.len > 255 {
		return error('handshake: HKDF-Expand-Label label too long')
	}
	if context.len > 255 {
		return error('handshake: HKDF-Expand-Label context too long')
	}

	mut hkdf_label := []u8{cap: 2 + 1 + full_label.len + 1 + context.len}
	hkdf_label << u8((length >> 8) & 0xff)
	hkdf_label << u8(length & 0xff)
	hkdf_label << u8(full_label.len)
	hkdf_label << full_label.bytes()
	hkdf_label << u8(context.len)
	hkdf_label << context

	return hkdf_expand(hash, secret, hkdf_label, length)!
}

// derive_secret implements Derive-Secret (RFC 8446 §7.1):
// HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length).
fn derive_secret(hash HashAlgorithm, secret []u8, label string, transcript_hash []u8) ![]u8 {
	return hkdf_expand_label(hash, secret, label, transcript_hash, hash.hash_len())!
}

// empty_transcript_hash returns the hash of an empty input (RFC 8446 §7.1 "derived" steps).
fn empty_transcript_hash(hash HashAlgorithm) []u8 {
	return hash.compute_hash([]u8{})
}

// TrafficKeys holds the derived AEAD key and IV for one traffic direction at one
// encryption level; its fields are module-private and read-only from outside.
pub struct TrafficKeys {
mut:
	key []u8 // AEAD key, suite-length bytes (16 for AES-128-GCM, 32 for the others)
	iv  []u8 // 12-byte nonce base; per-record nonces XOR in the sequence number
}

// key returns the AEAD key bytes.
pub fn (t &TrafficKeys) key() []u8 {
	return t.key
}

// iv returns the 12-byte nonce base.
pub fn (t &TrafficKeys) iv() []u8 {
	return t.iv
}

// derive_traffic_keys expands a traffic secret into an AEAD key and IV (RFC 8446
// §7.1, "key"/"iv" labels); the IV is the static nonce base the adapter consumes.
fn derive_traffic_keys(hash HashAlgorithm, secret []u8, key_len int, iv_len int) !TrafficKeys {
	key := hkdf_expand_label(hash, secret, 'key', []u8{}, key_len)!
	iv := hkdf_expand_label(hash, secret, 'iv', []u8{}, iv_len)!
	return TrafficKeys{
		key: key
		iv:  iv
	}
}

// derive_finished_key computes the finished_key = HKDF-Expand-Label(BaseKey, "finished",
// "", Hash.length) MAC key RFC 8446 §4.4.4 binds to a Finished message.
fn derive_finished_key(hash HashAlgorithm, base_key []u8) ![]u8 {
	return hkdf_expand_label(hash, base_key, 'finished', []u8{}, hash.hash_len())!
}

// compute_finished_verify_data derives finished_key and computes HMAC over
// transcript_hash (RFC 8446 §4.4.4).
fn compute_finished_verify_data(hash HashAlgorithm, base_key []u8, transcript_hash []u8) ![]u8 {
	finished_key := derive_finished_key(hash, base_key)!
	return hash.compute_hmac(finished_key, transcript_hash)
}
