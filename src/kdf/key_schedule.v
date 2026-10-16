// module kdf derives every handshake and application key through the RFC 8446
// §7.1 schedule: key_schedule.v runs the HKDF-Extract/Expand ladder over the
// (EC)DHE and traffic-secret stages, transcript.v maintains the running
// message hash the schedule and CertificateVerify both consume.
module kdf

import crypto.hmac
import crypto.sha256
import crypto.sha512

// HashAlgorithm specifies the hash function used by the negotiated cipher suite.
pub enum HashAlgorithm {
	sha256
	sha384
}

// hash_len returns the digest length in bytes.
pub fn (h HashAlgorithm) hash_len() int {
	return match h {
		.sha256 { 32 }
		.sha384 { 48 }
	}
}

// compute_hash calculates the hash of data.
pub fn (h HashAlgorithm) compute_hash(data []u8) []u8 {
	return match h {
		.sha256 { sha256.sum256(data) }
		.sha384 { sha512.sum384(data) }
	}
}

// HMAC block sizes in bytes (RFC 2104): the HMAC key is padded/compressed to
// one block, so these must match the underlying hash's block size exactly.
const sha256_block_size = 64
const sha384_block_size = 128

// compute_hmac calculates the HMAC of data using key.
pub fn (h HashAlgorithm) compute_hmac(key []u8, data []u8) []u8 {
	return match h {
		.sha256 { hmac.new(key, data, sha256.sum256, sha256_block_size) }
		.sha384 { hmac.new(key, data, sha512.sum384, sha384_block_size) }
	}
}

// hkdf_extract implements HKDF-Extract(salt, ikm) (RFC 5869 §2.2).
// If salt is empty, a string of Hash.length zeros is used — the RFC 5869 default,
// which TLS 1.3 relies on for the two "no real input" stages of the schedule:
// Early Secret (salt=0, IKM=0 without PSK) and Master Secret (salt=derived
// handshake secret, IKM=0 because no additional keying material exists there).
pub fn hkdf_extract(hash HashAlgorithm, salt []u8, ikm []u8) []u8 {
	effective_salt := if salt.len == 0 { []u8{len: hash.hash_len()} } else { salt }
	return hash.compute_hmac(effective_salt, ikm)
}

// hkdf_expand implements HKDF-Expand(prk, info, length) (RFC 5869 §2.3).
// Output is produced as T(1) || T(2) || … where T(i) = HMAC(PRK, T(i-1) || info || i);
// the 1-byte iteration counter is why the request limit is 255 * HashLen —
// asking for more would silently wrap the counter and repeat blocks.
pub fn hkdf_expand(hash HashAlgorithm, prk []u8, info []u8, length int) ![]u8 {
	hash_len := hash.hash_len()
	if length > 255 * hash_len {
		return error('hkdf_expand: requested length ${length} exceeds maximum (${255 * hash_len})')
	}
	mut out := []u8{cap: length}
	mut prev := []u8{}
	mut counter := u8(1)

	for out.len < length {
		mut step_input := []u8{cap: prev.len + info.len + 1}
		step_input << prev
		step_input << info
		step_input << counter

		prev = hash.compute_hmac(prk, step_input)
		needed := length - out.len
		to_copy := if needed < prev.len { needed } else { prev.len }
		out << prev[..to_copy]
		counter++
	}
	return out
}

// hkdf_expand_label implements RFC 8446 §7.1:
//
//	HKDF-Expand-Label(Secret, Label, Context, Length) =
//	    HKDF-Expand(Secret, HkdfLabel, Length)
//
//	struct {
//	    uint16 length = Length;
//	    opaque label<7..255> = "tls13 " + Label;
//	    opaque context<0..255> = Context;
//	} HkdfLabel;
//
// The mandatory "tls13 " prefix domain-separates these derivations from HKDF use
// by other protocols (and from older TLS versions), so an output labeled e.g.
// "key" can never be confused across stacks even with identical inputs.
pub fn hkdf_expand_label(hash HashAlgorithm, secret []u8, label string, context []u8, length int) ![]u8 {
	full_label := 'tls13 ' + label
	if full_label.len > 255 {
		return error('hkdf_expand_label: label too long')
	}
	if context.len > 255 {
		return error('hkdf_expand_label: context too long')
	}

	mut hkdf_label := []u8{cap: 2 + 1 + full_label.len + 1 + context.len}
	// 2-byte big-endian length
	hkdf_label << u8((length >> 8) & 0xff)
	hkdf_label << u8(length & 0xff)
	// 1-byte label length + label string bytes
	hkdf_label << u8(full_label.len)
	hkdf_label << full_label.bytes()
	// 1-byte context length + context bytes
	hkdf_label << u8(context.len)
	hkdf_label << context

	return hkdf_expand(hash, secret, hkdf_label, length)!
}

// derive_secret implements RFC 8446 §7.1:
//
//	Derive-Secret(Secret, Label, Messages) =
//	    HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
pub fn derive_secret(hash HashAlgorithm, secret []u8, label string, transcript_hash []u8) ![]u8 {
	return hkdf_expand_label(hash, secret, label, transcript_hash, hash.hash_len())!
}

// empty_transcript_hash returns the hash of an empty input (RFC 8446 §7.1 "derived" steps).
pub fn empty_transcript_hash(hash HashAlgorithm) []u8 {
	return hash.compute_hash([]u8{})
}

// TrafficKeys holds derived traffic write/read key and IV for AEAD record encryption.
pub struct TrafficKeys {
pub:
	key []u8 // AEAD key, suite-length bytes (16 for AES-128-GCM, 32 for the others)
	iv  []u8 // 12-byte nonce base; per-record nonces XOR in the sequence number
}

// derive_traffic_keys expands a traffic secret into an AEAD key and IV (RFC 8446 §7.1,
// "key"/"iv" labels). The IV output is the static nonce base consumed by
// record.RecordCipherState — per-record nonces are then formed by XORing the
// sequence number (§5.3), so no IV travels on the wire. Key and IV come from the
// same secret but different labels, which keeps them independent by design.
pub fn derive_traffic_keys(hash HashAlgorithm, secret []u8, key_len int, iv_len int) !TrafficKeys {
	key := hkdf_expand_label(hash, secret, 'key', []u8{}, key_len)!
	iv := hkdf_expand_label(hash, secret, 'iv', []u8{}, iv_len)!
	return TrafficKeys{
		key: key
		iv:  iv
	}
}

// compute_finished_verify_data derives finished_key and computes HMAC over transcript_hash (RFC 8446 §4.4.4).
// finished_key = Expand-Label(base_secret, "finished", "", Hash.length) first:
// the traffic secret is never used directly as an HMAC key, keeping the MAC key
// domain-separated from the record-layer keys derived from the same secret.
pub fn compute_finished_verify_data(hash HashAlgorithm, base_key []u8, transcript_hash []u8) ![]u8 {
	finished_key := hkdf_expand_label(hash, base_key, 'finished', []u8{}, hash.hash_len())!
	return hash.compute_hmac(finished_key, transcript_hash)
}
