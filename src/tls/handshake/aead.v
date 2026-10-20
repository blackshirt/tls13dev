// Copyright (c) 2026 blackshirt.
//
// aead.v adapts the AEAD cipher suites (AES-128/256-GCM and ChaCha20-Poly1305)
// to the single seal/open interface both protection styles need — the TLS
// record layer's cipher states and a QUIC engine's packet keys derive from the
// same constructors, which is why suite→AEAD is key-schedule knowledge and
// lives with the handshake core. Nonce construction and record limits live in
// the record layer (tls cipher_state.v), not here.
module handshake

import crypto.aes
import crypto.cipher
import x.crypto.chacha20poly1305
import x.crypto.chacha20

// aead_nonce_len is the fixed 12-byte AEAD nonce size for every TLS 1.3 cipher
// suite (AES-GCM and ChaCha20-Poly1305, RFC 8446 §5.3 / RFC 8439 §2.8). It
// lives here because the key schedule derives the nonce base to this length;
// the record layer consumes it through the tls.handshake import.
pub const aead_nonce_len = 12

// suite_hash_algo returns the HKDF hash for a cipher suite.
// Each TLS 1.3 suite names its own hash and the key schedule must use exactly
// that one (RFC 8446 §7.1). The match is exhaustive so a new suite forces a
// decision here rather than silently inheriting SHA-256. Pub for adapters that
// expand level secrets themselves (a QUIC engine needs the suite's hash to
// label-expand the RFC 9001 §5.1 material).
pub fn suite_hash_algo(suite CipherSuite) HashAlgorithm {
	return match suite {
		.tls_aes_128_gcm_sha256 { .sha256 }
		.tls_aes_256_gcm_sha384 { .sha384 }
		.tls_chacha20_poly1305_sha256 { .sha256 }
	}
}

// suite_key_len returns the AEAD key length for a cipher suite, fixed by the
// cipher itself (RFC 8446 §7.1). Pub for adapters sizing their own protection
// (QUIC packet keys and header protection expand to exactly this length).
pub fn suite_key_len(suite CipherSuite) int {
	return match suite {
		.tls_aes_128_gcm_sha256 { 16 }
		.tls_aes_256_gcm_sha384 { 32 }
		.tls_chacha20_poly1305_sha256 { 32 }
	}
}

// new_aead_for_suite constructs the AEAD cipher for the negotiated suite.
// ChaCha20-Poly1305 uses its standard 12-byte nonce, matching TLS 1.3's nonce
// construction (RFC 8446 §5.3 / RFC 8439 §2.8). Key length is not re-checked:
// both constructors reject wrong-sized keys, and every key reaching this point
// was expanded to suite_key_len bytes by the key schedule. Exported because
// suite→AEAD is the one piece of protection knowledge both adapters instantiate
// from record_traffic_keys(): the TCP Conn builds its record ciphers this way, and a
// QUIC engine's packet protection uses the same constructors.
pub fn new_aead_for_suite(suite CipherSuite, key []u8) !cipher.AEAD {
	return match suite {
		.tls_aes_128_gcm_sha256, .tls_aes_256_gcm_sha384 {
			aes.new_aes_gcm(key)!
		}
		.tls_chacha20_poly1305_sha256 {
			*chacha20poly1305.new(key, chacha20poly1305.nonce_size, chacha20.Options{})!
		}
	}
}
