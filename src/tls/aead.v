// Copyright (c) 2026 blackshirt.
//
// aead.v adapts the AEAD cipher suites (AES-128/256-GCM and ChaCha20-Poly1305) to
// the single seal/open interface the record layer needs, hiding the distinct crypto
// backends behind one type. Nonce construction and record limits live in
// cipher_state.v, not here.
module tls

import crypto.aes
import crypto.cipher
import x.crypto.chacha20poly1305
import x.crypto.chacha20

// suite_hash_algo returns the HKDF hash for a cipher suite.
// Each TLS 1.3 suite names its own hash and the key schedule must use exactly
// that one (RFC 8446 §7.1). The match is exhaustive so a new suite forces a
// decision here rather than silently inheriting SHA-256.
fn suite_hash_algo(suite CipherSuite) HashAlgorithm {
	return match suite {
		.tls_aes_128_gcm_sha256 { .sha256 }
		.tls_aes_256_gcm_sha384 { .sha384 }
		.tls_chacha20_poly1305_sha256 { .sha256 }
	}
}

// suite_key_len returns the AEAD key length for a cipher suite, fixed by the
// cipher itself (RFC 8446 §7.1).
fn suite_key_len(suite CipherSuite) int {
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
// was expanded to suite_key_len bytes by the key schedule.
fn new_aead_for_suite(suite CipherSuite, key []u8) !cipher.AEAD {
	return match suite {
		.tls_aes_128_gcm_sha256, .tls_aes_256_gcm_sha384 {
			aes.new_aes_gcm(key)!
		}
		.tls_chacha20_poly1305_sha256 {
			*chacha20poly1305.new(key, chacha20poly1305.nonce_size, chacha20.Options{})!
		}
	}
}
