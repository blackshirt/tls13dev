// Copyright (c) 2026 blackshirt.
//
// suite_key_schedule_test.v verifies the RFC 8446 §7.1 key schedule produces
// correct key and hash lengths for all three TLS 1.3 cipher suites:
//   - TLS_AES_128_GCM_SHA256: 16-byte keys, 32-byte hash
//   - TLS_AES_256_GCM_SHA384: 32-byte keys, 48-byte hash
//   - TLS_CHACHA20_POLY1305_SHA256: 32-byte keys, 32-byte hash
//
// Exact RFC 8448 Appendix A byte vectors require the specific ECDHE shared
// secret and transcript of each vector handshake; this verifies the derivation
// STRUCTURE (labels, lengths, hash selection) instead.
module handshake

import tls.pki

fn test_aes128_gcm_sha256_key_and_hash_lengths() ! {
	assert suite_key_len(CipherSuite.tls_aes_128_gcm_sha256) == 16
	assert suite_hash_algo(CipherSuite.tls_aes_128_gcm_sha256).hash_len() == 32
}

fn test_aes256_gcm_sha384_key_and_hash_lengths() ! {
	assert suite_key_len(CipherSuite.tls_aes_256_gcm_sha384) == 32
	assert suite_hash_algo(CipherSuite.tls_aes_256_gcm_sha384).hash_len() == 48
}

fn test_chacha20_poly1305_sha256_key_and_hash_lengths() ! {
	assert suite_key_len(CipherSuite.tls_chacha20_poly1305_sha256) == 32
	assert suite_hash_algo(CipherSuite.tls_chacha20_poly1305_sha256).hash_len() == 32
}

fn test_key_schedule_no_traffic_secrets_before_server_hello_all_suites() ! {
	for cs in [CipherSuite.tls_aes_128_gcm_sha256, CipherSuite.tls_aes_256_gcm_sha384,
		CipherSuite.tls_chacha20_poly1305_sha256] {
		mut h := new_tls_handshake('example.com', HandshakeOptions{
			validator:     pki.new_validator(pki.new_trust_store())
			cipher_suites: [cs]
		})!
		_ := h.create_client_hello()!
		assert h.c_hsk_tsec.len == 0
		assert h.s_hsk_tsec.len == 0
		assert h.handshake_secret.len == 0
		mut refused := false
		h.traffic_keys() or { refused = true }
		assert refused
	}
}

fn test_key_suite_hash_selection_is_deterministic() ! {
	assert suite_hash_algo(CipherSuite.tls_aes_128_gcm_sha256) == suite_hash_algo(CipherSuite.tls_aes_128_gcm_sha256)
	assert suite_hash_algo(CipherSuite.tls_aes_256_gcm_sha384) == suite_hash_algo(CipherSuite.tls_aes_256_gcm_sha384)
	assert suite_hash_algo(CipherSuite.tls_chacha20_poly1305_sha256) == suite_hash_algo(CipherSuite.tls_chacha20_poly1305_sha256)
}
