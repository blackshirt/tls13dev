// Copyright (c) 2026 blackshirt.
//
// Binding tests for verify_certificate_verify's scheme dispatch: every signature
// scheme must pair with the leaf's key type and exact ECDSA curve
// (RFC 8446 §4.2.3).
module handshake

import crypto.ecdsa

// test_verify_certificate_verify_requires_matching_key_type checks that each
// scheme is refused against a leaf of the wrong key type (RFC 8446 §4.2.3).
fn test_verify_certificate_verify_requires_matching_key_type() ! {
	content := 'x'.bytes()
	sig := [u8(0x01)]

	// RSA leaf offered an ECDSA scheme: refused before touching the key.
	rsa_leaf := LeafKey{
		public_key_algo: .rsa
		ecdsa_curve:     ecdsa.Nid.prime256v1
	}
	verify_certificate_verify(rsa_leaf, ParsedCertificateVerify{ algorithm: .ecdsa_secp256r1_sha256, signature: sig }, content) or {
		assert err.msg().contains('requires ECDSA certificate')
		return
	}
	assert false

	// ECDSA leaf offered an RSA-PSS scheme.
	ecdsa_leaf := LeafKey{
		public_key_algo: .ecdsa
		ecdsa_curve:     ecdsa.Nid.prime256v1
	}
	verify_certificate_verify(ecdsa_leaf, ParsedCertificateVerify{ algorithm: .rsa_pss_rsae_sha256, signature: sig }, content) or {
		assert err.msg().contains('requires RSA certificate')
		return
	}
	assert false

	// ECDSA leaf offered Ed25519.
	verify_certificate_verify(ecdsa_leaf, ParsedCertificateVerify{ algorithm: .ed25519, signature: sig }, content) or {
		assert err.msg().contains('requires Ed25519 certificate')
		return
	}
	assert false
}

// test_verify_certificate_verify_binds_ecdsa_curve checks that each ECDSA
// scheme requires its exact curve on the leaf (RFC 8446 §4.2.3).
fn test_verify_certificate_verify_binds_ecdsa_curve() ! {
	content := 'x'.bytes()
	sig := [u8(0x30), 0x03, 0x02, 0x01, 0x01]

	p256_leaf := LeafKey{
		public_key_algo: .ecdsa
		ecdsa_curve:     ecdsa.Nid.prime256v1
	}
	verify_certificate_verify(p256_leaf, ParsedCertificateVerify{ algorithm: .ecdsa_secp384r1_sha384, signature: sig }, content) or {
		assert err.msg().contains('curve mismatch')
		return
	}
	assert false

	p384_leaf := LeafKey{
		public_key_algo: .ecdsa
		ecdsa_curve:     ecdsa.Nid.secp384r1
	}
	verify_certificate_verify(p384_leaf, ParsedCertificateVerify{ algorithm: .ecdsa_secp256r1_sha256, signature: sig }, content) or {
		assert err.msg().contains('curve mismatch')
		return
	}
	assert false
}

// test_verify_certificate_verify_rejects_missing_or_malformed_keys checks that
// a missing SPKI key and a short Ed25519 raw are named errors, not panics.
fn test_verify_certificate_verify_rejects_missing_or_malformed_keys() ! {
	content := 'x'.bytes()
	sig := [u8(0x01)]

	// The SPKI parse produced no RsaPublicKey: name it, never deref nil.
	rsa_leaf := LeafKey{
		public_key_algo: .rsa
	}
	verify_certificate_verify(rsa_leaf, ParsedCertificateVerify{ algorithm: .rsa_pss_rsae_sha256, signature: sig }, content) or {
		assert err.msg().contains('missing RSA public key')
		return
	}
	assert false

	// Ed25519 keys are exactly 32 bytes; a short raw must be refused.
	short_leaf := LeafKey{
		public_key_algo: .ed25519
		public_key_raw:  []u8{len: 31, init: 0xaa}
	}
	verify_certificate_verify(short_leaf, ParsedCertificateVerify{ algorithm: .ed25519, signature: sig }, content) or {
		assert err.msg().contains('invalid Ed25519 public key length')
		return
	}
	assert false
}

// test_verify_certificate_verify_rejects_rsa_pkcs1 checks that PKCS#1 is
// refused for CertificateVerify, where TLS 1.3 RSA is PSS-only (RFC 8446 §4.4.3).
fn test_verify_certificate_verify_rejects_rsa_pkcs1() ! {
	content := 'x'.bytes()
	rsa_leaf := LeafKey{
		public_key_algo: .rsa
	}
	verify_certificate_verify(rsa_leaf, ParsedCertificateVerify{
		algorithm: .rsa_pkcs1_sha256
		signature: [u8(0x01)]
	}, content) or {
		assert err.msg().contains('not permitted for TLS 1.3 CertificateVerify')
		return
	}
	assert false
}

// test_verify_certificate_verify_ecdsa_uses_scheme_hash checks that ECDSA
// CertificateVerify uses the scheme's hash (not the curve's default
// with_recommended_hash). The ecdsa_hasher_for mapper returns hashers whose
// output size matches the hash named by each ECDSA scheme (RFC 8446 §4.2.3).
fn test_verify_certificate_verify_ecdsa_uses_scheme_hash() ! {
	// ecdsa_secp256r1_sha256 → SHA-256, 32-byte digest.
	mut h256 := ecdsa_hasher_for('sha256')!
	assert h256.size() == 32

	// ecdsa_secp384r1_sha384 → SHA-384, 48-byte digest.
	mut h384 := ecdsa_hasher_for('sha384')!
	assert h384.size() == 48
}

// test_hash_for_digest_rejects_unknown_digest checks that unknown digest types
// are refused instead of silently falling through to SHA-512.
fn test_hash_for_digest_rejects_unknown_digest() ! {
	hash_for_digest('sha1', []u8{}) or {
		assert err.msg().contains('unknown digest type')
		return
	}
	assert false, 'unknown digest type must be rejected'
}

fn test_ecdsa_hasher_for_rejects_unknown_digest() ! {
	ecdsa_hasher_for('sha1') or {
		assert err.msg().contains('unknown digest type')
		return
	}
	assert false, 'unknown digest type must be rejected'
}
