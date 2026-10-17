// Copyright (c) 2026 blackshirt.
//
// Binding tests for verify_certificate_verify's scheme dispatch: every signature
// scheme must pair with the leaf's key type, and each ECDSA scheme with its exact
// curve (RFC 8446 §4.2.3). These policy checks run before any key material is
// consumed, so keyless dummy leaves pin every rejection message — they are the
// guards an attacker presenting a mismatched CertificateVerify hits first.
module tls

import crypto.ecdsa

fn test_verify_certificate_verify_requires_matching_key_type() ! {
	content := 'x'.bytes()
	sig := [u8(0x01)]

	// RSA leaf offered an ECDSA scheme: refused before touching the key.
	rsa_leaf := Certificate{
		public_key_algo: .rsa
		ecdsa_curve:     ecdsa.Nid.prime256v1
	}
	verify_certificate_verify(rsa_leaf, ParsedCertificateVerify{ algorithm: .ecdsa_secp256r1_sha256, signature: sig }, content) or {
		assert err.msg().contains('requires ECDSA certificate')
		return
	}
	assert false

	// ECDSA leaf offered an RSA-PSS scheme.
	ecdsa_leaf := Certificate{
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

fn test_verify_certificate_verify_binds_ecdsa_curve() ! {
	// RFC 8446 §4.2.3: ecdsa_secp256r1_sha256 and ecdsa_secp384r1_sha384 each
	// require their matching curve on the leaf; a cross-curve pairing would let
	// a signature made under one curve authenticate a key on another.
	content := 'x'.bytes()
	sig := [u8(0x30), 0x03, 0x02, 0x01, 0x01]

	p256_leaf := Certificate{
		public_key_algo: .ecdsa
		ecdsa_curve:     ecdsa.Nid.prime256v1
	}
	verify_certificate_verify(p256_leaf, ParsedCertificateVerify{ algorithm: .ecdsa_secp384r1_sha384, signature: sig }, content) or {
		assert err.msg().contains('curve mismatch')
		return
	}
	assert false

	p384_leaf := Certificate{
		public_key_algo: .ecdsa
		ecdsa_curve:     ecdsa.Nid.secp384r1
	}
	verify_certificate_verify(p384_leaf, ParsedCertificateVerify{ algorithm: .ecdsa_secp256r1_sha256, signature: sig }, content) or {
		assert err.msg().contains('curve mismatch')
		return
	}
	assert false
}

fn test_verify_certificate_verify_rejects_missing_or_malformed_keys() ! {
	content := 'x'.bytes()
	sig := [u8(0x01)]

	// .rsa leaf whose SPKI parse never produced an RsaPublicKey: the optional
	// unwrap must name the missing key, not panic on a nil dereference.
	rsa_leaf := Certificate{
		public_key_algo: .rsa
	}
	verify_certificate_verify(rsa_leaf, ParsedCertificateVerify{ algorithm: .rsa_pss_rsae_sha256, signature: sig }, content) or {
		assert err.msg().contains('missing RSA public key')
		return
	}
	assert false

	// Ed25519 keys are exactly 32 bytes; a short raw must be refused before the
	// fixed-size ed25519.PublicKey cast.
	short_leaf := Certificate{
		public_key_algo: .ed25519
		public_key_raw:  []u8{len: 31, init: 0xaa}
	}
	verify_certificate_verify(short_leaf, ParsedCertificateVerify{ algorithm: .ed25519, signature: sig }, content) or {
		assert err.msg().contains('invalid Ed25519 public key length')
		return
	}
	assert false
}
