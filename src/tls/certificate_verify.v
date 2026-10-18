// Copyright (c) 2026 blackshirt.
//
// certificate_verify.v checks the server's CertificateVerify signature over the
// §4.4.3 transcript content. It is separate from state_machine.v because
// verification is a pure function of (leaf key, signature, content) that never
// advances protocol state.
module tls

import crypto.ed25519
import crypto.sha512

// hash_for_digest returns Hash(data) for the named digest ("sha256"/"sha384"/"sha512").
// RSA-PSS verifies over a pre-computed digest; the else arm handles sha512.
fn hash_for_digest(digest_type string, data []u8) []u8 {
	return match digest_type {
		'sha256' { HashAlgorithm.sha256.compute_hash(data) }
		'sha384' { HashAlgorithm.sha384.compute_hash(data) }
		else { sha512.sum512(data) }
	}
}

// verify_certificate_verify checks the server's CertificateVerify signature
// against the leaf certificate's public key over the §4.4.3 signed content
// (see certificate_verify_signed_content). RSA branches hash the content first
// and verify a digest, while the ECDSA/Ed25519 APIs take the raw message and
// hash internally per their own scheme.
fn verify_certificate_verify(leaf Certificate, cv ParsedCertificateVerify, signed_content []u8) ! {
	match cv.algorithm {
		.rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 {
			if leaf.public_key_algo != .rsa {
				return error('handshake: CertificateVerify algorithm ${cv.algorithm} requires RSA certificate')
			}
			rsa_key := leaf.rsa_public_key or { return error('handshake: missing RSA public key') }
			digest_type := match cv.algorithm {
				.rsa_pss_rsae_sha256 { 'sha256' }
				.rsa_pss_rsae_sha384 { 'sha384' }
				else { 'sha512' }
			}
			hash := hash_for_digest(digest_type, signed_content)
			ok := rsa_key.verify_pss(digest_type, hash, cv.signature)!
			if !ok {
				return error('handshake: RSA-PSS ${digest_type} CertificateVerify failed')
			}
		}
		.rsa_pkcs1_sha256 {
			// RFC 8446 §4.2.3/§4.4.3: rsa_pkcs1_* schemes refer to signatures in
			// certificates only and MUST NOT be used for the CertificateVerify
			// signature, whose RSA instances are RSASSA-PSS exclusively. A server
			// selecting it here is non-compliant; refuse rather than verify.
			return error('handshake: rsa_pkcs1_sha256 is not permitted for TLS 1.3 CertificateVerify (RFC 8446 §4.4.3)')
		}
		.ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384 {
			if leaf.public_key_algo != .ecdsa {
				return error('handshake: CertificateVerify algorithm ${cv.algorithm} requires ECDSA certificate')
			}
			// RFC 8446 §4.2.3: each ECDSA scheme requires its matching curve.
			match cv.algorithm {
				.ecdsa_secp256r1_sha256 {
					if leaf.ecdsa_curve != .prime256v1 {
						return error('handshake: ECDSA curve mismatch (secp256r1 required for ecdsa_secp256r1_sha256)')
					}
				}
				.ecdsa_secp384r1_sha384 {
					if leaf.ecdsa_curve != .secp384r1 {
						return error('handshake: ECDSA curve mismatch (secp384r1 required for ecdsa_secp384r1_sha384)')
					}
				}
				else {}
			}
			pubkey := leaf.ecdsa_public_key()!
			ok := pubkey.verify(signed_content, cv.signature)!
			if !ok {
				return error('handshake: ECDSA CertificateVerify failed (${cv.algorithm})')
			}
		}
		.ed25519 {
			if leaf.public_key_algo != .ed25519 {
				return error('handshake: CertificateVerify algorithm Ed25519 requires Ed25519 certificate')
			}
			if leaf.public_key_raw.len != ed25519.public_key_size {
				return error('handshake: invalid Ed25519 public key length')
			}
			ok := ed25519.verify(ed25519.PublicKey(leaf.public_key_raw), signed_content, cv.signature)!
			if !ok {
				return error('handshake: Ed25519 CertificateVerify failed')
			}
		}
	}
}
