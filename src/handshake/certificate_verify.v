// certificate_verify.v checks the server's CertificateVerify signature over the
// §4.4.3 transcript content. Separate from state_machine.v because verification
// is a pure function of (leaf key, signature, content) — it never advances
// protocol state, so the state machine only calls it once the message parses.

module handshake

import crypto.ed25519
import crypto.sha512
import kdf
import pki

// hash_for_digest returns Hash(data) for the named digest ("sha256"/"sha384"/"sha512").
fn hash_for_digest(digest_type string, data []u8) []u8 {
	// RSA-PSS verifies over a pre-computed digest, so pick the hash matching the
	// SignatureScheme's named algorithm; the else arm is the only remaining RSA-PSS
	// digest (sha512), routed through the standalone sha512 implementation.
	return match digest_type {
		'sha256' { kdf.HashAlgorithm.sha256.compute_hash(data) }
		'sha384' { kdf.HashAlgorithm.sha384.compute_hash(data) }
		else { sha512.sum512(data) }
	}
}

// verify_certificate_verify checks the server's CertificateVerify signature
// against the leaf certificate's public key over the §4.4.3 signed content
// (see certificate_verify_signed_content). Note the digest split: RSA branches
// hash the content first and verify a digest, while ECDSA/Ed25519 verify APIs
// take the raw message and hash internally per their own scheme (EdDSA is pure
// — the key, not the hash, is what binds the signature).
fn verify_certificate_verify(leaf pki.Certificate, cv ParsedCertificateVerify, signed_content []u8) ! {
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
			if leaf.public_key_algo != .rsa {
				return error('handshake: CertificateVerify algorithm ${cv.algorithm} requires RSA certificate')
			}
			rsa_key := leaf.rsa_public_key or { return error('handshake: missing RSA public key') }
			hash := kdf.HashAlgorithm.sha256.compute_hash(signed_content)
			ok := rsa_key.verify_pkcs1_v1_5('sha256', hash, cv.signature)!
			if !ok {
				return error('handshake: RSA-PKCS1 SHA-256 CertificateVerify failed')
			}
		}
		.ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384 {
			if leaf.public_key_algo != .ecdsa {
				return error('handshake: CertificateVerify algorithm ${cv.algorithm} requires ECDSA certificate')
			}
			// RFC 8446 §4.2.3: ecdsa_secp256r1_sha256 requires secp256r1, ecdsa_secp384r1_sha384 requires secp384r1
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
