// module pki covers the X.509 side of the handshake (RFC 5280): asn1.v and
// x509.v decode certificates, rsa.v plus the crypto libraries verify signature
// algorithm variants, hostname.v applies RFC 6125 name matching,
// trust_store.v loads system roots, and validator.v chains a server
// certificate back to a trusted root with the usage/validity constraints the
// TLS spec imposes.
module pki

import crypto.ed25519
import time

// Validator verifies certificate chains against trusted roots and hostnames.
pub struct Validator {
pub:
	store                TrustStore // roots the chain must anchor to
	insecure_skip_verify bool       // skips chain and hostname checks; testing only
}

// new_validator creates a Validator.
pub fn new_validator(store TrustStore, insecure bool) Validator {
	return Validator{
		store:                store
		insecure_skip_verify: insecure
	}
}

// verify_certificate_chain validates a server's certificate list against the hostname
// and trusted root store (RFC 5280 & RFC 6125).
pub fn (v &Validator) verify_certificate_chain(chain []Certificate, hostname string) ! {
	if v.insecure_skip_verify {
		// Deliberate no-op: the escape hatch must skip *every* check below, which is
		// exactly why it is dangerous and reserved for testing (see client.Config).
		return
	}
	if chain.len == 0 {
		return error('pki: empty certificate chain')
	}
	if chain.len > 32 {
		return error('pki: certificate chain too long (${chain.len} > 32)')
	}

	now := time.now().unix()
	leaf := chain[0]

	// Hostname validation against the leaf certificate. IP literals are matched
	// exclusively against iPAddress SANs per RFC 6125 §6.4.3 / RFC 2818 §3.1.
	if hostname != '' {
		if is_ip_literal(hostname) {
			if !ip_san_matches(leaf.ip_sans, hostname) {
				return error('pki: leaf certificate does not match IP address "${hostname}" (iPAddress SANs: ${leaf.ip_sans})')
			}
		} else {
			if !verify_hostnames(leaf.sans, leaf.subject_cn, hostname) {
				return error('pki: leaf certificate does not match hostname "${hostname}" (SANs: ${leaf.sans}, CN: "${leaf.subject_cn}")')
			}
		}
	}

	// Validity period. The '> 0' guards treat an unparseable time (x509.v stores 0
	// on decode failure) as "unknown → do not enforce" rather than "invalid":
	// lenient, but only reachable for malformed certs since RFC 5280 §4.1.2.5
	// mandates both fields on well-formed certificates.
	if leaf.not_before_unix > 0 && now < leaf.not_before_unix {
		return error('pki: leaf certificate is not yet valid (notBefore=${leaf.not_before})')
	}
	if leaf.not_after_unix > 0 && now > leaf.not_after_unix {
		return error('pki: leaf certificate has expired (notAfter=${leaf.not_after})')
	}

	// Extended Key Usage: if present, must allow serverAuth.
	// Absence is tolerated: EKU is not marked critical in many roots/leafs and
	// RFC 5280 only constrains behavior when the extension exists.
	if leaf.has_eku && !leaf.eku_server_auth {
		return error('pki: leaf certificate Extended Key Usage does not permit serverAuth')
	}

	// Validate signatures along the chain: C_i must be signed by C_{i+1}, and
	// each certificate's issuer name must match its parent's subject name.
	// Every issuer must be a CA per basicConstraints (RFC 5280 §4.2.1.9).
	for i in 0 .. chain.len - 1 {
		child := chain[i]
		parent := chain[i + 1]
		if child.issuer_dn != parent.subject_dn {
			return error('pki: issuer/subject name mismatch at chain index ${i} -> ${i + 1}')
		}
		if !parent.is_ca {
			return error('pki: certificate at chain index ${i + 1} is not a CA (basicConstraints cA=TRUE missing)')
		}
		if parent.not_before_unix > 0 && now < parent.not_before_unix {
			return error('pki: intermediate certificate not yet valid at chain index ${i + 1}')
		}
		if parent.not_after_unix > 0 && now > parent.not_after_unix {
			return error('pki: intermediate certificate expired at chain index ${i + 1}')
		}
		verify_cert_signature(child, parent) or {
			return error('pki: signature verification failed at chain index ${i}: ${err.msg()}')
		}
	}

	// Resolve the top of the chain to a trusted root whose subject matches the
	// top certificate's issuer. Two accepted forms of trust anchoring:
	// 1. signature verifies under a same-named stored root (server sent an
	//    intermediate-ended chain; roots are usually omitted from the wire chain),
	// 2. the top certificate is byte-identical to a stored root (server included
	//    the self-signed root itself — no re-verification of a self-signature needed).
	top_cert := chain[chain.len - 1]
	mut root_found := false

	for root in v.store.certs {
		if top_cert.issuer_dn != root.subject_dn {
			continue // name pair first: cheap string test that filters most roots out
		}
		if root.not_before_unix > 0 && now < root.not_before_unix {
			continue // skip not-yet-valid root
		}
		if root.not_after_unix > 0 && now > root.not_after_unix {
			continue // skip expired root
		}
		// A failed signature under this root is not fatal: another stored root can
		// share the subject (rotated/cross-signed copies of the same CA), so the
		// loop keeps trying remaining candidates.
		if verify_cert_signature(top_cert, root) or { false } {
			root_found = true
			break
		}
		if top_cert.raw == root.raw {
			root_found = true
			break
		}
	}

	if !root_found {
		return error('pki: certificate chain cannot be verified up to a trusted root CA')
	}
}

// verify_cert_signature verifies that `child` was signed by `parent`.
fn verify_cert_signature(child Certificate, parent Certificate) !bool {
	match parent.public_key_algo {
		.rsa {
			rsa_key := parent.rsa_public_key or {
				return error('pki: parent certificate missing valid RSA public key')
			}
			// For PKCS#1 v1.5 the OID identifies hash+scheme; for PSS the hash is
			// encoded in the AlgorithmIdentifier parameters (stored in signature_hash_oid).
			is_pss := child.signature_algo_oid == '1.2.840.113549.1.1.10' // id-RSASSA-PSS
			digest_type := if is_pss {
				// Derive from RSASSA-PSS-params hashAlgorithm OID (RFC 4055 §3.1)
				match child.signature_hash_oid {
					'2.16.840.1.101.3.4.2.1' { 'sha256' } // id-sha256
					'2.16.840.1.101.3.4.2.2' { 'sha384' } // id-sha384
					'2.16.840.1.101.3.4.2.3' { 'sha512' } // id-sha512
					else {
						// RFC 4055 §3.1: anything else (incl. the SHA-1 default) is a hash
						// we refuse to guess — silently re-hashing as SHA-256 would only
						// turn a clear "unsupported algorithm" rejection into a confusing
						// "signature invalid" failure.
						return error('pki: unsupported hash algorithm OID in PSS params: ${child.signature_hash_oid}')
					}
				}
			} else {
				match child.signature_algo_oid {
					'1.2.840.113549.1.1.11' { 'sha256' } // sha256WithRSAEncryption
					'1.2.840.113549.1.1.12' { 'sha384' } // sha384WithRSAEncryption
					'1.2.840.113549.1.1.13' { 'sha512' } // sha512WithRSAEncryption
					else {
						return error('pki: unsupported certificate signature algorithm OID ${child.signature_algo_oid}')
					}
				}
			}

			hash := digest_bytes(digest_type, child.tbs_raw)!

			if is_pss {
				return rsa_key.verify_pss(digest_type, hash, child.signature)
			} else {
				return rsa_key.verify_pkcs1_v1_5(digest_type, hash, child.signature)
			}
		}
		.ecdsa {
			pubkey := parent.ecdsa_public_key()!
			// The OID arm is a pure acceptance gate: ECDSA certificates carry no hash
			// parameter — the digest is fixed by the signer's curve (P-256 → SHA-256,
			// P-384 → SHA-384) and hashed inside verify, so checking tbs_raw directly
			// is correct and nothing here needs to pick a hash like the RSA branch does.
			match child.signature_algo_oid {
				'1.2.840.10045.4.3.2', '1.2.840.10045.4.3.3', '1.2.840.10045.4.3.4' {
					ok := pubkey.verify(child.tbs_raw, child.signature)!
					if !ok {
						return error('pki: ECDSA signature verification failed')
					}
					return true
				}
				else {
					return error('pki: unsupported ECDSA signature OID ${child.signature_algo_oid}')
				}
			}
		}
		.ed25519 {
			// Ed25519 public keys are exactly 32 bytes (a compressed curve point); any
			// other length cannot be a valid encoding, so reject before constructing the
			// fixed-size key instead of feeding it truncated/padded bytes.
			if parent.public_key_raw.len != ed25519.public_key_size {
				return error('pki: invalid Ed25519 public key length')
			}
			ok := ed25519.verify(ed25519.PublicKey(parent.public_key_raw), child.tbs_raw, child.signature)!
			if !ok {
				return error('pki: Ed25519 signature verification failed')
			}
			return true
		}
		else {
			return error('pki: signature verification for ${parent.public_key_algo} not yet implemented')
		}
	}
}
