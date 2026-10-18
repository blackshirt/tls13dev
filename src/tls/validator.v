// Copyright (c) 2026 blackshirt.
//
// validator.v chains a server certificate back to a trusted root, applying the X.509
// rules (RFC 5280) that asn1.v/x509.v decode, rsa.v and the crypto libraries verify,
// hostname.v matches (RFC 6125) and trust_store.v seeds from system roots.
module tls

import crypto.ed25519
import time

// max_cert_chain_depth bounds how many certificates a peer may place in a single
// Certificate message. Real webs end up under four; the cap is enforced at
// parse time (messages.v) so an oversized list cannot force expensive ASN.1
// decoding of thousands of entries before the chain walk rejects it, and again
// here as defense in depth. RFC 5280 imposes no hard limit, so we set one.
const max_cert_chain_depth = 32

// Validator verifies certificate chains against trusted roots and hostnames.
struct Validator {
mut:
	store                TrustStore // roots the chain must anchor to
	insecure_skip_verify bool       // skips chain and hostname checks; testing only
}

// new_validator creates a Validator.
fn new_validator(store TrustStore, insecure bool) Validator {
	return Validator{
		store:                store
		insecure_skip_verify: insecure
	}
}

// verify_certificate_chain validates a server's certificate list against the hostname
// and trusted root store (RFC 5280 & RFC 6125).
fn (v &Validator) verify_certificate_chain(chain []Certificate, hostname string) ! {
	if v.insecure_skip_verify {
		// Deliberate no-op: the escape hatch skips *every* check below, which is why
		// it is dangerous and reserved for testing (see Config).
		return
	}
	if chain.len == 0 {
		return error('pki: empty certificate chain')
	}
	if chain.len > max_cert_chain_depth {
		return error('pki: certificate chain too long (${chain.len} > ${max_cert_chain_depth})')
	}

	now := time.now().unix()
	leaf := chain[0]

	// Hostname validation against the leaf certificate. IP literals are matched
	// exclusively against iPAddress SANs per RFC 6125 §6.4.3 / RFC 2818 §3.1.
	// An empty name cannot be checked, so it must fail closed: otherwise a dial
	// address with no host part (e.g. ":443") would silently accept any trusted
	// certificate. (insecure_skip_verify already returned above.)
	if hostname == '' {
		return error('pki: empty server name; cannot verify certificate hostname')
	}
	if is_ip_literal(hostname) {
		if !ip_san_matches(leaf.ip_sans, hostname) {
			return error('pki: leaf certificate does not match IP address "${hostname}" (iPAddress SANs: ${leaf.ip_sans})')
		}
	} else {
		// RFC 6125 §6.4.4: a present SAN extension disables the CN entirely,
		// even when it holds no usable names — pass "" to express that.
		cn := if leaf.has_san { '' } else { leaf.subject_cn }
		if !verify_hostnames(leaf.sans, cn, hostname) {
			return error('pki: leaf certificate does not match hostname "${hostname}" (SANs: ${leaf.sans}, CN: "${cn}")')
		}
	}

	// Validity period. parse_certificate now rejects unparseable times (x509.v
	// fails the whole decode), so a stored value always reflects a real date;
	// RFC 5280 §4.1.2.5 mandates both fields on well-formed certificates.
	if now < leaf.not_before_unix {
		return error('pki: leaf certificate is not yet valid (notBefore=${leaf.not_before})')
	}
	if now > leaf.not_after_unix {
		return error('pki: leaf certificate has expired (notAfter=${leaf.not_after})')
	}

	// Key Usage (RFC 5280 §4.2.1.3): when the leaf asserts a keyUsage bitmap, it
	// must permit the TLS usage — server authentication consumes the certificate
	// with digitalSignature (or the non-standard-but-legal keyEncipherment for
	// RSA key transport); we require digitalSignature, which every modern server
	// cert sets, only when the extension exists at all (absence is unconstrained
	// per §4.2.1.3 "should be present" guidance for non-CA certs).
	if leaf.has_key_usage && !key_usage_bit(leaf.key_usage, 0) { // bit 0 = digitalSignature
		return error('pki: leaf certificate keyUsage does not permit digitalSignature')
	}

	// Extended Key Usage: if present it must allow serverAuth; absence is
	// tolerated because RFC 5280 only constrains behavior when the extension exists.
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
		// keyUsage bit 5 = keyCertSign: a CA that asserts a keyUsage bitmap
		// without it is not authorized to sign the child (RFC 5280 §4.2.1.3).
		if parent.has_key_usage && !key_usage_bit(parent.key_usage, 5) {
			return error('pki: CA at chain index ${i + 1} keyUsage does not permit keyCertSign')
		}
		// pathLenConstraint (RFC 5280 §4.2.1.9): the number of non-CA certs below
		// this CA must not exceed the limit. Intermediates strictly below `parent`
		// in the chain are indices 0 .. i-1, i.e. i of them; leaf-only (i == 0)
		// always satisfies any limit. A stored -1 means the INTEGER was absent.
		if parent.max_path_len >= 0 && i > parent.max_path_len {
			return error('pki: CA at chain index ${i + 1} violates pathLenConstraint (${i} intermediate certs below > limit ${parent.max_path_len})')
		}
		if now < parent.not_before_unix {
			return error('pki: intermediate certificate not yet valid at chain index ${i + 1}')
		}
		if now > parent.not_after_unix {
			return error('pki: intermediate certificate expired at chain index ${i + 1}')
		}
		verify_cert_signature(child, parent) or {
			return error('pki: signature verification failed at chain index ${i}: ${err.msg()}')
		}
	}

	// Resolve the top of the chain to a trusted root whose subject matches the top
	// certificate's issuer, by either form of anchoring: the top's signature
	// verifies under a same-named stored root (roots are usually omitted from the
	// wire chain), or the top certificate is byte-identical to a stored root.
	top_cert := chain[chain.len - 1]
	mut root_found := false

	for root in v.store.certs {
		if top_cert.issuer_dn != root.subject_dn {
			continue // name pair first: cheap string test that filters most roots out
		}
		if now < root.not_before_unix {
			continue // skip not-yet-valid root
		}
		if now > root.not_after_unix {
			continue // skip expired root
		}
		// A failed signature under this root is not fatal: another stored root can
		// share the subject (rotated/cross-signed copies), so keep trying.
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
			// A CA/parent RSA key below 2048 bits is refused regardless of trust-store
			// contents: 1024-bit RSA is inside precomputation reach for well-resourced
			// attackers, and CA/Browser Forum baselines require CAs to sign with
			// ≥2048. Only signing parents are floored — leaf keys keep their existing
			// strength policy so legacy test certificates still connect.
			if rsa_key.size_bytes < 256 {
				return error('pki: CA RSA key too short (${rsa_key.size_bytes * 8} bits < 2048)')
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
						// RFC 4055 §3.1: anything else (incl. the SHA-1 default) is refused
						// rather than guessed, so the error names the real problem.
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
			// ECDSA carries no hash parameter: the digest is fixed by the signer's
			// curve and hashed inside verify, so tbs_raw goes in directly.
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
			// Ed25519 public keys are exactly 32 bytes; reject any other length before
			// constructing the fixed-size key.
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
