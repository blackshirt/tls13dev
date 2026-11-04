// Copyright (c) 2026 blackshirt.
//
// validator.v chains a server certificate back to a trusted root, applying the X.509
// rules (RFC 5280): asn1.v/x509.v decode, rsa.v verifies, hostname.v matches
// (RFC 6125), trust_store.v seeds from system roots.
module pki

import crypto.ecdsa
import crypto.ed25519
import crypto.sha256
import crypto.sha512
import hash
import time

// max_cert_chain_depth bounds the certificates a peer may place in one
// Certificate message (RFC 5280 imposes no hard limit, so we set one).
pub const max_cert_chain_depth = 32

// default_min_rsa_bits is the minimum RSA modulus size accepted for a leaf
// (server) certificate (NIST SP 800-57 / CA-Browser Forum require ≥2048).
pub const default_min_rsa_bits = 2048

// min_rsa_bits_floor is the hard lower bound for an explicitly configured RSA
// leaf-key floor. Values below it are a broken-crypto typo, not a legitimate
// legacy-interop downgrade, so set_min_rsa_bits clamps them up to this bound.
pub const min_rsa_bits_floor = 1024

// Validator verifies certificate chains against trusted roots and hostnames.
@[noinit]
pub struct Validator {
mut:
	store                TrustStore // roots the chain must anchor to
	insecure_skip_verify bool       // set only via new_insecure_validator; skips every check
	// min_rsa_bits floors the accepted size of an RSA leaf (server) public key;
	// 0 means default_min_rsa_bits (lower = deliberate downgrade).
	min_rsa_bits int
}

// new_validator creates a Validator that always performs chain, hostname and
// key-strength verification against the given trust store. It is the only
// general-purpose constructor: there is no flag that can silently turn
// verification off. Use it for every real peer.
pub fn new_validator(store TrustStore) Validator {
	return Validator{
		store:        store
		min_rsa_bits: default_min_rsa_bits
	}
}

// new_insecure_validator creates a Validator that skips ALL certificate chain and
// hostname verification. It exists so the dangerous intent is spelled out at the
// call site instead of hidden in a positional `true`. Never use it to validate a
// real peer; it is for tests and deliberate local experiments only.
pub fn new_insecure_validator() Validator {
	return Validator{
		store:                new_trust_store()
		insecure_skip_verify: true
		min_rsa_bits:         default_min_rsa_bits
	}
}

// default_validator creates a validator using the system root CA bundle.
pub fn default_validator() !Validator {
	return new_validator(system_root_cas()!)
}

// set_min_rsa_bits overrides the RSA leaf-key floor (0 restores the default).
// A deliberate downgrade is honored only down to min_rsa_bits_floor; anything
// lower is clamped up, so the escape hatch cannot silently accept breakable keys.
pub fn (mut v Validator) set_min_rsa_bits(bits int) {
	if bits <= 0 {
		v.min_rsa_bits = default_min_rsa_bits
		return
	}
	v.min_rsa_bits = if bits < min_rsa_bits_floor { min_rsa_bits_floor } else { bits }
}

// effective_min_rsa_bits returns the floor in force, applying the default when zero.
fn (v &Validator) effective_min_rsa_bits() int {
	if v.min_rsa_bits <= 0 {
		return default_min_rsa_bits
	}
	return v.min_rsa_bits
}

// verify_certificate_chain validates a server's certificate list against the hostname
// and trusted root store (RFC 5280 & RFC 6125).
pub fn (v &Validator) verify_certificate_chain(chain []Certificate, hostname string) ! {
	if v.insecure_skip_verify {
		// Deliberate no-op: the escape hatch skips every check below (testing only).
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

	// Hostname validation: IP literals match iPAddress SANs only (RFC 6125 §6.4.3 /
	// RFC 2818 §3.1); an empty name fails closed.
	if hostname == '' {
		return error('pki: empty server name; cannot verify certificate hostname')
	}
	if is_ip_literal(hostname) {
		if !ip_san_matches(leaf.ip_sans, hostname) {
			return error('pki: leaf certificate does not match IP address "${hostname}" (iPAddress SANs: ${leaf.ip_sans})')
		}
	} else {
		// RFC 6125 §6.4.4: a present SAN extension disables the CN entirely (pass "" to express that).
		cn := if leaf.has_san { '' } else { leaf.subject_cn }
		if !verify_hostnames(leaf.sans, cn, hostname) {
			return error('pki: leaf certificate does not match hostname "${hostname}" (SANs: ${leaf.sans}, CN: "${cn}")')
		}
	}

	// Validity period: parse_certificate rejects unparseable times, so a stored
	// value is always a real date (RFC 5280 §4.1.2.5).
	if now < leaf.not_before_unix {
		return error('pki: leaf certificate is not yet valid (notBefore=${leaf.not_before})')
	}
	if now > leaf.not_after_unix {
		return error('pki: leaf certificate has expired (notAfter=${leaf.not_after})')
	}

	// Key Usage (RFC 5280 §4.2.1.3): when present, the bitmap must permit digitalSignature.
	if leaf.has_key_usage && !key_usage_bit(leaf.key_usage, 0) { // bit 0 = digitalSignature
		return error('pki: leaf certificate keyUsage does not permit digitalSignature')
	}

	// Extended Key Usage: when present it must allow serverAuth; absence is unconstrained (RFC 5280).
	if leaf.has_eku && !leaf.eku_server_auth {
		return error('pki: leaf certificate Extended Key Usage does not permit serverAuth')
	}

	// RSA leaf-key strength floor (default 2048 bits); escape hatch: Validator.set_min_rsa_bits.
	check_leaf_rsa_floor(leaf, v.effective_min_rsa_bits())!

	// A peer may append certificates beyond the point where its path is already
	// anchored. They are not part of the validated path and must not affect its
	// result.
	anchor_index := trusted_anchor_index(chain, v.store.certs, now)
	validation_end := if anchor_index >= 0 { anchor_index } else { chain.len - 1 }

	// Name constraints (RFC 5280 §4.2.1.10, §6.1.4(o)): a constraining CA binds every
	// subordinate beneath it, not just the leaf. Apply each CA's constraints to every
	// certificate it issues directly or indirectly — all chain indices below the CA.
	for i in 1 .. validation_end + 1 {
		for j in 0 .. i {
			enforce_name_constraints(chain[i], chain[j]) or {
				return error('pki: certificate at chain index ${i} restricts subordinate at index ${j}: ${err.msg()}')
			}
		}
	}

	// Validate signatures along the chain: C_i must be signed by C_{i+1}, whose
	// issuer name must match the child's subject; every issuer must be a CA
	// (RFC 5280 §4.2.1.9).
	for i in 0 .. validation_end {
		child := chain[i]
		parent := chain[i + 1]
		if child.issuer_dn != parent.subject_dn {
			return error('pki: issuer/subject name mismatch at chain index ${i} -> ${i + 1}')
		}
		if !parent.is_ca {
			return error('pki: certificate at chain index ${i + 1} is not a CA (basicConstraints cA=TRUE missing)')
		}
		// keyUsage bit 5 = keyCertSign: a CA asserting keyUsage must include it (RFC 5280 §4.2.1.3).
		if parent.has_key_usage && !key_usage_bit(parent.key_usage, 5) {
			return error('pki: CA at chain index ${i + 1} keyUsage does not permit keyCertSign')
		}
		if !is_trusted_anchor(parent, v.store.certs, now) && parent.has_eku && !parent.eku_server_auth {
			return error('pki: CA at chain index ${i + 1} Extended Key Usage does not permit serverAuth')
		}
		// pathLenConstraint (RFC 5280 §4.2.1.9) counts non-self-issued
		// intermediate CA certificates, excluding the target leaf.
		intermediate_cas_below := count_intermediate_cas_below(chain, i + 1)
		if parent.max_path_len >= 0 && intermediate_cas_below > parent.max_path_len {
			return error('pki: CA at chain index ${i + 1} violates pathLenConstraint (${intermediate_cas_below} intermediate CAs below > limit ${parent.max_path_len})')
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

	// Servers may send cross-signed CA certificates after an intermediate; the
	// trust path terminates at the first certificate already anchored to a root.
	if anchor_index < 0 {
		return error('pki: certificate chain cannot be verified up to a trusted root CA')
	}
}

fn is_trusted_anchor(cert Certificate, roots []Certificate, now i64) bool {
	for root in roots {
		if now < root.not_before_unix || now > root.not_after_unix {
			continue
		}
		if !root.is_ca {
			continue
		}
		if root.has_key_usage && !key_usage_bit(root.key_usage, 5) {
			continue
		}
		if cert.raw == root.raw {
			return true
		}
		if cert.issuer_dn != root.subject_dn {
			continue
		}
		verify_cert_signature(cert, root) or { continue }
		return true
	}
	return false
}

// count_intermediate_cas_below returns the number of non-self-issued CA
// certificates between the target leaf and the certificate at parent_index.
fn count_intermediate_cas_below(chain []Certificate, parent_index int) int {
	mut count := 0
	for i in 1 .. parent_index {
		cert := chain[i]
		if cert.is_ca && cert.subject_dn != cert.issuer_dn {
			count++
		}
	}
	return count
}

// trusted_anchor_index returns the earliest peer certificate that is itself a
// valid trust anchor or verifies directly under one.
fn trusted_anchor_index(chain []Certificate, roots []Certificate, now i64) int {
	for i, cert in chain {
		if is_trusted_anchor(cert, roots, now) {
			return i
		}
	}
	return -1
}

// check_leaf_rsa_floor enforces the minimum RSA modulus size for a leaf
// certificate; non-RSA leaves (EC, Ed25519) pass through.
fn check_leaf_rsa_floor(leaf Certificate, min_bits int) ! {
	if leaf.public_key_algo != .rsa {
		return
	}
	rsa_key := leaf.rsa_public_key or {
		return error('pki: leaf certificate missing valid RSA public key')
	}
	if rsa_key.size_bytes * 8 < min_bits {
		return error('pki: leaf RSA key too short (${rsa_key.size_bytes * 8} bits < ${min_bits})')
	}
}

// enforce_name_constraints applies a CA's name constraints to every DNS/IP name
// of the subordinate certificate (RFC 5280 §4.2.1.10).
fn enforce_name_constraints(ca Certificate, child Certificate) ! {
	if !ca.name_constraints_present {
		return
	}
	// dNSName subtrees constrain the subject's dNSNames; when no SAN is present the
	// subject Common Name is the constrained name instead (RFC 5280 §4.2.1.10, mirroring
	// the hostname check above, where a present SAN disables the CN).
	mut dns_names := child.sans.clone()
	if !child.has_san && child.subject_cn != '' {
		dns_names = [child.subject_cn]
	}
	// RFC 5280 §4.2.1.10 §6.1.4(o): permitted subtrees are per-name-form — a CA that
	// asserts only IP permitted subtrees does not constrain DNS names, and vice versa.
	// Excluded subtrees stay per-form as well.
	permitted_dns_any := ca.permitted_dns.len > 0
	permitted_ip_any := ca.permitted_ip.len > 0
	for name in dns_names {
		if ca.excluded_dns.len > 0 && dns_in_any_subtree(name, ca.excluded_dns) {
			return error('dNSName "${name}" is within an excluded subtree')
		}
		if permitted_dns_any && !dns_in_any_subtree(name, ca.permitted_dns) {
			return error('dNSName "${name}" is outside the permitted subtrees')
		}
	}
	for ip in child.ip_sans {
		if ca.excluded_ip.len > 0 && ip_in_any_subtree(ip, ca.excluded_ip) {
			return error('iPAddress ${ip} is within an excluded subtree')
		}
		if permitted_ip_any && !ip_in_any_subtree(ip, ca.permitted_ip) {
			return error('iPAddress ${ip} is outside the permitted subtrees')
		}
	}
}

// dns_in_any_subtree reports whether name falls within at least one dNSName
// subtree. RFC 5280 §4.2.1.10 defines a single "within a subtree" relation that
// both permitted and excluded constraints share; the caller supplies the meaning
// through how it uses the result (excluded: reject a match; permitted: require one).
fn dns_in_any_subtree(name string, subtrees []string) bool {
	for sub in subtrees {
		if dns_within_subtree(name, sub) {
			return true
		}
	}
	return false
}

// dns_within_subtree implements the RFC 5280 §4.2.1.10 "within a subtree"
// relation for dNSName; comparison is case-insensitive (RFC 5280 §7.2).
fn dns_within_subtree(name string, subtree string) bool {
	n := name.to_lower()
	s := subtree.to_lower()
	if s.len == 0 {
		return false
	}
	if s.starts_with('.') {
		// Leading-dot subtree: match any name ending in the dotted suffix.
		return n.ends_with(s) && n.len > s.len
	}
	if n == s {
		return true
	}
	return n.ends_with('.' + s)
}

// ip_in_any_subtree reports whether ip falls within at least one iPAddress
// subtree (RFC 5280 §4.2.1.10 encodes each as an address plus a mask). As with
// the DNS form, permitted and excluded share one relation and the caller's use
// of the result decides which applies.
fn ip_in_any_subtree(ip []u8, subtrees [][]u8) bool {
	for sub in subtrees {
		if ip_within_subtree(ip, sub) {
			return true
		}
	}
	return false
}

// ip_within_subtree matches an address against an RFC 5280 §4.2.1.10 iPAddress
// subtree (address+mask); the halves must match the candidate's length, so IPv4 and IPv6 never mix.
fn ip_within_subtree(ip []u8, subtree []u8) bool {
	if subtree.len != ip.len * 2 {
		return false
	}
	addr := subtree[..ip.len]
	mask := subtree[ip.len..]
	for i in 0 .. ip.len {
		if (ip[i] & mask[i]) != (addr[i] & mask[i]) {
			return false
		}
	}
	return true
}

// ecdsa_hasher_for returns a hash.Hash implementing the digest named by
// `digest_type`, used to make ecdsa.PublicKey.verify honor the signature
// algorithm OID's hash rather than the key's curve default.
// Rejects unknown digest types instead of falling through to SHA-512 silently.
fn ecdsa_hasher_for(digest_type string) !hash.Hash {
	if digest_type == 'sha256' {
		return sha256.new()
	}
	if digest_type == 'sha384' {
		return sha512.new384()
	}
	if digest_type == 'sha512' {
		return sha512.new()
	}
	return error('pki: unknown digest type ${digest_type}')
}

// verify_cert_signature verifies that `child` was signed by `parent`. Failure
// is signaled only by an error — no bool for the caller to silently discard.
fn verify_cert_signature(child Certificate, parent Certificate) ! {
	match parent.public_key_algo {
		.rsa {
			rsa_key := parent.rsa_public_key or {
				return error('pki: parent certificate missing valid RSA public key')
			}
			// CA signing keys are floored at 2048 bits regardless of trust-store
			// contents (CA/Browser Forum baseline).
			if rsa_key.size_bytes < 256 {
				return error('pki: CA RSA key too short (${rsa_key.size_bytes * 8} bits < 2048)')
			}
			// For PKCS#1 v1.5 the OID identifies hash+scheme; PSS carries the hash in signature_hash_oid.
			is_pss := child.signature_algo_oid == '1.2.840.113549.1.1.10' // id-RSASSA-PSS
			digest_type := if is_pss {
				// Derive from RSASSA-PSS-params hashAlgorithm OID (RFC 4055 §3.1)
				match child.signature_hash_oid {
					'2.16.840.1.101.3.4.2.1' { 'sha256' } // id-sha256
					'2.16.840.1.101.3.4.2.2' { 'sha384' } // id-sha384
					'2.16.840.1.101.3.4.2.3' { 'sha512' } // id-sha512
					else {
						// RFC 4055 §3.1: anything else (incl. the SHA-1 default) is refused, not guessed.
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

			digest := digest_bytes(digest_type, child.tbs_raw)!
			if is_pss {
				rsa_key.verify_pss(digest_type, digest, child.signature)!
			} else {
				rsa_key.verify_pkcs1_v1_5(digest_type, digest, child.signature)!
			}
		}
		.ecdsa {
			pubkey := parent.ecdsa_public_key()!
			// Map the signature algorithm OID to the hash the signer used.
			// RFC 5280 allows any hash with any curve, so the digest must come
			// from the OID — not the key's curve, which is what
			// ecdsa.PublicKey.verify defaults to (with_recommended_hash).
			digest_type := match child.signature_algo_oid {
				'1.2.840.10045.4.3.2' { 'sha256' } // ecdsa-with-SHA256
				'1.2.840.10045.4.3.3' { 'sha384' } // ecdsa-with-SHA384
				'1.2.840.10045.4.3.4' { 'sha512' } // ecdsa-with-SHA512
				else {
					return error('pki: unsupported ECDSA signature OID ${child.signature_algo_oid}')
				}
			}
			// Build a custom hasher so verify() hashes with the OID's hash
			// rather than the curve's default.
			mut hh := ecdsa_hasher_for(digest_type)!
			opts := ecdsa.SignerOpts{
				hash_config:        .with_custom_hash
				allow_custom_hash:  true
				allow_smaller_size: true
				custom_hash:        &hh
			}
			if !pubkey.verify(child.tbs_raw, child.signature, opts)! {
				return error('pki: ECDSA signature verification failed')
			}
		}
		.ed25519 {
			// Ed25519 public keys are exactly 32 bytes; reject any other length.
			if parent.public_key_raw.len != ed25519.public_key_size {
				return error('pki: invalid Ed25519 public key length')
			}
			if !ed25519.verify(ed25519.PublicKey(parent.public_key_raw), child.tbs_raw, child.signature)! {
				return error('pki: Ed25519 signature verification failed')
			}
		}
		else {
			return error('pki: signature verification for ${parent.public_key_algo} not yet implemented')
		}
	}
}
