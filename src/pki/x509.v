// Copyright (c) 2026 blackshirt.
// SPDX-License-Identifier: MIT
//
// x509.v decodes DER-encoded X.509 v3 certificates into a Cert, pulling out the
// subject/issuer names, validity window, public key, signature algorithm, and the
// SAN/basic-constraints extensions that validator.v and hostname.v consume.
module pki

import crypto.ecdsa
import time
import wire

// PublicKeyAlgorithm identifies the type of public key in a certificate.
pub enum PublicKeyAlgorithm {
	rsa
	ecdsa
	ed25519
	unknown
}

// Certificate represents a decoded X.509 certificate (RFC 5280).
pub struct Certificate {
pub:
	// Only the public-key fields read across the module boundary by the handshake's
	// CertificateVerify check (handshake/certificate_verify.v) are public; everything
	// else is consumed solely by the chain/hostname validation inside this module.
	public_key_algo PublicKeyAlgorithm
	public_key_raw  []u8          // SubjectPublicKeyInfo BIT STRING contents
	rsa_public_key  ?RsaPublicKey // set when public_key_algo is .rsa
	ecdsa_curve     ecdsa.Nid     // curve of the EC key, NID form
mut:
	raw                []u8   // full DER-encoded certificate as received
	tbs_raw            []u8   // DER of the TBSCertificate — exactly the bytes the issuer signed
	version            int    // X.509 version (3 = v3); encoded value is version-1
	serial_number      []u8   // issuer-assigned serial, big-endian
	signature_algo_oid string // OID of the signature AlgorithmIdentifier
	// signature_hash_oid holds the hash algorithm OID for PSS signatures
	// (parsed from AlgorithmIdentifier parameters when OID is id-RSASSA-PSS).
	signature_hash_oid string
	issuer_cn          string // commonName of the issuer
	subject_cn         string // commonName of the subject
	// issuer_dn and subject_dn hold the DER-encoded RDNSequence contents of the
	// Name fields, used to chain a certificate to its issuer.
	issuer_dn       []u8
	subject_dn      []u8
	not_before      string   // validity start, RFC 5280 UTCTime/GeneralizedTime as written
	not_after       string   // validity end, same encoding as not_before
	not_before_unix i64      // not_before in Unix seconds, for easy comparison
	not_after_unix  i64      // not_after in Unix seconds
	sans            []string // dNSName and rfc822Name SAN entries
	// ip_sans holds the raw bytes of each iPAddress SAN (4 bytes for IPv4,
	// 16 for IPv6), used to verify connections made to an IP literal.
	ip_sans         [][]u8
	is_ca           bool // basicConstraints CA flag; intermediates must have it
	has_eku         bool // an extendedKeyUsage extension was present at all
	eku_server_auth bool // EKU includes id-kp-serverAuth, required for TLS servers
	signature       []u8 // BIT STRING contents of signatureValue
}

// parse_certificate decodes an X.509 DER certificate.
//
//	Certificate ::= SEQUENCE {
//	    tbsCertificate       TBSCertificate,
//	    signatureAlgorithm   AlgorithmIdentifier,
//	    signatureValue       BIT STRING }
pub fn parse_certificate(der []u8) !Certificate {
	mut r := wire.new_reader(der)
	cert_seq := read_asn1_element(mut r)!
	if cert_seq.tag != 0x30 {
		return error('x509: certificate must begin with SEQUENCE (0x30), got 0x${cert_seq.tag:02x}')
	}
	// Re-parse the contents to capture the TBSCertificate's exact DER encoding
	// (tag + length + value); this byte range is the message that was signed.
	mut inner := wire.new_reader(cert_seq.data)
	tbs_start := inner.cursor
	tbs_elem := read_asn1_element(mut inner)!
	tbs_raw := cert_seq.data[tbs_start..inner.cursor].clone()
	// Skip the outer signatureAlgorithm: RFC 5280 §4.1.2.2 requires it to equal the
	// TBS copy, and only the TBS copy is covered by the signature.
	_ := read_asn1_element(mut inner)!
	sig_val_elem := read_asn1_element(mut inner)!

	tbs_elements := parse_sequence(tbs_elem.data)!
	// Minimum 6 elements = serial, signature alg, issuer, validity, subject, SPKI;
	// version is optional ([0] EXPLICIT, absent in v1) and extensions follow after.
	if tbs_elements.len < 6 {
		return error('x509: malformed TBSCertificate (${tbs_elements.len} elements)')
	}

	mut idx := 0

	// 1. Version [0] EXPLICIT. The field is absent for v1 certificates (the
	// default), so only consume it when the first element carries context tag 0.
	mut version := 1
	if (tbs_elements[0].tag & 0x1f) == 0 {
		mut vr := wire.new_reader(tbs_elements[0].data)
		v_elem := read_asn1_element(mut vr)!
		if v_elem.data.len > 0 {
			// Encoded 0-based (v1 = 0, v3 = 2); expose the human value.
			version = int(v_elem.data[0]) + 1
		}
		idx++
	}

	// 2. Serial Number (INTEGER)
	serial_number := tbs_elements[idx].data.clone()
	idx++

	// 3. Signature Algorithm (AlgorithmIdentifier)
	sig_alg_inner := parse_sequence(tbs_elements[idx].data)!
	mut tbs_sig_algo_oid := ''
	mut tbs_sig_hash_oid := ''
	if sig_alg_inner.len > 0 {
		tbs_sig_algo_oid = parse_oid(sig_alg_inner[0].data)
		// For id-RSASSA-PSS (1.2.840.113549.1.1.10), extract the hash OID from the
		// RSASSA-PSS-params SEQUENCE's hashAlgorithm [0] field.
		if tbs_sig_algo_oid == '1.2.840.113549.1.1.10' && sig_alg_inner.len >= 2 {
			pss_params := parse_sequence(sig_alg_inner[1].data) or { []Asn1Element{} }
			for param in pss_params {
				// [0] EXPLICIT -- hashAlgorithm: 0xa0 = context-specific class +
				// constructed bit, and & 0x1f == 0 pins the tag number to [0].
				if (param.tag & 0xe0) == 0xa0 && (param.tag & 0x1f) == 0 {
					hash_alg_inner := parse_sequence(param.data) or { []Asn1Element{} }
					if hash_alg_inner.len > 0 {
						tbs_sig_hash_oid = parse_oid(hash_alg_inner[0].data)
					}
					break
				}
			}
		}
	}
	idx++

	// 4. Issuer (Name)
	issuer_cn := extract_cn_from_name(tbs_elements[idx].data)
	issuer_dn := tbs_elements[idx].data.clone()
	idx++

	// 5. Validity (SEQUENCE: notBefore, notAfter)
	val_elems := parse_sequence(tbs_elements[idx].data)!
	mut not_before := ''
	mut not_after := ''
	mut not_before_unix := i64(0)
	mut not_after_unix := i64(0)
	if val_elems.len >= 2 {
		not_before = val_elems[0].data.bytestr()
		not_after = val_elems[1].data.bytestr()
		not_before_unix = parse_asn1_time(val_elems[0]) or { 0 }
		not_after_unix = parse_asn1_time(val_elems[1]) or { 0 }
	}
	idx++

	// 6. Subject (Name)
	subject_cn := extract_cn_from_name(tbs_elements[idx].data)
	subject_dn := tbs_elements[idx].data.clone()
	idx++

	// 7. SubjectPublicKeyInfo (SEQUENCE: AlgorithmIdentifier, BIT STRING)
	spki_elems := parse_sequence(tbs_elements[idx].data)!
	mut pk_algo := PublicKeyAlgorithm.unknown
	mut rsa_key := ?RsaPublicKey(none)
	mut raw_pk_bytes := []u8{}

	mut ecdsa_curve := ecdsa.Nid.prime256v1
	if spki_elems.len >= 2 {
		alg_seq := parse_sequence(spki_elems[0].data)!
		if alg_seq.len > 0 {
			alg_oid := parse_oid(alg_seq[0].data)
			match alg_oid {
				'1.2.840.113549.1.1.1' { // rsaEncryption
					pk_algo = .rsa
				}
				'1.2.840.10045.2.1' { // id-ecPublicKey
					pk_algo = .ecdsa
					// Parse the named curve OID from AlgorithmIdentifier.parameters
					if alg_seq.len >= 2 {
						curve_oid := parse_oid(alg_seq[1].data)
						if curve_oid == '1.2.840.10045.3.1.7' {
							ecdsa_curve = ecdsa.Nid.prime256v1 // P-256 / secp256r1
						} else if curve_oid == '1.3.132.0.34' {
							ecdsa_curve = ecdsa.Nid.secp384r1 // P-384 / secp384r1
						} else {
							// Unsupported curve (P-521, Brainpool, etc.): fail clearly
							pk_algo = .unknown
						}
					}
				}
				'1.3.101.112' { // Ed25519
					pk_algo = .ed25519
				}
				else {
					// Leave pk_algo == .unknown: verify_cert_signature's catch-all then
					// rejects the cert instead of us guessing a key type from raw bytes.
				}
			}
		}

		// The key lives in a BIT STRING whose first byte is the number of unused
		// trailing bits; it is always 0 here, so skip it to get the key bytes.
		bit_string := spki_elems[1].data
		if bit_string.len > 1 {
			raw_pk_bytes = bit_string[1..].clone()
			if pk_algo == .rsa {
				// RSA keys carry a PKCS#1 RSAPublicKey structure inside the BIT STRING.
				if k := parse_rsa_public_key(raw_pk_bytes) {
					rsa_key = k
				}
			}
		}
	}
	idx++

	// Extensions [3] EXPLICIT (optional; absent in v1 certificates).
	//   Extensions ::= SEQUENCE OF Extension
	//   Extension  ::= SEQUENCE { extnID OBJECT IDENTIFIER,
	//                             critical BOOLEAN DEFAULT FALSE,
	//                             extnValue OCTET STRING }
	mut sans := []string{}
	mut ip_sans := [][]u8{}
	mut is_ca := false
	mut has_eku := false
	mut eku_server_auth := false

	for i in idx .. tbs_elements.len {
		el := tbs_elements[i]
		if (el.tag & 0x1f) == 3 { // [3] Context tag
			ext_seq_wrap := parse_sequence(el.data) or { [] }
			if ext_seq_wrap.len > 0 {
				ext_list := parse_sequence(ext_seq_wrap[0].data) or { [] }
				for ext in ext_list {
					parts := parse_sequence(ext.data) or { continue }
					if parts.len < 2 {
						continue
					}
					ext_oid := parse_oid(parts[0].data)
					// extnValue is the last element: index 1 when `critical` is
					// absent, index 2 when it is present.
					ext_val_bytes := if parts.len == 2 { parts[1].data } else { parts[2].data }

					match ext_oid {
						'2.5.29.17' { // Subject Alternative Name (SAN)
							sans, ip_sans = parse_san_extension(ext_val_bytes)
						}
						'2.5.29.19' { // Basic Constraints
							is_ca = parse_basic_constraints(ext_val_bytes)
						}
						'2.5.29.37' { // Extended Key Usage
							has_eku = true
							eku_server_auth = parse_eku_server_auth(ext_val_bytes)
						}
						else {}
					}
				}
			}
		}
	}

	// Signature from outer Certificate
	mut signature_bytes := []u8{}
	if sig_val_elem.data.len > 1 {
		signature_bytes = sig_val_elem.data[1..].clone() // Skip unused bits byte
	}

	return Certificate{
		raw:                der.clone()
		tbs_raw:            tbs_raw
		version:            version
		serial_number:      serial_number
		signature_algo_oid: tbs_sig_algo_oid
		signature_hash_oid: tbs_sig_hash_oid
		issuer_cn:          issuer_cn
		subject_cn:         subject_cn
		issuer_dn:          issuer_dn
		subject_dn:         subject_dn
		not_before:         not_before
		not_after:          not_after
		not_before_unix:    not_before_unix
		not_after_unix:     not_after_unix
		public_key_algo:    pk_algo
		public_key_raw:     raw_pk_bytes
		rsa_public_key:     rsa_key
		ecdsa_curve:        ecdsa_curve
		sans:               sans
		ip_sans:            ip_sans
		is_ca:              is_ca
		has_eku:            has_eku
		eku_server_auth:    eku_server_auth
		signature:          signature_bytes
	}
}

// ecdsa_public_key reconstructs an ECDSA public key from the SPKI bit string
// using the curve stored during certificate parsing.
pub fn (c &Certificate) ecdsa_public_key() !ecdsa.PublicKey {
	if c.public_key_algo != .ecdsa {
		return error('x509: certificate public key is not ECDSA')
	}
	if c.public_key_raw.len == 0 {
		return error('x509: empty ECDSA public key')
	}
	// For EC keys public_key_raw is already the uncompressed 0x04||X||Y point this
	// constructor expects; the curve NID stored at parse time completes the input.
	return ecdsa.PublicKey.from_uncompressed_bytes(c.public_key_raw, nid: c.ecdsa_curve)!
}

// parse_asn1_time parses UTCTime (tag 0x17) or GeneralizedTime (tag 0x18) to unix
// seconds. RFC 5280 §4.1.2.5 mandates both forms across the 1950–2049 boundary;
// the two-digit UTCTime year uses the RFC 5280 pivot (YY ≥ 50 ⇒ 19xx, else 20xx).
fn parse_asn1_time(el Asn1Element) !i64 {
	s := el.data.bytestr()
	// UTCTime YYMMDDhhmmssZ: 13 chars = six 2-digit fields + trailing 'Z' (UTC)
	if el.tag == 0x17 && s.len >= 13 {
		yy := s[0..2].int()
		year := if yy >= 50 { 1900 + yy } else { 2000 + yy }
		return time.parse('${year:04}-${s[2..4]}-${s[4..6]} ${s[6..8]}:${s[8..10]}:${s[10..12]}')!.unix()
	}
	// GeneralizedTime YYYYMMDDhhmmssZ: 15 chars = seven 2-digit fields + 'Z'
	if el.tag == 0x18 && s.len >= 15 {
		return time.parse('${s[0..4]}-${s[4..6]}-${s[6..8]} ${s[8..10]}:${s[10..12]}:${s[12..14]}')!.unix()
	}
	return error('x509: unsupported time encoding')
}

// unwrap_octet_string returns the contents of an OCTET STRING TLV, or the input
// unchanged when not wrapped. RFC 5280 encodes extnValue as an OCTET STRING
// containing the extension's DER, but some callers hand us the inner bytes
// directly, so both forms are accepted.
fn unwrap_octet_string(data []u8) []u8 {
	if data.len > 0 && data[0] == 0x04 {
		mut r := wire.new_reader(data)
		elem := read_asn1_element(mut r) or { return data }
		return elem.data
	}
	return data
}

// parse_eku_server_auth reports whether an Extended Key Usage extension value
// (RFC 5280 §4.2.1.12) permits TLS server authentication: the list must contain
// id-kp-serverAuth or the wildcard anyExtendedKeyUsage.
fn parse_eku_server_auth(ext_bytes []u8) bool {
	data := unwrap_octet_string(ext_bytes)
	mut r := wire.new_reader(data)
	seq := read_asn1_element(mut r) or { return false }
	if seq.tag != 0x30 {
		return false
	}
	oids := parse_sequence(seq.data) or { return false }
	for el in oids {
		if el.tag == 0x06 {
			oid := parse_oid(el.data)
			// id-kp-serverAuth
			if oid == '1.3.6.1.5.5.7.3.1' {
				return true
			}
			// anyExtendedKeyUsage
			if oid == '2.5.29.37.0' {
				return true
			}
		}
	}
	return false
}

// extract_cn_from_name finds the Common Name (OID 2.5.4.3) in an ASN.1 Name sequence.
fn extract_cn_from_name(name_bytes []u8) string {
	rdn_seq := parse_sequence(name_bytes) or { return '' }
	for rdn_set in rdn_seq {
		rdn_elems := parse_sequence(rdn_set.data) or { continue }
		for attr in rdn_elems {
			attr_parts := parse_sequence(attr.data) or { continue }
			if attr_parts.len >= 2 {
				oid := parse_oid(attr_parts[0].data)
				if oid == '2.5.4.3' { // commonName
					val := attr_parts[1].data
					// Disallow null bytes (CVE-2009-2408 null byte injection attack)
					if val.contains(0) {
						return ''
					}
					return val.bytestr()
				}
			}
		}
	}
	return ''
}

// parse_san_extension extracts dNSName strings and raw iPAddress bytes (4 for
// IPv4, 16 for IPv6) from a Subject Alternative Name extension (RFC 5280
// §4.2.1.6).
fn parse_san_extension(ext_bytes []u8) ([]string, [][]u8) {
	mut dns := []string{}
	mut ip := [][]u8{}
	// May be wrapped in an OCTET STRING or directly GeneralNames
	inner := unwrap_octet_string(ext_bytes)

	mut r := wire.new_reader(inner)
	seq := read_asn1_element(mut r) or { return dns, ip }
	mut general_names_r := wire.new_reader(seq.data)

	for general_names_r.remaining() > 0 {
		gn := read_asn1_element(mut general_names_r) or { break }
		match gn.tag & 0x1f {
			2 { // [2] dNSName
				// Disallow null bytes (CVE-2009-2408)
				if !gn.data.contains(0) {
					dns << gn.data.bytestr()
				}
			}
			7 { // [7] iPAddress
				// Valid iPAddress must be 4 bytes (IPv4) or 16 bytes (IPv6)
				if gn.data.len == 4 || gn.data.len == 16 {
					ip << gn.data.clone()
				}
			}
			else {}
		}
	}
	return dns, ip
}

// parse_basic_constraints parses the cA boolean from a BasicConstraints extension
// value (RFC 5280 §4.2.1.9):
//
//	BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
fn parse_basic_constraints(ext_bytes []u8) bool {
	inner := unwrap_octet_string(ext_bytes)
	mut r := wire.new_reader(inner)
	seq := read_asn1_element(mut r) or { return false }
	if seq.tag != 0x30 {
		return false
	}
	elements := parse_sequence(seq.data) or { return false }
	// cA has DEFAULT FALSE, so it can be absent entirely: scanning for the first
	// BOOLEAN and finding none yields the default "not a CA".
	for el in elements {
		if el.tag == 0x01 && el.data.len > 0 { // BOOLEAN cA
			return el.data[0] != 0
		}
	}
	return false
}
