// Copyright (c) 2026 blackshirt.
//
// x509.v decodes DER-encoded X.509 v3 certificates into a Certificate: subject
// and issuer names, validity window, public key, signature algorithm and the
// SAN/basic-constraints extensions validator.v and hostname.v consume.
module pki

import crypto.ecdsa
import time
import tls.wire

// PublicKeyAlgorithm identifies the type of public key in a certificate.
pub enum PublicKeyAlgorithm {
	rsa
	ecdsa
	ed25519
	unknown
}

// Certificate represents a decoded X.509 certificate (RFC 5280); only
// parse_certificate may produce one (@[noinit], read-only fields).
@[noinit]
pub struct Certificate {
pub:
	// Read-only outside tls.pki; consumed by the CertificateVerify check and this module's chain/hostname validation.
	public_key_algo    PublicKeyAlgorithm
	public_key_raw     []u8          // SubjectPublicKeyInfo BIT STRING contents
	rsa_public_key     ?RsaPublicKey // set when public_key_algo is .rsa
	ecdsa_curve        ecdsa.Nid     // curve of the EC key, NID form
	raw                []u8          // full DER-encoded certificate as received
	tbs_raw            []u8          // DER of the TBSCertificate — exactly the bytes the issuer signed
	version            int           // X.509 version (3 = v3); encoded value is version-1
	serial_number      []u8          // issuer-assigned serial, big-endian
	signature_algo_oid string        // OID of the signature AlgorithmIdentifier
	// signature_hash_oid holds the hash algorithm OID for PSS signatures.
	signature_hash_oid string
	issuer_cn          string // commonName of the issuer
	subject_cn         string // commonName of the subject
	// issuer_dn and subject_dn hold the DER-encoded RDNSequence contents of the Name fields.
	issuer_dn       []u8
	subject_dn      []u8
	not_before      string // validity start, RFC 5280 UTCTime/GeneralizedTime as written
	not_after       string // validity end, same encoding as not_before
	not_before_unix i64    // not_before in Unix seconds, for easy comparison
	not_after_unix  i64    // not_after in Unix seconds
	// sans holds dNSName SAN entries only; rfc822Name is excluded (RFC 6125 §2.1).
	sans []string
	// ip_sans holds the raw bytes of each iPAddress SAN (4 bytes IPv4, 16 IPv6).
	ip_sans         [][]u8
	has_san         bool // the SAN extension was present at all (RFC 6125 §6.4.4 CN precedence)
	is_ca           bool // basicConstraints CA flag; intermediates must have it
	max_path_len    int  // basicConstraints pathLenConstraint; -1 when absent (unlimited)
	has_key_usage   bool // keyUsage extension present (RFC 5280 §4.2.1.3)
	key_usage       []u8 // BIT STRING contents of keyUsage, big-endian named bits
	has_eku         bool // an extendedKeyUsage extension was present at all
	eku_server_auth bool // EKU includes id-kp-serverAuth, required for TLS servers
	// name_constraints restricts the namespace of subordinate names (RFC 5280
	// §4.2.1.10); permitted_* / excluded_* hold the subtrees per name form.
	name_constraints_present bool
	permitted_dns            []string
	excluded_dns             []string
	permitted_ip             [][]u8
	excluded_ip              [][]u8
	signature                []u8 // BIT STRING contents of signatureValue
}

// parse_certificate decodes an X.509 DER certificate.
// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
pub fn parse_certificate(der []u8) !Certificate {
	mut r := wire.new_reader(der)
	cert_seq := read_asn1_element(mut r)!
	if cert_seq.tag != 0x30 {
		return error('x509: certificate must begin with SEQUENCE (0x30), got 0x${cert_seq.tag:02x}')
	}
	if r.remaining() != 0 {
		return error('x509: trailing data after certificate')
	}
	// Re-parse to capture the TBSCertificate's exact DER bytes: the message the issuer signed.
	mut inner := wire.new_reader(cert_seq.data)
	tbs_start := inner.pos()
	tbs_elem := read_asn1_element(mut inner)!
	if tbs_elem.tag != 0x30 {
		return error('x509: TBSCertificate must be a SEQUENCE')
	}
	tbs_raw := cert_seq.data[tbs_start..inner.pos()].clone()
	// RFC 5280 §4.1.2.3: the outer signatureAlgorithm must match TBSCertificate.signature.
	outer_sig_alg_elem := read_asn1_element(mut inner)!
	if outer_sig_alg_elem.tag != 0x30 {
		return error('x509: outer signatureAlgorithm must be a SEQUENCE')
	}
	sig_val_elem := read_asn1_element(mut inner)!
	if sig_val_elem.tag != 0x03 || sig_val_elem.data.len == 0
		|| sig_val_elem.data[0] != 0 {
		return error('x509: malformed signatureValue BIT STRING')
	}
	if inner.remaining() != 0 {
		return error('x509: trailing fields inside Certificate')
	}

	tbs_elements := parse_sequence(tbs_elem.data)!
	// Minimum 6 elements: serial, signature alg, issuer, validity, subject, SPKI.
	if tbs_elements.len < 6 {
		return error('x509: malformed TBSCertificate (${tbs_elements.len} elements)')
	}

	mut idx := 0

	// 1. Version [0] EXPLICIT, absent for v1 (the default): consume it only when the first element carries context tag 0.
	mut version := 1
	if (tbs_elements[0].tag & 0x1f) == 0 {
		mut version_r := wire.new_reader(tbs_elements[0].data)
		version_elem := read_asn1_element(mut version_r)!
		if version_elem.data.len > 0 {
			// Encoded 0-based (v1 = 0, v3 = 2); expose the human value.
			version = int(version_elem.data[0]) + 1
		}
		idx++
	}

	// The six mandatory fields after the optional version must all be present: measuring against the post-version idx closes the v3 index-shift gap.
	if tbs_elements.len - idx < 6 {
		return error('x509: malformed TBSCertificate (need 6 fields after version, have ${tbs_elements.len - idx})')
	}

	// 2. Serial Number (INTEGER)
	serial_number := tbs_elements[idx].data.clone()
	idx++

	// 3. Signature Algorithm (AlgorithmIdentifier)
	if tbs_elements[idx].tag != 0x30
		|| tbs_elements[idx].data != outer_sig_alg_elem.data {
		return error('x509: outer and TBSCertificate signatureAlgorithm mismatch')
	}
	sig_alg_inner := parse_sequence(tbs_elements[idx].data)!
	mut tbs_sig_algo_oid := ''
	mut tbs_sig_hash_oid := ''
	if sig_alg_inner.len > 0 {
		tbs_sig_algo_oid = parse_oid(sig_alg_inner[0].data)
		// For id-RSASSA-PSS (1.2.840.113549.1.1.10), extract the hash OID from the RSASSA-PSS-params SEQUENCE's hashAlgorithm [0] field.
		if tbs_sig_algo_oid == '1.2.840.113549.1.1.10' && sig_alg_inner.len >= 2 {
			pss_params := parse_sequence(sig_alg_inner[1].data) or { []Asn1Element{} }
			for param in pss_params {
				// [0] EXPLICIT -- hashAlgorithm: 0xa0 = context-specific class + constructed bit, & 0x1f == 0 pins the tag to [0].
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
	// RFC 5280 §4.1.2.5: both fields are mandatory; an unparseable time is a fatal decode error, never a stored 0.
	if val_elems.len < 2 {
		return error('x509: validity must hold notBefore and notAfter (${val_elems.len} elements)')
	}
	not_before := val_elems[0].data.bytestr()
	not_after := val_elems[1].data.bytestr()
	not_before_unix := parse_asn1_time(val_elems[0])!
	not_after_unix := parse_asn1_time(val_elems[1])!
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
					// Parse the named curve OID from AlgorithmIdentifier.parameters.
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
					// Leave pk_algo == .unknown; verify_cert_signature's catch-all rejects the cert.
				}
			}
		}

		// The BIT STRING's first byte is the unused-bits count (always 0 here); skip it.
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

	// Extensions [3] EXPLICIT (optional; absent in v1).
	// Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue }
	mut sans := []string{}
	mut ip_sans := [][]u8{}
	mut has_san := false
	mut is_ca := false
	mut max_path_len := -1
	mut has_key_usage := false
	mut key_usage := []u8{}
	mut has_eku := false
	mut eku_server_auth := false
	mut nc_present := false
	mut permitted_dns := []string{}
	mut excluded_dns := []string{}
	mut permitted_ip := [][]u8{}
	mut excluded_ip := [][]u8{}
	// RFC 5280 §4.2: each extension OID may appear at most once; a duplicate must not overwrite the first.
	mut seen_ext_oids := []string{}

	for i in idx .. tbs_elements.len {
		el := tbs_elements[i]
		if (el.tag & 0x1f) == 3 { // [3] Context tag
			ext_seq_wrap := parse_sequence(el.data)!
			if ext_seq_wrap.len > 0 {
				ext_list := parse_sequence(ext_seq_wrap[0].data)!
				for ext in ext_list {
					parts := parse_sequence(ext.data)!
					if parts.len < 2 || parts.len > 3 {
						return error('x509: malformed extension (${parts.len} elements)')
					}
					ext_oid := parse_oid(parts[0].data)
					if ext_oid in seen_ext_oids {
						return error('x509: duplicate extension ${ext_oid}')
					}
					seen_ext_oids << ext_oid
					// Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue }: with the critical flag omitted extnValue sits at index 1, else index 2.
					mut critical := false
					ext_val_bytes := if parts.len == 2 {
						parts[1].data
					} else {
						if parts[1].tag != 0x01 || parts[1].data.len != 1 {
							return error('x509: malformed critical flag for extension ${ext_oid}')
						}
						critical = parts[1].data[0] != 0
						parts[2].data
					}

					match ext_oid {
						'2.5.29.17' { // Subject Alternative Name (SAN)
							// Presence of the extension — even with no usable names — disables the CN fallback (RFC 6125 §6.4.4).
							has_san = true
							sans, ip_sans = parse_san_extension(ext_val_bytes)
						}
						'2.5.29.15' { // Key Usage
							key_usage = parse_key_usage(ext_val_bytes)
							has_key_usage = true
						}
						'2.5.29.19' { // Basic Constraints
							ca, path_len := parse_basic_constraints(ext_val_bytes)
							is_ca = ca
							max_path_len = path_len
						}
						'2.5.29.37' { // Extended Key Usage
							has_eku = true
							eku_server_auth = parse_eku_server_auth(ext_val_bytes)
						}
						'2.5.29.30' { // Name Constraints (RFC 5280 §4.2.1.10)
							nc_present = true
							permitted_dns, excluded_dns, permitted_ip, excluded_ip = parse_name_constraints(ext_val_bytes)
						}
						else {
							// RFC 5280 §4.2: an unknown critical extension MUST be rejected (a constrained CA must not issue outside its sandbox).
							if critical {
								return error('x509: unsupported critical extension ${ext_oid}')
							}
						}
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
		raw:                      der.clone()
		tbs_raw:                  tbs_raw
		version:                  version
		serial_number:            serial_number
		signature_algo_oid:       tbs_sig_algo_oid
		signature_hash_oid:       tbs_sig_hash_oid
		issuer_cn:                issuer_cn
		subject_cn:               subject_cn
		issuer_dn:                issuer_dn
		subject_dn:               subject_dn
		not_before:               not_before
		not_after:                not_after
		not_before_unix:          not_before_unix
		not_after_unix:           not_after_unix
		public_key_algo:          pk_algo
		public_key_raw:           raw_pk_bytes
		rsa_public_key:           rsa_key
		ecdsa_curve:              ecdsa_curve
		sans:                     sans
		ip_sans:                  ip_sans
		has_san:                  has_san
		is_ca:                    is_ca
		max_path_len:             max_path_len
		has_key_usage:            has_key_usage
		key_usage:                key_usage
		has_eku:                  has_eku
		eku_server_auth:          eku_server_auth
		name_constraints_present: nc_present
		permitted_dns:            permitted_dns
		excluded_dns:             excluded_dns
		permitted_ip:             permitted_ip
		excluded_ip:              excluded_ip
		signature:                signature_bytes
	}
}

// ecdsa_public_key reconstructs an ECDSA public key from the SPKI bit string and the parsed curve.
fn (c &Certificate) ecdsa_public_key() !ecdsa.PublicKey {
	if c.public_key_algo != .ecdsa {
		return error('x509: certificate public key is not ECDSA')
	}
	if c.public_key_raw.len == 0 {
		return error('x509: empty ECDSA public key')
	}
	// public_key_raw is already the uncompressed 0x04||X||Y point; the stored curve NID completes the input.
	return ecdsa.PublicKey.from_uncompressed_bytes(c.public_key_raw, nid: c.ecdsa_curve)!
}

// is_digits reports whether s is non-empty and all ASCII digits, so
// parse_asn1_time rejects a malformed time before slicing its fields.
fn is_digits(s string) bool {
	if s.len == 0 {
		return false
	}
	for b in s.bytes() {
		if b < `0` || b > `9` {
			return false
		}
	}
	return true
}

// parse_asn1_time parses UTCTime (0x17) or GeneralizedTime (0x18) to unix seconds
// (RFC 5280 §4.1.2.5, YY ≥ 50 ⇒ 19xx); widths and digits are enforced exactly.
fn parse_asn1_time(el Asn1Element) !i64 {
	s := el.data.bytestr()
	// UTCTime YYMMDDhhmmssZ: six 2-digit fields + trailing 'Z' (UTC)
	if el.tag == 0x17 && s.len == 13 && is_digits(s[..12]) && s[12] == `Z` {
		yy := s[0..2].int()
		year := if yy >= 50 { 1900 + yy } else { 2000 + yy }
		return time.parse('${year:04}-${s[2..4]}-${s[4..6]} ${s[6..8]}:${s[8..10]}:${s[10..12]}')!.unix()
	}
	// GeneralizedTime YYYYMMDDhhmmssZ: seven 2-digit fields + trailing 'Z' (UTC)
	if el.tag == 0x18 && s.len == 15 && is_digits(s[..14]) && s[14] == `Z` {
		return time.parse('${s[0..4]}-${s[4..6]}-${s[6..8]} ${s[8..10]}:${s[10..12]}:${s[12..14]}')!.unix()
	}
	return error('x509: unsupported time encoding')
}

// unwrap_octet_string returns the contents of an OCTET STRING TLV, or the input
// unchanged when not wrapped (RFC 5280 wraps extnValue in an OCTET STRING).
fn unwrap_octet_string(data []u8) []u8 {
	if data.len > 0 && data[0] == 0x04 {
		mut r := wire.new_reader(data)
		elem := read_asn1_element(mut r) or { return data }
		return elem.data
	}
	return data
}

// parse_eku_server_auth reports whether an EKU extension value (RFC 5280
// §4.2.1.12) permits server authentication (id-kp-serverAuth or anyExtendedKeyUsage).
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
					// Disallow null bytes (CVE-2009-2408 null byte injection).
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
// IPv4, 16 for IPv6) from a SAN extension (RFC 5280 §4.2.1.6).
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
		// GeneralName choices are context-specific and primitive ([2] = 0x82, [7] = 0x87); a clear constructed bit stops a tag collision.
		if (gn.tag & 0xc0) != 0x80 || (gn.tag & 0x20) != 0 {
			continue
		}
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

// parse_name_constraints decodes the NameConstraints value (RFC 5280 §4.2.1.10)
// into the permitted/excluded dNSName and iPAddress subtrees (the only forms kept).
fn parse_name_constraints(ext_bytes []u8) ([]string, []string, [][]u8, [][]u8) {
	mut permitted_dns := []string{}
	mut excluded_dns := []string{}
	mut permitted_ip := [][]u8{}
	mut excluded_ip := [][]u8{}

	inner := unwrap_octet_string(ext_bytes)
	mut r := wire.new_reader(inner)
	seq := read_asn1_element(mut r) or { return permitted_dns, excluded_dns, permitted_ip, excluded_ip }
	mut body := wire.new_reader(seq.data)

	for body.remaining() > 0 {
		field := read_asn1_element(mut body) or { break }
		// [0] permittedSubtrees and [1] excludedSubtrees are context-specific CONSTRUCTED tags (0xa0, 0xa1).
		is_permitted := field.tag == 0xa0
		is_excluded := field.tag == 0xa1
		if !is_permitted && !is_excluded {
			continue
		}
		mut subtrees := wire.new_reader(field.data)
		// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree, wrapped by the [0]/[1] field.
		if subtrees.remaining() == 0 {
			continue
		}
		list := read_asn1_element(mut subtrees) or { continue }
		mut entries := wire.new_reader(list.data)
		for entries.remaining() > 0 {
			gs := read_asn1_element(mut entries) or { break }
			// Each GeneralSubtree is a SEQUENCE whose first element is the base GeneralName.
			mut gs_body := wire.new_reader(gs.data)
			if gs_body.remaining() == 0 {
				continue
			}
			base := read_asn1_element(mut gs_body) or { continue }
			if (base.tag & 0xc0) != 0x80 || (base.tag & 0x20) != 0 {
				continue
			}
			match base.tag & 0x1f {
				2 { // [2] dNSName
					if base.data.contains(0) {
						continue // null-byte smuggling guard, as in SAN parsing
					}
					name := base.data.bytestr()
					if is_permitted {
						permitted_dns << name
					} else {
						excluded_dns << name
					}
				}
				7 { // [7] iPAddress
					// In nameConstraints an iPAddress subtree is address+mask (8 bytes IPv4, 32 IPv6), not the bare 4/16 of a SAN.
					if base.data.len == 8 || base.data.len == 32 {
						if is_permitted {
							permitted_ip << base.data.clone()
						} else {
							excluded_ip << base.data.clone()
						}
					}
				}
				else {}
			}
		}
	}
	return permitted_dns, excluded_dns, permitted_ip, excluded_ip
}

// parse_path_len_constraint decodes a BasicConstraints pathLenConstraint INTEGER,
// enforcing the RFC 5280 §4.2.1.9 (0..MAX) range and DER minimal encoding;
// any invalid/negative/non-minimal/oversized form collapses to 0 (never -1).
fn parse_path_len_constraint(data []u8) int {
	if data.len == 0 || data.len > 4 {
		return 0
	}
	// Negative INTEGER: the sign bit of the first content octet is set.
	if data[0] & 0x80 != 0 {
		return 0
	}
	// Non-minimal: a leading 0x00 is only legal to keep a high-bit-set value
	// positive, but that case is excluded above, so any leading zero is redundant.
	if data.len > 1 && data[0] == 0 {
		return 0
	}
	mut v := u32(0)
	for b in data {
		// Accumulated unsigned so the byte-wise shift can never trip a signed
		// overflow, then widened into the int field.
		v = (v << 8) | u32(b)
	}
	return int(v)
}

// parse_basic_constraints parses the cA boolean and pathLenConstraint (RFC 5280 §4.2.1.9).
// The path limit is -1 only when the INTEGER is absent (unlimited); a present-but-malformed one yields 0.
fn parse_basic_constraints(ext_bytes []u8) (bool, int) {
	inner := unwrap_octet_string(ext_bytes)
	mut r := wire.new_reader(inner)
	seq := read_asn1_element(mut r) or { return false, -1 }
	if seq.tag != 0x30 {
		return false, -1
	}
	elements := parse_sequence(seq.data) or { return false, -1 }
	mut ca := false
	mut found_ca := false
	mut path_len := -1
	mut found_path := false
	for el in elements {
		if el.tag == 0x01 && el.data.len > 0 && !found_ca { // BOOLEAN cA
			ca = el.data[0] != 0
			found_ca = true
		} else if el.tag == 0x02 && !found_path { // INTEGER pathLen (first wins)
			found_path = true
			path_len = parse_path_len_constraint(el.data)
		}
	}
	// cA has DEFAULT FALSE, so an absent BOOLEAN means "not a CA".
	return ca, path_len
}

// parse_key_usage returns the BIT STRING contents of a keyUsage extension
// (RFC 5280 §4.2.1.3), big-endian named bits; an empty result means "no usage asserted".
fn parse_key_usage(ext_bytes []u8) []u8 {
	inner := unwrap_octet_string(ext_bytes)
	mut r := wire.new_reader(inner)
	seq := read_asn1_element(mut r) or { return []u8{} }
	if seq.tag != 0x03 || seq.data.len < 1 {
		return []u8{}
	}
	unused_bits := seq.data[0]
	bits := seq.data[1..]
	// BIT STRING constraint of X.690 §10.5: unused bits must fit in the last octet; a violation makes the whole extension untrustworthy.
	if unused_bits > 7 || (bits.len == 0 && unused_bits != 0) {
		return []u8{}
	}
	return bits.clone()
}

// key_usage_bit reports whether named bit `n` (0 = digitalSignature, from the MSB of the first octet per RFC 5280 §4.2.1.3) is asserted.
fn key_usage_bit(ku []u8, n int) bool {
	byte_idx := n >> 3
	if byte_idx >= ku.len {
		return false
	}
	return (ku[byte_idx] & u8(0x80 >> (n & 7))) != 0
}
