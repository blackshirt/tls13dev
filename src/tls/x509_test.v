// Copyright (c) 2026 blackshirt.
//
// X.509 decoding tests aimed at the extension/name helpers that parse_certificate
// delegates to, built from hand-assembled DER: SAN dNSName/iPAddress extraction
// with the CVE-2009-2408 null-byte and bad-length guards, BasicConstraints CA
// flag (including the DEFAULT-FALSE absent case), ExtendedKeyUsage serverAuth /
// anyExtendedKeyUsage recognition, commonName extraction from a Name, UTCTime /
// GeneralizedTime parsing with the RFC 5280 year pivot, OCTET STRING unwrapping,
// and parse_certificate's structural rejection of non-SEQUENCE/truncated input.
module tls

fn test_parse_san_extension() ! {
	// GeneralNames = SEQUENCE of dNSName [2] "example.com" and iPAddress [7] 1.1.1.1.
	// Context tags are primitive: [2] => 0x82, [7] => 0x87.
	dns_bytes := 'example.com'.bytes() // 11 ASCII bytes
	mut body := []u8{}
	body << u8(0x82)
	body << u8(dns_bytes.len)
	body << dns_bytes
	body << u8(0x87)
	body << u8(4)
	body << [u8(1), 1, 1, 1]
	mut der := []u8{}
	der << u8(0x30)
	der << u8(body.len)
	der << body

	dns, ip := parse_san_extension(der)
	assert dns == ['example.com']
	assert ip.len == 1
	assert ip[0] == [u8(1), 1, 1, 1]
}

fn test_parse_san_extension_rejects_null_and_bad_ip() ! {
	// dNSName with an embedded NUL (0x00) is dropped (CVE-2009-2408); an
	// iPAddress of 5 bytes (neither 4 nor 16) is ignored.
	mut body := []u8{}
	body << u8(0x82)
	body << u8(3)
	body << [u8(0x61), 0x00, 0x62]
	body << u8(0x87)
	body << u8(5)
	body << [u8(1), 2, 3, 4, 5]
	mut der := []u8{}
	der << u8(0x30)
	der << u8(body.len)
	der << body

	dns, ip := parse_san_extension(der)
	assert dns.len == 0
	assert ip.len == 0
}

fn test_parse_basic_constraints() {
	// SEQUENCE { BOOLEAN cA = TRUE }
	ca := [u8(0x30), 0x03, 0x01, 0x01, 0xff]
	assert parse_basic_constraints(ca)
	// cA DEFAULT FALSE when the SEQUENCE is empty.
	empty_seq := [u8(0x30), 0x00]
	assert !parse_basic_constraints(empty_seq)
	// Explicit cA = FALSE.
	not_ca := [u8(0x30), 0x03, 0x01, 0x01, 0x00]
	assert !parse_basic_constraints(not_ca)
}

fn test_parse_eku_server_auth() {
	// SEQUENCE { OID id-kp-serverAuth (1.3.6.1.5.5.7.3.1) }
	server_auth := [u8(0x30), 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]
	assert parse_eku_server_auth(server_auth)
	// SEQUENCE { OID anyExtendedKeyUsage (2.5.29.37.0) } also satisfies it.
	any_eku := [u8(0x30), 0x06, 0x06, 0x04, 0x55, 0x1d, 0x25, 0x00]
	assert parse_eku_server_auth(any_eku)
	// id-kp-clientAuth (...3.2) is NOT server auth.
	client_auth := [u8(0x30), 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]
	assert !parse_eku_server_auth(client_auth)
}

fn test_extract_cn_from_name() {
	// A single RDN SET holding one Attribute SEQUENCE: OID commonName (2.5.4.3)
	// plus a PrintableString value. extract_cn receives the Name's child bytes.
	mut oid_el := []u8{}
	oid_el << [u8(0x06), 0x03, 0x55, 0x04, 0x03]
	val_bytes := 'example'.bytes()
	mut val_el := []u8{}
	val_el << u8(0x13)
	val_el << u8(val_bytes.len)
	val_el << val_bytes
	mut attr_body := []u8{}
	attr_body << oid_el
	attr_body << val_el
	mut attr := []u8{}
	attr << u8(0x30)
	attr << u8(attr_body.len)
	attr << attr_body
	mut name := []u8{}
	name << u8(0x31)
	name << u8(attr.len)
	name << attr
	assert extract_cn_from_name(name) == 'example'

	// A NUL byte in the value must yield "" (CVE-2009-2408).
	mut bad_val := []u8{}
	bad_val << [u8(0x13), 0x03, 0x61, 0x00, 0x62]
	mut bad_attr_body := []u8{}
	bad_attr_body << oid_el
	bad_attr_body << bad_val
	mut bad_attr := []u8{}
	bad_attr << u8(0x30)
	bad_attr << u8(bad_attr_body.len)
	bad_attr << bad_attr_body
	mut bad_name := []u8{}
	bad_name << u8(0x31)
	bad_name << u8(bad_attr.len)
	bad_name << bad_attr
	assert extract_cn_from_name(bad_name) == ''
}

fn test_parse_asn1_time() ! {
	// UTCTime (0x17) and GeneralizedTime (0x18) both decode to a unix value;
	// any other tag is an unsupported encoding.
	utc := Asn1Element{ tag: u8(0x17), is_construct: false, data: '210101000000Z'.bytes() }
	assert parse_asn1_time(utc)! != 0
	gen := Asn1Element{ tag: u8(0x18), is_construct: false, data: '20210101000000Z'.bytes() }
	assert parse_asn1_time(gen)! != 0

	bad := Asn1Element{ tag: u8(0x0c), is_construct: false, data: 'whatever'.bytes() }
	parse_asn1_time(bad) or {
		assert err.msg().contains('unsupported time encoding')
		return
	}
	assert false
}

fn test_unwrap_octet_string() {
	// A DER OCTET STRING (0x04) wrapper is unwrapped to its contents...
	wrapped := [u8(0x04), 0x03, 0xaa, 0xbb, 0xcc]
	assert unwrap_octet_string(wrapped) == [u8(0xaa), 0xbb, 0xcc]
	// ...while non-OCTET-STRING input is returned unchanged.
	raw := [u8(0x30), 0x00]
	assert unwrap_octet_string(raw) == raw
}

fn test_parse_certificate_rejects_non_sequence() ! {
	// A certificate must begin with an ASN.1 SEQUENCE (0x30); an INTEGER (0x02)
	// header is rejected rather than walked further.
	if _ := parse_certificate([u8(0x02), 0x01, 0x05]) {
		assert false
	}
}

fn test_parse_certificate_rejects_truncated() ! {
	// A single byte cannot even hold a TLV header.
	if _ := parse_certificate([u8(0x30)]) {
		assert false
	}
}
