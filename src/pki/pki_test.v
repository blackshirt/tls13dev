module pki

// PKI tests: RFC 6125 hostname/wildcard matching, ASN.1 OID decoding, raw
// iPAddress SAN comparison, and loading the host's system trust bundle.

fn test_hostname_matching() {
	// Exact matches
	assert match_hostname('example.com', 'example.com')
	assert match_hostname('EXAMPLE.COM', 'example.com')
	assert match_hostname('api.example.com', 'API.EXAMPLE.COM')

	// Wildcard matches
	assert match_hostname('*.example.com', 'foo.example.com')
	assert match_hostname('*.example.com', 'api.example.com')
	assert match_hostname('*.EXAMPLE.COM', 'api.example.com')

	// Negative wildcard matches
	assert !match_hostname('*.example.com', 'example.com') // Cannot match empty prefix

	assert !match_hostname('*.example.com', 'sub.api.example.com') // Cannot cross label boundaries

	assert !match_hostname('*.example.com', 'foo.badexample.com')
}

fn test_asn1_oid_parsing() {
	// OID 1.2.840.113549.1.1.1 (rsaEncryption) = 2a 86 48 86 f7 0d 01 01 01
	rsa_oid_bytes := [u8(0x2a), 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]
	assert parse_oid(rsa_oid_bytes) == '1.2.840.113549.1.1.1'

	// OID 2.5.4.3 (commonName) = 55 04 03
	cn_oid_bytes := [u8(0x55), 0x04, 0x03]
	assert parse_oid(cn_oid_bytes) == '2.5.4.3'

	// OID 2.100.3: first subidentifier = 2*40 + 100 = 180, a multi-byte varint
	// (81 34), followed by 03.
	multi_byte_first := [u8(0x81), 0x34, 0x03]
	assert parse_oid(multi_byte_first) == '2.100.3'
}

fn test_ip_san_matching() {
	// IPv4 SAN 1.1.1.1
	ipv4 := [u8(1), 1, 1, 1]
	assert ip_san_matches([ipv4], '1.1.1.1')
	assert !ip_san_matches([ipv4], '1.1.1.2')
	assert !ip_san_matches([ipv4], 'example.com')

	// IPv6 SAN ::1 (15 zero bytes followed by 0x01)
	mut ipv6 := []u8{len: 16}
	ipv6[15] = 1
	assert ip_san_matches([ipv6], '::1')
	assert ip_san_matches([ipv6], '0:0:0:0:0:0:0:1')
	assert !ip_san_matches([ipv6], '::2')

	// Both families in one certificate
	assert ip_san_matches([ipv4, ipv6], '::1')
	assert !ip_san_matches([], '1.1.1.1')
}

fn test_system_trust_store_loading() {
	mut ts := new_trust_store()
	count := ts.load_system_ca_bundle() or { 0 }
	// On this Linux system, ca-certificates should contain > 50 root CAs
	assert count > 0
}
