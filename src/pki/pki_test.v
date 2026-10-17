// PKI tests: RFC 6125 hostname/wildcard matching including the SAN-vs-CN
// precedence rule, ASN.1 OID decoding, raw iPAddress SAN comparison, and
// loading the host's system trust bundle.
module pki

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

	// Only a leftmost full-label '*' is special (CA/Browser Baseline profile):
	// a bare '*', a partial-label '*x', or an inner '.*.' must never wildcard.
	assert !match_hostname('*', 'example.com')
	assert !match_hostname('*x.example.com', 'ax.example.com')
	assert !match_hostname('foo.*.com', 'foo.bar.com')

	// Wildcards must never match TLDs (RFC 6125 §6.4.3)
	assert !match_hostname('*.com', 'example.com')
	assert !match_hostname('*.org', 'site.org')

	// Wildcards must never match IP addresses (RFC 6125 §6.4.3)
	assert !match_hostname('*.1.1.1', '1.1.1.1')
	assert !match_hostname('*.168.1.1', '192.168.1.1')
}

// test_verify_hostnames pins the SAN-vs-CN precedence rule of RFC 6125 §6.4.4:
// the presence of ANY dNSName SAN disables CN checking entirely; the CN is only
// consulted for legacy certs with no SAN list at all.
fn test_verify_hostnames() {
	// SAN list present but non-matching while the CN WOULD match: must still
	// fail — this is the exact confused-deputy case that deprecated CN checks.
	assert !verify_hostnames(['a.example'], 'example.com', 'example.com')

	// Any matching SAN wins; non-matching siblings and the CN are irrelevant.
	assert verify_hostnames(['a.example', 'b.example'], 'wrong.cn', 'b.example')

	// Wildcards inside the SAN list follow the matcher's rules.
	assert verify_hostnames(['*.example.com'], '', 'api.example.com')
	assert !verify_hostnames(['*.example.com'], '', 'a.b.example.com')

	// No SANs: legacy CN fallback, wildcard included.
	assert verify_hostnames([], 'example.com', 'example.com')
	assert verify_hostnames([], '*.example.com', 'api.example.com')

	// Neither SANs nor CN: nothing can authorize the name.
	assert !verify_hostnames([], '', 'example.com')
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

	// Unterminated varint in OID must return empty string
	truncated_oid := [u8(0x2a), 0x86, 0x48, 0x86]
	assert parse_oid(truncated_oid) == ''
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
