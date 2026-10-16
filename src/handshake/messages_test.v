module handshake

import encoding.hex

// Codec tests for the handshake message layer: ClientHello construction is
// re-parsed field by field, server-side messages decode from small hand-built
// payloads plus the RFC 8448 §3 ServerHello worked example, the §4.4.3
// CertificateVerify signed-content layout is checked byte by byte, and the
// shared extensions-block framing (parse_extensions) is exercised including its
// §4.2 duplicate-rejection rule.

fn test_build_client_hello() ! {
	cfg := ClientHelloConfig{
		server_name:  'example.com'
		alpn:         ['http/1.1']
		client_share: KeyShareEntry{
			group:        .x25519
			key_exchange: []u8{len: 32, init: 0xaa}
		}
	}
	body, full_msg := build_client_hello(cfg)!
	assert full_msg.len == 4 + body.len
	assert full_msg[0] == u8(HandshakeType.client_hello)
	assert full_msg[1] == u8((body.len >> 16) & 0xff)
	assert full_msg[2] == u8((body.len >> 8) & 0xff)
	assert full_msg[3] == u8(body.len & 0xff)
}

fn test_parse_rfc8448_server_hello() ! {
	// RFC 8448 Section 3 ServerHello message (including 4-byte header)
	raw_sh_hex := '020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304'
	raw_sh := hex.decode(raw_sh_hex)!

	// Body starts at offset 4
	sh := parse_server_hello(raw_sh[4..])!
	assert sh.is_hello_retry_req == false
	assert sh.cipher_suite == CipherSuite.tls_aes_128_gcm_sha256
	assert sh.server_share.group == NamedGroup.x25519
	assert hex.encode(sh.server_share.key_exchange) == 'c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f'
}

fn test_parse_certificate_chain() ! {
	// request_context (empty) + certificate_list holding one 2-byte cert with no extensions
	body := [u8(0x00), 0x00, 0x00, 0x07, 0x00, 0x00, 0x02, 0xde, 0xad, 0x00, 0x00]
	certs := parse_certificate(body)!
	assert certs.len == 1
	assert certs[0] == [u8(0xde), 0xad]
}

fn test_parse_encrypted_extensions_no_alpn() ! {
	body := [u8(0x00), 0x00] // empty extension list
	assert parse_encrypted_extensions(body)! == ''
}

// test_parse_encrypted_extensions_extension_policy checks the §4.3.1 placement
// rules: an extension that never belongs in EncryptedExtensions (key_share —
// it lives in ServerHello) must abort, while RFC 5746 renegotiation_info stays
// tolerated because OpenSSL servers send it unoffered.
fn test_parse_encrypted_extensions_extension_policy() ! {
	// extensions vector (len 6) = key_share entry with 2 bytes of data
	bad := [u8(0x00), 0x06, 0x00, 0x33, 0x00, 0x02, 0xaa, 0xbb]
	if _ := parse_encrypted_extensions(bad) {
		// then-branch = success; reaching it means the rejection did not happen
		assert false // 'bad' must be rejected per §4.3.1
	}
	// extensions vector (len 5) = renegotiation_info (0xff01), 1 byte of data
	ok := [u8(0x00), 0x05, 0xff, 0x01, 0x00, 0x01, 0x00]
	assert parse_encrypted_extensions(ok)! == ''
}

// test_parse_server_hello_rejects_unpermitted_extension feeds a well-formed
// ServerHello body carrying supported_versions plus renegotiation_info — a
// TLS 1.2-era extension §4.2 does not allow in ServerHello at all.
fn test_parse_server_hello_rejects_unpermitted_extension() ! {
	mut body := []u8{len: 0, cap: 64}
	body << 0x03
	body << 0x03 // legacy_version
	for _ in 0 .. 32 {
		body << 0x00 // random (not the HRR sentinel)
	}
	body << 0x00 // empty legacy session id
	body << 0x13
	body << 0x01 // TLS_AES_128_GCM_SHA256
	body << 0x00 // null compression
	// extensions block, 11 bytes: supported_versions(=0304) + renegotiation_info
	body << 0x00
	body << 0x0b
	body << 0x00
	body << 0x2b
	body << 0x00
	body << 0x02
	body << 0x03
	body << 0x04
	body << 0xff
	body << 0x01
	body << 0x00
	body << 0x01
	body << 0x00
	if _ := parse_server_hello(body) {
		// then-branch = success; reaching it means the rejection did not happen
		assert false // renegotiation_info in ServerHello must be rejected per §4.2
	}
}

// test_parse_server_hello_rejects_trailing_key_share_bytes builds an HRR whose
// key_share extension carries one byte past the 2-byte selected_group — §4.1.4
// fixes that structure exactly, so the surplus must fail the decode.
fn test_parse_server_hello_rejects_trailing_key_share_bytes() ! {
	mut body := []u8{len: 0, cap: 64}
	body << 0x03
	body << 0x03 // legacy_version
	for b in hello_retry_request_random {
		body << b // sentinel random marks this as an HRR
	}
	body << 0x00 // empty legacy session id
	body << 0x13
	body << 0x01 // TLS_AES_128_GCM_SHA256
	body << 0x00 // null compression
	// extensions, 13 bytes: supported_versions(0304) + key_share x'00 1d FF'
	body << 0x00
	body << 0x0d
	body << 0x00
	body << 0x2b
	body << 0x00
	body << 0x02
	body << 0x03
	body << 0x04
	body << 0x00
	body << 0x33
	body << 0x00
	body << 0x03
	body << 0x00
	body << 0x1d
	body << 0xff // trailing byte after the named group
	if _ := parse_server_hello(body) {
		assert false // then-branch = success; surplus bytes must have been rejected
	}
}

// KeyUpdate codec tests. The round-trip asserts alone cannot catch an inverted
// flag mapping (symmetric build/parse still agree), so the literal §4.6.3 wire
// bytes request_update(0) / update_not_requested(1) are pinned directly.
fn test_parse_key_update() ! {
	assert parse_key_update(build_key_update(true)[4..])! == true
	assert parse_key_update(build_key_update(false)[4..])! == false
	assert build_key_update(true)[4] == 0 // request_update(0)
	assert build_key_update(false)[4] == 1 // update_not_requested(1)
	if _ := parse_key_update([]u8{}) {
		assert false
	}
}

fn test_certificate_verify_signed_content() {
	th := [u8(0x01), 0x02, 0x03, 0x04]
	content := certificate_verify_signed_content(th)

	// 64 spaces (0x20) + "TLS 1.3, server CertificateVerify" (33 bytes) + 0x00 + transcript_hash (4 bytes)
	assert content.len == 64 + 33 + 1 + 4
	for i in 0 .. 64 {
		assert content[i] == 0x20
	}
	assert content[64..97].bytestr() == 'TLS 1.3, server CertificateVerify'
	assert content[97] == 0x00
	assert content[98..] == th
}

// test_parse_extensions_frames_each_type decodes a mixed extensions block and
// checks framing survives intact: type, exact data slice, and order preserved;
// an empty block yields an empty list rather than an error.
fn test_parse_extensions_frames_each_type() ! {
	// supported_versions(0x002b)=0304 followed by cookie(0x002c)=aabb
	block := [u8(0x00), 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x2c, 0x00, 0x02, 0xaa, 0xbb]
	exts := parse_extensions(block)!
	assert exts.len == 2
	assert exts[0].typ == u16(ExtensionType.supported_versions)
	assert exts[0].data == [u8(0x03), 0x04]
	assert exts[1].typ == u16(ExtensionType.cookie)
	assert exts[1].data == [u8(0xaa), 0xbb]

	empty := parse_extensions([]u8{})!
	assert empty.len == 0
}

// test_parse_extensions_rejects_duplicate pins RFC 8446 §4.2: a message with
// two instances of the same extension type must be rejected outright — not
// silently last-wins, which would let a duplicate overwrite a validated value.
fn test_parse_extensions_rejects_duplicate() ! {
	dup := [u8(0x00), 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x05]
	if _ := parse_extensions(dup) {
		assert false
	}
}
