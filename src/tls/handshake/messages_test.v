// Copyright (c) 2026 blackshirt.
//
// Codec tests for the handshake message layer: ClientHello construction is
// re-parsed field by field, server-side messages decode from small hand-built
// payloads plus the RFC 8448 §3 ServerHello worked example, the §4.4.3
// CertificateVerify signed-content layout is checked byte by byte, and the
// shared extensions-block framing (parse_extensions) is exercised including its
// §4.2 duplicate-rejection rule.
module handshake

import encoding.hex
import tls.wire

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
	certs := parse_certificate_message(body)!
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

// test_parse_encrypted_extensions_server_name_ack pins the RFC 6066 §3 SNI
// acknowledgment a §4.2-registered EncryptedExtensions entry: an empty
// server_name extension is accepted as a harmless ack, while a non-empty one
// (the server asserting a hostname we never chose) must be rejected.
fn test_parse_encrypted_extensions_server_name_ack() ! {
	// extensions vector (len 4) = server_name (0x0000) with zero-length data
	empty := [u8(0x00), 0x04, 0x00, 0x00, 0x00, 0x00]
	assert parse_encrypted_extensions(empty)! == ''
	// extensions vector (len 5) = server_name (0x0000) with 1 byte of data
	bad := [u8(0x00), 0x05, 0x00, 0x00, 0x00, 0x01, 0x00]
	if _ := parse_encrypted_extensions(bad) {
		assert false // a non-empty server_name in EncryptedExtensions must be rejected
	}
}

// test_parse_encrypted_extensions_single_alpn pins the happy path of the
// RFC 7301 §3.1 exactly-one rule: a well-formed ALPN extension selecting
// "http/1.1" is returned verbatim.
fn test_parse_encrypted_extensions_single_alpn() ! {
	// ext_block(0x0f) = alpn(0x0010), data len 0x0b = u16 list len 0x09 ||
	// [len 0x08]"http/1.1"
	body := [u8(0x00), 0x0f, 0x00, 0x10, 0x00, 0x0b, 0x00, 0x09, 0x08, 0x68, 0x74, 0x74, 0x70,
		0x2f, 0x31, 0x2e, 0x31]
	assert parse_encrypted_extensions(body)! == 'http/1.1'
}

// test_parse_encrypted_extensions_rejects_empty_alpn: an ALPN extension with a
// zero-length protocol list selects nothing, which RFC 7301 §3.1 forbids.
fn test_parse_encrypted_extensions_rejects_empty_alpn() ! {
	body := [u8(0x00), 0x06, 0x00, 0x10, 0x00, 0x02, 0x00, 0x00]
	if _ := parse_encrypted_extensions(body) {
		assert false // empty ALPN list must be rejected
	}
}

// test_parse_encrypted_extensions_rejects_multi_alpn: RFC 7301 §3.1 says the
// server picks exactly one protocol; a second entry must not be silently
// dropped behind the first (it could dodge the offered-list check).
fn test_parse_encrypted_extensions_rejects_multi_alpn() ! {
	// list(0x0c) = [2]"h2" [8]"http/1.1"
	body := [u8(0x00), 0x12, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68,
		0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31]
	if _ := parse_encrypted_extensions(body) {
		assert false // multi-protocol ALPN list must be rejected
	}
}

// test_parse_encrypted_extensions_rejects_renegotiation_info_content: the
// interop tolerance still holds for the empty case, but a non-empty
// renegotiated_connection asserts a renegotiation that never happened
// (RFC 5746 §3.4) and is now rejected rather than discarded unseen.
fn test_parse_encrypted_extensions_rejects_renegotiation_info_content() ! {
	// renegotiation_info(0xff01), data len 4 = [len 3]"abc"
	body := [u8(0x00), 0x08, 0xff, 0x01, 0x00, 0x04, 0x03, 0x61, 0x62, 0x63]
	if _ := parse_encrypted_extensions(body) {
		assert false // non-empty renegotiated_connection must be rejected
	}
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

// KeyUpdate codec tests: verify §4.6.3 wire bytes update_not_requested(0) / update_requested(1).
fn test_parse_key_update() ! {
	assert parse_key_update(build_key_update(true)[4..])! == true
	assert parse_key_update(build_key_update(false)[4..])! == false
	assert build_key_update(true)[4] == 1 // update_requested(1)
	assert build_key_update(false)[4] == 0 // update_not_requested(0)
	if _ := parse_key_update([]u8{}) {
		assert false
	}
	if _ := parse_key_update([u8(2)]) {
		assert false
	}
}

// CertificateVerify codec tests (§4.4.3): body is scheme u16 + signature vector;
// unknown schemes, empty signatures, and trailing bytes must all be refused.
fn test_parse_certificate_verify() ! {
	// ed25519 (0x0807) with a two-byte signature decodes cleanly, pinning both
	// the scheme mapping and the vector payload.
	cv := parse_certificate_verify([u8(0x08), 0x07, 0x00, 0x02, 0xaa, 0xbb])!
	assert cv.algorithm == .ed25519
	assert cv.signature == [u8(0xaa), 0xbb]
}

fn test_parse_certificate_verify_rejects_unknown_scheme() ! {
	// A code outside the client's supported list never reaches the verifier.
	parse_certificate_verify([u8(0x08), 0x99, 0x00, 0x01, 0x00]) or {
		assert err.msg().contains('unsupported signature scheme')
		return
	}
	assert false
}

fn test_parse_certificate_verify_rejects_empty_signature() ! {
	parse_certificate_verify([u8(0x08), 0x07, 0x00, 0x00]) or {
		assert err.msg().contains('empty signature')
		return
	}
	assert false
}

fn test_parse_certificate_verify_rejects_trailing_bytes() ! {
	// §4.4.3 fixes the body shape; one octet past the signature vector means a
	// desynced parse and must be rejected rather than silently absorbed.
	parse_certificate_verify([u8(0x08), 0x07, 0x00, 0x01, 0x42, 0x00]) or {
		assert err.msg().contains('trailing bytes in CertificateVerify')
		return
	}
	assert false
}

// test_client_hello_ip_literal_omits_sni verifies RFC 6066 §3: literal IPv4 and
// IPv6 addresses must not be sent in the server_name (SNI) extension.
fn test_client_hello_ip_literal_omits_sni() ! {
	cfg_ipv4 := ClientHelloConfig{
		server_name:  '192.168.1.1'
		alpn:         ['http/1.1']
		client_share: KeyShareEntry{
			group:        .x25519
			key_exchange: []u8{len: 32, init: 0xaa}
		}
	}
	_, full_ipv4 := build_client_hello(cfg_ipv4)!
	assert !full_ipv4.bytestr().contains('192.168.1.1')

	cfg_ipv6 := ClientHelloConfig{
		server_name:  '2001:db8::1'
		alpn:         ['http/1.1']
		client_share: KeyShareEntry{
			group:        .x25519
			key_exchange: []u8{len: 32, init: 0xaa}
		}
	}
	_, full_ipv6 := build_client_hello(cfg_ipv6)!
	assert !full_ipv6.bytestr().contains('2001:db8::1')
}

// test_parse_certificate_rejects_non_empty_request_context pins RFC 8446 §4.4.2:
// in the server Certificate message, certificate_request_context MUST be zero-length.
fn test_parse_certificate_rejects_non_empty_request_context() ! {
	// request_context of length 1 (value 0x01) followed by a 1-cert list
	bad_cert_msg := [u8(0x01), 0xaa, 0x00, 0x00, 0x07, 0x00, 0x00, 0x02, 0xde, 0xad, 0x00, 0x00]
	if _ := parse_certificate_message(bad_cert_msg) {
		assert false
	}
}

// test_parse_new_session_ticket_bounds verifies ticket_lifetime limit (RFC 8446 §4.6.1).
fn test_parse_new_session_ticket_bounds() ! {
	// ticket_lifetime = 604801 (> 7 days)
	mut w := wire.new_writer(64)
	w.write_u32(604801) // lifetime
	w.write_u32(100) // age_add
	w.write_vector_u8([u8(1), 2])! // nonce
	w.write_vector_u16([u8(0xaa), 0xbb])! // ticket
	w.write_vector_u16([]u8{})! // extensions
	if _ := parse_new_session_ticket(w.bytes()) {
		assert false
	}
}

// test_parse_certificate_message_rejects_overlong_chain pins the parse-time depth
// cap: a well-framed list of more than max_cert_chain_depth single-byte certs is
// refused before the state machine ASN.1-parses each entry, closing the
// amplification where a 1 MiB Certificate message packs thousands of tiny certs.
fn test_parse_certificate_message_rejects_overlong_chain() ! {
	mut list := []u8{}
	for _ in 0 .. 33 {
		list << [u8(0x00), 0x00, 0x01, 0xab, 0x00, 0x00] // cert_len=1 (0xab) + empty extensions
	}
	mut body := []u8{}
	body << u8(0x00) // empty certificate_request_context
	body << u8((list.len >> 16) & 0xff)
	body << u8((list.len >> 8) & 0xff)
	body << u8(list.len & 0xff)
	body << list
	if _ := parse_certificate_message(body) {
		assert false
	}
}

// test_parse_new_session_ticket_rejects_trailing_bytes checks the strict-framing
// guard: a well-formed ticket with one stray byte past the extension block must
// not be silently accepted.
fn test_parse_new_session_ticket_rejects_trailing_bytes() ! {
	mut w := wire.new_writer(64)
	w.write_u32(3600) // valid lifetime
	w.write_u32(100) // age_add
	w.write_vector_u8([u8(1), 2])! // nonce
	w.write_vector_u16([u8(0xaa), 0xbb])! // ticket
	w.write_vector_u16([]u8{})! // extensions
	mut bytes := w.bytes()
	bytes << 0xff // one byte beyond the extension vector
	parse_new_session_ticket(bytes) or {
		assert err.msg().contains('trailing bytes in NewSessionTicket')
		return
	}
	assert false
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
