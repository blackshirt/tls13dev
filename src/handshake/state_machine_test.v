module handshake

import encoding.hex
import record
import wire

// Client state-machine tests focused on the HelloRetryRequest path: hand-built
// HRR bodies are parsed and fed through process_server_hello to exercise the
// RFC 8446 §4.1.2/§4.1.4 validation rules (single HRR only, must-change-something,
// group reselection rejection) plus the second-ClientHello follow-ups.

// build_hrr_body assembles a HelloRetryRequest message body for tests. Pass a
// group to include a key_share extension (group change request) and/or non-empty
// cookie bytes to include a cookie extension.
fn build_hrr_body(session_id []u8, group ?NamedGroup, cookie []u8) ![]u8 {
	mut w := wire.new_writer(128)
	w.write_u16(0x0303)
	w.write_bytes(hello_retry_request_random)
	w.write_vector_u8(session_id)!
	w.write_u16(u16(CipherSuite.tls_aes_128_gcm_sha256))
	w.write_u8(0)

	mut ext := wire.new_writer(64)
	mut sv := wire.new_writer(2)
	sv.write_u16(0x0304)
	write_extension(mut ext, .supported_versions, sv.bytes())!
	if g := group {
		mut ks := wire.new_writer(2)
		ks.write_u16(u16(g))
		write_extension(mut ext, .key_share, ks.bytes())!
	}
	if cookie.len > 0 {
		mut cw := wire.new_writer(cookie.len + 2)
		cw.write_vector_u16(cookie)!
		write_extension(mut ext, .cookie, cw.bytes())!
	}
	w.write_vector_u16(ext.bytes())!
	return w.bytes()
}

// hrr_record frames an HRR body in a plaintext handshake record — the form the
// client receives it in: ServerHello (and the HRR that reuses its type) is the
// last unencrypted server message; encryption starts immediately after it
// (RFC 8446 §5.1; unlike the client, the server sends no dummy ChangeCipherSpec).
fn hrr_record(body []u8) record.Record {
	return record.new_record(.handshake, wrap_handshake_message(.server_hello, body))
}

// build_server_hello_body assembles a normal (non-HRR) ServerHello body for
// tests: a random that is not the HRR sentinel plus the given selected suite and
// the always-required supported_versions. A key_share entry with a placeholder
// key_exchange is included so the parser accepts the message; the state machine
// rejects a suite mismatch before ever touching the share.
fn build_server_hello_body(session_id []u8, suite CipherSuite) ![]u8 {
	mut w := wire.new_writer(128)
	w.write_u16(0x0303)
	w.write_bytes([]u8{len: 32, init: 0x7f})
	w.write_vector_u8(session_id)!
	w.write_u16(u16(suite))
	w.write_u8(0)

	mut ext := wire.new_writer(64)
	mut sv := wire.new_writer(2)
	sv.write_u16(0x0304)
	write_extension(mut ext, .supported_versions, sv.bytes())!
	mut ks := wire.new_writer(8)
	ks.write_u16(u16(NamedGroup.secp256r1))
	ks.write_vector_u16([]u8{})!
	write_extension(mut ext, .key_share, ks.bytes())!
	w.write_vector_u16(ext.bytes())!
	return w.bytes()
}

fn server_hello_record(body []u8) record.Record {
	return record.new_record(.handshake, wrap_handshake_message(.server_hello, body))
}

fn test_hrr_sentinel_random_matches_rfc() {
	assert hello_retry_request_random.len == 32
	assert hex.encode(hello_retry_request_random) == 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c'
}

fn test_parse_hello_retry_request_with_group() ! {
	sid := []u8{len: 32, init: 0x01}
	body := build_hrr_body(sid, NamedGroup.secp256r1, []u8{})!
	sh := parse_server_hello(body)!
	assert sh.is_hello_retry_req
	assert sh.has_key_share
	assert sh.server_share.group == NamedGroup.secp256r1
	assert sh.server_share.key_exchange.len == 0
	assert sh.session_id_echo == sid
}

fn test_parse_hrr_cookie_only() ! {
	sid := []u8{len: 32, init: 0x02}
	body := build_hrr_body(sid, none, [u8(0xaa), 0xbb, 0xcc])!
	sh := parse_server_hello(body)!
	assert sh.is_hello_retry_req
	assert !sh.has_key_share
	assert sh.cookie == [u8(0xaa), 0xbb, 0xcc]
}

// test_compute_shared_secret_rejects_bad_share_size checks the §4.2.8.2 size
// gate: wrong-length shares and a right-length but compressed-style P-256
// point must fail with our named errors before any crypto library sees them.
fn test_compute_shared_secret_rejects_bad_share_size() ! {
	mut h := new_client_handshake('example.com', [])!
	h.create_client_hello()!

	short_x := KeyShareEntry{
		group:        .x25519
		key_exchange: []u8{len: 31}
	}
	if _ := h.compute_shared_secret(short_x) {
		assert false // 31 bytes must be rejected
	}

	short_p256 := KeyShareEntry{
		group:        .secp256r1
		key_exchange: []u8{len: 64}
	}
	if _ := h.compute_shared_secret(short_p256) {
		assert false // 64 bytes must be rejected before the prefix check
	}

	// correct 65-byte length but all zeros — no 0x04 uncompressed-point prefix
	compressed_p256 := KeyShareEntry{
		group:        .secp256r1
		key_exchange: []u8{len: 65}
	}
	if _ := h.compute_shared_secret(compressed_p256) {
		assert false // missing 0x04 prefix must be rejected
	}
}

// test_hrr_helpers sanity-checks the two small predicates HRR handling relies
// on: the set of implemented named groups and the default offered suites.
fn test_hrr_helpers() ! {
	assert is_supported_group(.x25519)
	assert is_supported_group(.secp256r1)

	mut h := new_client_handshake('example.com', [])!
	assert h.is_offered_cipher_suite(.tls_aes_128_gcm_sha256)
	assert h.is_offered_cipher_suite(.tls_aes_256_gcm_sha384)
	assert h.is_offered_cipher_suite(.tls_chacha20_poly1305_sha256)
}

fn test_process_hrr_group_change() ! {
	mut h := new_client_handshake('example.com', [])!
	h.create_client_hello()!
	sid := h.config.session_id.clone()

	body := build_hrr_body(sid, NamedGroup.secp256r1, []u8{})!
	followups, sh := h.process_server_hello(hrr_record(body))!
	assert sh.is_hello_retry_req
	assert h.hrr_received
	assert followups.len == 2
	assert followups[0].content_type == .handshake
	assert followups[1].content_type == .change_cipher_spec
	assert h.config.client_share.group == .secp256r1
	assert h.ecdhe_group == .secp256r1
}

fn test_process_hrr_cookie_only_keeps_share() ! {
	mut h := new_client_handshake('example.com', [])!
	h.create_client_hello()!
	sid := h.config.session_id.clone()

	body := build_hrr_body(sid, none, [u8(1), 2, 3, 4])!
	followups, sh := h.process_server_hello(hrr_record(body))!
	assert sh.is_hello_retry_req
	assert followups.len == 2
	assert h.config.client_share.group == .x25519
	assert h.ecdhe_group == .x25519
	assert h.config.cookie == [u8(1), 2, 3, 4]
}

// test_hrr_second_client_hello_frozen_fields guards the pinning of the
// generated random/session id (they must live in config, not just inside the
// built message) and the §4.1.4 freeze: the retry ClientHello must be
// byte-identical to the first in those fields — only key_share/cookie change.
fn test_hrr_second_client_hello_frozen_fields() ! {
	mut h := new_client_handshake('example.com', [])!
	_, ch1 := h.create_client_hello()!
	assert h.config.random.len == client_hello_random_len
	assert h.config.session_id.len == legacy_session_id_len

	body := build_hrr_body(h.config.session_id, NamedGroup.secp256r1, []u8{})!
	followups, _ := h.process_server_hello(hrr_record(body))!
	ch2 := followups[0].payload
	// handshake msg: 4-byte header + 2-byte legacy_version, then 32-byte random,
	// then the u8-length-prefixed legacy_session_id.
	assert ch2[6..38] == ch1[6..38] // random unchanged
	assert ch2[38] == ch1[38] // session id length unchanged
	sid_len := int(ch2[38])
	assert ch2[39..39 + sid_len] == ch1[39..39 + sid_len] // session id bytes unchanged
}

fn test_process_hrr_session_id_mismatch_rejected() ! {
	mut h := new_client_handshake('example.com', [])!
	h.create_client_hello()!

	body := build_hrr_body([]u8{len: 32, init: 0xff}, NamedGroup.secp256r1, []u8{})!
	h.process_server_hello(hrr_record(body)) or {
		assert err.msg().contains('legacy_session_id_echo')
		return
	}
	assert false
}

fn test_process_hrr_no_change_rejected() ! {
	mut h := new_client_handshake('example.com', [])!
	h.create_client_hello()!
	sid := h.config.session_id.clone()

	body := build_hrr_body(sid, none, []u8{})!
	h.process_server_hello(hrr_record(body)) or {
		assert err.msg().contains('would not change')
		return
	}
	assert false
}

fn test_process_hrr_reselect_offered_group_rejected() ! {
	mut h := new_client_handshake('example.com', [])!
	h.create_client_hello()!
	sid := h.config.session_id.clone()

	body := build_hrr_body(sid, NamedGroup.x25519, []u8{})!
	h.process_server_hello(hrr_record(body)) or {
		assert err.msg().contains('reselected')
		return
	}
	assert false
}

fn test_process_second_hrr_rejected() ! {
	mut h := new_client_handshake('example.com', [])!
	h.create_client_hello()!
	sid := h.config.session_id.clone()

	body := build_hrr_body(sid, NamedGroup.secp256r1, []u8{})!
	h.process_server_hello(hrr_record(body))!
	// A second HelloRetryRequest in the same connection is a protocol error.
	h.process_server_hello(hrr_record(body)) or {
		assert err.msg().contains('second HelloRetryRequest')
		return
	}
	assert false
}

// test_process_hrr_cipher_suite_change_rejected pins RFC 8446 §4.1.4: the
// cipher suite in the ServerHello MUST equal the one carried by the preceding
// HelloRetryRequest; a server that switches suites must be rejected with
// illegal_parameter.
fn test_process_hrr_cipher_suite_change_rejected() ! {
	mut h := new_client_handshake('example.com', [])!
	h.create_client_hello()!
	sid := h.config.session_id.clone()

	// HRR selects AES-128 (0x1301) while requesting the P-256 group.
	hrr_body := build_hrr_body(sid, NamedGroup.secp256r1, []u8{})!
	followups, sh := h.process_server_hello(hrr_record(hrr_body))!
	assert followups.len == 2
	assert sh.cipher_suite == .tls_aes_128_gcm_sha256
	assert h.hrr_cipher_suite == ?CipherSuite(CipherSuite.tls_aes_128_gcm_sha256)

	// The final ServerHello instead picks AES-256 (0x1302), a suite the client
	// did offer, so the mismatch is the only thing that should fail.
	sh_body := build_server_hello_body(sid, .tls_aes_256_gcm_sha384)!
	h.process_server_hello(server_hello_record(sh_body)) or {
		assert err.msg().contains('differs from HelloRetryRequest')
		return
	}
	assert false
}

// test_process_hrr_cipher_suite_match_proceeds pins the positive half of the
// §4.1.4 rule: a ServerHello that reuses the HelloRetryRequest's suite must pass
// the consistency check and advance to key exchange. The placeholder server
// share is empty, so the failure here is the ECDHE decode — never the cipher
// suite mismatch.
fn test_process_hrr_cipher_suite_match_proceeds() ! {
	mut h := new_client_handshake('example.com', [])!
	h.create_client_hello()!
	sid := h.config.session_id.clone()

	hrr_body := build_hrr_body(sid, NamedGroup.secp256r1, []u8{})!
	h.process_server_hello(hrr_record(hrr_body))!

	sh_body := build_server_hello_body(sid, .tls_aes_128_gcm_sha256)!
	h.process_server_hello(server_hello_record(sh_body)) or {
		assert !err.msg().contains('differs from HelloRetryRequest')
		return
	}
	assert false
}

// test_process_hrr_empty_cookie_rejected checks that an HRR carrying a
// zero-length cookie extension value is rejected: RFC 8446 §4.2.2 defines the
// cookie as opaque<1..2^16-1>, so an empty cookie is malformed.
fn test_process_hrr_empty_cookie_rejected() ! {
	mut h := new_client_handshake('example.com', [])!
	h.create_client_hello()!
	sid := h.config.session_id.clone()

	mut w := wire.new_writer(128)
	w.write_u16(0x0303)
	w.write_bytes(hello_retry_request_random)
	w.write_vector_u8(sid)!
	w.write_u16(u16(CipherSuite.tls_aes_128_gcm_sha256))
	w.write_u8(0)

	mut ext := wire.new_writer(64)
	mut sv := wire.new_writer(2)
	sv.write_u16(0x0304)
	write_extension(mut ext, .supported_versions, sv.bytes())!
	mut cw := wire.new_writer(2)
	cw.write_vector_u16([]u8{})!
	write_extension(mut ext, .cookie, cw.bytes())!
	w.write_vector_u16(ext.bytes())!

	h.process_server_hello(hrr_record(w.bytes())) or {
		assert err.msg().contains('cookie')
		return
	}
	assert false
}

// test_process_hrr_cookie_only_echos_cookie_in_ch2 verifies the cookie from a
// cookie-only HRR is echoed into the second ClientHello's cookie extension.
fn test_process_hrr_cookie_only_echos_cookie_in_ch2() ! {
	mut h := new_client_handshake('example.com', [])!
	h.create_client_hello()!
	sid := h.config.session_id.clone()

	body := build_hrr_body(sid, none, [u8(1), 2, 3, 4])!
	followups, _ := h.process_server_hello(hrr_record(body))!
	ch2 := followups[0].payload
	// The cookie extension is 00 0a || len 00 06 || vector 00 04 || 01 02 03 04.
	// cookie extension: type 44 (0x002c) || data_len 00 06 || vector 00 04 || 01 02 03 04
	cookie_type := u16(ExtensionType.cookie)
	needle := [
		u8(cookie_type >> 8),
		u8(cookie_type & 0xff),
		0x00,
		0x06,
		0x00,
		0x04,
		0x01,
		0x02,
		0x03,
		0x04,
	]
	mut found := false
	for i := 0; i <= ch2.len - needle.len; i++ {
		if ch2[i..i + needle.len] == needle {
			found = true
			break
		}
	}
	assert found
}
