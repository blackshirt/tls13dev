// Copyright (c) 2026 blackshirt.
//
// Client state-machine tests focused on the HelloRetryRequest path: hand-built
// HRR bodies are parsed and fed through process_server_hello to exercise the
// RFC 8446 §4.1.2/§4.1.4 validation rules (single HRR only, must-change-something,
// group reselection rejection) plus the second-ClientHello follow-ups, and the
// reassembly cap that bounds what a fragmented handshake message can pin in
// memory, plus the §1.3.1/§7.5 zeroization hygiene that releases handshake and
// application secrets once they can no longer be needed.
module tls

import encoding.hex
import crypto.aes

// build_hrr_body assembles a HelloRetryRequest message body for tests. Pass a
// group to include a key_share extension (group change request) and/or non-empty
// cookie bytes to include a cookie extension.
fn build_hrr_body(session_id []u8, group ?NamedGroup, cookie []u8) ![]u8 {
	mut w := new_writer(128)
	w.write_u16(0x0303)
	w.write_bytes(hello_retry_request_random)
	w.write_vector_u8(session_id)!
	w.write_u16(u16(CipherSuite.tls_aes_128_gcm_sha256))
	w.write_u8(0)

	mut ext := new_writer(64)
	mut sv := new_writer(2)
	sv.write_u16(0x0304)
	write_extension(mut ext, .supported_versions, sv.bytes())!
	if g := group {
		mut ks := new_writer(2)
		ks.write_u16(u16(g))
		write_extension(mut ext, .key_share, ks.bytes())!
	}
	if cookie.len > 0 {
		mut cw := new_writer(cookie.len + 2)
		cw.write_vector_u16(cookie)!
		write_extension(mut ext, .cookie, cw.bytes())!
	}
	w.write_vector_u16(ext.bytes())!
	return w.bytes()
}

// hrr_message wraps an HRR body as the raw ServerHello-typed handshake message.
// The ServerHello (and the HRR reusing its type) is the last unencrypted server
// message, so on the record-free core boundary it is read straight from the
// message bytes (RFC 8446 §5.1; the server, unlike the client, sends no dummy CCS).
fn hrr_message(body []u8) []u8 {
	return wrap_handshake_message(.server_hello, body)
}

// build_server_hello_body assembles a normal (non-HRR) ServerHello body for
// tests: a random that is not the HRR sentinel plus the given selected suite and
// the always-required supported_versions. A key_share entry with a placeholder
// key_exchange is included so the parser accepts the message; the state machine
// rejects a suite mismatch before ever touching the share.
fn build_server_hello_body(session_id []u8, suite CipherSuite) ![]u8 {
	mut w := new_writer(128)
	w.write_u16(0x0303)
	w.write_bytes([]u8{len: 32, init: 0x7f})
	w.write_vector_u8(session_id)!
	w.write_u16(u16(suite))
	w.write_u8(0)

	mut ext := new_writer(64)
	mut sv := new_writer(2)
	sv.write_u16(0x0304)
	write_extension(mut ext, .supported_versions, sv.bytes())!
	mut ks := new_writer(8)
	ks.write_u16(u16(NamedGroup.secp256r1))
	ks.write_vector_u16([]u8{})!
	write_extension(mut ext, .key_share, ks.bytes())!
	w.write_vector_u16(ext.bytes())!
	return w.bytes()
}

fn server_hello_message(body []u8) []u8 {
	return wrap_handshake_message(.server_hello, body)
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

// test_compute_shared_secret_rejects_zero_shared_secret pins RFC 8446 §4.2.8.2 / RFC 7748 §6.1:
// an all-zero shared secret (e.g. from a low-order point) must be rejected with illegal_parameter.
fn test_compute_shared_secret_rejects_zero_shared_secret() ! {
	mut h := new_client_handshake('example.com', [])!
	h.create_client_hello()!

	// An all-zero X25519 peer public key computes to an all-zero shared secret
	zero_x := KeyShareEntry{
		group:        .x25519
		key_exchange: []u8{len: 32, init: 0}
	}
	h.compute_shared_secret(zero_x) or {
		assert err.msg().contains('all-zero value')
		return
	}
	assert false
}

// test_hrr_helpers sanity-checks the predicates ServerHello validation relies
// on: the set of implemented named groups and the default offered suites.
fn test_hrr_helpers() ! {
	assert is_supported_group(.x25519)
	assert is_supported_group(.secp256r1)

	mut h := new_client_handshake('example.com', [])!
	// With no explicit config the offer is the three TLS 1.3 AEAD suites; a
	// ServerHello selecting anything else is rejected by sh.validate().
	offered := offered_cipher_suites(&h.config)
	assert offered.contains(.tls_aes_128_gcm_sha256)
	assert offered.contains(.tls_aes_256_gcm_sha384)
	assert offered.contains(.tls_chacha20_poly1305_sha256)
}

fn test_process_hrr_group_change() ! {
	mut h := new_client_handshake('example.com', [])!
	h.create_client_hello()!
	sid := h.config.session_id.clone()

	body := build_hrr_body(sid, NamedGroup.secp256r1, []u8{})!
	followups, sh := h.process_server_hello(hrr_message(body))!
	assert sh.is_hello_retry_req
	assert h.hrr_received
	assert followups.len == 1
	assert followups[0].content_type == .handshake
	assert h.config.client_share.group == .secp256r1
	assert h.ecdhe_group == .secp256r1
}

fn test_process_hrr_cookie_only_keeps_share() ! {
	mut h := new_client_handshake('example.com', [])!
	h.create_client_hello()!
	sid := h.config.session_id.clone()

	body := build_hrr_body(sid, none, [u8(1), 2, 3, 4])!
	followups, sh := h.process_server_hello(hrr_message(body))!
	assert sh.is_hello_retry_req
	assert followups.len == 1
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
	ch1 := h.create_client_hello()!
	assert h.config.random.len == client_hello_random_len
	assert h.config.session_id.len == legacy_session_id_len

	body := build_hrr_body(h.config.session_id, NamedGroup.secp256r1, []u8{})!
	followups, _ := h.process_server_hello(hrr_message(body))!
	ch2 := followups[0].msg
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
	h.process_server_hello(hrr_message(body)) or {
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
	h.process_server_hello(hrr_message(body)) or {
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
	h.process_server_hello(hrr_message(body)) or {
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
	h.process_server_hello(hrr_message(body))!
	// A second HelloRetryRequest in the same connection is a protocol error.
	h.process_server_hello(hrr_message(body)) or {
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
	followups, sh := h.process_server_hello(hrr_message(hrr_body))!
	assert followups.len == 1
	assert sh.cipher_suite == .tls_aes_128_gcm_sha256
	assert h.hrr_cipher_suite == ?CipherSuite(CipherSuite.tls_aes_128_gcm_sha256)

	// The final ServerHello instead picks AES-256 (0x1302), a suite the client
	// did offer, so the mismatch is the only thing that should fail.
	sh_body := build_server_hello_body(sid, .tls_aes_256_gcm_sha384)!
	h.process_server_hello(server_hello_message(sh_body)) or {
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
	h.process_server_hello(hrr_message(hrr_body))!

	sh_body := build_server_hello_body(sid, .tls_aes_128_gcm_sha256)!
	h.process_server_hello(server_hello_message(sh_body)) or {
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

	mut w := new_writer(128)
	w.write_u16(0x0303)
	w.write_bytes(hello_retry_request_random)
	w.write_vector_u8(sid)!
	w.write_u16(u16(CipherSuite.tls_aes_128_gcm_sha256))
	w.write_u8(0)

	mut ext := new_writer(64)
	mut sv := new_writer(2)
	sv.write_u16(0x0304)
	write_extension(mut ext, .supported_versions, sv.bytes())!
	mut cw := new_writer(2)
	cw.write_vector_u16([]u8{})!
	write_extension(mut ext, .cookie, cw.bytes())!
	w.write_vector_u16(ext.bytes())!

	h.process_server_hello(hrr_message(w.bytes())) or {
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
	followups, _ := h.process_server_hello(hrr_message(body))!
	ch2 := followups[0].msg
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

// test_reassembly_rejects_oversized_message_length: the 24-bit handshake length
// field permits declaring ~16 MiB, which a fragmenting server could then force
// the client to buffer. The cap must bite at the header — before any fragments
// accumulate — so the four-byte header alone triggers the error.
fn test_reassembly_rejects_oversized_message_length() ! {
	mut h := new_client_handshake('example.com', [])!
	h.state = .wait_encrypted_extensions
	// EncryptedExtensions (type 8) with declared length 0x100001 — exactly one
	// byte past max_handshake_message_len (1 MiB).
	h.reassembly_buf = [u8(HandshakeType.encrypted_extensions), 0x10, 0x00, 0x01]

	v := new_validator(new_trust_store(), false)
	h.process_reassembled_messages(&v) or {
		assert err.msg().contains('exceeds maximum')
		return
	}
	assert false
}

// test_zeroize_handshake_secrets_releases_material pins the scrub that runs at
// .connected: the handshake-stage secrets and both ephemeral private keys must
// be released, so a later memory read or core dump cannot recover the material
// that decrypts a recorded handshake (RFC 8446 §1.3.1/§7.5 forward secrecy).
fn test_zeroize_handshake_secrets_releases_material() ! {
	mut h := new_client_handshake('example.com', [])!
	// Populate both key halves: the x25519 arm sets priv_x25519, the secp256r1
	// arm sets priv_p256 and (per generate_key_share) leaves the X25519 key.
	h.generate_key_share(.x25519)!
	h.generate_key_share(.secp256r1)!
	assert h.priv_x25519 != unsafe { nil }
	assert h.priv_p256 != none
	h.handshake_secret = []u8{len: 32, init: 0x5a}
	h.client_hs_traffic = []u8{len: 32, init: 0xa5}
	h.server_hs_traffic = []u8{len: 32, init: 0x3c}

	h.zeroize_handshake_secrets()

	assert h.handshake_secret.len == 0
	assert h.client_hs_traffic.len == 0
	assert h.server_hs_traffic.len == 0
	assert h.priv_x25519 == unsafe { nil }
	assert h.priv_p256 == none
}

// test_zeroize_app_secrets_releases_traffic_secrets pins the close()/alert
// hygiene: the two §7.1 application traffic secrets must be gone once the
// connection ends, denying after-the-fact decryption of captured records.
fn test_zeroize_app_secrets_releases_traffic_secrets() ! {
	mut h := new_client_handshake('example.com', [])!
	h.client_ap_traffic = []u8{len: 32, init: 0x11}
	h.server_ap_traffic = []u8{len: 32, init: 0x22}
	h.zeroize_app_secrets()
	assert h.client_ap_traffic.len == 0
	assert h.server_ap_traffic.len == 0
}

// test_process_server_hello_rejects_trailing_data: RFC 8446 §5.1 requires the
// ServerHello to align with a record boundary. A record that coalesces extra
// bytes after the ServerHello would have them silently dropped (and any
// following handshake flight would then be mis-framed), so it is refused as
// unexpected_message instead of being accepted.
fn test_process_server_hello_rejects_trailing_data() ! {
	mut h := new_client_handshake('example.com', [])!
	h.create_client_hello()!

	sid := []u8{len: 32, init: 0x01}
	body := build_server_hello_body(sid, CipherSuite.tls_aes_128_gcm_sha256)!
	// Valid ServerHello handshake message, plus one coalesced trailing byte.
	mut payload := wrap_handshake_message(.server_hello, body)
	payload << u8(0x00)

	h.process_server_hello(payload) or {
		assert err.msg().contains('trailing data after ServerHello')
		return
	}
	assert false
}

fn test_process_server_hello_accepts_aligned_record() ! {
	mut h := new_client_handshake('example.com', [])!
	h.create_client_hello()!

	sid := []u8{len: 32, init: 0x01}
	body := build_server_hello_body(sid, CipherSuite.tls_aes_128_gcm_sha256)!
	rec := server_hello_message(body) // header + body only, no trailing bytes

	// An aligned record must get past the alignment gate (it may fail later on
	// key_share contents, but never on 'trailing data').
	if _, _ := h.process_server_hello(rec) {
		// accepted (or failed later) — either is fine, just not on alignment.
	} else {
		assert !err.msg().contains('trailing data after ServerHello')
	}
}

// test_feed_encrypted_record_surfaces_handshake_alert: RFC 8446 §6 lets the
// server send a fatal alert under the handshake keys after ServerHello (e.g.
// decrypt_error, certificate_required). Previously it was collapsed into a
// generic 'unexpected content type', losing the peer's reason; the alert code
// must now be decoded and surfaced verbatim.
fn test_feed_encrypted_record_surfaces_handshake_alert() ! {
	key := [u8(0x01), 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
		0x0f, 0x10]
	iv := [u8(0xa0), 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab]
	gcm_enc := aes.new_aes_gcm(key)!
	gcm_dec := aes.new_aes_gcm(key)!
	mut enc_state := new_record_cipher_state(gcm_enc, iv)!
	mut dec_state := new_record_cipher_state(gcm_dec, iv)!

	mut h := new_client_handshake('example.com', [])!
	h.server_hs_cipher = dec_state

	// A fatal (level 2) internal_error (80) alert, encrypted under the handshake keys.
	alert_rec := enc_state.encrypt_record(.alert, [u8(2), 80])!
	h.feed_encrypted_record(.handshake, alert_rec) or {
		assert err.msg().contains('received alert')
		return
	}
	assert false
}

// Non-.handshake levels (RFC 9001 §4.9) must be refused before cipher state is touched.
fn test_feed_encrypted_record_rejects_other_levels() ! {
	mut h := new_client_handshake('example.com', [])!
	dummy := new_record(.application_data, [u8(0x01)])
	for level in [SecretLevel.initial, .application] {
		h.feed_encrypted_record(level, dummy) or {
			assert err.msg().contains('encryption level')
			continue
		}
		assert false
	}
}

// .initial derives from the destination connection ID (RFC 9001 §5.2), not the TLS schedule.
fn test_exported_secrets_rejects_initial_level() ! {
	mut h := new_client_handshake('example.com', [])!
	h.exported_secrets(.initial) or {
		assert err.msg().contains('destination connection ID')
		return
	}
	assert false
}

// Both secret sets must error while empty, not hand out empty slices.
fn test_exported_secrets_requires_available_secrets() ! {
	mut h := new_client_handshake('example.com', [])!
	h.exported_secrets(.handshake) or {
		assert err.msg().contains('handshake traffic secrets unavailable')
		h.exported_secrets(.application) or {
			assert err.msg().contains('application traffic secrets unavailable')
			return
		}
		assert false
	}
	assert false
}

// Exports are clones: scrubbing the core's secrets leaves the exported copies intact.
fn test_exported_secrets_returns_independent_copies() ! {
	mut h := new_client_handshake('example.com', [])!
	h.client_hs_traffic = []u8{len: 32, init: 0xa5}
	h.server_hs_traffic = []u8{len: 32, init: 0x3c}
	client, server := h.exported_secrets(.handshake)!
	assert client.len == 32
	assert server.len == 32
	assert client[0] == 0xa5
	assert server[0] == 0x3c
	// Scrub the core's secrets; the exported clones must keep their bytes.
	h.client_hs_traffic[0] = 0
	h.server_hs_traffic[0] = 0
	assert client[0] == 0xa5
	assert server[0] == 0x3c

	h.client_ap_traffic = []u8{len: 32, init: 0x11}
	h.server_ap_traffic = []u8{len: 32, init: 0x22}
	c2, s2 := h.exported_secrets(.application)!
	assert c2.len == 32
	assert s2.len == 32
	assert c2[0] == 0x11
	assert s2[0] == 0x22
	h.client_ap_traffic[0] = 0
	assert c2[0] == 0x11
}
