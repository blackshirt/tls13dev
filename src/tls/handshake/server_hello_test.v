// Copyright (c) 2026 blackshirt.
//
// ServerHello decoding tests against the RFC 8446 §4.2 placement allowlist:
// only supported_versions, key_share and (HRR-only) cookie may appear; every
// other extension is fatal, and a normal ServerHello must never smuggle a cookie.
module handshake

import tls.wire

// sh_body assembles a well-formed ServerHello body (RFC 8446 §4.1.3 field
// order) carrying exactly the given extensions block.
fn sh_body(exts []u8) ![]u8 {
	mut w := wire.new_writer(48 + exts.len)
	w.write_u16(0x0303) // legacy_version
	w.write_bytes([]u8{len: 32, init: 0xab})
	w.write_vector_u8([u8(0x11), 0x22, 0x33])! // session id (echo checked by validate, not parse)
	w.write_u16(0x1301) // TLS_AES_128_GCM_SHA256
	w.write_u8(0x00) // legacy compression: null
	w.write_vector_u16(exts)!
	return w.bytes()
}

// ext_block frames one [u16 type][u16 length][data] extension.
fn ext_block(typ u16, data []u8) ![]u8 {
	mut w := wire.new_writer(data.len + 4)
	w.write_u16(typ)
	w.write_vector_u16(data)!
	return w.bytes()
}

// test_server_hello_rejects_disallowed_extensions pins the §4.2 allowlist: a
// server_name or supported_groups extension in ServerHello must abort with
// unsupported_extension, not be silently skipped.
fn test_server_hello_rejects_disallowed_extensions() ! {
	disallowed := [u16(ExtensionType.server_name), u16(ExtensionType.supported_groups),
		u16(ExtensionType.alpn)]
	for code in disallowed {
		body := sh_body(ext_block(code, [u8(0x00), 0x01])!)!
		mut rejected := false
		parse_server_hello(body) or {
			assert err.msg().contains('not permitted in ServerHello')
			rejected = true
		}
		assert rejected, 'extension 0x${code:04x} must not be tolerated in ServerHello'
	}
}

// test_server_hello_rejects_cookie_without_hrr checks §4.2: the cookie
// extension belongs to a HelloRetryRequest only; a random that is not the §4.1.3
// sentinel makes it fatal.
fn test_server_hello_rejects_cookie_without_hrr() ! {
	mut exts := wire.new_writer(64)
	exts.write_bytes(ext_block(u16(ExtensionType.supported_versions), [u8(0x03), 0x04])!)
	exts.write_bytes(ext_block(u16(ExtensionType.cookie), [u8(0x00), 0x04, 0xaa, 0xbb, 0xcc, 0xdd])!)
	body := sh_body(exts.bytes())!
	mut rejected := false
	parse_server_hello(body) or {
		assert err.msg().contains('cookie extension in a normal ServerHello')
		rejected = true
	}
	assert rejected, 'a cookie in a non-HRR ServerHello must be fatal'
}

// test_server_hello_rejects_hrr_cookie_edge_cases checks the HRR cookie
// framing: an empty cookie or trailing bytes after it are both refused.
fn test_server_hello_rejects_hrr_cookie_edge_cases() ! {
	mut cookie_w := wire.new_writer(24)
	cookie_w.write_bytes(ext_block(u16(ExtensionType.supported_versions), [u8(0x03), 0x04])!)
	cookie_w.write_bytes(ext_block(u16(ExtensionType.cookie), [u8(0x00), 0x00])!) // empty cookie
	mut random := hello_retry_request_random.clone()
	parse_server_hello(sh_body_at(random, cookie_w.bytes())!) or {
		assert err.msg().contains('cookie must be non-empty')
		return
	}
	assert false, 'an empty HRR cookie must be rejected'

	random = hello_retry_request_random.clone()
	mut trailing := wire.new_writer(32)
	trailing.write_bytes(ext_block(u16(ExtensionType.supported_versions), [u8(0x03), 0x04])!)
	trailing.write_bytes(ext_block(u16(ExtensionType.cookie), [u8(0x00), 0x01, 0xaa, 0xbb])!) // 1 byte past the vector
	parse_server_hello(sh_body_at(random, trailing.bytes())!) or {
		assert err.msg().contains('trailing bytes in HelloRetryRequest cookie')
		return
	}
	assert false, 'trailing bytes after the HRR cookie must be rejected'
}

// sh_body_at assembles a ServerHello body with an explicit random, so tests can
// plant the HelloRetryRequest sentinel.
fn sh_body_at(random []u8, exts []u8) ![]u8 {
	mut w := wire.new_writer(48 + exts.len)
	w.write_u16(0x0303)
	w.write_bytes(random)
	w.write_vector_u8([u8(0x11), 0x22, 0x33])!
	w.write_u16(0x1301)
	w.write_u8(0x00)
	w.write_vector_u16(exts)!
	return w.bytes()
}

// test_server_hello_rejects_duplicate_extensions checks §4.2's no-repeat rule
// reaches ServerHello decoding via parse_extensions.
fn test_server_hello_rejects_duplicate_extensions() ! {
	mut exts := wire.new_writer(32)
	exts.write_bytes(ext_block(u16(ExtensionType.supported_versions), [u8(0x03), 0x04])!)
	exts.write_bytes(ext_block(u16(ExtensionType.supported_versions), [u8(0x03), 0x04])!)
	mut rejected := false
	parse_server_hello(sh_body(exts.bytes())!) or {
		assert err.msg().contains('duplicate extension type')
		rejected = true
	}
	assert rejected, 'a repeated extension must be fatal'
}

// test_server_hello_accepts_minimal_good_shape guards the allowlist from
// over-rejection: the exact §4.1.3 extension set parses and reports the fields.
fn test_server_hello_accepts_minimal_good_shape() ! {
	mut exts := wire.new_writer(80)
	exts.write_bytes(ext_block(u16(ExtensionType.supported_versions), [u8(0x03), 0x04])!)
	// key_share: one entry of group 0x001d (x25519) with a 32-byte share.
	mut ks := wire.new_writer(40)
	ks.write_u16(0x001d)
	ks.write_vector_u16([]u8{len: 32, init: 0x22})!
	exts.write_bytes(ext_block(u16(ExtensionType.key_share), ks.bytes())!)
	sh := parse_server_hello(sh_body(exts.bytes())!)!
	assert sh.cipher_suite == .tls_aes_128_gcm_sha256
	assert sh.server_share.group == .x25519
	assert sh.server_share.key_exchange.len == 32
	assert !sh.is_hello_retry_req
	assert sh.session_id_echo == [u8(0x11), 0x22, 0x33]
}

// test_server_hello_rejects_oversized_hrr_cookie pins the echo-budget bound: the
// retry ClientHello must fit one record, so a near-64 KiB cookie is refused at
// parse time instead of being echoed into an unframeable flight.
fn test_server_hello_rejects_oversized_hrr_cookie() ! {
	mut cookie_body := [u8(0x20), 0x01] // u16 vector length 8193 == max_hrr_cookie_len + 1
	cookie_body << []u8{len: max_hrr_cookie_len + 1, init: 0xaa}
	mut exts := wire.new_writer(8300)
	exts.write_bytes(ext_block(u16(ExtensionType.supported_versions), [u8(0x03), 0x04])!)
	exts.write_bytes(ext_block(u16(ExtensionType.cookie), cookie_body)!)
	mut rejected := false
	parse_server_hello(sh_body_at(hello_retry_request_random.clone(), exts.bytes())!) or {
		assert err.msg().contains('cookie exceeds')
		rejected = true
	}
	assert rejected, 'an oversized HRR cookie must be rejected'
}

// test_build_client_hello_echoes_cookie verifies that when a cookie was received
// in an HRR (cookie_received=true), the retry ClientHello includes the cookie
// extension verbatim (RFC 8446 §4.1.4/§4.2.2).
fn test_build_client_hello_echoes_cookie() ! {
	cfg := ClientHelloConfig{
		server_name:           'example.com'
		alpn:                  []
		session_id:            [u8(0x11), 0x22]
		random:                []u8{len: 32, init: 0xab}
		cipher_suites:         default_cipher_suites()
		supported_groups:      default_supported_groups()
		signature_algorithms:  default_signature_algorithms()
		psks:                  []Psk{}
		is_quic:               false
		quic_transport_params: none
		cookie:                [u8(0xde), 0xad, 0xbe, 0xef]
		cookie_received:       true
		client_share:          KeyShareEntry{
			group:        .x25519
			key_exchange: []u8{len: 32, init: 0x01}
		}
	}
	_, full := build_client_hello(cfg)! or { return err }
	// The echoed cookie bytes must appear in the ClientHello.
	mut found := false
	for i in 0 .. full.len - 3 {
		if full[i] == 0xde && full[i + 1] == 0xad && full[i + 2] == 0xbe && full[i + 3] == 0xef {
			found = true
			break
		}
	}
	assert found, 'retry ClientHello must include the echoed cookie bytes'
	// And the handshake message must be a ClientHello.
	assert full[0] == u8(HandshakeType.client_hello)
}

// test_build_client_hello_rejects_unechoed_cookie enforces RFC 8446 §4.1.4:
// when cookie_received is true but cookie is empty, the retry ClientHello must
// fail — the cookie must be echoed verbatim.
fn test_build_client_hello_rejects_unechoed_cookie() ! {
	cfg := ClientHelloConfig{
		server_name:           'example.com'
		alpn:                  []
		session_id:            [u8(0x11), 0x22]
		random:                []u8{len: 32, init: 0xab}
		cipher_suites:         default_cipher_suites()
		supported_groups:      default_supported_groups()
		signature_algorithms:  default_signature_algorithms()
		psks:                  []Psk{}
		is_quic:               false
		quic_transport_params: none
		cookie:                []u8{}
		cookie_received:       true
		client_share:          KeyShareEntry{
			group:        .x25519
			key_exchange: []u8{len: 32, init: 0x01}
		}
	}
	build_client_hello(cfg) or {
		assert err.msg().contains('cookie was received but is empty')
		return
	}
	assert false, 'an unechoed cookie in the retry ClientHello must be fatal'
}

// test_build_client_hello_rejects_oversized_cookie_echo verifies that echoing
// an oversized cookie is rejected before it can make the ClientHello
// unframeable (§5.1).
fn test_build_client_hello_rejects_oversized_cookie_echo() ! {
	mut cookie := []u8{len: max_hrr_cookie_len + 1, init: 0xaa}
	cfg := ClientHelloConfig{
		server_name:           'example.com'
		alpn:                  []
		session_id:            [u8(0x11), 0x22]
		random:                []u8{len: 32, init: 0xab}
		cipher_suites:         default_cipher_suites()
		supported_groups:      default_supported_groups()
		signature_algorithms:  default_signature_algorithms()
		psks:                  []Psk{}
		is_quic:               false
		quic_transport_params: none
		cookie:                cookie
		cookie_received:       true
		client_share:          KeyShareEntry{
			group:        .x25519
			key_exchange: []u8{len: 32, init: 0x01}
		}
	}
	build_client_hello(cfg) or {
		assert err.msg().contains('exceeds')
		return
	}
	assert false, 'an oversized cookie echo must be fatal'
}

// test_build_client_hello_without_cookie_is_fine checks that a ClientHello with
// no cookie (first flight) builds successfully — cookie_received defaults to
// false and cookie stays empty.
fn test_build_client_hello_without_cookie_is_fine() ! {
	cfg := ClientHelloConfig{
		server_name:           'example.com'
		alpn:                  []
		session_id:            [u8(0x11), 0x22]
		random:                []u8{len: 32, init: 0xab}
		cipher_suites:         default_cipher_suites()
		supported_groups:      default_supported_groups()
		signature_algorithms:  default_signature_algorithms()
		psks:                  []Psk{}
		is_quic:               false
		quic_transport_params: none
		cookie:                []u8{}
		cookie_received:       false
		client_share:          KeyShareEntry{
			group:        .x25519
			key_exchange: []u8{len: 32, init: 0x01}
		}
	}
	_, full := build_client_hello(cfg)! or { return err }
	assert full.len > 0
	assert full[0] == u8(HandshakeType.client_hello)
}

// test_server_hello_reports_missing_supported_versions distinguishes the two
// version failures: an absent mandatory extension (§4.2.1) is worded as a
// missing extension, not as a negotiated 0x0000 the peer never sent, while a
// present-but-wrong version keeps the explicit wrong-value wording.
fn test_server_hello_reports_missing_supported_versions() ! {
	mut missing := false
	parse_server_hello(sh_body([]u8{})!) or { // no extensions at all
		assert err.msg().contains('missing required supported_versions')
		missing = true
	}
	assert missing, 'an absent supported_versions must be worded as a missing extension'

	mut wrong := false
	bad_exts := ext_block(u16(ExtensionType.supported_versions), [u8(0x03), 0x03])! // TLS 1.2 offer
	parse_server_hello(sh_body(bad_exts)!) or {
		assert err.msg().contains('negotiated version must be 0x0304')
		assert err.msg().contains('0x0303')
		wrong = true
	}
	assert wrong, 'a present-but-wrong version must keep the wrong-value wording'
}

// test_server_hello_pre_shared_key_selection checks the §4.2.11 ServerHello
// shape: a single u16 selected_identity is decoded, while an empty or overlong
// extension is fatal rather than silently treated as "no PSK selected".
fn test_server_hello_pre_shared_key_selection() ! {
	mut exts := wire.new_writer(96)
	exts.write_bytes(ext_block(u16(ExtensionType.supported_versions), [u8(0x03), 0x04])!)
	mut ks := wire.new_writer(40)
	ks.write_u16(0x001d)
	ks.write_vector_u16([]u8{len: 32, init: 0x22})!
	exts.write_bytes(ext_block(u16(ExtensionType.key_share), ks.bytes())!)
	exts.write_bytes(ext_block(u16(ExtensionType.pre_shared_key), [u8(0x00), 0x01])!)
	sh := parse_server_hello(sh_body(exts.bytes())!)!
	assert sh.selected_psk? == u16(1)

	for bad in [[]u8{}, [u8(0x00)], [u8(0x00), 0x00, 0x01]] {
		mut bad_exts := wire.new_writer(96)
		bad_exts.write_bytes(ext_block(u16(ExtensionType.supported_versions), [
			u8(0x03),
			0x04,
		])!)
		bad_exts.write_bytes(ext_block(u16(ExtensionType.pre_shared_key), bad)!)
		mut rejected := false
		parse_server_hello(sh_body(bad_exts.bytes())!) or {
			assert err.msg().contains('pre_shared_key')
			rejected = true
		}
		assert rejected, 'malformed pre_shared_key data ${bad.len} must be rejected'
	}
}

// test_server_hello_rejects_pre_shared_key_in_hrr pins §4.2.11: the extension
// may only appear in a ServerHello, never in a HelloRetryRequest.
fn test_server_hello_rejects_pre_shared_key_in_hrr() ! {
	mut exts := wire.new_writer(96)
	exts.write_bytes(ext_block(u16(ExtensionType.supported_versions), [u8(0x03), 0x04])!)
	exts.write_bytes(ext_block(u16(ExtensionType.pre_shared_key), [u8(0x00), 0x00])!)
	mut rejected := false
	parse_server_hello(sh_body_at(hello_retry_request_random.clone(), exts.bytes())!) or {
		assert err.msg().contains('illegal in HelloRetryRequest')
		rejected = true
	}
	assert rejected, 'pre_shared_key in a HelloRetryRequest must be fatal'
}

// test_server_hello_rejects_psk_hash_incompatible_with_suite pins the
// RFC 8446 §4.2.11 rule that a selected PSK's Hash must match the suite's.
fn test_server_hello_rejects_psk_hash_incompatible_with_suite() ! {
	mut exts := wire.new_writer(96)
	exts.write_bytes(ext_block(u16(ExtensionType.supported_versions), [u8(0x03), 0x04])!)
	exts.write_bytes(ext_block(u16(ExtensionType.pre_shared_key), [u8(0x00), 0x00])!)
	sh := parse_server_hello(sh_body(exts.bytes())!)!
	cfg := ClientHelloConfig{
		session_id: [u8(0x11), 0x22, 0x33]
		psks:       [
			Psk{
				identity:  [u8(0x01)]
				key:       []u8{len: 32, init: 0x42}
				hash_algo: .sha384
			},
		]
	}
	mut rejected := false
	sh.validate(&cfg) or {
		assert err.msg().contains('incompatible with PSK hash')
		rejected = true
	}
	assert rejected, 'a SHA-256 suite must not accept a SHA-384 PSK'
}

// test_server_hello_rejects_trailing_body_bytes ensures a ServerHello body that
// continues past its extensions block is a decode error, not silently ignored.
fn test_server_hello_rejects_trailing_body_bytes() ! {
	mut exts := wire.new_writer(32)
	exts.write_bytes(ext_block(u16(ExtensionType.supported_versions), [u8(0x03), 0x04])!)
	mut body := sh_body(exts.bytes())!
	body << u8(0x00)
	mut rejected := false
	parse_server_hello(body) or {
		assert err.msg().contains('trailing bytes after ServerHello extensions')
		rejected = true
	}
	assert rejected, 'trailing bytes after the ServerHello extensions must be fatal'
}
