// Copyright (c) 2026 blackshirt.
//
// Core-contract suite for the transport-neutral handshake: level-tagged receive_msgs_at_level()
// reassembly across adversarial splits, the unconsumed-bytes accessor, the
// confirm/zeroize secret lifecycle, and the traffic-keys guards.
module handshake

import tls.pki
import tls.wire

// fixture_validator builds a Validator over an empty trust store; none of these
// tests reach chain verification.
fn fixture_validator() pki.Validator {
	return pki.new_validator(pki.new_trust_store())
}

// wrap_hsk frames a handshake body with its 4-byte header, mirroring the core's
// own framing so tests can plant complete messages on a level stream.
fn wrap_hsk(typ HandshakeType, body []u8) []u8 {
	mut w := wire.new_writer(4 + body.len)
	w.write_u8(u8(typ))
	w.write_u24(u32(body.len))
	w.write_bytes(body)
	return w.bytes()
}

// ---- TLS encryption-level contract ----

fn test_encryption_level_order() ! {
	assert u8(EncryptionLevel.initial) == 0
	assert u8(EncryptionLevel.handshake) == 1
	assert u8(EncryptionLevel.application) == 2
}

// test_encryption_level_rejects_unsupported_operation checks that a shared
// level value is rejected when it does not apply to the selected API operation.
fn test_encryption_level_rejects_unsupported_operation() ! {
	mut record := new_tls_handshake('example.com', HandshakeOptions{
		validator: fixture_validator()
	})!
	_ = record.create_client_hello()!
	mut rejected := false
	record.receive_msgs_at_level(.application, []u8{}) or {
		assert err.msg().contains('does not accept application-level bytes')
		rejected = true
	}
	assert rejected
	rejected = false
	record.record_traffic_keys(.initial) or {
		assert err.msg().contains('initial level has no traffic keys')
		rejected = true
	}
	assert rejected

	quic := new_quic_handshake('example.com', HandshakeOptions{
		validator: fixture_validator()
	})!
	rejected = false
	quic.peer_traffic_secrets(.initial) or {
		assert err.msg().contains('initial level has no traffic secrets')
		rejected = true
	}
	assert rejected
}

// test_handshake_message_carries_level_and_bytes checks that a message carries
// its level tag and the full framed bytes.
fn test_handshake_message_carries_level_and_bytes() ! {
	m := new_handshake_message(.handshake, [u8(0x14), 0x00, 0x00, 0x01, 0xff])!
	assert m.level == .handshake
	assert m.msg.len == 5
}

// test_new_handshake_message_rejects_length_mismatch checks that a header
// disagreeing with the body it carries is refused.
fn test_new_handshake_message_rejects_length_mismatch() ! {
	// Finished header declaring a 5-byte body, message carrying only 1.
	bad := [u8(0x14), 0x00, 0x00, 0x05, 0xff]
	new_handshake_message(.handshake, bad) or {
		assert err.msg().contains('declares 5 body bytes, message carries 1')
		return
	}
	assert false
}

// test_new_handshake_message_rejects_truncated_header checks that a message
// shorter than its own header surfaces the header error.
fn test_new_handshake_message_rejects_truncated_header() ! {
	new_handshake_message(.initial, [u8(0x01), 0x00]) or {
		assert err.msg().contains('header truncated')
		return
	}
	assert false
}

// ---- receive_msgs_at_level() reassembly: split and coalesced delivery ----

// test_feed_initial_buffers_incomplete_message checks that an incomplete
// ServerHello parks in the initial-level buffer without parsing.
fn test_feed_initial_buffers_incomplete_message() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	_ = h.create_client_hello()!

	full := wrap_hsk(.server_hello, []u8{len: 10, init: 0xAA})
	split := full.len / 2

	first := h.receive_msgs_at_level(.initial, full[..split])!
	assert first.len == 0
	assert h.unconsumed_bytes(.initial) == split

	// Completing the frame consumes it; the garbage body then fails to parse.
	h.receive_msgs_at_level(.initial, full[split..]) or {
		assert h.unconsumed_bytes(.initial) == 0
		return
	}
	assert false // a garbage ServerHello body must never parse cleanly
}

// test_unconsumed_bytes_levels_start_empty checks that both handshake
// reassembly buffers start empty and the accessor tracks a parked fragment.
fn test_unconsumed_bytes_levels_start_empty() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	assert h.unconsumed_bytes(.handshake) == 0
	assert h.unconsumed_bytes(.initial) == 0
	_ = h.create_client_hello()!
	h.state = .wait_server_flight
	// A 2-byte fragment parked at the Handshake level is buffered, not dropped.
	_ = h.receive_msgs_at_level(.handshake, [u8(2), 0x00])!
	assert h.unconsumed_bytes(.handshake) == 2
}

// ---- state machine accessor ----

fn test_record_and_quic_facades_share_handshake_state() ! {
	mut record := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	mut quic := new_quic_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!

	assert record.state() == .start
	assert quic.state() == .start
	assert record.failure_alert() == .internal_error
	assert quic.failure_alert() == .internal_error

	_ = record.create_client_hello()!
	_ = quic.create_client_hello()!
	assert record.state() == .wait_server_hello
	assert quic.state() == .wait_server_hello
}

fn test_handshake_options_select_initial_key_share() ! {
	options := HandshakeOptions{
		alpn:             ['h2']
		validator:        fixture_validator()
		key_share_group:  .secp256r1
		supported_groups: [.secp256r1]
	}
	mut h := new_tls_handshake('example.com', options)!
	assert h.config.alpn == ['h2']
	assert h.ecdhe_group == .secp256r1
	assert h.config.client_share.group == .secp256r1
	assert h.config.client_share.key_exchange.len == 65
	_ = h.create_client_hello()!
}

fn test_handshake_options_reject_unoffered_initial_group() ! {
	new_tls_handshake('example.com', HandshakeOptions{
		validator:        fixture_validator()
		key_share_group:  .x25519
		supported_groups: [.secp256r1]
	}) or {
		assert err.msg().contains('must be included in supported_groups')
		return
	}
	assert false
}

fn test_handshake_options_reject_empty_alpn_name() {
	new_tls_handshake('example.com', HandshakeOptions{
		alpn:      ['']
		validator: fixture_validator()
	}) or {
		assert err.msg().contains('ALPN protocol names must not be empty')
		return
	}
	assert false
}

fn test_handshake_options_reject_overlong_alpn_name() {
	new_tls_handshake('example.com', HandshakeOptions{
		alpn:      ['a'.repeat(256)]
		validator: fixture_validator()
	}) or {
		assert err.msg().contains('ALPN protocol name exceeds 255 bytes')
		return
	}
	assert false
}

// test_handshake_options_reject_overlong_legacy_session_id pins RFC 8446 §4.1.2:
// legacy_session_id MUST NOT exceed 32 bytes — the wire vector would frame up to
// 255, so the config gate is the normative bound.
fn test_handshake_options_reject_overlong_legacy_session_id() {
	new_tls_handshake('example.com', HandshakeOptions{
		legacy_session_id: []u8{len: 33, init: 0x55}
		validator:         fixture_validator()
	}) or {
		assert err.msg().contains('legacy_session_id exceeds 32 bytes')
		return
	}
	assert false
}

// test_handshake_options_keeps_legacy_session_id_verbatim guards both edges of
// the legal range: the App. D.4 default length (32) and a short (still legal)
// value must reach config unchanged, because the ServerHello echo check compares
// by equality — any rewrite would break it silently.
fn test_handshake_options_keeps_legacy_session_id_verbatim() ! {
	sid := []u8{len: 32, init: 0x55}
	h := new_tls_handshake('example.com', HandshakeOptions{
		legacy_session_id: sid
		validator:         fixture_validator()
	})!
	assert h.config.session_id == sid
	short := [u8(0xAA), 0xBB]
	h2 := new_tls_handshake('example.com', HandshakeOptions{
		legacy_session_id: short
		validator:         fixture_validator()
	})!
	assert h2.config.session_id == short
}

// test_handshake_options_reject_unsupported_cipher_suite closes the raw-cast hole:
// an unsafe CipherSuite(0x1399) cast is constructible in V, would be advertised on
// the wire, and an echoed server choice would match it against the offered list.
// Config must fail fast at a membership gate instead.
fn test_handshake_options_reject_unsupported_cipher_suite() {
	// Held in a variable: a literal unsafe cast constant-folds into an enum-value
	// warning, while the runtime value is exactly the un-checkable cast a
	// hostile config caller could produce.
	raw_suite := u16(0x1399)
	new_tls_handshake('example.com', HandshakeOptions{
		cipher_suites: [unsafe { CipherSuite(raw_suite) }]
		validator:     fixture_validator()
	}) or {
		assert err.msg().contains('unsupported configured cipher suite')
		return
	}
	assert false
}

// test_handshake_options_reject_unsupported_signature_scheme: offering a scheme
// the verifier cannot check in CertificateVerify is a self-inflicted failure;
// only the signature_scheme_from_u16 set is acceptable.
fn test_handshake_options_reject_unsupported_signature_scheme() {
	raw_scheme := u16(0x0999) // runtime value, same warning-avoiding indirection
	new_tls_handshake('example.com', HandshakeOptions{
		signature_algorithms: [unsafe { SignatureScheme(raw_scheme) }]
		validator:            fixture_validator()
	}) or {
		assert err.msg().contains('unsupported configured signature scheme')
		return
	}
	assert false
}

// test_handshake_options_accepts_full_capability_lists guards over-rejection:
// every implementable suite, scheme, and group configured at once must pass.
fn test_handshake_options_accepts_full_capability_lists() ! {
	h := new_tls_handshake('example.com', HandshakeOptions{
		validator:            fixture_validator()
		key_share_group:      .x25519
		supported_groups:     default_supported_groups()
		cipher_suites:        [CipherSuite.tls_aes_128_gcm_sha256, .tls_aes_256_gcm_sha384,
			.tls_chacha20_poly1305_sha256]
		signature_algorithms: default_signature_algorithms()
	})!
	assert h.config.cipher_suites.len == 3
	assert h.config.signature_algorithms.len == 7
	assert h.config.supported_groups.len == 2
}

// ---- capability single-source lock (dedup regression) ----

// test_capability_decoders_roundtrip pins that every member of a supported_*
// list decodes from its own wire code — the *_from_u16 scanners and the lists
// in messages.v cannot drift, because the scanner walks the same list.
fn test_capability_decoders_roundtrip() ! {
	for cs in supported_cipher_suites {
		assert cipher_suite_from_u16(u16(cs))! == cs
	}
	for s in supported_signature_schemes {
		assert signature_scheme_from_u16(u16(s))! == s
	}
	for g in supported_named_groups {
		assert named_group_from_u16(u16(g))! == g
	}
}

// test_capability_unknown_codes_rejected_by_decoder_and_gate locks that an
// absent wire code fails BOTH paths with the pinned decoder message: the
// decoder rejects it on the wire, the membership gate rejects it at config, so
// acceptance and advertisement stay one source.
fn test_capability_unknown_codes_rejected_by_decoder_and_gate() ! {
	unknown_suites := [u16(0x1399), 0x1300, 0x0000]
	unknown_schemes := [u16(0x0201), 0x0808, 0x0402]
	unknown_groups := [u16(0x001f), 0x001e, 0x0000]
	for raw in unknown_suites {
		cipher_suite_from_u16(raw) or {
			assert err.msg() == 'handshake: unsupported cipher suite 0x${raw:04x}'
		}
		assert !(is_supported_cipher_suite(unsafe { CipherSuite(raw) }))
	}
	for raw in unknown_schemes {
		signature_scheme_from_u16(raw) or {
			assert err.msg() == 'handshake: unsupported signature scheme 0x${raw:04x}'
		}
		assert !(is_supported_signature_scheme(unsafe { SignatureScheme(raw) }))
	}
	for raw in unknown_groups {
		named_group_from_u16(raw) or {
			assert err.msg() == 'handshake: unsupported group 0x${raw:04x}'
		}
		assert !(is_supported_group(unsafe { NamedGroup(raw) }))
	}
}

// test_capability_default_offer_order pins the wire-byte identity of the default
// offer lists: preference order carries meaning (ChaCha20 first for the
// software-only AEAD), so any reorder must be a deliberate, fixture-reviewed
// change to the supported_* lists in messages.v.
fn test_capability_default_offer_order() ! {
	assert default_cipher_suites() == [CipherSuite.tls_chacha20_poly1305_sha256,
		.tls_aes_128_gcm_sha256, .tls_aes_256_gcm_sha384]
	assert default_signature_algorithms() == [SignatureScheme.rsa_pss_rsae_sha256,
		.rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512, .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384,
		.ed25519, .rsa_pkcs1_sha256]
	assert default_supported_groups() == [NamedGroup.x25519, .secp256r1]
	// The offered-set fallback reads the same single source.
	assert offered_supported_groups([]) == supported_named_groups
}

fn test_handshake_options_default_validator() ! {
	h := new_tls_handshake('example.com')!
	assert h.state() == .start
}

fn test_quic_handshake_options_include_alpn_and_validator() ! {
	mut h := new_quic_handshake('example.com', alpn: ['h3'], validator: fixture_validator())!
	assert h.config.alpn == ['h3']
	assert h.state() == .start
}

fn test_record_handshake_accepts_named_options() ! {
	h := new_tls_handshake('example.com', alpn: ['h2'], validator: fixture_validator())!
	assert h.config.alpn == ['h2']
}

fn test_reassembly_is_owned_by_each_handshake_core() ! {
	mut record := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	mut quic := new_quic_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	_ = record.create_client_hello()!
	_ = quic.create_client_hello()!

	_ = record.receive_msgs_at_level(.initial, [u8(2), 0])!
	_ = quic.receive_msgs_at_level(.initial, [u8(2)])!

	assert record.HandshakeCore.buffers.initial.len == 2
	assert quic.HandshakeCore.buffers.initial.len == 1
	assert record.unconsumed_bytes(.initial) == 2
	record.fail_and_zeroize_secrets()
	assert record.unconsumed_bytes(.initial) == 0
	assert quic.HandshakeCore.buffers.initial.len == 1
}

// test_state_progression_to_wait_server_hello checks that the machine starts at
// .start and moves to .wait_server_hello once the ClientHello is built.
fn test_state_progression_to_wait_server_hello() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	assert h.state() == .start
	_ = h.create_client_hello()!
	assert h.state() == .wait_server_hello
}

// test_feed_rejects_out_of_order_message checks that a Certificate arriving
// while the ServerHello is awaited is rejected before parsing.
fn test_feed_rejects_out_of_order_message() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	_ = h.create_client_hello()!
	cert := wrap_hsk(.certificate, []u8{len: 4, init: 0x01})
	h.receive_msgs_at_level(.handshake, cert) or {
		assert err.msg().contains('only expected after ServerHello')
		assert h.unconsumed_bytes(.handshake) == 0
		assert h.state() == .wait_server_hello
		return
	}
	assert false
}

// ---- receive_msgs_at_level() phase guards & failure semantics ----

// test_create_client_hello_only_runs_once checks that the single-shot entry
// point refuses a second call that would poison the transcript.
fn test_create_client_hello_only_runs_once() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	_ = h.create_client_hello()!
	h.create_client_hello() or {
		assert err.msg().contains('only runs once')
		assert h.state == .wait_server_hello
		return
	}
	assert false
}

// test_feed_before_client_hello_refused checks that peer bytes before the
// ClientHello are refused as a contract error, leaving the state .start.
fn test_feed_before_client_hello_refused() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.receive_msgs_at_level(.initial, wrap_hsk(.server_hello, []u8{len: 4})) or {
		assert err.msg().contains('receive_msgs_at_level() before create_client_hello()')
		assert h.state == .start
		return
	}
	assert false
}

// test_feed_initial_after_server_hello_refused checks that initial-level bytes
// after the ServerHello wait are refused, leaving the machine usable.
fn test_feed_initial_after_server_hello_refused() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	_ = h.create_client_hello()!
	h.state = .wait_server_flight
	h.receive_msgs_at_level(.initial, wrap_hsk(.server_hello, []u8{len: 4})) or {
		assert err.msg().contains('while awaiting ServerHello')
		assert h.state == .wait_server_flight
		return
	}
	assert false
}

// test_feed_marks_failed_and_refuses_after_protocol_error checks that a parse
// failure is terminal: the state becomes .failed and later feeds are refused.
fn test_feed_marks_failed_and_refuses_after_protocol_error() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	_ = h.create_client_hello()!
	// A garbage ServerHello body fails to parse; the failure is terminal.
	bad := wrap_hsk(.server_hello, []u8{len: 8, init: 0x01})
	h.receive_msgs_at_level(.initial, bad) or {
		assert h.state == .failed
		// No later receive_msgs_at_level() may make progress against a dead machine.
		h.receive_msgs_at_level(.initial, bad) or {
			assert err.msg().contains('state machine has failed')
			return
		}
		assert false
		return
	}
	assert false
}

// test_class_a_failure_zeroizes_and_parks_failed locks the failure-path choke-point:
// a Class A dispatch failure (an explicit classify) at the handshake level must both
// park the machine in .failed and zeroize every derived secret — not just record the
// alert. Planting key-schedule material first makes the zeroization observable.
fn test_class_a_failure_zeroizes_and_parks_failed() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	_ = h.create_client_hello()!
	h.handshake_secret = [u8(9), 8, 7]
	h.secrets.handshake.client = [u8(1), 2, 3]
	h.secrets.handshake.server = [u8(4), 5, 6]
	h.state = .wait_server_flight
	// Class A: a Certificate is illegal while EncryptedExtensions is awaited (unexpected_message).
	h.receive_msgs_at_level(.handshake, wrap_hsk(.certificate, []u8{len: 4, init: 0x01})) or {
		assert h.state == .failed
		assert h.handshake_secret.len == 0
		assert h.secrets.handshake.client.len == 0
		assert h.secrets.handshake.server.len == 0
		return
	}
	assert false, 'an out-of-order Certificate must abort the handshake'
}

// test_class_b_parse_failure_zeroizes_and_reports_decode_error locks the Phase-2
// classification fix: a Class B internal error (a peer-triggered parse that uses `!`)
// now routes through classify_failure, so it BOTH tears down and surfaces the
// RFC-correct decode_error instead of the stale .internal_error default.
fn test_class_b_parse_failure_zeroizes_and_reports_decode_error() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	_ = h.create_client_hello()!
	h.handshake_secret = [u8(9), 8, 7]
	h.secrets.handshake.client = [u8(1), 2, 3]
	h.state = .wait_server_flight
	h.flight_step = .certificate
	// Class B: a malformed Certificate body fails to decode while in the right state.
	h.receive_msgs_at_level(.handshake, wrap_hsk(.certificate, []u8{len: 8, init: 0x01})) or {
		assert h.state == .failed
		assert h.failure_alert() == .decode_error
		assert h.handshake_secret.len == 0
		assert h.secrets.handshake.client.len == 0
		return
	}
	assert false, 'a malformed Certificate must abort the handshake'
}

// test_malformed_finished_reports_decode_error checks that a Finished shorter than
// Hash.length is classified decode_error (not the stale internal_error) and is terminal.
fn test_malformed_finished_reports_decode_error() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	_ = h.create_client_hello()!
	h.secrets.handshake.server = [u8(1), 2, 3]
	h.state = .wait_server_flight
	h.flight_step = .finished
	h.receive_msgs_at_level(.handshake, wrap_hsk(.finished, []u8{len: 4, init: 0xab})) or {
		assert h.state == .failed
		assert h.failure_alert() == .decode_error
		return
	}
	assert false, 'a malformed Finished must abort the handshake'
}

// test_feed_handshake_level_after_connected_refused checks that the handshake
// API refuses handshake-flight input after Finished without buffering it.
fn test_feed_handshake_level_after_connected_refused() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	_ = h.create_client_hello()!
	h.state = .connected
	h.receive_msgs_at_level(.handshake, wrap_hsk(.new_session_ticket, [u8(0)])) or {
		assert err.msg().contains('only expected after ServerHello')
		assert h.state == .connected
		assert h.unconsumed_bytes(.handshake) == 0
		return
	}
	assert false
}

// ---- traffic_keys / peer_traffic_secrets lifecycle (white-box) ----

// test_traffic_keys_unavailable_before_derivation checks that the accessors
// refuse until the handshake derives keys.
fn test_traffic_keys_unavailable_before_derivation() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	_ = h.create_client_hello()!
	_, _, _, _ := h.record_traffic_keys(.handshake) or {
		return
	}
	assert false
}

// A rejected input at the wrong handshake phase must not discard usable keys.
fn test_nonfatal_receive_error_preserves_record_keys() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.keys.application.client = TrafficKeys{ key: [u8(1)], iv: [u8(2)] }
	h.keys.application.server = TrafficKeys{ key: [u8(3)], iv: [u8(4)] }
	h.state = .connected

	h.receive_msgs_at_level(.initial, [u8(0)]) or {
		assert err.msg().contains('only expected while awaiting ServerHello')
		assert h.state == .connected
		assert h.keys.application.client.key.len == 1
		assert h.keys.application.server.key.len == 1
		return
	}
	assert false
}

// test_zeroize_traffic_secrets_handshake drops cached handshake keys and secrets.
fn test_zeroize_traffic_secrets_handshake() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.secrets.handshake.client = [u8(1), 2, 3]
	h.secrets.handshake.server = [u8(4), 5, 6]
	h.keys.handshake.client = TrafficKeys{ key: [u8(7)], iv: [u8(8)] }
	h.keys.handshake.server = TrafficKeys{ key: [u8(9)], iv: [u8(10)] }
	h.state = .connected

	h.zeroize_traffic_secrets(.handshake)!

	assert h.secrets.handshake.client.len == 0
	assert h.secrets.handshake.server.len == 0
	assert h.keys.handshake.client.key.len == 0
	assert h.keys.handshake.server.key.len == 0
	// Handshake keys/secrets are gone: the record accessor now refuses.
	_, _, _, _ := h.record_traffic_keys(.handshake) or {
		return
	}
	assert false
}

// test_zeroize_traffic_secrets_handshake_requires_connected_state checks that
// early cleanup is refused with nothing wiped.
fn test_zeroize_traffic_secrets_handshake_requires_connected_state() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.secrets.handshake.client = [u8(1), 2, 3]
	h.keys.handshake.client = TrafficKeys{ key: [u8(7)], iv: [u8(8)] }
	h.zeroize_traffic_secrets(.handshake) or {
		assert err.msg().contains('reaches .connected')
		assert h.secrets.handshake.client.len == 3
		assert h.keys.handshake.client.key.len == 1
		return
	}
	assert false
}

// test_zeroize_traffic_secrets_application_clears_and_refuses checks that zeroization forgets
// the application secrets and their cached keys (§7.5).
fn test_zeroize_traffic_secrets_application_clears_and_refuses() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.state = .connected
	h.secrets.application.client = [u8(11), 12]
	h.secrets.application.server = [u8(13), 14]
	h.keys.application.client = TrafficKeys{ key: [u8(1)], iv: [u8(2)] }
	h.keys.application.server = TrafficKeys{ key: [u8(3)], iv: [u8(4)] }

	h.zeroize_traffic_secrets(.application)!

	assert h.secrets.application.client.len == 0
	assert h.secrets.application.server.len == 0
	// §7.5 says forget the secret values *and* the keys: the cached TrafficKeys die with them.
	assert h.keys.application.client.key.len == 0
	assert h.keys.application.client.iv.len == 0
	assert h.keys.application.server.key.len == 0
	_, _, _, _ := h.record_traffic_keys(.application) or {
		return
	}
	assert false
}

// test_zeroize_traffic_secrets_application_refuses_before_connected keeps an out-of-phase
// cleanup call from silently destroying keys needed by the handshake.
fn test_zeroize_traffic_secrets_application_refuses_before_connected() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.secrets.application.client = [u8(11), 12]
	h.secrets.application.server = [u8(13), 14]
	h.keys.application.client = TrafficKeys{ key: [u8(1)], iv: [u8(2)] }

	h.zeroize_traffic_secrets(.application) or {
		assert err.msg().contains('only valid once the handshake reaches .connected')
		assert h.state() == .start
		assert h.secrets.application.client == [u8(11), 12]
		assert h.keys.application.client.key == [u8(1)]
		return
	}
	assert false
}

// test_zeroize_traffic_secrets_refuses_initial checks the initial level, which has
// no TLS traffic secrets, is refused rather than silently accepted.
fn test_zeroize_traffic_secrets_refuses_initial() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.state = .connected
	h.zeroize_traffic_secrets(.initial) or {
		assert err.msg().contains('initial level has no traffic secrets')
		return
	}
	assert false
}

// test_update_traffic_keys_refuse_missing_secrets checks that a key
// update refuses while the application traffic secrets are still empty.
fn test_update_traffic_keys_refuse_missing_secrets() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.state = .connected
	h.update_traffic_keys(true) or {
		assert err.msg().contains('server application traffic secret')
		h.update_traffic_keys(false) or {
			assert err.msg().contains('client application traffic secret')
			return
		}
		assert false
		return
	}
	assert false
}

// test_update_traffic_keys_refuse_before_connected ensures a caller
// cannot update secrets merely because they are present in the core.
fn test_update_traffic_keys_refuse_before_connected() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.secrets.application.server = []u8{len: 32, init: 1}
	h.secrets.application.client = []u8{len: 32, init: 2}
	old_server := h.secrets.application.server.clone()
	old_client := h.secrets.application.client.clone()

	h.update_traffic_keys(true) or {
		assert err.msg().contains('before the handshake is connected')
		assert h.state() == .start
		assert h.secrets.application.server == old_server
		assert h.keys.application.server.key.len == 0
		h.update_traffic_keys(false) or {
			assert err.msg().contains('before the handshake is connected')
			assert h.state() == .start
			assert h.secrets.application.client == old_client
			assert h.keys.application.client.key.len == 0
			return
		}
		assert false
		return
	}
	assert false
}

// test_update_traffic_keys_derives_next_keys checks that the key update
// derives the next secrets and rebuilds the cached keys (§7.2).
fn test_update_traffic_keys_derives_next_keys() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.state = .connected
	h.secrets.application.server = []u8{len: 32, init: 1}
	h.secrets.application.client = []u8{len: 32, init: 2}
	old_server := h.secrets.application.server.clone()
	old_client := h.secrets.application.client.clone()
	h.update_traffic_keys(true)!
	h.update_traffic_keys(false)!
	assert h.secrets.application.server != old_server
	assert h.secrets.application.client != old_client
	assert h.secrets.application.server.len == 32
	assert h.secrets.application.client.len == 32
	key, _, _, _ := h.record_traffic_keys(.application)!
	assert key.len > 0
}

// test_update_traffic_keys_refuses_after_zeroize checks that a key update
// after teardown is refused instead of resurrecting the secret.
fn test_update_traffic_keys_refuses_after_zeroize() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.state = .connected
	h.secrets.application.client = [u8(1), 2, 3]
	h.keys.application.client = TrafficKeys{ key: [u8(4)], iv: [u8(5)] }
	h.zeroize_traffic_secrets(.application)!
	h.update_traffic_keys(false) or {
		assert err.msg().contains('destroyed by zeroize_traffic_secrets(.application)')
		return
	}
	assert false
}

// ---- HRR second-hello identity (§4.1.4) via the codec ----

// test_second_hello_reproduces_pinned_random checks that the retry ClientHello
// carries the same pinned random as the first (§4.1.4).
fn test_second_hello_reproduces_pinned_random() ! {
	mut cfg := ClientHelloConfig{
		server_name:  'example.com'
		session_id:   []u8{len: 32, init: 0xAA} // App. D.4's default length; §4.1.2 caps at 32
		random:       []u8{len: 32, init: 0x42}
		client_share: KeyShareEntry{
			group:        .x25519
			key_exchange: []u8{len: 32, init: 0x01}
		}
	}
	_, full1 := build_client_hello(cfg)!
	cfg.cookie = [u8(0xC0), 0x69, 0x65] // a retry hello carries a cookie
	_, full2 := build_client_hello(cfg)!
	assert full1 != full2 // the cookie changes the bytes
	// Both hellos embed the identical 32-byte random (§4.1.4); layout puts it at offset 6.
	random1 := full1[6..6 + 32]
	random2 := full2[6..6 + 32]
	assert random1 == cfg.random
	assert random2 == cfg.random
}

// ---- recordless framing ----

// test_next_recordless_splits_one_byte_cadence checks that a message
// materializes exactly once, at the final byte (RFC 9001 §4).
fn test_next_recordless_splits_one_byte_cadence() ! {
	mut buf := []u8{}
	full := wrap_hsk(.finished, [u8(0xDE), 0xAD, 0xBE, 0xEF])
	mut got := 0
	for b in full {
		buf << b
		msg := next_recordless_message(mut buf)!
		if msg.len > 0 {
			got += 1
			assert msg == full
			assert buf.len == 0
		}
	}
	assert got == 1
}

// test_next_recordless_two_messages_sequential checks that two coalesced
// messages are extracted one at a time.
fn test_next_recordless_two_messages_sequential() ! {
	// `+` cannot join []u8 in V, so the second frame is appended with `<<`.
	mut buf := wrap_hsk(.encrypted_extensions, [u8(0x00)])
	buf << wrap_hsk(.certificate, [u8(0x01), 0x02])
	m1 := next_recordless_message(mut buf)!
	assert m1.len == 5 // 4-byte header + 1-byte body
	m2 := next_recordless_message(mut buf)!
	assert m2.len == 6
	assert buf.len == 0
}

// test_next_recordless_rejects_oversize_length checks that a length above
// max_handshake_message_len aborts at the header.
fn test_next_recordless_rejects_oversize_length() ! {
	mut w := wire.new_writer(4)
	w.write_u8(u8(HandshakeType.certificate))
	w.write_u24(u32(max_handshake_message_len + 1))
	mut buf := w.bytes()
	next_recordless_message(mut buf) or {
		return
	}
	assert false
}

// test_traffic_keys_returns_independent_copies checks that the accessor returns
// copies, so a key update cannot wipe keys an adapter still holds.
fn test_traffic_keys_returns_independent_copies() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.keys.handshake.client = TrafficKeys{ key: [u8(1), 2, 3], iv: [u8(4), 5] }
	h.keys.handshake.server = TrafficKeys{ key: [u8(6), 7], iv: [u8(8)] }
	ck, civ, sk, _ := h.record_traffic_keys(.handshake)!
	assert unsafe { voidptr(&ck[0]) } != unsafe { voidptr(&h.keys.handshake.client.key[0]) }
	assert unsafe { voidptr(&civ[0]) } != unsafe { voidptr(&h.keys.handshake.client.iv[0]) }
	assert unsafe { voidptr(&sk[0]) } != unsafe { voidptr(&h.keys.handshake.server.key[0]) }
	assert ck == [u8(1), 2, 3]
	assert sk == [u8(6), 7]
}

// test_update_traffic_keys_wipes_superseded_generation checks that the
// superseded generation is zeroed in place after the key update.
fn test_update_traffic_keys_wipes_superseded_generation() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.state = .connected
	h.secrets.application.server = []u8{len: 32, init: 7}
	h.keys.application.server = TrafficKeys{ key: [u8(9), 9, 9], iv: [u8(9)] }
	// Aliases into the old generation, captured before the key update runs.
	old_secret := h.secrets.application.server
	old_key := h.keys.application.server.key

	h.update_traffic_keys(true)!

	// The update derives the successor first, then zeroes the superseded material in place.
	assert old_secret.len == 32
	for b in old_secret {
		assert b == 0
	}
	for b in old_key {
		assert b == 0
	}
	assert h.secrets.application.server != old_secret
	assert h.secrets.application.server.len == 32
	assert h.keys.application.server.key.len > 0
}

// test_available_secret_phases_tracks_derivation locks the transport-neutral
// readiness query the adapters now rely on instead of decoding HandshakeState:
// each phase flips true only once both directions' secrets exist, and a terminal
// failure that wipes the schedule drops readiness back to none.
fn test_available_secret_phases_tracks_derivation() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	_ = h.create_client_hello()!
	// Before ServerHello: no phase material yet.
	assert h.available_secret_phases().handshake == false
	assert h.available_secret_phases().application == false
	// Plant handshake secrets (as the ServerHello derivation would).
	h.secrets.handshake.client = [u8(1), 2, 3]
	h.secrets.handshake.server = [u8(4), 5, 6]
	assert h.available_secret_phases().handshake
	assert h.available_secret_phases().application == false
	// Plant application secrets (as the server Finished derivation would).
	h.secrets.application.client = [u8(7)]
	h.secrets.application.server = [u8(8)]
	assert h.available_secret_phases().application
	// A terminal failure wipes the whole schedule: readiness drops to none.
	h.fail_and_zeroize_secrets()
	assert h.available_secret_phases().handshake == false
	assert h.available_secret_phases().application == false
}
