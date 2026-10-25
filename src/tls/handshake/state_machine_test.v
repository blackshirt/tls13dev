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
	return pki.new_validator(pki.new_trust_store(), false)
}

// wrap_hs frames a handshake body with its 4-byte header, mirroring the core's
// own framing so tests can plant complete messages on a level stream.
fn wrap_hs(typ HandshakeType, body []u8) []u8 {
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
	quic.quic_traffic_secrets(.initial) or {
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

// test_feed_plaintext_buffers_incomplete_message checks that an incomplete
// ServerHello parks in the plaintext buffer without parsing.
fn test_feed_plaintext_buffers_incomplete_message() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	_ = h.create_client_hello()!

	full := wrap_hs(.server_hello, []u8{len: 10, init: 0xAA})
	split := full.len / 2

	first := h.receive_msgs_at_level(.initial, full[..split])!
	assert first.len == 0
	assert h.record_unconsumed_bytes(.initial) == split

	// Completing the frame consumes it; the garbage body then fails to parse.
	h.receive_msgs_at_level(.initial, full[split..]) or {
		assert h.record_unconsumed_bytes(.initial) == 0
		return
	}
	assert false // a garbage ServerHello body must never parse cleanly
}

// test_record_unconsumed_bytes_levels_start_empty checks that both handshake
// reassembly buffers start empty and the accessor tracks a parked fragment.
fn test_record_unconsumed_bytes_levels_start_empty() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	assert h.record_unconsumed_bytes(.handshake) == 0
	assert h.record_unconsumed_bytes(.initial) == 0
	_ = h.create_client_hello()!
	// A 2-byte fragment parked at the Handshake level is buffered, not dropped.
	_ = h.receive_msgs_at_level(.handshake, [u8(2), 0x00])!
	assert h.record_unconsumed_bytes(.handshake) == 2
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

	assert record.HandshakeCore.plaintext_reassembly.len == 2
	assert quic.HandshakeCore.plaintext_reassembly.len == 1
	assert record.record_unconsumed_bytes(.initial) == 2
	record.fail_and_destroy_secrets()
	assert record.record_unconsumed_bytes(.initial) == 0
	assert quic.HandshakeCore.plaintext_reassembly.len == 1
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
	cert := wrap_hs(.certificate, []u8{len: 4, init: 0x01})
	h.receive_msgs_at_level(.handshake, cert) or {
		assert h.record_unconsumed_bytes(.handshake) == 0
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
	h.receive_msgs_at_level(.initial, wrap_hs(.server_hello, []u8{len: 4})) or {
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
	h.state = .wait_encrypted_extensions
	h.receive_msgs_at_level(.initial, wrap_hs(.server_hello, []u8{len: 4})) or {
		assert err.msg().contains('while awaiting ServerHello')
		assert h.state == .wait_encrypted_extensions
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
	bad := wrap_hs(.server_hello, []u8{len: 8, init: 0x01})
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

// test_feed_reassembly_is_bounded_after_connected checks that late bytes after
// .connected trip the reassembly cap instead of growing memory.
fn test_feed_reassembly_is_bounded_after_connected() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	_ = h.create_client_hello()!
	h.state = .connected
	h.receive_msgs_at_level(.handshake, []u8{len: handshake_header_len + max_handshake_message_len + 1, init: 0xAA}) or {
		assert err.msg().contains('reassembly exceeds')
		assert h.state == .failed
		return
	}
	assert false
}

// ---- traffic_keys / quic_traffic_secrets lifecycle (white-box) ----

// test_traffic_keys_unavailable_before_derivation checks that the accessors
// refuse until the handshake derives keys.
fn test_traffic_keys_unavailable_before_derivation() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	_ = h.create_client_hello()!
	_, _ := h.record_traffic_keys(.handshake) or {
		return
	}
	assert false
}

// A rejected input at the wrong handshake phase must not discard usable keys.
fn test_nonfatal_receive_error_preserves_record_keys() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.app_keys.client = TrafficKeys{ key: [u8(1)], iv: [u8(2)] }
	h.app_keys.server = TrafficKeys{ key: [u8(3)], iv: [u8(4)] }
	h.state = .connected

	h.receive_msgs_at_level(.initial, [u8(0)]) or {
		assert err.msg().contains('only expected while awaiting ServerHello')
		assert h.state == .connected
		assert h.app_keys.client.key.len == 1
		assert h.app_keys.server.key.len == 1
		return
	}
	assert false
}

// test_zeroize_handshake_traffic_secrets drops cached handshake keys and secrets.
fn test_zeroize_handshake_traffic_secrets() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.client_hs_traffic = [u8(1), 2, 3]
	h.server_hs_traffic = [u8(4), 5, 6]
	h.hs_keys.client = TrafficKeys{ key: [u8(7)], iv: [u8(8)] }
	h.hs_keys.server = TrafficKeys{ key: [u8(9)], iv: [u8(10)] }
	h.state = .connected

	h.zeroize_handshake_traffic_secrets()!

	assert h.client_hs_traffic.len == 0
	assert h.server_hs_traffic.len == 0
	assert h.hs_keys.client.key.len == 0
	assert h.hs_keys.server.key.len == 0
	// Handshake keys/secrets are gone: the record accessor now refuses.
	_, _ := h.record_traffic_keys(.handshake) or {
		return
	}
	assert false
}

// test_zeroize_handshake_traffic_secrets_requires_connected_state checks that
// early cleanup is refused with nothing wiped.
fn test_zeroize_handshake_traffic_secrets_requires_connected_state() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.client_hs_traffic = [u8(1), 2, 3]
	h.hs_keys.client = TrafficKeys{ key: [u8(7)], iv: [u8(8)] }
	h.zeroize_handshake_traffic_secrets() or {
		assert err.msg().contains('reached .connected')
		assert h.client_hs_traffic.len == 3
		assert h.hs_keys.client.key.len == 1
		return
	}
	assert false
}

// test_zeroize_app_secrets_clears_and_refuses checks that zeroization forgets
// the application secrets and their cached keys (§7.5).
fn test_zeroize_app_secrets_clears_and_refuses() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.client_ap_traffic = [u8(11), 12]
	h.server_ap_traffic = [u8(13), 14]
	h.app_keys.client = TrafficKeys{ key: [u8(1)], iv: [u8(2)] }
	h.app_keys.server = TrafficKeys{ key: [u8(3)], iv: [u8(4)] }

	h.zeroize_app_secrets()

	assert h.client_ap_traffic.len == 0
	assert h.server_ap_traffic.len == 0
	// §7.5 says forget the secret values *and* the keys: the cached TrafficKeys die with them.
	assert h.app_keys.client.key.len == 0
	assert h.app_keys.client.iv.len == 0
	assert h.app_keys.server.key.len == 0
	_, _ := h.record_traffic_keys(.application) or {
		return
	}
	assert false
}

// test_record_update_traffic_keys_refuse_missing_secrets checks that the
// ratchet refuses while the application traffic secrets are still empty.
fn test_record_update_traffic_keys_refuse_missing_secrets() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.record_update_read_traffic_keys() or {
		assert err.msg().contains('server application traffic secret')
		h.record_update_write_traffic_keys() or {
			assert err.msg().contains('client application traffic secret')
			return
		}
		assert false
		return
	}
	assert false
}

// test_record_update_traffic_keys_ratchet_forward checks that the ratchet
// advances the secrets and rebuilds the cached keys (§7.2).
fn test_record_update_traffic_keys_ratchet_forward() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.server_ap_traffic = []u8{len: 32, init: 1}
	h.client_ap_traffic = []u8{len: 32, init: 2}
	old_server := h.server_ap_traffic.clone()
	old_client := h.client_ap_traffic.clone()
	h.record_update_read_traffic_keys()!
	h.record_update_write_traffic_keys()!
	assert h.server_ap_traffic != old_server
	assert h.client_ap_traffic != old_client
	assert h.server_ap_traffic.len == 32
	assert h.client_ap_traffic.len == 32
	keys, _ := h.record_traffic_keys(.application)!
	assert keys.key.len > 0
}

// test_record_update_traffic_keys_refuses_after_zeroize checks that a ratchet
// after teardown is refused instead of resurrecting the secret.
fn test_record_update_traffic_keys_refuses_after_zeroize() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.client_ap_traffic = [u8(1), 2, 3]
	h.app_keys.client = TrafficKeys{ key: [u8(4)], iv: [u8(5)] }
	h.zeroize_app_secrets()
	h.record_update_write_traffic_keys() or {
		assert err.msg().contains('destroyed by zeroize_app_secrets')
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
		session_id:   [u8(0xAA), 0xBB]
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
	full := wrap_hs(.finished, [u8(0xDE), 0xAD, 0xBE, 0xEF])
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
	mut buf := wrap_hs(.encrypted_extensions, [u8(0x00)])
	buf << wrap_hs(.certificate, [u8(0x01), 0x02])
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
// copies, so a ratchet cannot wipe keys an adapter still holds.
fn test_traffic_keys_returns_independent_copies() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.hs_keys.client = TrafficKeys{ key: [u8(1), 2, 3], iv: [u8(4), 5] }
	h.hs_keys.server = TrafficKeys{ key: [u8(6), 7], iv: [u8(8)] }
	ck, sk := h.record_traffic_keys(.handshake)!
	assert unsafe { voidptr(&ck.key[0]) } != unsafe { voidptr(&h.hs_keys.client.key[0]) }
	assert unsafe { voidptr(&ck.iv[0]) } != unsafe { voidptr(&h.hs_keys.client.iv[0]) }
	assert unsafe { voidptr(&sk.key[0]) } != unsafe { voidptr(&h.hs_keys.server.key[0]) }
	assert ck.key == [u8(1), 2, 3]
	assert sk.key == [u8(6), 7]
}

// test_record_update_traffic_keys_wipes_superseded_generation checks that the
// superseded generation is zeroed in place after the ratchet.
fn test_record_update_traffic_keys_wipes_superseded_generation() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })!
	h.server_ap_traffic = []u8{len: 32, init: 7}
	h.app_keys.server = TrafficKeys{ key: [u8(9), 9, 9], iv: [u8(9)] }
	// Aliases into the old generation, captured before the ratchet runs.
	old_secret := h.server_ap_traffic
	old_key := h.app_keys.server.key

	h.record_update_read_traffic_keys()!

	// The ratchet computes the successor first, then zeroes the superseded material in place.
	assert old_secret.len == 32
	for b in old_secret {
		assert b == 0
	}
	for b in old_key {
		assert b == 0
	}
	assert h.server_ap_traffic != old_secret
	assert h.server_ap_traffic.len == 32
	assert h.app_keys.server.key.len > 0
}
