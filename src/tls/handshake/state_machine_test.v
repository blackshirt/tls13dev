// Copyright (c) 2026 blackshirt.
//
// Core-contract suite for the transport-neutral handshake (module tls.handshake),
// where the ClientHandshake private fields stay reachable. It exercises the
// adapter seam the TCP record layer and a QUIC engine share: level-tagged feed()
// reassembly across adversarial splits, buffered_bytes(), the confirm/zeroize
// secret lifecycle, the traffic_keys/exported_secrets guards before derivation,
// and the recordless passthrough framing. No sockets, no records.
module handshake

import tls.pki
import tls.wire

// make_validator builds a Validator over an empty trust store; none of these
// tests reach chain verification (feed() stops earlier or no Certificate message
// is ever fed), so it only has to be a well-formed injected value. Named without
// the `test_` prefix so V's runner does not treat this helper as a test case.
fn make_validator() pki.Validator {
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

// ---- SecretLevel / HandshakeMessage contract ----

fn test_secret_level_order() ! {
	// The enum order is the RFC 9001 §4.1 level order; pin the implicit ordinals
	// so adapters that index by level cannot silently drift.
	assert u8(SecretLevel.initial) == 0
	assert u8(SecretLevel.handshake) == 1
	assert u8(SecretLevel.application) == 2
}

fn test_handshake_message_carries_level_and_bytes() ! {
	m := new_handshake_message(.handshake, [u8(0x14), 0x00, 0x00, 0x01, 0xff])!
	assert m.level == .handshake
	assert m.msg.len == 5
}

// The @[noinit] gate leaves new_handshake_message as the only way in, and it
// refuses bytes whose 4-byte header disagrees with the body it is carrying —
// a well-formed header must never vouch for truncated or padded message bytes.
fn test_new_handshake_message_rejects_length_mismatch() ! {
	// Finished header declaring a 5-byte body, message carrying only 1.
	bad := [u8(0x14), 0x00, 0x00, 0x05, 0xff]
	new_handshake_message(.handshake, bad) or {
		assert err.msg().contains('declares 5 body bytes, message carries 1')
		return
	}
	assert false
}

// A message shorter than its own header cannot even be parsed, so the
// constructor surfaces the header error rather than building a shell.
fn test_new_handshake_message_rejects_truncated_header() ! {
	new_handshake_message(.initial, [u8(0x01), 0x00]) or {
		assert err.msg().contains('header truncated')
		return
	}
	assert false
}

// ---- feed() reassembly: split and coalesced delivery ----

fn test_feed_initial_buffers_incomplete_message() ! {
	mut h := new_client_handshake('example.com', []string{}, make_validator())!
	_ = h.create_client_hello()!

	// An incomplete ServerHello frame must park in the Initial buffer without
	// parsing — the record-boundary-independence proof at the reassembly layer.
	full := wrap_hs(.server_hello, []u8{len: 10, init: 0xAA})
	split := full.len / 2

	first := h.feed(.initial, full[..split])!
	assert first.len == 0
	assert h.buffered_bytes(.initial) == split

	// Completing the frame consumes it from the buffer; the garbage body then
	// fails to parse, proving the whole message was taken off the stream.
	h.feed(.initial, full[split..]) or {
		assert h.buffered_bytes(.initial) == 0
		return
	}
	assert false // a garbage ServerHello body must never parse cleanly
}

fn test_feed_application_level_rejected() ! {
	mut h := new_client_handshake('example.com', []string{}, make_validator())!
	_ = h.create_client_hello()!
	// Application-level bytes are post-handshake traffic; feed refuses them.
	h.feed(.application, [u8(1)]) or {
		return
	}
	assert false
}

fn test_buffered_bytes_levels_start_empty() ! {
	mut h := new_client_handshake('example.com', []string{}, make_validator())!
	assert h.buffered_bytes(.handshake) == 0
	assert h.buffered_bytes(.application) == 0
	_ = h.create_client_hello()!
	// A 2-byte fragment parked at the Handshake level is buffered, not dropped.
	_ = h.feed(.handshake, [u8(2), 0x00])!
	assert h.buffered_bytes(.handshake) == 2
}

// ---- state machine accessor ----

fn test_state_progression_to_wait_server_hello() ! {
	mut h := new_client_handshake('example.com', []string{}, make_validator())!
	assert h.state() == .start
	_ = h.create_client_hello()!
	assert h.state() == .wait_server_hello
}

fn test_feed_rejects_out_of_order_message() ! {
	mut h := new_client_handshake('example.com', []string{}, make_validator())!
	_ = h.create_client_hello()!
	// A Certificate at the Handshake level while still awaiting the ServerHello:
	// the wait-order guards reject it before parsing, and the consumed frame
	// leaves nothing parked behind.
	cert := wrap_hs(.certificate, []u8{len: 4, init: 0x01})
	h.feed(.handshake, cert) or {
		assert h.buffered_bytes(.handshake) == 0
		return
	}
	assert false
}

// ---- feed() phase guards & failure semantics ----

fn test_create_client_hello_only_runs_once() ! {
	mut h := new_client_handshake('example.com', []string{}, make_validator())!
	_ = h.create_client_hello()!
	// A second call would inject a duplicate ClientHello into the transcript and
	// poison every later hash with it — the single-shot entry point refuses.
	h.create_client_hello() or {
		assert err.msg().contains('only runs once')
		assert h.state == .wait_server_hello
		return
	}
	assert false
}

fn test_feed_before_client_hello_refused() ! {
	mut h := new_client_handshake('example.com', []string{}, make_validator())!
	// Nothing has been sent yet, so there is nothing for peer bytes to answer;
	// the refusal is a contract error, not a failure — state stays .start.
	h.feed(.initial, wrap_hs(.server_hello, []u8{len: 4})) or {
		assert err.msg().contains('feed() before create_client_hello()')
		assert h.state == .start
		return
	}
	assert false
}

fn test_feed_initial_after_server_hello_refused() ! {
	mut h := new_client_handshake('example.com', []string{}, make_validator())!
	_ = h.create_client_hello()!
	// The ServerHello wait is over: further Initial-level bytes have no legal
	// meaning, and refusing them leaves the machine usable (state untouched).
	h.state = .wait_encrypted_extensions
	h.feed(.initial, wrap_hs(.server_hello, []u8{len: 4})) or {
		assert err.msg().contains('while awaiting ServerHello')
		assert h.state == .wait_encrypted_extensions
		return
	}
	assert false
}

fn test_feed_marks_failed_and_refuses_after_protocol_error() ! {
	mut h := new_client_handshake('example.com', []string{}, make_validator())!
	_ = h.create_client_hello()!
	// A ServerHello carrying a garbage body fails to parse; that failure is
	// terminal, so the documented .failed state must actually be set ...
	bad := wrap_hs(.server_hello, []u8{len: 8, init: 0x01})
	h.feed(.initial, bad) or {
		assert h.state == .failed
		// ... and no later feed() may make progress against a dead machine.
		h.feed(.initial, bad) or {
			assert err.msg().contains('state machine has failed')
			return
		}
		assert false
		return
	}
	assert false
}

fn test_feed_reassembly_is_bounded_after_connected() ! {
	mut h := new_client_handshake('example.com', []string{}, make_validator())!
	_ = h.create_client_hello()!
	// Late Handshake-level retransmits after .connected skip the drain loop, so
	// without the cap an unbounded stream would park in hs_reassembly; the cap
	// must trip first and fail the machine rather than grow memory.
	h.state = .connected
	h.feed(.handshake, []u8{len: 4 + max_handshake_message_len + 1, init: 0xAA}) or {
		assert err.msg().contains('reassembly exceeds')
		assert h.state == .failed
		return
	}
	assert false
}

// ---- traffic_keys / exported_secrets lifecycle (white-box) ----

fn test_traffic_keys_unavailable_before_derivation() ! {
	mut h := new_client_handshake('example.com', []string{}, make_validator())!
	_ = h.create_client_hello()!
	// No level has cached keys yet: .handshake/.application refuse until
	// ServerHello / server Finished derive them. Reaching an `assert false`
	// would mean an accessor wrongly handed back material.
	_, _ := h.traffic_keys(.handshake) or {
		_, _ := h.exported_secrets(.handshake) or {
			return
		}
		assert false
	}
	assert false
}

fn test_confirm_handshake_drops_handshake_material() ! {
	mut h := new_client_handshake('example.com', []string{}, make_validator())!
	// Plant cached handshake keys/secrets directly (white-box, same module) to
	// observe exactly what confirm_handshake() destroys.
	h.client_hs_traffic = [u8(1), 2, 3]
	h.server_hs_traffic = [u8(4), 5, 6]
	h.client_hs_keys = TrafficKeys{ key: [u8(7)], iv: [u8(8)] }
	h.server_hs_keys = TrafficKeys{ key: [u8(9)], iv: [u8(10)] }

	h.confirm_handshake()

	assert h.client_hs_traffic.len == 0
	assert h.server_hs_traffic.len == 0
	assert h.client_hs_keys.key.len == 0
	assert h.server_hs_keys.key.len == 0
	// Handshake keys/secrets are gone: both accessors now refuse.
	_, _ := h.traffic_keys(.handshake) or {
		_, _ := h.exported_secrets(.handshake) or {
			return
		}
		assert false
	}
	assert false
}

fn test_zeroize_app_secrets_clears_and_refuses() ! {
	mut h := new_client_handshake('example.com', []string{}, make_validator())!
	h.client_ap_traffic = [u8(11), 12]
	h.server_ap_traffic = [u8(13), 14]

	h.zeroize_app_secrets()

	assert h.client_ap_traffic.len == 0
	assert h.server_ap_traffic.len == 0
	_, _ := h.exported_secrets(.application) or {
		return
	}
	assert false
}

// ---- HRR second-hello identity (§4.1.4) via the codec ----

fn test_second_hello_reproduces_pinned_random() ! {
	// The retry ClientHello must carry the same pinned random as the first
	// (§4.1.4); build_client_hello with a fixed config is deterministic except
	// for the cookie, so compare the random field across two builds.
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
	// Both hellos still embed the identical 32-byte random (§4.1.4 identity).
	// Layout: [type 1][len 3][legacy_version 2][random 32] ⇒ random at offset 6.
	random1 := full1[6..6 + 32]
	random2 := full2[6..6 + 32]
	assert random1 == cfg.random
	assert random2 == cfg.random
}

// ---- recordless passthrough framing ----

fn test_next_passthrough_splits_one_byte_cadence() ! {
	// Drive reassembly at a 1-byte cadence: the message materializes exactly
	// once, at the final byte (RFC 9001 §4 self-framing).
	mut buf := []u8{}
	full := wrap_hs(.finished, [u8(0xDE), 0xAD, 0xBE, 0xEF])
	mut got := 0
	for b in full {
		buf << b
		msg := next_passthrough_message(mut buf)!
		if msg.len > 0 {
			got += 1
			assert msg == full
			assert buf.len == 0
		}
	}
	assert got == 1
}

fn test_next_passthrough_two_messages_sequential() ! {
	// Two coalesced messages are extracted one at a time; `+` cannot join []u8
	// in V, so the second frame is appended with the `<<` accumulation operator.
	mut buf := wrap_hs(.encrypted_extensions, [u8(0x00)])
	buf << wrap_hs(.certificate, [u8(0x01), 0x02])
	m1 := next_passthrough_message(mut buf)!
	assert m1.len == 5 // 4-byte header + 1-byte body
	m2 := next_passthrough_message(mut buf)!
	assert m2.len == 6
	assert buf.len == 0
}

fn test_next_passthrough_rejects_oversize_length() ! {
	// A declared length above max_handshake_message_len must abort at the header,
	// not allocate toward a gigantic message.
	mut w := wire.new_writer(4)
	w.write_u8(u8(HandshakeType.certificate))
	w.write_u24(u32(max_handshake_message_len + 1))
	mut buf := w.bytes()
	next_passthrough_message(mut buf) or {
		return
	}
	assert false
}
