// Copyright (c) 2026 blackshirt.
//
// transport_guard_test.v locks the is_quic guards on the unified HandshakeCore:
// a TLS-record-only call on a QUIC-mode core, and a QUIC-only call on a TLS-mode
// core, must refuse with a plain error — no state change, no teardown, no key
// material touched — mirroring the out-of-phase guard convention.
module handshake

import tls.pki
import tls.wire

// fixture_validator builds a Validator over an empty trust store; none of these
// tests reach chain verification. Defined locally because V compiles each
// _test.v file as its own program, so helpers are not shared across test files.
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

fn tls_mode_core() !HandshakeCore {
	return new_tls_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })
}

fn quic_mode_core() !HandshakeCore {
	return new_quic_handshake('example.com', HandshakeOptions{ validator: fixture_validator() })
}

// test_tls_mode_refuses_quic_only_calls covers the QUIC-only seams on a TLS-mode
// core: raw-secret export, transport parameters, and the HelloRetryRequest flag.
// Each must refuse, and the guards must not tear the machine down.
fn test_tls_mode_refuses_quic_only_calls() ! {
	mut h := tls_mode_core()!
	_ = h.create_client_hello()!
	mut rejected := false

	h.peer_handshake_secrets() or {
		rejected = err.msg().contains('QUIC-only')
	}
	assert rejected
	rejected = false
	h.peer_application_secrets() or {
		rejected = err.msg().contains('QUIC-only')
	}
	assert rejected
	rejected = false
	h.peer_transport_parameters() or {
		rejected = err.msg().contains('QUIC-only')
	}
	assert rejected
	rejected = false
	h.is_hello_retry_request_received() or {
		rejected = err.msg().contains('QUIC-only')
	}
	assert rejected

	// Plain guards: no classify_failure, no teardown — state and alert untouched.
	assert h.state() == .wait_sh
	assert h.failure_alert() == .internal_error
}

// test_quic_mode_refuses_tls_only_calls covers the TLS-record surface on a
// QUIC-mode core: the record-key accessors, KeyUpdate, the backlog accessors, and the
// coalesced-bytes handoff.
fn test_quic_mode_refuses_tls_only_calls() ! {
	mut h := quic_mode_core()!
	_ = h.create_client_hello()!
	mut rejected := false

	h.handshake_traffic_keys() or {
		rejected = err.msg().contains('TLS-record-only')
	}
	assert rejected
	rejected = false
	h.application_traffic_keys() or {
		rejected = err.msg().contains('TLS-record-only')
	}
	assert rejected
	rejected = false
	h.update_traffic_keys(true) or {
		rejected = err.msg().contains('TLS-record-only')
	}
	assert rejected
	rejected = false
	h.update_traffic_keys(false) or {
		rejected = err.msg().contains('TLS-record-only')
	}
	assert rejected
	rejected = false
	h.initial_backlog() or {
		rejected = err.msg().contains('TLS-record-only')
	}
	assert rejected
	rejected = false
	h.handshake_backlog() or {
		rejected = err.msg().contains('TLS-record-only')
	}
	assert rejected
	rejected = false
	h.take_buffered_handshake_bytes() or {
		rejected = err.msg().contains('TLS-record-only')
	}
	assert rejected

	assert h.state() == .wait_sh
	assert h.failure_alert() == .internal_error
}

// test_quic_mode_tls_accessors_refuse_even_with_secrets locks the is_quic guard
// precedence on a QUIC-mode core: even with handshake traffic secrets planted, the
// TLS-record accessors refuse with the transport guard — never a derivation, never a
// silent empty result.
fn test_quic_mode_tls_accessors_refuse_even_with_secrets() ! {
	mut h := quic_mode_core()!
	_ = h.create_client_hello()!
	h.c_hsk_tsec = [u8(1), 2, 3]
	h.s_hsk_tsec = [u8(4), 5, 6]
	mut rejected := false
	h.handshake_traffic_keys() or {
		rejected = err.msg().contains('TLS-record-only')
	}
	assert rejected
	// A garbage ServerHello still tears the machine down through the normal parse path.
	h.receive_initial_bytes(wrap_hsk(.server_hello, []u8{len: 4, init: 0xAA})) or {}
	assert h.state() == .failed
}

// test_tls_mode_zeroize_and_failure_retire_record_keys guards the behavior-preserving
// half of the change: on a TLS-mode core the unified teardown still makes the record
// accessor refuse, because it now derives from secrets the wipe just cleared.
fn test_tls_mode_zeroize_and_failure_retire_record_keys() ! {
	mut h := tls_mode_core()!
	h.state = HandshakeState.connected
	h.c_app_tsec = [u8(11), 12]
	h.s_app_tsec = [u8(13), 14]
	// While both secrets live the accessor derives; the guard is presence, not a cache.
	h.application_traffic_keys() or {
		assert false, 'record keys should derive while the application secrets live'
	}
	h.zeroize_application_secrets()!
	assert h.c_app_tsec.len == 0
	assert h.s_app_tsec.len == 0
	h.application_traffic_keys() or {
		assert err.msg().contains('application traffic keys unavailable')
	}

	// The failure path wipes both levels too (§7.5), so the secrets go with them.
	h.c_hsk_tsec = [u8(1), 2]
	h.s_hsk_tsec = [u8(3), 4]
	h.fail_and_zeroize_secrets()
	assert h.c_hsk_tsec.len == 0
	assert h.s_hsk_tsec.len == 0
	assert h.state() == .failed
}
