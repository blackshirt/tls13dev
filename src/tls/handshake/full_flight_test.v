// Copyright (c) 2026 blackshirt.
//
// full_flight_test.v drives the real handshake core against the adaptive
// fakeserver through a complete TLS 1.3 handshake — ClientHello through client
// Finished, both HelloRetryRequest shapes, and the negative flights — proving
// the client reaches .connected with byte-correct secrets and rejects
// misbehaviour, without sockets or OpenSSL.
module handshake

import tls.fakeserver
import tls.pki

// make_trusted_validator builds a Validator over the fakeserver's embedded
// test CA so the Certificate message authenticates exactly the fake chain.
fn make_trusted_validator() pki.Validator {
	ts := fakeserver.test_trust_store() or { panic('fakeserver trust store: ${err.msg()}') }
	return pki.new_validator(ts, false)
}

// expect_no_handshake_keys reports whether traffic_keys(.handshake) refuses —
// the expected state once confirm_handshake() dropped the handshake material.
fn expect_no_handshake_keys(h &ClientHandshake) bool {
	h.traffic_keys(.handshake) or {
		return true
	}
	return false
}

// expect_no_exported_handshake_secrets reports whether exported_secrets(.handshake)
// refuses — the expected state once the handshake traffic secrets were wiped.
fn expect_no_exported_handshake_secrets(h &ClientHandshake) bool {
	h.exported_secrets(.handshake) or {
		return true
	}
	return false
}

// assert_handshake_material_destroyed checks the Phase 1 failure-path contract:
// after any failed feed, the state machine is .failed AND every secret the
// handshake had derived by that point (cached TrafficKeys and the traffic
// secrets themselves) is gone. Before abort() existed, a failed Finished left
// both live in the discarded object — the very residue RFC 8446 §7.5 forbids.
fn assert_handshake_material_destroyed(h &ClientHandshake) {
	assert h.state() == .failed
	assert expect_no_handshake_keys(h), 'handshake TrafficKeys survived a failed feed'
	assert expect_no_exported_handshake_secrets(h), 'handshake traffic secrets survived a failed feed'
}

// feed_encrypted_flight feeds the whole server flight one byte at a time and
// returns every outbound message the client produced along the way. Byte-wise
// feeding exercises the reassembly path across every possible split point of
// the EE/Cert/CV/Finished stream.
fn feed_encrypted_flight(mut h ClientHandshake, flight []u8) ![]HandshakeMessage {
	mut produced := []HandshakeMessage{}
	for i in 0 .. flight.len {
		msgs := h.feed(.handshake, [flight[i]])!
		produced << msgs
	}
	return produced
}

fn test_client_auth_request_answered_with_empty_certificate() ! {
	// A server CertificateRequest must not derail the client: it answers with an
	// empty Certificate (§4.4.2) whose bytes are folded into the transcript,
	// then continues to authenticate the server as usual. This drives the whole
	// exchange: EE+CReq → client empty Certificate → server Cert/CV/Fin →
	// client Finished.
	mut h := new_client_handshake(fakeserver.server_name, []string{}, make_trusted_validator())!
	mut srv := fakeserver.new_server(client_auth: true)!

	ch := h.create_client_hello()!
	fl := srv.handle_client_hello(ch)!
	assert !fl.is_hrr
	h.feed(.initial, fl.server_hello)!

	// EE + CertificateRequest: the client must emit exactly its empty Certificate.
	assert fl.rest.len == 2
	produced := feed_encrypted_flight(mut h, fakeserver.flatten(fl.rest))!
	assert produced.len == 1
	assert produced[0].level == .handshake
	assert h.state() == .wait_certificate

	// Feed the client's empty Certificate to the server; it validates the echo
	// and returns the deferred Cert/CV/Fin tail.
	tail := srv.handle_client_certificate(produced[0].msg)!
	assert tail.len == 3

	// The tail completes the handshake and yields the client Finished.
	out := feed_encrypted_flight(mut h, fakeserver.flatten(tail))!
	assert out.len == 1
	assert h.state() == .connected
	srv.handle_client_finished(out[0].msg)!

	assert h.server_certs.len == 1
}

fn test_full_handshake_reaches_connected_byte_by_byte() ! {
	mut h := new_client_handshake(fakeserver.server_name, ['h2'], make_trusted_validator())!
	mut srv := fakeserver.new_server(alpn: ['h2', 'http/1.1'])!

	ch := h.create_client_hello()!
	fl := srv.handle_client_hello(ch)!
	assert !fl.is_hrr

	// Plaintext ServerHello on the Initial level; nothing outbound yet.
	out := h.feed(.initial, fl.server_hello)!
	assert out.len == 0
	assert h.state() == .wait_encrypted_extensions

	// The encrypted flight, one byte at a time, across every reassembly boundary.
	produced := feed_encrypted_flight(mut h, fakeserver.flatten(fl.rest))!
	assert produced.len == 1
	assert produced[0].level == .handshake
	assert h.state() == .connected

	// The server must accept the exact client Finished the core produced.
	srv.handle_client_finished(produced[0].msg)!

	assert h.negotiated_alpn() == 'h2'
	assert h.server_certs.len == 1

	// Application traffic keys are the reusable post-handshake state (§7.1).
	ck, sk := h.traffic_keys(.application)!
	assert ck.key.len == 16
	assert ck.iv.len == 12
	assert sk.key.len == 16
	assert sk.iv.len == 12

	// confirm_handshake() destroys the handshake stage but keeps application
	// material alive for the connection's lifetime (RFC 8446 §7.5).
	h.confirm_handshake()!
	assert expect_no_handshake_keys(&h)
	akc, aks := h.traffic_keys(.application)!
	assert akc.key.len == 16
	assert aks.key.len == 16
	assert aks.iv.len == 12
}

fn test_hello_retry_request_change_group_reaches_connected() ! {
	mut h := new_client_handshake(fakeserver.server_name, []string{}, make_trusted_validator())!
	mut srv := fakeserver.new_server(hrr: .change_group)!

	ch := h.create_client_hello()!
	fl1 := srv.handle_client_hello(ch)!
	assert fl1.is_hrr

	// The HRR arrives at Initial level; the core answers with the retry
	// ClientHello (P-256 share) and rearms the ServerHello wait.
	out := h.feed(.initial, fl1.server_hello)!
	assert out.len == 1
	assert out[0].level == .initial
	assert h.state() == .wait_server_hello

	fl2 := srv.handle_client_hello(out[0].msg)!
	assert !fl2.is_hrr
	out2 := h.feed(.initial, fl2.server_hello)!
	assert out2.len == 0
	assert h.state() == .wait_encrypted_extensions

	produced := h.feed(.handshake, fakeserver.flatten(fl2.rest))!
	assert produced.len == 1
	srv.handle_client_finished(produced[0].msg)!
	assert h.state() == .connected
	assert h.negotiated_alpn() == ''
}

fn test_hello_retry_request_cookie_only_reaches_connected() ! {
	mut h := new_client_handshake(fakeserver.server_name, []string{}, make_trusted_validator())!
	mut srv := fakeserver.new_server(hrr: .cookie_only)!

	ch := h.create_client_hello()!
	fl1 := srv.handle_client_hello(ch)!
	assert fl1.is_hrr

	out := h.feed(.initial, fl1.server_hello)!
	assert out.len == 1
	// The retry ClientHello must carry the echoed cookie; the fakeserver
	// verifies it and rejects a wrong echo.
	fl2 := srv.handle_client_hello(out[0].msg)!
	assert !fl2.is_hrr

	out2 := h.feed(.initial, fl2.server_hello)!
	assert out2.len == 0
	produced := h.feed(.handshake, fakeserver.flatten(fl2.rest))!
	assert produced.len == 1
	srv.handle_client_finished(produced[0].msg)!
	assert h.state() == .connected
}

fn test_rejects_bad_server_finished() ! {
	mut h := new_client_handshake(fakeserver.server_name, []string{}, make_trusted_validator())!
	mut srv := fakeserver.new_server(bad_finished: true)!

	ch := h.create_client_hello()!
	fl := srv.handle_client_hello(ch)!
	h.feed(.initial, fl.server_hello)!

	h.feed(.handshake, fakeserver.flatten(fl.rest)) or {
		assert err.msg().contains('Finished verify_data mismatch')
		assert h.failure_alert() == .decrypt_error
		assert_handshake_material_destroyed(h)
		return
	}
	assert false, 'a corrupted server Finished must abort the handshake'
}

fn test_rejects_bad_certificate_verify() ! {
	mut h := new_client_handshake(fakeserver.server_name, []string{}, make_trusted_validator())!
	mut srv := fakeserver.new_server(bad_certificate_verify: true)!

	ch := h.create_client_hello()!
	fl := srv.handle_client_hello(ch)!
	h.feed(.initial, fl.server_hello)!

	h.feed(.handshake, fakeserver.flatten(fl.rest)) or {
		assert err.msg().contains('Ed25519 CertificateVerify failed')
		assert h.failure_alert() == .decrypt_error
		assert_handshake_material_destroyed(h)
		return
	}
	assert false, 'a corrupted CertificateVerify must abort the handshake'
}

fn test_rejects_out_of_order_certificate() ! {
	mut h := new_client_handshake(fakeserver.server_name, []string{}, make_trusted_validator())!
	mut srv := fakeserver.new_server()!

	ch := h.create_client_hello()!
	fl := srv.handle_client_hello(ch)!
	h.feed(.initial, fl.server_hello)!

	// fl.rest is [EE, Cert, CV, Fin]; feed Certificate where EncryptedExtensions
	// is expected — the state machine must reject the reorder (§4.4.1).
	assert fl.rest.len == 4
	h.feed(.handshake, fl.rest[1]) or {
		assert err.msg().contains('unexpected Certificate')
		assert h.failure_alert() == .unexpected_message
		assert_handshake_material_destroyed(h)
		return
	}
	assert false, 'an out-of-order Certificate must abort the handshake'
}

fn test_rejects_unoffered_alpn() ! {
	// Client offers nothing; the server "picks" h2 — the RFC 7301 §3.1 check
	// must abort rather than negotiate an unoffered protocol.
	mut h := new_client_handshake(fakeserver.server_name, []string{}, make_trusted_validator())!
	mut srv := fakeserver.new_server(force_alpn: 'h2')!

	ch := h.create_client_hello()!
	fl := srv.handle_client_hello(ch)!
	h.feed(.initial, fl.server_hello)!

	h.feed(.handshake, fakeserver.flatten(fl.rest)) or {
		assert err.msg().contains('not offered by client')
		assert h.failure_alert() == .illegal_parameter
		assert_handshake_material_destroyed(h)
		return
	}
	assert false, 'an unoffered ALPN selection must abort the handshake'
}

fn test_abort_before_secrets_is_safe() ! {
	// abort() must tolerate being called when nothing has been derived yet —
	// dial()'s failure path invokes it on every error, including ones that
	// occur before the ClientHello was even built.
	mut h := new_client_handshake(fakeserver.server_name, []string{}, make_trusted_validator())!
	h.abort()
	assert h.state() == .failed
	assert expect_no_handshake_keys(h)
	assert expect_no_exported_handshake_secrets(h)
}

fn test_malformed_server_hello_aborts_and_destroys() ! {
	// A ServerHello that cannot even parse fails before the key schedule ran;
	// the failure path still parks the machine in .failed and leaves no keys.
	mut h := new_client_handshake(fakeserver.server_name, []string{}, make_trusted_validator())!
	_ := h.create_client_hello()!
	// A complete ServerHello header with an empty body: parse fails before the
	// key schedule ran, so the failure path must still leave no keys behind.
	h.feed(.initial, [u8(0x02), 0x00, 0x00, 0x00]) or {
		assert h.state() == .failed
		assert expect_no_handshake_keys(h)
		return
	}
	assert false, 'a malformed ServerHello must abort the handshake'
}

fn test_default_failure_alert_is_internal_error() ! {
	// A failure that never classified itself reports internal_error, the §6
	// catch-all, so an adapter always has a legal alert to send.
	mut h := new_client_handshake(fakeserver.server_name, []string{}, make_trusted_validator())!
	_ := h.create_client_hello()!
	assert h.failure_alert() == .internal_error
}
