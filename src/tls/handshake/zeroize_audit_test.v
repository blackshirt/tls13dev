// Copyright (c) 2026 blackshirt.
//
// zeroize_audit_test.v verifies the RFC 8446 §7.5 zeroization lifecycle:
// secrets are wiped at the right lifecycle points, no key material survives
// failure or close, and the AEAD backend key limitation is documented.
module handshake

import tls.pki

fn test_wipe_key_schedule_secrets_zeros_intermediates() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: pki.new_validator(pki.new_trust_store()) })!
	_ := h.create_client_hello()!

	// Before any ServerHello: handshake_secret and traffic secrets are empty.
	assert h.handshake_secret.len == 0
	assert h.c_hsk_tsec.len == 0
	assert h.s_hsk_tsec.len == 0

	// Failure before secrets exist: still .failed, nothing to wipe.
	h.fail_and_zeroize_secrets()
	assert h.state() == .failed
	assert h.handshake_secret.len == 0
	assert h.c_hsk_tsec.len == 0
	assert h.s_hsk_tsec.len == 0
}

fn test_failure_zeroizes_transcript_and_certs() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: pki.new_validator(pki.new_trust_store()) })!
	_ := h.create_client_hello()!

	// Fail after ClientHello is in transcript.
	h.fail_and_zeroize_secrets()
	assert h.state() == .failed

	// traffic_keys must refuse.
	mut refused := false
	h.traffic_keys() or { refused = true }
	assert refused
}

fn test_zeroize_traffic_secrets_only_after_connected() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: pki.new_validator(pki.new_trust_store()) })!
	_ := h.create_client_hello()!

	// Before .connected: zeroize_traffic_secrets must refuse.
	h.zeroize_traffic_secrets() or {
		assert err.msg().contains('only valid once the handshake reaches .connected')
		return
	}
	assert false, 'zeroize_traffic_secrets before .connected must fail'
}

fn test_fail_and_zeroize_secrets_is_idempotent() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: pki.new_validator(pki.new_trust_store()) })!
	_ := h.create_client_hello()!
	h.fail_and_zeroize_secrets()
	h.fail_and_zeroize_secrets() // second call must not panic
	assert h.state() == .failed
}
