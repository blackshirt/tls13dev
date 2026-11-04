// Copyright (c) 2026 blackshirt.
//
// protocol_audit_test.v verifies protocol-level correctness:
// state machine ordering, message type acceptance, HRR handling,
// Finished verification, and alert classification.
module handshake

import tls.pki

fn test_message_type_acceptance_matrix() ! {
	mut h := new_tls_handshake('example.com', HandshakeOptions{ validator: pki.new_validator(pki.new_trust_store()) })!
	_ := h.create_client_hello()!

	// In .wait_ee, Certificate should be rejected.
	h.state = .wait_ee
	h.receive_handshake_bytes([u8(11), 0x00, 0x00, 0x00]) or {
		assert err.msg().contains('unexpected Certificate')
		return
	}
	assert false, 'Certificate in WAIT_EE must be rejected'
}
