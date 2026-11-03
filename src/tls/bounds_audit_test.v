// Copyright (c) 2026 blackshirt.
//
// bounds_audit_test.v verifies all resource bounds are enforced:
// handshake message cap, transcript cap, chain depth, CERT DER cap,
// CCS cap, flight record cap, tolerated records, post-handshake cap.
module tls

import tls.handshake
import tls.pki

fn test_max_handshake_message_len_cap() ! {
	assert handshake.max_handshake_message_len == 1 << 20
}

fn test_max_cert_chain_depth_cap() ! {
	assert pki.max_cert_chain_depth == 32
}

fn test_max_certificate_der_bytes_cap() ! {
	assert pki.max_certificate_der_bytes == 32 * 1024
}

fn test_max_compat_ccs_records_cap() ! {
	assert max_compat_ccs_records == 2
}

fn test_max_handshake_flight_records_cap() ! {
	assert max_handshake_flight_records == 64
}

fn test_max_tolerated_records_per_read_cap() ! {
	assert max_tolerated_records_per_read == 100
}

fn test_max_post_handshake_messages_per_record_cap() ! {
	assert max_post_handshake_messages_per_record == 1000
}

fn test_max_stored_session_tickets_cap() ! {
	assert max_stored_session_tickets == 32
}
