// Copyright (c) 2026 blackshirt.
//
// Alert vocabulary tests against the transport-neutral home of the enums
// (tls.handshake): the RFC 8446 §6.2 2-byte alert payload round-trips through
// encode/parse_alert with its wire bytes pinned literally, malformed framing
// (wrong length, unknown level) is rejected, an unenumerated description byte
// is preserved verbatim, and the QUIC mapping turns a description into a
// CRYPTO_ERROR connection-close code (RFC 9001 §4.8). The record framing of an
// alert (a TLS-only concern) is tested in tls' record_test.v.
module handshake

fn test_alert_close_notify_roundtrip() ! {
	a := new_close_notify()
	enc := a.encode()
	// §6.2/§6.1: warning(1) || close_notify(0), pinned to literal bytes so a
	// symmetric encode/parse bug cannot pass a round-trip unnoticed.
	assert enc == [u8(0x01), 0x00]

	parsed := parse_alert(enc)!
	assert parsed.level == .warning
	assert parsed.description == .close_notify
}

fn test_parse_alert_rejects_bad_length() ! {
	// An alert is exactly 2 bytes; 0-, 1-, and 3-byte payloads are framing errors.
	if _ := parse_alert([]u8{}) {
		assert false
	}
	if _ := parse_alert([u8(0x02)]) {
		assert false
	}
	if _ := parse_alert([u8(0x02), 0x00, 0x00]) {
		assert false
	}
}

fn test_parse_alert_rejects_invalid_level() ! {
	// Only warning(1) and fatal(2) are valid levels (RFC 8446 §6).
	parse_alert([u8(0x00), 0x00]) or {
		assert err.msg().contains('invalid alert level')
		return
	}
	assert false
}

fn test_parse_alert_preserves_unknown_description() ! {
	// An unenumerated description must survive the unsafe cast (only the level
	// is validated), so re-encoding yields the original bytes back.
	a := parse_alert([u8(0x02), 0xfe])!
	assert a.level == .fatal
	assert a.encode() == [u8(0x02), 0xfe]
}

fn test_quic_connection_error_mapping() ! {
	// RFC 9001 §4.8: an alert surfaces over QUIC as 0x100 + the description
	// byte. close_notify(0) → 0x100, handshake_failure(40) → 0x128.
	assert AlertDescription.close_notify.quic_connection_error() == u32(0x100)
	assert AlertDescription.handshake_failure.quic_connection_error() == u32(0x128)
	assert AlertDescription.decode_error.quic_connection_error() == 0x100 + u32(AlertDescription.decode_error)
}
