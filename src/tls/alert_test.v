// Copyright (c) 2026 blackshirt.
//
// Alert protocol tests: the RFC 8446 §6.2 2-byte alert payload round-trips
// through encode/parse_alert with its wire bytes pinned literally, malformed
// framing (wrong length, unknown level) is rejected, and an unenumerated
// description byte is preserved verbatim — §6 treats unknown alerts as errors
// the receiving caller must still see, so the raw byte must survive the decode.
module tls

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

fn test_alert_record_framing() ! {
	// alert_record wraps the 2-byte payload in a plaintext .alert record.
	rec := alert_record(new_close_notify())
	assert rec.content_type == .alert
	assert rec.legacy_version == legacy_record_version
	assert rec.payload == [u8(0x01), 0x00]
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
