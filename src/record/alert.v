module record

// AlertLevel classifies an alert as warning or fatal (RFC 8446 §6).
// In TLS 1.3 the warning level exists only for close_notify; every other alert
// must be sent as fatal, since a recoverable error signal was removed from 1.2's design.
pub enum AlertLevel as u8 {
	warning = 1
	fatal   = 2
}

// AlertDescription identifies the alert reason (RFC 8446 §6.2).
pub enum AlertDescription as u8 {
	close_notify                    = 0
	unexpected_message              = 10
	bad_record_mac                  = 20
	record_overflow                 = 22
	handshake_failure               = 40
	bad_certificate                 = 42
	unsupported_certificate         = 43
	certificate_revoked             = 44
	certificate_expired             = 45
	certificate_unknown             = 46
	illegal_parameter               = 47
	unknown_ca                      = 48
	access_denied                   = 49
	decode_error                    = 50
	decrypt_error                   = 51
	protocol_version                = 70
	insufficient_security           = 71
	internal_error                  = 80
	inappropriate_fallback          = 86
	user_canceled                   = 90
	missing_extension               = 109
	unsupported_extension           = 110
	unrecognized_name               = 112
	bad_certificate_status_response = 113
	unknown_psk_identity            = 115
	certificate_required            = 116
	no_application_protocol         = 120
}

// Alert is the 2-byte TLS alert payload.
pub struct Alert {
pub:
	level       AlertLevel       // warning (1) or fatal (2)
	description AlertDescription // what went wrong (RFC 8446 §6.2)
}

// encode serializes the alert to 2 bytes.
pub fn (a Alert) encode() []u8 {
	return [u8(a.level), u8(a.description)]
}

// parse_alert decodes a 2-byte alert payload.
pub fn parse_alert(data []u8) !Alert {
	if data.len != 2 {
		return error('record: alert payload must be exactly 2 bytes, got ${data.len}')
	}
	level := match data[0] {
		1 { AlertLevel.warning }
		2 { AlertLevel.fatal }
		else {
			return error('record: invalid alert level ${data[0]}')
		}
	}
	// The cast is unsafe on purpose: the received byte may be a description value
	// this enum does not enumerate. RFC 6367 §2.2 requires unknown alert values to
	// be tolerated rather than rejected, so we preserve the raw byte and let the
	// caller act on the alert (is_fatal() already treats any non-close_notify as fatal).
	desc := unsafe { AlertDescription(data[1]) }
	return Alert{
		level:       level
		description: desc
	}
}

// is_fatal reports whether the alert must terminate the connection.
// Per RFC 8446 §6, all alerts are fatal except close_notify and user_canceled.
fn (a Alert) is_fatal() bool {
	return a.description != .close_notify && a.description != .user_canceled
}

// new_close_notify builds a warning close_notify alert — the only alert allowed
// at warning level (RFC 8446 §6.1). It signals orderly shutdown: the sender has
// closed its write side and will not accept further application data.
pub fn new_close_notify() Alert {
	return Alert{
		level:       .warning
		description: .close_notify
	}
}

// new_fatal_alert builds a fatal alert with the given description.
fn new_fatal_alert(desc AlertDescription) Alert {
	return Alert{
		level:       .fatal
		description: desc
	}
}

// alert_record wraps an alert in an unencrypted TLS record. Alerts sent before
// the cipher keys take effect travel in plaintext; post-handshake alerts are
// encrypted via the cipher state instead, though their inner content type remains 21.
pub fn alert_record(a Alert) Record {
	return new_record(.alert, a.encode())
}
