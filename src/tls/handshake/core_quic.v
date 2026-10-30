// Copyright (c) 2026 blackshirt.
//
// core_quic.v holds the QUIC side of the unified HandshakeCore: raw traffic-secret
// export (QUIC derives packet protection from it; the record side caches record
// keys instead and has no caller for these), the opaque server transport parameters,
// and the HelloRetryRequest flag the QUIC adapter needs for Initial re-keying.
// Every entry point here is guarded by is_quic — a TLS-mode core refuses it with a
// plain error, without touching state or keys.
module handshake

// peer_traffic_secrets_at returns copies of the client and server traffic secrets
// for one encryption level; the initial level has no TLS traffic secrets. Module-
// private QUIC seam: the engine expands the two secrets into RFC 9001 §5.1 packet
// keys through the phase-named peer_handshake_secrets() / peer_application_secrets()
// below, and the TLS record path never reads raw secrets — the record side serves
// handshake_record_keys() / application_record_keys() from its phase-typed cached
// key handles instead.
fn (h &HandshakeCore) peer_traffic_secrets_at(level EncryptionLevel) !([]u8, []u8) {
	if !h.is_quic {
		return error('handshake: traffic-secret export is QUIC-only (the record path serves cached record keys)')
	}
	if level == .initial {
		return error('handshake: initial level has no traffic secrets')
	}
	mut c := []u8{}
	mut s := []u8{}
	match level {
		.initial {}
		.handshake {
			c = h.c_hsk_tsec.clone()
			s = h.s_hsk_tsec.clone()
		}
		.application {
			c = h.c_app_tsec.clone()
			s = h.s_app_tsec.clone()
		}
	}
	if c.len == 0 || s.len == 0 {
		if level == .handshake {
			return error('handshake: handshake traffic secrets unavailable (available after ServerHello, dropped by zeroize_handshake_secrets())')
		}
		return error('handshake: application traffic secrets unavailable before the server Finished')
	}
	return c, s
}

// peer_handshake_secrets returns the (client, server) handshake traffic secrets the
// engine expands into Handshake packet keys (RFC 9001 §5.1).
pub fn (h &HandshakeCore) peer_handshake_secrets() !([]u8, []u8) {
	c, s := h.peer_traffic_secrets_at(.handshake)!
	return c, s
}

// peer_application_secrets returns the (client, server) application traffic secrets
// the engine expands into 1-RTT packet keys (RFC 9001 §5.1).
pub fn (h &HandshakeCore) peer_application_secrets() !([]u8, []u8) {
	c, s := h.peer_traffic_secrets_at(.application)!
	return c, s
}

// peer_transport_parameters returns the raw bytes of the server's
// quic_transport_parameters extension, captured from EncryptedExtensions once the
// server sends it — an empty slice until it arrives. TLS never interprets them: the
// QUIC adapter decodes the id/length/value triplets (RFC 9000 §7.3).
pub fn (h &HandshakeCore) peer_transport_parameters() ![]u8 {
	if !h.is_quic {
		return error('handshake: peer_transport_parameters() is QUIC-only (TLS never interprets them)')
	}
	params := h.quic_params or { return []u8{} }
	return params.clone()
}

// hello_retry_request_received reports whether the core has already accepted a
// HelloRetryRequest. TLS itself has no further use for the flag once it has
// built the retry ClientHello, but a QUIC adapter must: the retry is sent under a
// different destination connection ID, and Initial protection is a function of
// that ID, so the adapter's Initial keys go stale here (RFC 9001 §5.5).
pub fn (h &HandshakeCore) hello_retry_request_received() !bool {
	if !h.is_quic {
		return error('handshake: hello_retry_request_received() is QUIC-only (the record path re-keys inside the core)')
	}
	return h.hrr_cipher_suite != none
}
