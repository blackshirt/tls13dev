// Copyright (c) 2026 blackshirt.
//
// QuicHandshake is the QUIC adapter facade over shared TLS handshake
// semantics. QUIC derives packet protection from the exported traffic secrets,
// so the raw-secret accessor peer_traffic_secrets() lives here: the record
// facade caches derived TrafficKeys and has no caller for it.
module handshake

// QuicHandshake exposes only operations needed by a QUIC adapter.
@[noinit]
pub struct QuicHandshake {
	HandshakeCore
}

// new_quic_handshake creates a QUIC handshaker. HandshakeOptions fields can
// be supplied as optional named arguments after server_name.
pub fn new_quic_handshake(server_name string, options HandshakeOptions) !QuicHandshake {
	return QuicHandshake{
		HandshakeCore: new_handshake_core(server_name, options, true)!
	}
}

// peer_traffic_secrets returns copies of the client and server traffic secrets
// for one encryption level; the initial level has no TLS traffic secrets. QUIC
// seam: the engine expands the pair into RFC 9001 §5.1 packet keys itself, and
// the TLS record path never reads raw secrets — TLSHandshake serves
// record_traffic_keys() from its cached TrafficKeys instead.
pub fn (h &QuicHandshake) peer_traffic_secrets(level EncryptionLevel) !([]u8, []u8) {
	if level == .initial {
		return error('handshake: initial level has no traffic secrets')
	}
	secrets := h.secret_pair(level)
	if !secrets.available() {
		if level == .handshake {
			return error('handshake: handshake traffic secrets unavailable (available after ServerHello, dropped by zeroize_traffic_secrets(.handshake))')
		}
		return error('handshake: application traffic secrets unavailable before the server Finished')
	}
	return secrets.client.clone(), secrets.server.clone()
}

// peer_transport_parameters returns the raw bytes of the server's
// quic_transport_parameters extension, captured from EncryptedExtensions once the
// server sends it. TLS never interprets them: the QUIC adapter decodes the
// id/length/value triplets (RFC 9000 §7.3). Returns none before EncryptedExtensions
// arrives.
pub fn (h &QuicHandshake) peer_transport_parameters() ?[]u8 {
	params := h.quic_params or { return none }
	return params.clone()
}

// hello_retry_request_received reports whether the core has already accepted a
// HelloRetryRequest. TLS itself has no further use for the flag once it has
// built the retry ClientHello, but a QUIC adapter must: the retry is sent under a
// different destination connection ID, and Initial protection is a function of
// that ID, so the adapter's Initial keys go stale here (RFC 9001 §5.5).
pub fn (h &QuicHandshake) hello_retry_request_received() bool {
	return h.hrr_cipher_suite != none
}
