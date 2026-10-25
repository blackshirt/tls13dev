// Copyright (c) 2026 blackshirt.
//
// QuicHandshake is the QUIC adapter facade over shared TLS handshake
// semantics. QUIC derives packet protection from the exported traffic secrets.
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
	return h.hrr_received
}

// quic_traffic_secrets returns copies of TLS traffic secrets for QUIC packet-key derivation.
pub fn (h &QuicHandshake) quic_traffic_secrets(level EncryptionLevel) !([]u8, []u8) {
	return h.traffic_secret_pair(level)
}
