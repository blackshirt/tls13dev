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

// peer_transport_parameters returns the server's QUIC transport parameters,
// parsed from EncryptedExtensions once the server sends them.
pub fn (h &QuicHandshake) peer_transport_parameters() ?QuicTransportParameters {
	params := h.quic_params or { return none }
	return QuicTransportParameters{
		initial_scid: params.initial_scid.clone()
	}
}

// quic_traffic_secrets returns copies of TLS traffic secrets for QUIC packet-key derivation.
pub fn (h &QuicHandshake) quic_traffic_secrets(level EncryptionLevel) !([]u8, []u8) {
	return h.traffic_secret_pair(level)
}
