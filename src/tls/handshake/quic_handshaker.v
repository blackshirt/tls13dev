// Copyright (c) 2026 blackshirt.
//
// QuicHandshaker is the QUIC adapter facade over shared TLS handshake
// semantics. QUIC derives packet protection from the exported traffic secrets.
module handshake

// QuicHandshaker exposes only operations needed by a QUIC adapter.
@[noinit]
pub struct QuicHandshaker {
	HandshakeCore
}

// new_quic_handshake creates a QUIC handshaker. HandshakeOptions fields can
// be supplied as optional named arguments after server_name.
pub fn new_quic_handshake(server_name string, options HandshakeOptions) !QuicHandshaker {
	return QuicHandshaker{
		HandshakeCore: new_handshake_core(server_name, options)!
	}
}

// quic_traffic_secrets returns copies of TLS traffic secrets for QUIC packet-key derivation.
pub fn (h &QuicHandshaker) quic_traffic_secrets(level TrafficSecretLevel) !([]u8, []u8) {
	match level {
		.handshake {
			if h.client_hs_traffic.len == 0 || h.server_hs_traffic.len == 0 {
				return error('handshake: handshake traffic secrets unavailable (available after ServerHello, dropped by zeroize_handshake_traffic_secrets)')
			}
			return h.client_hs_traffic.clone(), h.server_hs_traffic.clone()
		}
		.application {
			if h.client_ap_traffic.len == 0 || h.server_ap_traffic.len == 0 {
				return error('handshake: application traffic secrets unavailable before the server Finished')
			}
			return h.client_ap_traffic.clone(), h.server_ap_traffic.clone()
		}
	}
}
