// Copyright (c) 2026 blackshirt.
//
// QuicHandshaker is the QUIC adapter facade over shared TLS handshake
// semantics. QUIC derives packet protection from the exported traffic secrets.
module handshake

import tls.pki

// QuicHandshaker exposes only operations needed by a QUIC adapter.
@[noinit]
pub struct QuicHandshaker {
	HandshakeCore
}

// new_quic_handshake creates a QUIC handshaker.
pub fn new_quic_handshake(server_name string, alpn []string, validator pki.Validator) !QuicHandshaker {
	return QuicHandshaker{
		HandshakeCore: new_handshake_core(server_name, alpn, validator)!
	}
}
