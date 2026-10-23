// Copyright (c) 2026 blackshirt.
//
// Config contains the TLS handshake options for a QUIC client connection.
module quic

import tls.handshake

// Config holds options consumed when creating a QUIC client connection.
@[params]
pub struct Config {
pub:
	// hsk_options configures certificate validation, ALPN, and ClientHello preferences.
	hsk_options handshake.HandshakeOptions = handshake.HandshakeOptions{}
}
