// Copyright (c) 2026 blackshirt.
//
// options.v defines the configuration shared by the record and QUIC handshake
// facades.
module handshake

import tls.pki

// HandshakeOptions configures the shared TLS handshake, including peer
// validation, ALPN, and the ClientHello preferences offered by the client.
@[params]
pub struct HandshakeOptions {
pub:
	// alpn is the preference-ordered list of application protocols to offer.
	alpn []string
	// validator verifies the server's certificate chain and hostname; omitted
	// options use the system root CA bundle.
	validator ?pki.Validator
	// key_share_group is the group used for the initial ECDHE share.
	key_share_group NamedGroup = .x25519
	// supported_groups is preference-ordered; empty uses X25519 then P-256.
	supported_groups []NamedGroup
	// cipher_suites is preference-ordered; empty uses the built-in TLS 1.3 suites.
	cipher_suites []CipherSuite
	// signature_algorithms is preference-ordered; empty uses the built-in list.
	signature_algorithms []SignatureScheme
	// legacy_session_id and random are for deterministic test vectors only.
	legacy_session_id []u8
	random            []u8
pub mut:
	// quic_transport_params is the already-encoded content of the TLS
	// quic_transport_parameters extension (RFC 9001 §8.2), sent only by the QUIC
	// handshake facade. TLS copies these bytes in and stores them back out
	// without interpreting them: transport parameters are QUIC's own vocabulary,
	// so the adapter above encodes and decodes them.
	quic_transport_params []u8
}
