// Copyright (c) 2026 blackshirt.
//
// config.v holds the caller-facing options passed to dial(): server_name (SNI and
// hostname verification), the ALPN protocols to offer, insecure_skip_verify,
// root_cas, min_rsa_bits and the socket timeouts. conn.v consumes it at dial time.
module tls

import time
import tls.handshake
import tls.pki

// Config holds TLS client connection options, consumed by dial(). It is marked
// @[params] so dial() can be called with the fields as trailing named arguments.
@[params]
pub struct Config {
pub:
	// server_name is used for SNI and certificate hostname verification.
	server_name string
	// alpn overrides handshake_options.alpn when non-empty; the server's pick must be one of them (RFC 7301 §3.1).
	alpn []string = []string{}
	// handshake_options configures ALPN, certificate validation, and ClientHello preferences.
	handshake_options handshake.HandshakeOptions = handshake.HandshakeOptions{}
	// insecure_skip_verify disables certificate chain and hostname validation (tests only).
	insecure_skip_verify bool
	// root_cas, when set, is used instead of the system trust store.
	root_cas ?pki.TrustStore
	// min_rsa_bits floors the accepted RSA leaf key size; 0 keeps the 2048-bit default.
	min_rsa_bits int
	// timeout sets the socket read and write timeouts; defaults to 30 seconds.
	timeout time.Duration = 30 * time.second
}

// default_config builds a Config for the given hostname that trusts the system
// root store (root_cas stays none, so dial loads it) and keeps verification on.
pub fn default_config(server_name string) Config {
	return Config{
		server_name:          server_name
		insecure_skip_verify: false
		root_cas:             none
		handshake_options:    handshake.HandshakeOptions{}
	}
}
