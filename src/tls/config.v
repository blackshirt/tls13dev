// Copyright (c) 2026 blackshirt.
//
// config.v holds the caller-facing options passed to dial(): the SNI /
// verification server_name, ALPN protocols to negotiate, the insecure_skip_verify
// escape hatch, and the handshake/read timeouts. conn.v consumes it at dial time.
module tls

import time
import tls.pki

// Config holds TLS client connection options, consumed by dial(). It is marked
// @[params] so dial — whose last parameter is a Config — can be called with the
// fields as trailing named arguments, e.g. tls.dial('host:443',
// server_name: 'example.com', alpn: ['h2']). Any field left out falls back to the
// default declared on it below. default_config() stays the explicit way to build
// a fully-populated Config.
@[params]
pub struct Config {
pub:
	// server_name is used for SNI and certificate hostname verification.
	server_name string
	// alpn is the list of application protocols to offer (e.g. ['h2', 'http/1.1']).
	// The server's pick is verified against this list (RFC 7301 §3.1): an unoffered
	// selection aborts the handshake, and an empty list forbids an ALPN response.
	alpn []string = []string{}
	// insecure_skip_verify disables certificate chain and hostname validation.
	// This removes all authentication the handshake provides; intended for tests
	// and pinned lab environments only, never shipped enabled.
	insecure_skip_verify bool
	// root_cas, when set, is used instead of the system trust store — e.g. for
	// private CAs in enterprise or testing setups.
	root_cas ?pki.TrustStore
	// timeout sets the socket read and write timeouts; defaults to 30 seconds.
	timeout time.Duration = 30 * time.second
}

// default_config builds a Config for the given hostname that trusts the system
// root store (root_cas stays none, so dial loads it). alpn and timeout inherit
// their declared field defaults. Deliberately conservative: no ALPN offer
// (server picks its default) and verification strictly on.
pub fn default_config(server_name string) Config {
	return Config{
		server_name:          server_name
		insecure_skip_verify: false
		root_cas:             none
	}
}
