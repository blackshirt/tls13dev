module client

import time
import pki

// Config holds TLS client connection options.
pub struct Config {
pub:
	// server_name is used for SNI and certificate hostname verification.
	server_name string
	// alpn is the list of application protocols to offer (e.g. ['h2', 'http/1.1']).
	// The server's pick is verified against this list (RFC 7301 §3.1): an unoffered
	// selection aborts the handshake, and an empty list forbids an ALPN response.
	alpn []string
	// insecure_skip_verify disables certificate chain and hostname validation.
	// This removes all authentication the handshake provides; intended for tests
	// and pinned lab environments only, never shipped enabled.
	insecure_skip_verify bool
	// root_cas, when set, is used instead of the system trust store — e.g. for
	// private CAs in enterprise or testing setups.
	root_cas ?pki.TrustStore
	// timeout sets the socket read and write timeouts. Defaults to 30 seconds if 0.
	timeout time.Duration
}

// default_config builds a Config for the given hostname that trusts the system
// root store (root_cas is left unset, so dial loads it).
// Deliberately conservative: no ALPN offer (server picks its default) and
// verification strictly on.
pub fn default_config(server_name string) Config {
	return Config{
		server_name:          server_name
		alpn:                 []string{}
		insecure_skip_verify: false
		timeout:              30 * time.second
	}
}
