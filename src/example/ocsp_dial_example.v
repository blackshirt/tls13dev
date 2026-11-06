// Copyright (c) 2026 blackshirt.
//
// Minimal demo of OCSP stapling over TLS 1.3: offer status_request in the
// ClientHello, consume the stapled OCSP response from CertificateStatus, and
// run it through an OcspStaplingChecker before accepting the chain.
//
// Usage:
//
//	v run src/example/ocsp_dial_example.v [host[:port]] [--ocsp-strict]
//
// With --ocsp-strict, the handshake fails if the server does not staple an
// OCSP response (fail-closed). Without it, a missing staple is accepted
// (soft-fail, matching the library default).
module main

import os
import time
import tls
import tls.handshake
import tls.pki

const default_host = 'tls-v1-3.testserver.host'

fn main() {
	mut strict := false
	mut address := default_host
	for a in os.args[1..] {
		match a {
			'--ocsp-strict' { strict = true }
			else { address = a }
		}
	}
	if !address.ends_with(']') && !address.contains(':') {
		address = '${address}:443'
	}

	mut host := address
	if i := address.last_index(':') {
		host = address[..i]
	}

	// Wire an OcspStaplingChecker through the Validator.
	// strict=true  -> fail-closed when no stapled OCSP response is present
	// strict=false -> soft-fail accept when no stapled response is present
	mut validator := pki.new_validator(pki.system_root_cas()!)
	validator.set_revocation_checker(pki.new_ocsp_stapling_checker(strict))
	validator.set_revocation_scope(pki.RevocationScope.leaf_only)

	mut conn := tls.dial(address,
		server_name:            host
		hsk_options:            handshake.HandshakeOptions{
			validator:             validator
		}
		insecure_skip_verify:   false
		request_ocsp_stapling:  strict
		timeout:                30 * time.second
	) or {
		eprintln('dial failed: ${err}')
		exit(1)
	}
	defer { conn.close() or {} }

	eprintln('OCSP stapling: requested (strict=${strict})')
	eprintln('connected to ${host}')
}
