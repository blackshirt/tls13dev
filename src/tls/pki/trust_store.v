// Copyright (c) 2026 blackshirt.
//
// trust_store.v loads and indexes trusted root CA certificates, seeding the
// verifier's chain-of-trust check from the host's system trust bundle so leaf
// certificates can be anchored back to a known-good root.
//
// This file is annotated @[has_globals] for one purpose: the process-wide
// parsed-bundle cache (cached_system_roots) below. V rejects __global in
// normal files, so the attribute opts this file in explicitly.
@[has_globals]
module pki

import encoding.base64
import os

// TrustStore stores trusted root CA certificates. Instances come from
// new_trust_store(); @[noinit] stops a bare TrustStore{} from silently existing
// with a garbage internal slice.
@[noinit]
pub struct TrustStore {
mut:
	certs []Certificate // trusted roots, checked against the chain in order
}

// new_trust_store creates an empty TrustStore.
pub fn new_trust_store() TrustStore {
	return TrustStore{
		certs: []Certificate{}
	}
}

// add_der parses and appends a single DER-encoded certificate into the store.
pub fn (mut ts TrustStore) add_der(der []u8) ! {
	cert := parse_certificate(der)!
	ts.certs << cert
}

// add_pem parses and appends all certificates from a PEM string into the store.
// PEM is just a base64-of-DER wrapper, so the real parsing target is the decoded
// DER between the markers. Unparseable blocks are skipped rather than failing the
// whole bundle, since system bundles occasionally contain unsupported formats.
pub fn (mut ts TrustStore) add_pem(pem_content string) !int {
	mut count := 0
	lines := pem_content.split_into_lines()
	mut in_cert := false
	// Lines append into bytes and are joined once per certificate: string `+=`
	// reallocated and copied on every line, making the bundle parse quadratic
	// in the number of base64 lines.
	mut b64_buf := []u8{}

	for line in lines {
		trimmed := line.trim_space()
		if trimmed.starts_with('-----BEGIN ') && trimmed.ends_with('CERTIFICATE-----') {
			in_cert = true
			b64_buf = []u8{}
			continue
		}
		if trimmed.starts_with('-----END ') && trimmed.ends_with('CERTIFICATE-----') {
			in_cert = false
			der := base64.decode(b64_buf.bytestr())
			cert := parse_certificate(der) or {
				continue
			}
			ts.certs << cert
			count++
			continue
		}
		if in_cert {
			b64_buf << trimmed.bytes()
		}
	}
	return count
}

// load_system_ca_bundle attempts to load trusted root CAs from standard system
// paths. There is no portable trust-store API across Linux distributions, so each
// known bundle location is probed and the first that yields certificates wins.
pub fn (mut ts TrustStore) load_system_ca_bundle() !int {
	paths := [
		'/etc/ssl/certs/ca-certificates.crt', // Debian/Ubuntu/Gentoo
		'/etc/pki/tls/certs/ca-bundle.crt', // Fedora/RHEL/CentOS
		'/etc/ca-certificates/extracted/tls-ca-bundle.pem', // Arch Linux
		'/etc/ssl/ca-bundle.pem', // OpenSUSE
		'/etc/pki/tls/cacert.pem', // OpenELEC
		'/usr/local/share/certs/ca-root-nss.crt', // FreeBSD
		'/etc/ssl/cert.pem', // Alpine / macOS
	]

	for path in paths {
		if os.exists(path) {
			content := os.read_file(path) or { continue }
			count := ts.add_pem(content) or { continue }
			if count > 0 {
				return count
			}
		}
	}
	return error('trust_store: no system root CA bundle found')
}

// cached_system_roots memoizes the parsed system trust bundle for the lifetime
// of the process. Parsing a typical ~150-root host bundle is the single most
// expensive step of a dial (tens of milliseconds), yet its contents are a
// read-only property of the machine, so re-parsing it for every connection is
// pure waste. The update is deliberately lock-free: two concurrent first dials
// may both parse, and the loser's identical result overwrites the winner's —
// a benign race, because both copies describe the same on-disk file. Every
// caller receives a private clone via system_root_cas(), so mutating the
// returned store can never touch the cache.
__global cached_system_roots []Certificate

// system_root_cas returns a TrustStore backed by the process-wide parsed
// system bundle, parsing it on first use. dial() uses this instead of
// load_system_ca_bundle() so an application that opens many connections pays
// the bundle parse once per process rather than once per connection. The
// returned store is a private clone, safe for the caller to mutate.
pub fn system_root_cas() !TrustStore {
	if cached_system_roots.len == 0 {
		mut loader := new_trust_store()
		loader.load_system_ca_bundle()!
		cached_system_roots = loader.certs
	}
	mut ts := new_trust_store()
	ts.certs = cached_system_roots.clone()
	return ts
}
