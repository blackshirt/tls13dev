module pki

import encoding.base64
import os

// TrustStore stores trusted root CA certificates.
pub struct TrustStore {
pub mut:
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
	mut b64_buf := ''

	for line in lines {
		trimmed := line.trim_space()
		if trimmed.starts_with('-----BEGIN ') && trimmed.ends_with('CERTIFICATE-----') {
			in_cert = true
			b64_buf = ''
			continue
		}
		if trimmed.starts_with('-----END ') && trimmed.ends_with('CERTIFICATE-----') {
			in_cert = false
			der := base64.decode(b64_buf)
			cert := parse_certificate(der) or {
				continue
			}
			ts.certs << cert
			count++
			continue
		}
		if in_cert {
			b64_buf += trimmed
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
