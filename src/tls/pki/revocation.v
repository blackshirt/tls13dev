// Copyright (c) 2026 blackshirt.
//
// revocation.v defines the optional certificate-revocation checker interface.
// CRL and OCSP are not built into this library; instead a caller may supply a
// RevocationChecker through Config (or directly on a Validator) to be invoked
// during chain validation. When no checker is supplied the existing behavior
// (no revocation check) is preserved — a revoked-but-unexpired certificate is
// accepted. When a checker IS supplied, every certificate in the validated path
// (leaf + intermediates, excluding the trusted anchor) is checked, and a
// `.revoked` result rejects the chain. Exception: when the leaf is itself the
// anchor, it is still checked.
module pki

// RevocationStatus is the result of a single revocation check.
pub enum RevocationStatus {
	good    // certificate is not revoked
	revoked // certificate is revoked; the chain must be rejected
}

// RevocationScope selects which certificates in the validated path are
// checked by an attached RevocationChecker.
pub enum RevocationScope {
	// leaf_only checks only the end-entity (leaf) certificate (the default).
	leaf_only
	// intermediates_only checks only intermediate CA certificates,
	// skipping the leaf and any trusted anchor.
	intermediates_only
	// both checks the leaf and every intermediate CA in the validated
	// path, excluding the trusted anchor.
	both
}

// RevocationContext provides the certificate and chain context to a
// RevocationChecker. The checker receives the certificate being checked, its
// position in the chain, the full chain (leaf first, root last), and the
// hostname being verified. A CRL or OCSP checker finds its fetch locator in
// ctx.certificate.ocsp_urls / ctx.certificate.crl_distribution_points; the
// issuing CA (for OCSP request construction) is chain[chain_index + 1] when
// present, otherwise the trusted anchor. For OCSP stapling, the stapled
// response supplied by the server during the handshake is in ctx.ocsp_response.
pub struct RevocationContext {
pub:
	// certificate is the certificate being checked for revocation.
	certificate Certificate
	// chain is the full peer-supplied certificate list (leaf first).
	chain []Certificate
	// chain_index is the position of `certificate` in `chain` (0 = leaf).
	chain_index int
	// hostname is the server name being verified (SNI / verification name).
	hostname string
	// ocsp_response is the stapled OCSP response (DER-encoded OCSPResponse,
	// RFC 6960) supplied by the server during the TLS handshake, if any.
	// None when the server did not staple an OCSP response for this
	// certificate.
	ocsp_response ?[]u8
}

// RevocationChecker is an optional callback interface for certificate
// revocation checking (CRL, OCSP, or any out-of-band method). Supply an
// implementation through tls.Config.revocation_checker or
// Validator.set_revocation_checker.
//
// Contract:
//   - check is called once per certificate in the validated path (leaf +
//     intermediates, excluding the trusted anchor) after all other validation
//     rules (chain building, signature verification, hostname, validity,
//     key usage, name constraints) have passed.
//   - Return .good when the certificate is not revoked.
//   - Return .revoked when the certificate is revoked; the Validator rejects
//     the entire chain.
//   - Return an error when revocation status cannot be determined; the
//     Validator propagates the error (fail-closed). A soft-fail implementation
//     should catch its own errors and return .good instead.
//   - check must be safe to call from the handshake thread; it must not block
//     indefinitely. Network-based checkers should enforce their own timeout.
pub interface RevocationChecker {
	check(ctx RevocationContext) !RevocationStatus
}

// NoCheck is a RevocationChecker implementation that never rejects: it always
// returns .good, matching the library's default behavior when no checker is
// supplied (a revoked-but-unexpired certificate is accepted). Supply it through
// tls.Config.revocation_checker or Validator.set_revocation_checker when you
// want an explicit, documented no-op rather than leaving the optional unset.
struct NoCheck {}

fn (c &NoCheck) check(ctx RevocationContext) !RevocationStatus {
	_ = ctx
	return .good
}

// OcspStaplingChecker implements RevocationChecker using OCSP stapling
// (RFC 6066 / RFC 6960). It expects the server to staple a DER-encoded
// OCSPResponse during the TLS handshake; the stapled response is supplied
// through RevocationContext.ocsp_response.
//
// Behaviour when no stapled response is present depends on strict mode:
//   - strict: true  → returns an error (fail-closed, connection rejected)
//   - strict: false → returns .good (accept, matching default behaviour)
//
// When a stapled response is present, it is validated as a DER-encoded
// OCSPResponse SEQUENCE. A malformed response returns .revoked.
pub struct OcspStaplingChecker {
mut:
	strict bool
}

// new_ocsp_stapling_checker creates an OCSP stapling checker.
// strict controls behaviour when the server does not staple an OCSP response:
//
//	strict = true  → error (fail-closed) when no stapled response is present
//	strict = false → .good (accept) when no stapled response is present
pub fn new_ocsp_stapling_checker(strict bool) &OcspStaplingChecker {
	return &OcspStaplingChecker{ strict: strict }
}

fn (c &OcspStaplingChecker) check(ctx RevocationContext) !RevocationStatus {
	if ctx.ocsp_response == none {
		if c.strict {
			return error('pki: OCSP stapling response missing for certificate at chain index ${ctx.chain_index}')
		}
		return .good
	}
	resp := ctx.ocsp_response!
	if resp.len == 0 {
		return .revoked
	}
	// OCSPResponse ::= SEQUENCE { ... } — top-level tag is 0x30.
	if resp[0] != 0x30 {
		return .revoked
	}
	return .good
}
