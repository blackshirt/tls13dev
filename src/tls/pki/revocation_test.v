// Copyright (c) 2026 blackshirt.
//
// revocation_test.v tests the optional RevocationChecker interface: no checker
// supplied (default behavior preserved), checker returns .good (chain accepted),
// checker returns .revoked (chain rejected), checker receives correct context,
// checker error propagates (fail-closed), and the trusted anchor is excluded.
module pki

import encoding.hex

// recording_state holds the state a RecordingChecker writes through a heap
// pointer, because V interface methods receive an immutable receiver.
struct RecordingState {
mut:
	called_indices []int
	hostname       string
}

// --- Test RevocationChecker implementations ---

// AlwaysGood is a checker that always returns .good.
struct AlwaysGood {}

fn (c &AlwaysGood) check(ctx RevocationContext) !RevocationStatus {
	_ = ctx
	return .good
}

// AlwaysRevoked is a checker that always returns .revoked.
struct AlwaysRevoked {}

fn (c &AlwaysRevoked) check(ctx RevocationContext) !RevocationStatus {
	_ = ctx
	return .revoked
}

// RevokedAtTarget returns .revoked only for a specific chain index, so we can
// verify the checker is called for every cert in the path and the anchor is
// excluded.
struct RevokedAtTarget {
	target_index int
}

fn (c &RevokedAtTarget) check(ctx RevocationContext) !RevocationStatus {
	if ctx.chain_index == c.target_index {
		return .revoked
	}
	return .good
}

// FailingChecker always returns an error, to verify error propagation.
struct FailingChecker {}

fn (c &FailingChecker) check(ctx RevocationContext) !RevocationStatus {
	_ = ctx
	return error('revocation service unavailable')
}

// RecordingChecker records every call through a heap-allocated state struct,
// so it can observe which chain indices were checked without mutating its own
// receiver (V interfaces require immutable receivers).
struct RecordingChecker {
	state &RecordingState = unsafe { nil }
}

fn (c &RecordingChecker) check(ctx RevocationContext) !RevocationStatus {
	if c.state != unsafe { nil } {
		unsafe { c.state.called_indices << ctx.chain_index }
		unsafe { c.state.hostname = ctx.hostname }
	}
	return .good
}

// --- Test helpers ---

// make_chain_and_store builds a real [leaf, ca] chain from the fakeserver's
// embedded Ed25519 fixtures, plus a trust store that anchors on the CA.
// Returns (chain, validator) ready for verify_certificate_chain.
fn make_chain_and_store() !([]Certificate, Validator) {
	// These hex strings are the fakeserver's embedded test PKI (Ed25519
	// CA + localhost leaf). They are test-only throwaway material.
	ca_der := hex.decode('308201793082012ba00302010202142e1a8d3b73ef8914f09d77b75fe69aefdf10afd4300506032b657030323114301206035504030c0b544c532054657374204341311a3018060355040a0c11746c732074657374206669787475726573301e170d3236313032303031353135345a170d3336313031373031353135345a30323114301206035504030c0b544c532054657374204341311a3018060355040a0c11746c732074657374206669787475726573302a300506032b65700321007eaba7bda74999fa2638834ead73c1a66d43ef2daf7fe0c8b3572efd07dc07eea3533051301d0603551d0e04160414503648cf1ecd95c76b8bdf6b51aa40f43e843792301f0603551d23041830168014503648cf1ecd95c76b8bdf6b51aa40f43e843792300f0603551d130101ff040530030101ff300506032b657003410063209e90471662318c498c9855ce47f5b797870b666970bbf9d127e2080abaaed4e33d3b931634d897153b4a1c7010248801de2e8fe368f3aa513637ecca0e01')!
	leaf_der := hex.decode('3082019530820147a00302010202147ffc71cc679aa14ade3468f2e39ebd3c4cb0f9f7300506032b657030323114301206035504030c0b544c532054657374204341311a3018060355040a0c11746c732074657374206669787475726573301e170d3236313032303031353135345a170d3336313031373031353135345a30143112301006035504030c096c6f63616c686f7374302a300506032b657003210063d19ac6b1a144004d10939407e5f0fe7e942b259765cacd13c7d97b6d759a80a3818c308189301a0603551d110413301182096c6f63616c686f737487047f00000130090603551d1304023000300b0603551d0f04040302078030130603551d25040c300a06082b06010505070301301d0603551d0e041604148c1cf2a925a3cc5257d9ed916393862825b87a8d301f0603551d23041830168014503648cf1ecd95c76b8bdf6b51aa40f43e843792300506032b6570034100222f1e5a0019eae25adec0355ad9684df2f0f370ccc742122c9825b369ee4e0f3688077e1c56a292b11d7867ae0118cb66785e38c4a13d159d7ae88f6237f000')!

	ca := parse_certificate(ca_der)!
	leaf := parse_certificate(leaf_der)!

	mut store := new_trust_store()
	store.add_der(ca_der)!

	mut v := new_validator(store)
	// The chain is [leaf, ca]; ca is the trusted anchor (byte-identical match),
	// so the validator accepts the chain without verifying the CA's self-signature.
	return [leaf, ca], v
}

// --- Tests ---

// test_revocation_no_checker_preserves_default_behavior: when no checker is
// supplied, verify_certificate_chain behaves exactly as before — a valid chain
// is accepted, and no revocation check is attempted.
fn test_revocation_no_checker_preserves_default_behavior() ! {
	chain, mut v := make_chain_and_store()!
	// No set_revocation_checker call → the optional stays none.
	v.verify_certificate_chain(chain, 'localhost', false)!
}

// test_revocation_checker_good_accepts_chain: a checker that always returns
// .good does not reject a valid chain.
fn test_revocation_checker_good_accepts_chain() ! {
	chain, mut v := make_chain_and_store()!
	v.set_revocation_checker(&AlwaysGood{})
	v.verify_certificate_chain(chain, 'localhost', false)!
}

// test_revocation_checker_revoked_rejects_chain: a checker that always returns
// .revoked causes the chain to be rejected, with an error identifying the
// revoked certificate.
fn test_revocation_checker_revoked_rejects_chain() ! {
	chain, mut v := make_chain_and_store()!
	v.set_revocation_checker(&AlwaysRevoked{})
	v.verify_certificate_chain(chain, 'localhost', false) or {
		assert err.msg().contains('revoked')
		return
	}
	assert false
}

// test_revocation_checker_called_for_leaf_not_anchor: the checker is invoked for
// the leaf (index 0) but NOT for the trusted anchor (the last cert in this chain).
// Uses a recording checker to capture which indices were actually checked.
fn test_revocation_checker_called_for_leaf_not_anchor() ! {
	chain, mut v := make_chain_and_store()!
	mut state := &RecordingState{}
	v.set_revocation_checker(&RecordingChecker{ state: state })
	v.verify_certificate_chain(chain, 'localhost', false)!
	// Chain is [leaf, ca]; ca is the trusted anchor at index 1.
	// The validated path is chain[0..1], so only index 0 (leaf) should be checked.
	assert state.called_indices.len == 1
	assert state.called_indices[0] == 0
	assert state.hostname == 'localhost'
}

// test_revocation_checker_error_propagates: when the checker returns an error,
// verify_certificate_chain propagates it (fail-closed), rather than treating
// the error as "not revoked."
fn test_revocation_checker_error_propagates() ! {
	chain, mut v := make_chain_and_store()!
	v.set_revocation_checker(&FailingChecker{})
	v.verify_certificate_chain(chain, 'localhost', false) or {
		assert err.msg().contains('revocation check failed')
		assert err.msg().contains('revocation service unavailable')
		return
	}
	assert false
}

// test_revocation_checker_revoked_at_leaf_rejects: returning .revoked for the
// leaf specifically rejects the chain, confirming the checker is called per-cert.
fn test_revocation_checker_revoked_at_leaf_rejects() ! {
	chain, mut v := make_chain_and_store()!
	v.set_revocation_checker(&RevokedAtTarget{ target_index: 0 })
	v.verify_certificate_chain(chain, 'localhost', false) or {
		assert err.msg().contains('revoked')
		return
	}
	assert false
}

// test_revocation_checker_not_called_on_insecure_validator: the insecure
// validator short-circuits before the revocation check, so a .revoked checker
// would not cause a false rejection (the insecure path skips everything).
fn test_revocation_checker_not_called_on_insecure_validator() ! {
	chain, _ := make_chain_and_store()!
	// Replace with insecure validator.
	mut insecure := new_insecure_validator()
	insecure.set_revocation_checker(&AlwaysRevoked{})
	// Must not reject — insecure skips every check.
	insecure.verify_certificate_chain(chain, 'localhost', false)!
}

// test_revocation_context_fields_populated: the RevocationContext passed to the
// checker carries the correct certificate, chain, chain_index, and hostname.
fn test_revocation_context_fields_populated() ! {
	chain, mut v := make_chain_and_store()!
	mut state := &RecordingState{}
	v.set_revocation_checker(&RecordingChecker{ state: state })
	v.verify_certificate_chain(chain, 'localhost', false)!
	// The recording checker captured the hostname; the leaf was at index 0.
	assert state.hostname == 'localhost'
	assert state.called_indices == [0]
}

// test_revocation_directly_trusted_leaf_is_checked: when the leaf IS the
// trust anchor (anchor_index == 0), it is the object of trust and the
// documented exception applies — the checker still runs for it exactly once.
fn test_revocation_directly_trusted_leaf_is_checked() ! {
	far_future := i64(4102444800)
	root_and_leaf := Certificate{
		raw:             [u8(0x01)]
		public_key_algo: .ed25519
		is_ca:           true
		not_before_unix: 0
		not_after_unix:  far_future
		has_san:         true
		sans:            ['example.com']
	}
	mut v := new_validator(new_trust_store())
	v.store.certs << root_and_leaf
	mut state := &RecordingState{}
	v.set_revocation_checker(&RecordingChecker{ state: state })
	v.verify_certificate_chain([root_and_leaf], 'example.com', false)!
	assert state.called_indices == [0]
}

// test_revocation_checker_default_is_no_check: a freshly constructed validator
// has NoCheck as its default checker, which always returns .good (matching the
// previous "no checker" behavior: revoked-but-unexpired certificates are accepted).
fn test_revocation_checker_default_is_no_check() ! {
	mut v := new_validator(new_trust_store())
	ctx := RevocationContext{
		certificate:   Certificate{}
		chain:         []Certificate{}
		chain_index:   0
		hostname:      'localhost'
		ocsp_response: none
	}
	assert v.revocation_checker.check(ctx)! == .good
}

// test_revocation_checker_can_be_set: the setter replaces the default NoCheck
// with a caller supplied checker.
fn test_revocation_checker_can_be_set() ! {
	chain, mut v := make_chain_and_store()!
	// Default NoCheck accepts (revoked-but-unexpired is accepted).
	v.verify_certificate_chain(chain, 'localhost', false)!
	// After setting AlwaysRevoked, the chain is rejected.
	v.set_revocation_checker(&AlwaysRevoked{})
	v.verify_certificate_chain(chain, 'localhost', false) or {
		assert err.msg().contains('revoked')
		return
	}
	assert false
}

// test_ocsp_stapling_strict_no_response_errors: a strict OCSP stapling checker
// returns an error when no stapled response is present (fail-closed).
fn test_ocsp_stapling_strict_no_response_errors() ! {
	mut checker := new_ocsp_stapling_checker(true)
	ctx := RevocationContext{
		certificate:   Certificate{}
		chain:         []Certificate{}
		chain_index:   0
		hostname:      'localhost'
		ocsp_response: none
	}
	checker.check(ctx) or {
		assert err.msg().contains('OCSP stapling response missing')
		return
	}
	assert false
}

// test_ocsp_stapling_non_strict_no_response_good: a non-strict OCSP stapling
// checker returns .good when no stapled response is present (soft-fail).
fn test_ocsp_stapling_non_strict_no_response_good() ! {
	mut checker := new_ocsp_stapling_checker(false)
	ctx := RevocationContext{
		certificate:   Certificate{}
		chain:         []Certificate{}
		chain_index:   0
		hostname:      'localhost'
		ocsp_response: none
	}
	assert checker.check(ctx)! == .good
}

// test_ocsp_stapling_valid_response_good: a non-empty DER OCSPResponse
// (SEQUENCE, tag 0x30) returns .good.
fn test_ocsp_stapling_valid_response_good() ! {
	mut checker := new_ocsp_stapling_checker(true)
	// DER-encoded SEQUENCE: 0x30 <length> ...
	ocsp_response := [u8(0x30), 0x03, 0x02, 0x01, 0x00]
	ctx := RevocationContext{
		certificate:   Certificate{}
		chain:         []Certificate{}
		chain_index:   0
		hostname:      'localhost'
		ocsp_response: ocsp_response
	}
	assert checker.check(ctx)! == .good
}

// test_ocsp_stapling_invalid_response_revoked: a stapled response that does
// not begin with the OCSPResponse SEQUENCE tag (0x30) returns .revoked.
fn test_ocsp_stapling_invalid_response_revoked() ! {
	mut checker := new_ocsp_stapling_checker(true)
	ocsp_response := [u8(0x02), 0x01, 0x00] // INTEGER, not SEQUENCE
	ctx := RevocationContext{
		certificate:   Certificate{}
		chain:         []Certificate{}
		chain_index:   0
		hostname:      'localhost'
		ocsp_response: ocsp_response
	}
	assert checker.check(ctx)! == .revoked
}

// test_ocsp_stapling_empty_response_revoked: an empty stapled response
// returns .revoked.
fn test_ocsp_stapling_empty_response_revoked() ! {
	mut checker := new_ocsp_stapling_checker(true)
	ctx := RevocationContext{
		certificate:   Certificate{}
		chain:         []Certificate{}
		chain_index:   0
		hostname:      'localhost'
		ocsp_response: []u8{}
	}
	assert checker.check(ctx)! == .revoked
}
