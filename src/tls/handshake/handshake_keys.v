// Copyright (c) 2026 blackshirt.
//
// handshake_keys.v adapts the pure §7.1 secret derivations (handshake and application
// phases) and the group policy the ClientHello offers to the handshake flow;
// state_machine.v sequences these calls.
module handshake

// TrafficSecrets groups one key-schedule stage's output; the handshake phase fills all
// three, the application phase leaves handshake_secret empty.
struct TrafficSecrets {
mut:
	handshake_secret []u8
	client_traffic   []u8
	server_traffic   []u8
}

// is_supported_group reports whether the client advertised support for a group in its supported_groups.
fn is_supported_group(g NamedGroup) bool {
	return g == .x25519 || g == .secp256r1
}

// is_supported_cipher_suite reports whether this stack can implement the suite —
// exactly the three TLS 1.3 suites of RFC 8446 §B.4. Must stay in lockstep with
// cipher_suite_from_u16, the ServerHello decoder.
fn is_supported_cipher_suite(cs CipherSuite) bool {
	return cs in [CipherSuite.tls_aes_128_gcm_sha256, .tls_aes_256_gcm_sha384,
		.tls_chacha20_poly1305_sha256]
}

// is_supported_signature_scheme reports whether the verifier can check the
// scheme — exactly the set signature_scheme_from_u16 accepts (§4.2.3). A client
// must never offer a scheme it could not verify in CertificateVerify.
fn is_supported_signature_scheme(s SignatureScheme) bool {
	return s in [SignatureScheme.rsa_pkcs1_sha256, .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384,
		.rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512, .ed25519]
}

// derive_hs_secrets runs the §7.1 handshake phase: the zero-PSK Early Secret, the
// Handshake Secret mixing in the ECDHE shared secret, and the handshake traffic secrets.
fn derive_hs_secrets(hash_algo HashAlgorithm, shared_secret []u8, th_ch_sh []u8) !TrafficSecrets {
	// Early Secret = HKDF-Extract(0, 0); without a PSK the IKM is empty but is still mixed in.
	mut early_secret := hkdf_extract(hash_algo, []u8{}, []u8{len: hash_algo.hash_len()})
	mut derived_early := derive_secret(hash_algo, early_secret, 'derived', empty_transcript_hash(hash_algo))!
	// §7.5: the early chain is dead once the Handshake extract consumed it — these
	// locals never reach the core's tracked secrets, so they zeroize here.
	wipe_secret(mut early_secret)
	// Handshake Secret = HKDF-Extract(Derive-Secret(Early, "derived"), ECDHE)
	handshake_secret := hkdf_extract(hash_algo, derived_early, shared_secret)
	wipe_secret(mut derived_early)

	client_hs := derive_secret(hash_algo, handshake_secret, 'c hs traffic', th_ch_sh)!
	server_hs := derive_secret(hash_algo, handshake_secret, 's hs traffic', th_ch_sh)!

	return TrafficSecrets{
		handshake_secret: handshake_secret
		client_traffic:   client_hs
		server_traffic:   server_hs
	}
}

// derive_app_secrets runs the §7.1 application phase from the Handshake Secret: the
// Master Secret, then the client/server application traffic secrets (KeyUpdate updates them, §7.2).
fn derive_app_secrets(hash_algo HashAlgorithm, handshake_secret []u8, th_sfin []u8) !TrafficSecrets {
	mut derived_hs := derive_secret(hash_algo, handshake_secret, 'derived', empty_transcript_hash(hash_algo))!
	mut master_secret := hkdf_extract(hash_algo, derived_hs, []u8{len: hash_algo.hash_len()})
	wipe_secret(mut derived_hs)

	client_ap := derive_secret(hash_algo, master_secret, 'c ap traffic', th_sfin)!
	server_ap := derive_secret(hash_algo, master_secret, 's ap traffic', th_sfin)!
	// §7.1/§7.5: the Master Secret is never stored — KeyUpdate (§7.2) chains from the
	// traffic secrets alone — so it dies with this call.
	wipe_secret(mut master_secret)

	return TrafficSecrets{
		client_traffic: client_ap
		server_traffic: server_ap
	}
}
