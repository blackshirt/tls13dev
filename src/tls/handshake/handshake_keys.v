// Copyright (c) 2026 blackshirt.
//
// handshake_keys.v adapts the pure §7.1 secret derivations (handshake and application
// phases) and the group policy the ClientHello offers to the handshake flow.
// state_machine.v sequences these calls; nothing here touches the transcript or
// advances protocol state.
module handshake

// TrafficSecrets groups one key-schedule stage's output: the handshake phase
// fills all three (handshake_secret is needed again for the Master Secret), the
// application phase leaves handshake_secret empty.
struct TrafficSecrets {
mut:
	handshake_secret []u8
	client_traffic   []u8
	server_traffic   []u8
}

// is_supported_group reports whether the client advertised support for a group
// in its supported_groups extension (see build_client_hello).
fn is_supported_group(g NamedGroup) bool {
	return g == .x25519 || g == .secp256r1
}

// derive_hs_secrets runs the §7.1 handshake phase: the fixed zero-PSK Early
// Secret, the Handshake Secret mixing in the ECDHE shared secret, and the
// client/server handshake traffic secrets bound to the transcript through
// ServerHello (th_ch_sh).
fn derive_hs_secrets(hash_algo HashAlgorithm, shared_secret []u8, th_ch_sh []u8) !TrafficSecrets {
	// Early Secret = HKDF-Extract(0, 0). Without a PSK the IKM is empty but is
	// still mixed in via Derive-Secret so the schedule matches the RFC.
	early_secret := hkdf_extract(hash_algo, []u8{}, []u8{len: hash_algo.hash_len()})
	derived_early := derive_secret(hash_algo, early_secret, 'derived', empty_transcript_hash(hash_algo))!
	// Handshake Secret = HKDF-Extract(Derive-Secret(Early, "derived"), ECDHE)
	handshake_secret := hkdf_extract(hash_algo, derived_early, shared_secret)

	client_hs := derive_secret(hash_algo, handshake_secret, 'c hs traffic', th_ch_sh)!
	server_hs := derive_secret(hash_algo, handshake_secret, 's hs traffic', th_ch_sh)!

	return TrafficSecrets{
		handshake_secret: handshake_secret
		client_traffic:   client_hs
		server_traffic:   server_hs
	}
}

// derive_app_secrets runs the §7.1 application phase from the Handshake Secret:
// the Master Secret, then the client/server application traffic secrets bound
// to the transcript including server Finished (th_sfin). The traffic secrets
// are the reusable state (KeyUpdate ratchets them, §7.2); callers derive keys
// and ciphers from them locally.
fn derive_app_secrets(hash_algo HashAlgorithm, handshake_secret []u8, th_sfin []u8) !TrafficSecrets {
	derived_hs := derive_secret(hash_algo, handshake_secret, 'derived', empty_transcript_hash(hash_algo))!
	master_secret := hkdf_extract(hash_algo, derived_hs, []u8{len: hash_algo.hash_len()})

	client_ap := derive_secret(hash_algo, master_secret, 'c ap traffic', th_sfin)!
	server_ap := derive_secret(hash_algo, master_secret, 's ap traffic', th_sfin)!

	return TrafficSecrets{
		client_traffic: client_ap
		server_traffic: server_ap
	}
}
