// Copyright (c) 2026 blackshirt.
//
// TLSHandshake is the TLS record adapter facade over shared handshake
// semantics. Record traffic keys, TLS KeyUpdate state, and the record-side
// reassembly hooks (unconsumed_bytes / take_buffered_handshake_bytes) live
// here — none of them has a QUIC caller, so none belongs to the core.
module handshake

// TLSHandshake exposes only operations needed by the TLS record layer.
// The four record-key fields are ordered protocol-first to mirror the core's
// client/server_*_traffic secret names.
@[noinit]
pub struct TLSHandshake {
	HandshakeCore
mut:
	client_hsk_keys TrafficKeys // Cached record keys for the client at the handshake level.
	server_hsk_keys TrafficKeys // Cached record keys for the server at the handshake level.
	client_app_keys TrafficKeys // Cached record keys for the client at the application level.
	server_app_keys TrafficKeys // Cached record keys for the server at the application level.
}

//  Public API: construction and dispatch driver

// new_tls_handshake creates a TLS-over-records handshake facade.
// HandshakeOptions fields can be supplied as optional named arguments.
pub fn new_tls_handshake(server_name string, options HandshakeOptions) !TLSHandshake {
	return TLSHandshake{
		HandshakeCore: new_handshake_core(server_name, options, false)!
	}
}

// receive_msgs_at_level feeds TLS handshake bytes at one encryption level and returns
// any complete outbound handshake messages triggered by the input.
pub fn (mut h TLSHandshake) receive_msgs_at_level(level EncryptionLevel, bytes []u8) ![]HandshakeMessage {
	messages := h.HandshakeCore.receive_msgs_at_level(level, bytes) or {
		if h.state() == .failed {
			h.wipe_record_keys()
		}
		return err
	}
	h.sync_record_keys() or {
		h.fail_and_zeroize_secrets()
		return err
	}
	return messages
}

//  Public API: record-layer accessors and reassembly hooks

// unconsumed_bytes reports bytes the core's reassembly retained after complete
// TLS messages were consumed. Record-path scope: only the TLS adapter enforces
// the §5.1 ServerHello record-boundary rule; QUIC frames its own CRYPTO stream.
pub fn (h &TLSHandshake) unconsumed_bytes(level EncryptionLevel) int {
	return match level {
		.initial { h.init_buf.len }
		.handshake { h.hsk_buf.len }
		.application { 0 }
	}
}

// take_buffered_handshake_bytes moves whatever the core's drain left buffered at
// .connected (legal only per RFC 8446 §4.6.1 coalescing) to the record adapter,
// zeroizing the core's copy (§7.5).
pub fn (mut h TLSHandshake) take_buffered_handshake_bytes() []u8 {
	taken := h.hsk_buf.clone()
	for i in 0 .. h.hsk_buf.len {
		h.hsk_buf[i] = 0
	}
	h.hsk_buf = []u8{}
	return taken
}

// record_traffic_keys returns independent copies of the cached client/server
// record key and IV bytes at one TLS encryption level, ordered as
// (client_key, client_iv, server_key, server_iv). TrafficKeys stays a module-internal
// type: the tls record layer receives plain []u8 instead of a named key handle.
pub fn (h &TLSHandshake) record_traffic_keys(level EncryptionLevel) !([]u8, []u8, []u8, []u8) {
	match level {
		.initial {
			return error('handshake: initial level has no traffic keys')
		}
		.handshake {
			if h.client_hsk_keys.key.len == 0 || h.server_hsk_keys.key.len == 0 {
				return error('handshake: handshake traffic keys unavailable (available after ServerHello, dropped by zeroize_traffic_secrets(.handshake))')
			}
			return h.client_hsk_keys.key.clone(), h.client_hsk_keys.iv.clone(), h.server_hsk_keys.key.clone(), h.server_hsk_keys.iv.clone()
		}
		.application {
			if h.client_app_keys.key.len == 0 || h.server_app_keys.key.len == 0 {
				return error('handshake: application traffic keys unavailable before the server Finished')
			}
			return h.client_app_keys.key.clone(), h.client_app_keys.iv.clone(), h.server_app_keys.key.clone(), h.server_app_keys.iv.clone()
		}
	}
}

// update_traffic_keys updates one direction's application traffic keys around a
// TLS KeyUpdate (RFC 8446 §7.2); only valid once connected. is_server selects
// the read leg (server keys, after receiving) vs the write leg (client keys,
// before sending). The two legs are the same routine over different
// secret/keys field pairs, so they share this body: is_server selects the pair
// and the direction word in the two guards.
pub fn (mut h TLSHandshake) update_traffic_keys(is_server bool) ! {
	side := if is_server { 'server' } else { 'client' }
	if h.state() != .connected {
		return error('handshake: cannot update ${side} application traffic keys before the handshake is connected (state: ${h.state()})')
	}
	secret := if is_server {
		h.server_app_traffic
	} else {
		h.client_app_traffic
	}
	if secret.len == 0 {
		return error('handshake: cannot update the ${side} application traffic secret (unavailable before the server Finished, destroyed by zeroize_traffic_secrets(.application))')
	}
	new_secret, next := derive_updated_traffic_keys(h.hash_algo, h.key_len, secret) or {
		h.fail_and_zeroize_secrets()
		return err
	}
	if is_server {
		wipe_secret(mut h.server_app_traffic)
		h.server_app_traffic = new_secret
		wipe_traffic_keys(mut h.server_app_keys)
		h.server_app_keys = next
	} else {
		wipe_secret(mut h.client_app_traffic)
		h.client_app_traffic = new_secret
		wipe_traffic_keys(mut h.client_app_keys)
		h.client_app_keys = next
	}
}

//  Public API: secret lifecycle (facade overrides of the core)

// fail_and_zeroize_secrets marks the handshake failed and wipes TLS secrets and
// all cached record keys. It does not close the TCP connection.
pub fn (mut h TLSHandshake) fail_and_zeroize_secrets() {
	h.HandshakeCore.fail_and_zeroize_secrets()
	h.wipe_record_keys()
}

// zeroize_traffic_secrets destroys the traffic secrets for one encryption level
// plus that level's cached record keys; valid only after .connected (core guard)
// and the initial level is refused. Used both for application teardown and, once
// the record adapter no longer needs them, for the handshake keys/secrets.
pub fn (mut h TLSHandshake) zeroize_traffic_secrets(level EncryptionLevel) ! {
	h.HandshakeCore.zeroize_traffic_secrets(level)!
	h.wipe_record_keys_at(level)
}

//  Private: record-key cache derivation and wiping

// derive_updated_traffic_keys performs the TLS KeyUpdate "traffic upd" derivation:
// the next application traffic secret from the current one, then its cached keys.
fn derive_updated_traffic_keys(hash_algo HashAlgorithm, key_len int, secret []u8) !([]u8, TrafficKeys) {
	new_secret := hkdf_expand_label(hash_algo, secret, 'traffic upd', []u8{},
		hash_algo.hash_len())!
	next := derive_traffic_keys(hash_algo, new_secret, key_len, aead_nonce_len)!
	return new_secret, next
}

// derive_record_key_pair expands one level's client and server traffic secrets into
// their cached record keys (RFC 8446 §7.1). Both directions are derived before either
// is returned, so a derivation failure can never leave a level half-installed — the
// same atomicity sync_record_keys relies on.
fn derive_record_key_pair(hash_algo HashAlgorithm, key_len int, client_secret []u8, server_secret []u8) !(TrafficKeys, TrafficKeys) {
	ck := derive_traffic_keys(hash_algo, client_secret, key_len, aead_nonce_len)!
	sk := derive_traffic_keys(hash_algo, server_secret, key_len, aead_nonce_len)!
	return ck, sk
}

// sync_record_keys derives and caches record keys when the core exposes
// corresponding handshake or application traffic secrets. The client key of each
// level doubles as the derived-once marker, so each level expands exactly once.
// Each level's pair is derived atomically via derive_record_key_pair before either
// field is written.
fn (mut h TLSHandshake) sync_record_keys() ! {
	if h.client_hsk_keys.key.len == 0 && h.client_hsk_traffic.len > 0 {
		ck, sk := derive_record_key_pair(h.hash_algo, h.key_len, h.client_hsk_traffic, h.server_hsk_traffic)!
		h.client_hsk_keys = ck
		h.server_hsk_keys = sk
	}
	if h.client_app_keys.key.len == 0 && h.client_app_traffic.len > 0 {
		ck, sk := derive_record_key_pair(h.hash_algo, h.key_len, h.client_app_traffic, h.server_app_traffic)!
		h.client_app_keys = ck
		h.server_app_keys = sk
	}
}

// wipe_record_keys_at zeroes the cached client/server record keys for one level;
// the initial level has no cached keys.
fn (mut h TLSHandshake) wipe_record_keys_at(level EncryptionLevel) {
	match level {
		.initial {}
		.handshake {
			wipe_traffic_keys(mut h.client_hsk_keys)
			wipe_traffic_keys(mut h.server_hsk_keys)
		}
		.application {
			wipe_traffic_keys(mut h.client_app_keys)
			wipe_traffic_keys(mut h.server_app_keys)
		}
	}
}

// wipe_record_keys clears all cached handshake and application record keys.
fn (mut h TLSHandshake) wipe_record_keys() {
	h.wipe_record_keys_at(.handshake)
	h.wipe_record_keys_at(.application)
}
