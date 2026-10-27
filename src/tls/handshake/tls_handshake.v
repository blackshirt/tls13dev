// Copyright (c) 2026 blackshirt.
//
// TLSHandshake is the TLS record adapter facade over shared handshake
// semantics. Record traffic keys, TLS KeyUpdate state, and the record-side
// reassembly hooks (unconsumed_bytes / take_buffered_handshake_bytes) live
// here — none of them has a QUIC caller, so none belongs to the core.
module handshake

// TrafficKeyPair holds one traffic phase's cached client and server record keys.
struct TrafficKeyPair {
mut:
	client TrafficKeys
	server TrafficKeys
}

// available reports whether both directions' keys are present.
fn (p &TrafficKeyPair) available() bool {
	return p.client.key.len > 0 && p.server.key.len > 0
}

// wipe zeroes both directions' cached keys.
fn (mut p TrafficKeyPair) wipe() {
	wipe_traffic_keys(mut p.client)
	wipe_traffic_keys(mut p.server)
}

// PhaseKeys groups the handshake and application cached record-key pairs.
struct PhaseKeys {
mut:
	handshake   TrafficKeyPair
	application TrafficKeyPair
}

// pair selects one phase's cached record-key pair; the initial level has none.
fn (k &PhaseKeys) pair(level EncryptionLevel) TrafficKeyPair {
	return match level {
		.initial { TrafficKeyPair{} }
		.handshake { k.handshake }
		.application { k.application }
	}
}

// wipe zeroes one phase's cached record-key pair; the initial level has none.
fn (mut k PhaseKeys) wipe(level EncryptionLevel) {
	match level {
		.initial {}
		.handshake { k.handshake.wipe() }
		.application { k.application.wipe() }
	}
}

// TLSHandshake exposes only operations needed by the TLS record layer.
@[noinit]
pub struct TLSHandshake {
	HandshakeCore
mut:
	keys PhaseKeys // Cached record keys, grouped by protection phase.
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
	return h.buffers.len(level)
}

// take_buffered_handshake_bytes moves whatever the core's drain left buffered at
// .connected (legal only per RFC 8446 §4.6.1 coalescing) to the record adapter,
// zeroizing the core's copy (§7.5).
pub fn (mut h TLSHandshake) take_buffered_handshake_bytes() []u8 {
	return h.buffers.take_handshake()
}

// record_traffic_keys returns independent copies of the cached client/server
// record key and IV bytes at one TLS encryption level, ordered as
// (client_key, client_iv, server_key, server_iv). TrafficKeys stays a module-internal
// type: the tls record layer receives plain []u8 instead of a named key handle.
pub fn (h &TLSHandshake) record_traffic_keys(level EncryptionLevel) !([]u8, []u8, []u8, []u8) {
	if level == .initial {
		return error('handshake: initial level has no traffic keys')
	}
	keys := h.keys.pair(level)
	if !keys.available() {
		if level == .handshake {
			return error('handshake: handshake traffic keys unavailable (available after ServerHello, dropped by zeroize_traffic_secrets(.handshake))')
		}
		return error('handshake: application traffic keys unavailable before the server Finished')
	}
	return keys.client.key.clone(), keys.client.iv.clone(), keys.server.key.clone(), keys.server.iv.clone()
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
		h.secrets.application.server
	} else {
		h.secrets.application.client
	}
	if secret.len == 0 {
		return error('handshake: cannot update the ${side} application traffic secret (unavailable before the server Finished, destroyed by zeroize_traffic_secrets(.application))')
	}
	new_secret, next := derive_updated_traffic_keys(h.hash_algo, h.key_len, secret) or {
		h.fail_and_zeroize_secrets()
		return err
	}
	if is_server {
		wipe_secret(mut h.secrets.application.server)
		h.secrets.application.server = new_secret
		wipe_traffic_keys(mut h.keys.application.server)
		h.keys.application.server = next
	} else {
		wipe_secret(mut h.secrets.application.client)
		h.secrets.application.client = new_secret
		wipe_traffic_keys(mut h.keys.application.client)
		h.keys.application.client = next
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
// corresponding handshake or application traffic secrets. A complete pair marks
// a level as derived, so each level expands exactly once. Each level's pair is
// derived atomically via derive_record_key_pair before either direction is written.
fn (mut h TLSHandshake) sync_record_keys() ! {
	if !h.keys.handshake.available() && h.secrets.handshake.available() {
		ck, sk := derive_record_key_pair(h.hash_algo, h.key_len, h.secrets.handshake.client,
			h.secrets.handshake.server)!
		h.keys.handshake = TrafficKeyPair{
			client: ck
			server: sk
		}
	}
	if !h.keys.application.available() && h.secrets.application.available() {
		ck, sk := derive_record_key_pair(h.hash_algo, h.key_len, h.secrets.application.client,
			h.secrets.application.server)!
		h.keys.application = TrafficKeyPair{
			client: ck
			server: sk
		}
	}
}

// wipe_record_keys_at zeroes the cached client/server record keys for one level;
// the initial level has no cached keys.
fn (mut h TLSHandshake) wipe_record_keys_at(level EncryptionLevel) {
	h.keys.wipe(level)
}

// wipe_record_keys clears all cached handshake and application record keys.
fn (mut h TLSHandshake) wipe_record_keys() {
	h.wipe_record_keys_at(.handshake)
	h.wipe_record_keys_at(.application)
}
