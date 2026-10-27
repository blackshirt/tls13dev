// Copyright (c) 2026 blackshirt.
//
// TLSHandshake is the TLS record adapter facade over shared handshake
// semantics. Record traffic keys (held as flat []u8 fields keyed by
// c_/s_ direction and hsk_/app_ phase), TLS KeyUpdate state, and the record-side
// reassembly hooks (unconsumed_bytes / take_buffered_handshake_bytes) live
// here — none of them has a QUIC caller, so none belongs to the core.
module handshake

// TLSHandshake exposes only operations needed by the TLS record layer.
@[noinit]
pub struct TLSHandshake {
	HandshakeCore
mut:
	// Cached record keys, flat []u8 per phase and direction; a nonce base (iv)
	// always pairs with its key, and every install or wipe takes both together.
	c_hsk_key []u8 // client handshake AEAD key
	c_hsk_iv  []u8 // client handshake nonce base
	s_hsk_key []u8 // server handshake AEAD key
	s_hsk_iv  []u8 // server handshake nonce base
	c_app_key []u8 // client application AEAD key
	c_app_iv  []u8 // client application nonce base
	s_app_key []u8 // server application AEAD key
	s_app_iv  []u8 // server application nonce base
}

// new_tls_handshake creates a TLS-over-records handshake facade.
// HandshakeOptions fields can be supplied as optional named arguments.
pub fn new_tls_handshake(server_name string, options HandshakeOptions) !TLSHandshake {
	return TLSHandshake{
		HandshakeCore: new_handshake_core(server_name, options, false)!
	}
}

// Curated forwarders. HandshakeCore is an internal type and all its methods are
// module-private, so nothing reaches outside tls.handshake through embedded-field
// promotion; the tls record layer sees only these entry points, each delegating
// to the core by an explicit qualified call (never h.X(), which would resolve
// back to the forwarder and recurse).

// state reports the handshake position; the record adapter polls it (§A.1).
pub fn (h &TLSHandshake) state() HandshakeState {
	return h.HandshakeCore.state()
}

// negotiated_alpn returns the ALPN protocol the server picked ('' when none).
pub fn (h &TLSHandshake) negotiated_alpn() string {
	return h.HandshakeCore.negotiated_alpn()
}

// negotiated_cipher_suite reports the suite selected by the server in ServerHello.
pub fn (h &TLSHandshake) negotiated_cipher_suite() CipherSuite {
	return h.HandshakeCore.negotiated_cipher_suite()
}

// failure_alert returns the alert the adapter surfaces when the handshake dies (§6).
pub fn (h &TLSHandshake) failure_alert() AlertDescription {
	return h.HandshakeCore.failure_alert()
}

// available_secret_phases reports which traffic-secret phases the core holds.
pub fn (h &TLSHandshake) available_secret_phases() SecretPhases {
	return h.HandshakeCore.available_secret_phases()
}

// create_client_hello generates the initial ClientHello bytes (RFC 8446 App. D.4).
pub fn (mut h TLSHandshake) create_client_hello() ![]u8 {
	return h.HandshakeCore.create_client_hello()!
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
// (client_key, client_iv, server_key, server_iv). The flat key fields stay
// module-internal: the tls record layer receives plain []u8, never a named
// key handle.
pub fn (h &TLSHandshake) record_traffic_keys(level EncryptionLevel) !([]u8, []u8, []u8, []u8) {
	if level == .initial {
		return error('handshake: initial level has no traffic keys')
	}
	keys_ready := if level == .handshake {
		h.c_hsk_key.len > 0 && h.s_hsk_key.len > 0
	} else {
		h.c_app_key.len > 0 && h.s_app_key.len > 0
	}
	if !keys_ready {
		if level == .handshake {
			return error('handshake: handshake traffic keys unavailable (available after ServerHello, dropped by zeroize_traffic_secrets(.handshake))')
		}
		return error('handshake: application traffic keys unavailable before the server Finished')
	}
	if level == .handshake {
		return h.c_hsk_key.clone(), h.c_hsk_iv.clone(), h.s_hsk_key.clone(), h.s_hsk_iv.clone()
	}
	return h.c_app_key.clone(), h.c_app_iv.clone(), h.s_app_key.clone(), h.s_app_iv.clone()
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
	secret := if is_server { h.s_app_tsec } else { h.c_app_tsec }
	if secret.len == 0 {
		return error('handshake: cannot update the ${side} application traffic secret (unavailable before the server Finished, destroyed by zeroize_traffic_secrets(.application))')
	}
	next_secret, next_key, next_iv := derive_updated_traffic_keys(h.hash_algo, h.key_len, secret) or {
		h.fail_and_zeroize_secrets()
		return err
	}
	// Today's pair-shaped wipe-and-replace is kept as one block per leg, since V
	// only forms multi-value results into fresh bindings, not existing fields.
	if is_server {
		wipe_secret(mut h.s_app_tsec)
		h.s_app_tsec = next_secret
		wipe_secret(mut h.s_app_key)
		wipe_secret(mut h.s_app_iv)
		h.s_app_key = next_key
		h.s_app_iv = next_iv
	} else {
		wipe_secret(mut h.c_app_tsec)
		h.c_app_tsec = next_secret
		wipe_secret(mut h.c_app_key)
		wipe_secret(mut h.c_app_iv)
		h.c_app_key = next_key
		h.c_app_iv = next_iv
	}
}

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

// derive_updated_traffic_keys performs the TLS KeyUpdate "traffic upd" derivation:
// the next application traffic secret from the current one, then its cached
// record key and IV.
fn derive_updated_traffic_keys(hash_algo HashAlgorithm, key_len int, secret []u8) !([]u8, []u8, []u8) {
	new_secret := hkdf_expand_label(hash_algo, secret, 'traffic upd', []u8{},
		hash_algo.hash_len())!
	key := derive_traffic_key(hash_algo, new_secret, key_len)!
	iv := derive_traffic_iv(hash_algo, new_secret, aead_nonce_len)!
	return new_secret, key, iv
}

// sync_keys_level expands one phase's traffic secrets into its cached record
// keys exactly once; complete keys or absent secrets both short-circuit (§7.1).
// All four key and IV values are derived into locals before any field is written, so
// a failure can never leave a level half-installed — the same atomicity
// sync_record_keys relies on.
fn (mut h TLSHandshake) sync_keys_level(level EncryptionLevel) ! {
	mut keys_ready := false
	mut secrets_ready := false
	if level == .handshake {
		keys_ready = h.c_hsk_key.len > 0 && h.s_hsk_key.len > 0
		secrets_ready = h.c_hsk_tsec.len > 0 && h.s_hsk_tsec.len > 0
	} else if level == .application {
		keys_ready = h.c_app_key.len > 0 && h.s_app_key.len > 0
		secrets_ready = h.c_app_tsec.len > 0 && h.s_app_tsec.len > 0
	}
	// The initial level has neither traffic secrets nor cached keys to sync.
	if keys_ready || !secrets_ready {
		return
	}
	if level == .handshake {
		ck := derive_traffic_key(h.hash_algo, h.c_hsk_tsec, h.key_len)!
		ci := derive_traffic_iv(h.hash_algo, h.c_hsk_tsec, aead_nonce_len)!
		sk := derive_traffic_key(h.hash_algo, h.s_hsk_tsec, h.key_len)!
		si := derive_traffic_iv(h.hash_algo, h.s_hsk_tsec, aead_nonce_len)!
		h.c_hsk_key = ck
		h.c_hsk_iv = ci
		h.s_hsk_key = sk
		h.s_hsk_iv = si
	} else {
		ck := derive_traffic_key(h.hash_algo, h.c_app_tsec, h.key_len)!
		ci := derive_traffic_iv(h.hash_algo, h.c_app_tsec, aead_nonce_len)!
		sk := derive_traffic_key(h.hash_algo, h.s_app_tsec, h.key_len)!
		si := derive_traffic_iv(h.hash_algo, h.s_app_tsec, aead_nonce_len)!
		h.c_app_key = ck
		h.c_app_iv = ci
		h.s_app_key = sk
		h.s_app_iv = si
	}
}

// sync_record_keys derives and caches record keys when the core exposes
// corresponding handshake or application traffic secrets.
fn (mut h TLSHandshake) sync_record_keys() ! {
	h.sync_keys_level(.handshake)!
	h.sync_keys_level(.application)!
}

// wipe_keys_at zeroes the cached client/server record key and IV for one level;
// the initial level has no cached keys. wipe_secret is the same scrub the secret
// fields use: zero the bytes, then drop the handle.
fn (mut h TLSHandshake) wipe_keys_at(level EncryptionLevel) {
	match level {
		.initial {}
		.handshake {
			wipe_secret(mut h.c_hsk_key)
			wipe_secret(mut h.c_hsk_iv)
			wipe_secret(mut h.s_hsk_key)
			wipe_secret(mut h.s_hsk_iv)
		}
		.application {
			wipe_secret(mut h.c_app_key)
			wipe_secret(mut h.c_app_iv)
			wipe_secret(mut h.s_app_key)
			wipe_secret(mut h.s_app_iv)
		}
	}
}

// wipe_record_keys_at zeroes one level's cached record keys (facade half of the
// zeroize_traffic_secrets override).
fn (mut h TLSHandshake) wipe_record_keys_at(level EncryptionLevel) {
	h.wipe_keys_at(level)
}

// wipe_record_keys clears all cached handshake and application record keys.
fn (mut h TLSHandshake) wipe_record_keys() {
	h.wipe_keys_at(.handshake)
	h.wipe_keys_at(.application)
}
