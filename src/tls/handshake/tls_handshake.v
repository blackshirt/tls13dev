// Copyright (c) 2026 blackshirt.
//
// TLSHandshake is the TLS record adapter facade over shared handshake
// semantics. Record traffic keys and TLS KeyUpdate state live here.
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

// record_unconsumed_bytes reports buffered TLS handshake bytes at a level that
// have not yet formed a complete handshake message.
pub fn (h &TLSHandshake) record_unconsumed_bytes(level EncryptionLevel) int {
	return h.HandshakeCore.unconsumed_bytes(level)
}

// take_buffered_handshake_bytes transfers the bytes the core left buffered after
// .connected (a NewSessionTicket coalesced behind the server's Finished, §4.6.1)
// into the record adapter's post-handshake reassembler; the core's copy is
// zeroized.
pub fn (mut h TLSHandshake) take_buffered_handshake_bytes() []u8 {
	return h.HandshakeCore.take_buffered_handshake_bytes()
}

// record_update_read_traffic_keys updates the server application traffic keys
// after receiving a TLS KeyUpdate (RFC 8446 §7.2); only valid once connected.
pub fn (mut h TLSHandshake) record_update_read_traffic_keys() ! {
	h.update_app_traffic_keys(true)!
}

// record_update_write_traffic_keys updates the client application traffic keys
// before sending a TLS KeyUpdate (RFC 8446 §7.2); only valid once connected.
pub fn (mut h TLSHandshake) record_update_write_traffic_keys() ! {
	h.update_app_traffic_keys(false)!
}

// update_app_traffic_keys derives the next application traffic secret and its
// cached keys for one direction after a TLS KeyUpdate. The read and write legs
// are the same routine over different secret/keys field pairs, so they share this
// body: is_server selects the pair and the direction word in the two guards.
fn (mut h TLSHandshake) update_app_traffic_keys(is_server bool) ! {
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

// derive_updated_traffic_keys performs the TLS KeyUpdate "traffic upd" derivation:
// the next application traffic secret from the current one, then its cached keys.
fn derive_updated_traffic_keys(hash_algo HashAlgorithm, key_len int, secret []u8) !([]u8, TrafficKeys) {
	new_secret := hkdf_expand_label(hash_algo, secret, 'traffic upd', []u8{},
		hash_algo.hash_len())!
	next := derive_traffic_keys(hash_algo, new_secret, key_len, aead_nonce_len)!
	return new_secret, next
}

// sync_record_keys derives and caches record keys when the core exposes
// corresponding handshake or application traffic secrets. The client key of each
// level doubles as the derived-once marker, so each level expands exactly once.
// Both directions are derived before either field is written, so a derivation
// failure can never leave a level half-installed (matches the old atomic commit).
fn (mut h TLSHandshake) sync_record_keys() ! {
	if h.client_hsk_keys.key.len == 0 && h.client_hsk_traffic.len > 0 {
		ck := derive_traffic_keys(h.hash_algo, h.client_hsk_traffic, h.key_len, aead_nonce_len)!
		sk := derive_traffic_keys(h.hash_algo, h.server_hsk_traffic, h.key_len, aead_nonce_len)!
		h.client_hsk_keys = ck
		h.server_hsk_keys = sk
	}
	if h.client_app_keys.key.len == 0 && h.client_app_traffic.len > 0 {
		ck := derive_traffic_keys(h.hash_algo, h.client_app_traffic, h.key_len, aead_nonce_len)!
		sk := derive_traffic_keys(h.hash_algo, h.server_app_traffic, h.key_len, aead_nonce_len)!
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
