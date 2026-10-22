// Copyright (c) 2026 blackshirt.
//
// RecordHandshaker is the TLS record adapter facade over shared handshake
// semantics. Record traffic keys and TLS KeyUpdate state live here.
module handshake

import tls.pki

// RecordHandshaker exposes only operations needed by the TLS record layer.
@[noinit]
pub struct RecordHandshaker {
	HandshakeCore
mut:
	client_hs_keys  TrafficKeys
	server_hs_keys  TrafficKeys
	client_app_keys TrafficKeys
	server_app_keys TrafficKeys
}

// new_record_handshake creates a TLS 1.3 record-layer handshaker.
pub fn new_record_handshake(server_name string, alpn []string, validator pki.Validator) !RecordHandshaker {
	return RecordHandshaker{
		HandshakeCore: new_handshake_core(server_name, alpn, validator)!
	}
}

pub fn (mut h RecordHandshaker) receive(level HandshakeLevel, bytes []u8) ![]HandshakeMessage {
	messages := h.HandshakeCore.receive(level, bytes) or {
		if h.state() == .failed {
			h.wipe_record_keys()
		}
		return err
	}
	h.sync_record_keys() or {
		h.fail_and_destroy_secrets()
		return err
	}
	return messages
}

pub fn (mut h RecordHandshaker) fail_and_destroy_secrets() {
	h.HandshakeCore.fail_and_destroy_secrets()
	h.wipe_record_keys()
}

pub fn (mut h RecordHandshaker) zeroize_app_secrets() {
	h.HandshakeCore.zeroize_app_secrets()
	h.wipe_application_keys()
}

// record_traffic_keys returns independent copies of the cached client/server
// TrafficKeys at one TLS encryption level.
pub fn (h &RecordHandshaker) record_traffic_keys(level TrafficSecretLevel) !(TrafficKeys, TrafficKeys) {
	match level {
		.handshake {
			if h.client_hs_keys.key.len == 0 || h.server_hs_keys.key.len == 0 {
				return error('handshake: handshake traffic keys unavailable (available after ServerHello, dropped by on_handshake_confirmed)')
			}
			return clone_traffic_keys(h.client_hs_keys), clone_traffic_keys(h.server_hs_keys)
		}
		.application {
			if h.client_app_keys.key.len == 0 || h.server_app_keys.key.len == 0 {
				return error('handshake: application traffic keys unavailable before the server Finished')
			}
			return clone_traffic_keys(h.client_app_keys), clone_traffic_keys(h.server_app_keys)
		}
	}
}

pub fn (h &RecordHandshaker) record_unconsumed_bytes(level HandshakeLevel) int {
	return h.HandshakeCore.unconsumed_bytes(level)
}

pub fn (mut h RecordHandshaker) on_handshake_confirmed() ! {
	h.HandshakeCore.on_handshake_confirmed()!
	wipe_traffic_keys(mut h.client_hs_keys)
	wipe_traffic_keys(mut h.server_hs_keys)
}

// record_update_read_traffic_keys ratchets the server application keys after
// receiving a TLS KeyUpdate (RFC 8446 §7.2).
pub fn (mut h RecordHandshaker) record_update_read_traffic_keys() ! {
	if h.server_ap_traffic.len == 0 {
		return error('handshake: cannot ratchet the server application traffic secret (unavailable before the server Finished, destroyed by zeroize_app_secrets)')
	}
	new_secret := hkdf_expand_label(h.hash_algo, h.server_ap_traffic, 'traffic upd', []u8{},
		h.hash_algo.hash_len())!
	next := derive_traffic_keys(h.hash_algo, new_secret, h.key_len, aead_nonce_len) or {
		h.fail_and_destroy_secrets()
		return err
	}
	wipe_secret(mut h.server_ap_traffic)
	h.server_ap_traffic = new_secret
	wipe_traffic_keys(mut h.server_app_keys)
	h.server_app_keys = next
}

// record_update_write_traffic_keys ratchets the client application keys before
// sending a TLS KeyUpdate (RFC 8446 §7.2).
pub fn (mut h RecordHandshaker) record_update_write_traffic_keys() ! {
	if h.client_ap_traffic.len == 0 {
		return error('handshake: cannot ratchet the client application traffic secret (unavailable before the server Finished, destroyed by zeroize_app_secrets)')
	}
	new_secret := hkdf_expand_label(h.hash_algo, h.client_ap_traffic, 'traffic upd', []u8{},
		h.hash_algo.hash_len())!
	next := derive_traffic_keys(h.hash_algo, new_secret, h.key_len, aead_nonce_len) or {
		h.fail_and_destroy_secrets()
		return err
	}
	wipe_secret(mut h.client_ap_traffic)
	h.client_ap_traffic = new_secret
	wipe_traffic_keys(mut h.client_app_keys)
	h.client_app_keys = next
}

fn (mut h RecordHandshaker) sync_record_keys() ! {
	if h.client_hs_keys.key.len == 0 && h.client_hs_traffic.len > 0 {
		client_keys := derive_traffic_keys(h.hash_algo, h.client_hs_traffic, h.key_len,
			aead_nonce_len)!
		server_keys := derive_traffic_keys(h.hash_algo, h.server_hs_traffic, h.key_len,
			aead_nonce_len)!
		h.client_hs_keys = client_keys
		h.server_hs_keys = server_keys
	}
	if h.client_app_keys.key.len == 0 && h.client_ap_traffic.len > 0 {
		client_keys := derive_traffic_keys(h.hash_algo, h.client_ap_traffic, h.key_len,
			aead_nonce_len)!
		server_keys := derive_traffic_keys(h.hash_algo, h.server_ap_traffic, h.key_len,
			aead_nonce_len)!
		h.client_app_keys = client_keys
		h.server_app_keys = server_keys
	}
}

fn (mut h RecordHandshaker) wipe_record_keys() {
	wipe_traffic_keys(mut h.client_hs_keys)
	wipe_traffic_keys(mut h.server_hs_keys)
	h.wipe_application_keys()
}

fn (mut h RecordHandshaker) wipe_application_keys() {
	wipe_traffic_keys(mut h.client_app_keys)
	wipe_traffic_keys(mut h.server_app_keys)
}

fn clone_traffic_keys(keys TrafficKeys) TrafficKeys {
	return TrafficKeys{
		key: keys.key.clone()
		iv:  keys.iv.clone()
	}
}

fn wipe_secret(mut secret []u8) {
	for i in 0 .. secret.len {
		secret[i] = 0
	}
	secret = []u8{}
}

fn wipe_traffic_keys(mut keys TrafficKeys) {
	for i in 0 .. keys.key.len {
		keys.key[i] = 0
	}
	for i in 0 .. keys.iv.len {
		keys.iv[i] = 0
	}
	keys = TrafficKeys{}
}
