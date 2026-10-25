// Copyright (c) 2026 blackshirt.
//
// TLSHandshake is the TLS record adapter facade over shared handshake
// semantics. Record traffic keys and TLS KeyUpdate state live here.
module handshake

// RecordKeyPair caches the client/server record keys for one encryption level.
struct RecordKeyPair {
mut:
	client TrafficKeys // Keys for records sent by the client.
	server TrafficKeys // Keys for records received from the server.
}

// TLSHandshake exposes only operations needed by the TLS record layer.
@[noinit]
pub struct TLSHandshake {
	HandshakeCore
mut:
	hs_keys  RecordKeyPair // Cached record keys for the handshake level.
	app_keys RecordKeyPair // Cached record keys for the application level.
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
		h.fail_and_destroy_secrets()
		return err
	}
	return messages
}

// fail_and_destroy_secrets marks the handshake failed and wipes TLS secrets and
// all cached record keys. It does not close the TCP connection.
pub fn (mut h TLSHandshake) fail_and_destroy_secrets() {
	h.HandshakeCore.fail_and_destroy_secrets()
	h.wipe_record_keys()
}

// zeroize_app_secrets destroys application traffic secrets and cached record
// keys, for example when the connection is closed.
pub fn (mut h TLSHandshake) zeroize_app_secrets() ! {
	h.HandshakeCore.zeroize_app_secrets()!
	h.app_keys.wipe()
}

// record_traffic_keys returns independent copies of the cached client/server
// TrafficKeys at one TLS encryption level.
pub fn (h &TLSHandshake) record_traffic_keys(level EncryptionLevel) !(TrafficKeys, TrafficKeys) {
	match level {
		.initial {
			return error('handshake: initial level has no traffic keys')
		}
		.handshake {
			if h.hs_keys.client.key.len == 0 || h.hs_keys.server.key.len == 0 {
				return error('handshake: handshake traffic keys unavailable (available after ServerHello, dropped by zeroize_handshake_traffic_secrets)')
			}
			return clone_traffic_keys(h.hs_keys.client), clone_traffic_keys(h.hs_keys.server)
		}
		.application {
			if h.app_keys.client.key.len == 0 || h.app_keys.server.key.len == 0 {
				return error('handshake: application traffic keys unavailable before the server Finished')
			}
			return clone_traffic_keys(h.app_keys.client), clone_traffic_keys(h.app_keys.server)
		}
	}
}

// record_unconsumed_bytes reports buffered TLS handshake bytes at a level that
// have not yet formed a complete handshake message.
pub fn (h &TLSHandshake) record_unconsumed_bytes(level EncryptionLevel) int {
	return h.HandshakeCore.unconsumed_bytes(level)
}

// zeroize_handshake_traffic_secrets destroys handshake secrets and cached keys
// after the record adapter no longer needs them; only valid when connected.
pub fn (mut h TLSHandshake) zeroize_handshake_traffic_secrets() ! {
	h.HandshakeCore.zeroize_handshake_traffic_secrets()!
	h.hs_keys.wipe()
}

// record_update_read_traffic_keys ratchets the server application keys after
// receiving a TLS KeyUpdate (RFC 8446 §7.2); only valid once connected.
pub fn (mut h TLSHandshake) record_update_read_traffic_keys() ! {
	if h.state() != .connected {
		return error('handshake: cannot update server application traffic keys before the handshake is connected (state: ${h.state()})')
	}
	if h.server_ap_traffic.len == 0 {
		return error('handshake: cannot ratchet the server application traffic secret (unavailable before the server Finished, destroyed by zeroize_app_secrets)')
	}
	new_secret, next := ratchet_application_traffic(h.hash_algo, h.key_len, h.server_ap_traffic) or {
		h.fail_and_destroy_secrets()
		return err
	}
	wipe_secret(mut h.server_ap_traffic)
	h.server_ap_traffic = new_secret
	wipe_traffic_keys(mut h.app_keys.server)
	h.app_keys.server = next
}

// record_update_write_traffic_keys ratchets the client application keys before
// sending a TLS KeyUpdate (RFC 8446 §7.2); only valid once connected.
pub fn (mut h TLSHandshake) record_update_write_traffic_keys() ! {
	if h.state() != .connected {
		return error('handshake: cannot update client application traffic keys before the handshake is connected (state: ${h.state()})')
	}
	if h.client_ap_traffic.len == 0 {
		return error('handshake: cannot ratchet the client application traffic secret (unavailable before the server Finished, destroyed by zeroize_app_secrets)')
	}
	new_secret, next := ratchet_application_traffic(h.hash_algo, h.key_len, h.client_ap_traffic) or {
		h.fail_and_destroy_secrets()
		return err
	}
	wipe_secret(mut h.client_ap_traffic)
	h.client_ap_traffic = new_secret
	wipe_traffic_keys(mut h.app_keys.client)
	h.app_keys.client = next
}

// ratchet_application_traffic advances one application traffic secret with the
// TLS KeyUpdate "traffic upd" label and derives the next cached keys.
fn ratchet_application_traffic(hash_algo HashAlgorithm, key_len int, secret []u8) !([]u8, TrafficKeys) {
	new_secret := hkdf_expand_label(hash_algo, secret, 'traffic upd', []u8{},
		hash_algo.hash_len())!
	next := derive_traffic_keys(hash_algo, new_secret, key_len, aead_nonce_len)!
	return new_secret, next
}

// sync_record_keys derives and caches record keys when the core exposes
// corresponding handshake or application traffic secrets.
fn (mut h TLSHandshake) sync_record_keys() ! {
	if h.hs_keys.client.key.len == 0 && h.client_hs_traffic.len > 0 {
		h.hs_keys = derive_record_key_pair(h.hash_algo, h.client_hs_traffic,
			h.server_hs_traffic, h.key_len)!
	}
	if h.app_keys.client.key.len == 0 && h.client_ap_traffic.len > 0 {
		h.app_keys = derive_record_key_pair(h.hash_algo, h.client_ap_traffic,
			h.server_ap_traffic, h.key_len)!
	}
}

// derive_record_key_pair expands both directions of one encryption level.
fn derive_record_key_pair(hash_algo HashAlgorithm, client_secret []u8, server_secret []u8, key_len int) !RecordKeyPair {
	return RecordKeyPair{
		client: derive_traffic_keys(hash_algo, client_secret, key_len, aead_nonce_len)!
		server: derive_traffic_keys(hash_algo, server_secret, key_len, aead_nonce_len)!
	}
}

// wipe zeroes both directions of a cached record-key pair.
fn (mut keys RecordKeyPair) wipe() {
	wipe_traffic_keys(mut keys.client)
	wipe_traffic_keys(mut keys.server)
}

// wipe_record_keys clears all cached handshake and application record keys.
fn (mut h TLSHandshake) wipe_record_keys() {
	h.hs_keys.wipe()
	h.app_keys.wipe()
}

// clone_traffic_keys returns an independent copy of a traffic key and IV.
fn clone_traffic_keys(keys TrafficKeys) TrafficKeys {
	return TrafficKeys{
		key: keys.key.clone()
		iv:  keys.iv.clone()
	}
}
