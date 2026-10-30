// Copyright (c) 2026 blackshirt.
//
// core_record.v holds the TLS-record side of the unified HandshakeCore: the cached
// record keys, the TLS KeyUpdate derivation, and the record-side backlog hooks.
// Every entry point here is guarded by is_quic — a QUIC-mode core refuses it with a
// plain error, without touching state or keys, mirroring the out-of-phase guards.
module handshake

// initial_backlog reports bytes the initial-phase reassembly retained after
// complete TLS messages were consumed. TLS-record scope: only the record adapter
// enforces the §5.1 ServerHello record-boundary rule; QUIC frames its own CRYPTO
// stream, so the accessor refuses a QUIC-mode core.
pub fn (h &HandshakeCore) initial_backlog() !int {
	if h.is_quic {
		return error('handshake: initial_backlog() is TLS-record-only (QUIC frames its own CRYPTO stream)')
	}
	return h.buffers.len(.initial)
}

// handshake_backlog reports bytes the handshake-phase reassembly retained — the
// drain check the record adapter runs once the encrypted flight is consumed.
pub fn (h &HandshakeCore) handshake_backlog() !int {
	if h.is_quic {
		return error('handshake: handshake_backlog() is TLS-record-only (QUIC frames its own CRYPTO stream)')
	}
	return h.buffers.len(.handshake)
}

// take_buffered_handshake_bytes moves whatever drain_at() left buffered at
// .connected (legal only per RFC 8446 §4.6.1 coalescing) to the record adapter,
// zeroizing the core's copy (§7.5).
pub fn (mut h HandshakeCore) take_buffered_handshake_bytes() ![]u8 {
	if h.is_quic {
		return error('handshake: take_buffered_handshake_bytes() is TLS-record-only (QUIC reassembles its own CRYPTO stream)')
	}
	return h.buffers.take_handshake()
}

// handshake_record_keys returns an independent copy of the cached handshake generation
// for the record layer to install. The handle is opaque and caller-owned: drain it with
// take_client() / take_server(), which move each pair out, and wipe() whatever is left,
// so no copy of the key material escapes unscrubbed (§7.5). The initial phase has no
// record keys and no accessor either, so asking for it is not expressible rather than
// refused.
pub fn (h &HandshakeCore) handshake_record_keys() !HandshakeRecordKeys {
	if h.is_quic {
		return error('handshake: handshake_record_keys() is TLS-record-only (QUIC derives packet keys from peer_handshake_secrets())')
	}
	if !h.hsk_keys.ready() {
		return error('handshake: handshake traffic keys unavailable (available after ServerHello, dropped by zeroize_handshake_secrets())')
	}
	return h.hsk_keys.copies()
}

// application_record_keys returns an independent copy of the cached application
// generation — the pair a KeyUpdate re-keys — under the same ownership rule as
// handshake_record_keys(): the taker scrubs what it reads and wipes the rest.
pub fn (h &HandshakeCore) application_record_keys() !ApplicationRecordKeys {
	if h.is_quic {
		return error('handshake: application_record_keys() is TLS-record-only (QUIC derives packet keys from peer_application_secrets())')
	}
	if !h.app_keys.ready() {
		return error('handshake: application traffic keys unavailable before the server Finished')
	}
	return h.app_keys.copies()
}

// update_traffic_keys updates one direction's application traffic keys around a
// TLS KeyUpdate (RFC 8446 §7.2); TLS-record-only, and valid only once connected.
// is_server selects the read leg (server keys, after receiving) vs the write leg
// (client keys, before sending). The two legs are the same routine over different
// secret/keys field pairs, so they share this body: is_server selects the pair
// and the direction word in the two guards.
pub fn (mut h HandshakeCore) update_traffic_keys(is_server bool) ! {
	if h.is_quic {
		return error('handshake: update_traffic_keys() is TLS-record-only (QUIC key updates live in the packet layer)')
	}
	side := if is_server { 'server' } else { 'client' }
	if h.state() != .connected {
		return error('handshake: cannot update ${side} application traffic keys before the handshake is connected (state: ${h.state()})')
	}
	secret := if is_server { h.s_app_tsec } else { h.c_app_tsec }
	if secret.len == 0 {
		return error('handshake: cannot update the ${side} application traffic secret (unavailable before the server Finished, destroyed by zeroize_application_secrets())')
	}
	next_secret, next_key, next_iv := derive_updated_traffic_keys(h.hash_algo, h.key_len, secret) or {
		h.fail_and_zeroize_secrets()
		return err
	}
	// Each leg replaces its whole key handle, so the pair cannot be updated
	// asymmetrically. The superseded generation is zeroed in place before its handle is
	// rebound, which is what lets an adapter aliasing the old bytes observe the zeros.
	if is_server {
		wipe_secret(mut h.s_app_tsec)
		h.s_app_tsec = next_secret
		h.app_keys.server.wipe()
		h.app_keys.server = RecordKeys{
			key: next_key
			iv:  next_iv
		}
	} else {
		wipe_secret(mut h.c_app_tsec)
		h.c_app_tsec = next_secret
		h.app_keys.client.wipe()
		h.app_keys.client = RecordKeys{
			key: next_key
			iv:  next_iv
		}
	}
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

// sync_hsk_keys expands the handshake traffic secrets into the cached handshake
// generation exactly once; a complete generation or absent secrets both
// short-circuit (§7.1). All four key and IV values are derived into locals before the
// generation is assigned, so a failure can never leave the phase half-installed — the
// same atomicity sync_record_keys relies on.
fn (mut h HandshakeCore) sync_hsk_keys() ! {
	if h.hsk_keys.ready() || h.c_hsk_tsec.len == 0 || h.s_hsk_tsec.len == 0 {
		return
	}
	ck := derive_traffic_key(h.hash_algo, h.c_hsk_tsec, h.key_len)!
	ci := derive_traffic_iv(h.hash_algo, h.c_hsk_tsec, aead_nonce_len)!
	sk := derive_traffic_key(h.hash_algo, h.s_hsk_tsec, h.key_len)!
	si := derive_traffic_iv(h.hash_algo, h.s_hsk_tsec, aead_nonce_len)!
	client := RecordKeys{
		key: ck
		iv:  ci
	}
	server := RecordKeys{
		key: sk
		iv:  si
	}
	h.hsk_keys = HandshakeRecordKeys{
		client: client
		server: server
	}
}

// sync_app_keys is the application-phase twin of sync_hsk_keys, over the secrets a
// KeyUpdate later chains from.
fn (mut h HandshakeCore) sync_app_keys() ! {
	if h.app_keys.ready() || h.c_app_tsec.len == 0 || h.s_app_tsec.len == 0 {
		return
	}
	ck := derive_traffic_key(h.hash_algo, h.c_app_tsec, h.key_len)!
	ci := derive_traffic_iv(h.hash_algo, h.c_app_tsec, aead_nonce_len)!
	sk := derive_traffic_key(h.hash_algo, h.s_app_tsec, h.key_len)!
	si := derive_traffic_iv(h.hash_algo, h.s_app_tsec, aead_nonce_len)!
	client := RecordKeys{
		key: ck
		iv:  ci
	}
	server := RecordKeys{
		key: sk
		iv:  si
	}
	h.app_keys = ApplicationRecordKeys{
		client: client
		server: server
	}
}

// sync_record_keys derives and caches record keys when the core exposes
// corresponding handshake or application traffic secrets. Called only on the
// TLS-record receive path, behind the is_quic branch.
fn (mut h HandshakeCore) sync_record_keys() ! {
	h.sync_hsk_keys()!
	h.sync_app_keys()!
}

// wipe_record_keys_at zeroes one level's cached record keys. wipe() is the same
// scrub the secret fields use — zero the bytes, then drop the handle — applied to a
// whole generation; the initial level never has cached keys.
fn (mut h HandshakeCore) wipe_record_keys_at(level EncryptionLevel) {
	match level {
		.initial {}
		.handshake {
			h.hsk_keys.wipe()
		}
		.application {
			h.app_keys.wipe()
		}
	}
}

// wipe_record_keys zeroes both cached generations through the level accessor, so
// what wiping a level means is defined in exactly one place.
fn (mut h HandshakeCore) wipe_record_keys() {
	h.wipe_record_keys_at(.handshake)
	h.wipe_record_keys_at(.application)
}
