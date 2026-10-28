// Copyright (c) 2026 blackshirt.
//
// TLSHandshake is the TLS record adapter facade over shared handshake semantics.
// The cached record keys, TLS KeyUpdate state, and the record-side reassembly
// backlog hooks live here — none has a QUIC caller, so none belongs to the core.
module handshake

// TLSHandshake exposes only operations needed by the TLS record layer.
@[noinit]
pub struct TLSHandshake {
	HandshakeCore
mut:
	// Cached record keys, one opaque generation per protection phase; each generation
	// holds one handle per direction, so a key never travels without its nonce base.
	hsk_keys HandshakeRecordKeys   // cached handshake-phase record keys
	app_keys ApplicationRecordKeys // cached application-phase record keys
}

// new_tls_handshake creates a TLS-over-records handshake facade.
// HandshakeOptions fields can be supplied as optional named arguments.
pub fn new_tls_handshake(server_name string, options HandshakeOptions) !TLSHandshake {
	return TLSHandshake{
		HandshakeCore: new_handshake_core(server_name, options, false)!
		hsk_keys:      HandshakeRecordKeys{}
		app_keys:      ApplicationRecordKeys{}
	}
}

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
// any complete outbound handshake messages triggered by the input. Module-private:
// the phase type is an implementation detail, so adapters call the phase-named
// receive_initial_bytes() / receive_handshake_bytes() below, which add the same
// TLS record-key sync and failure wipe.
fn (mut h TLSHandshake) receive_msgs_at_level(level EncryptionLevel, bytes []u8) ![]HandshakeMessage {
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

// receive_initial_bytes feeds pre-ServerHello (plaintext) handshake bytes.
pub fn (mut h TLSHandshake) receive_initial_bytes(bytes []u8) ![]HandshakeMessage {
	return h.receive_msgs_at_level(.initial, bytes)!
}

// receive_handshake_bytes feeds bytes protected by the handshake traffic keys.
pub fn (mut h TLSHandshake) receive_handshake_bytes(bytes []u8) ![]HandshakeMessage {
	return h.receive_msgs_at_level(.handshake, bytes)!
}

// initial_backlog reports bytes the core's initial-phase reassembly retained after
// complete TLS messages were consumed. Record-path scope: only the TLS adapter
// enforces the §5.1 ServerHello record-boundary rule; QUIC frames its own CRYPTO stream.
pub fn (h &TLSHandshake) initial_backlog() int {
	return h.buffers.len(.initial)
}

// handshake_backlog reports bytes the core's handshake-phase reassembly retained —
// the drain check the record adapter runs once the encrypted flight is consumed.
pub fn (h &TLSHandshake) handshake_backlog() int {
	return h.buffers.len(.handshake)
}

// take_buffered_handshake_bytes moves whatever the core's drain_at() left buffered at
// .connected (legal only per RFC 8446 §4.6.1 coalescing) to the record adapter,
// zeroizing the core's copy (§7.5).
pub fn (mut h TLSHandshake) take_buffered_handshake_bytes() []u8 {
	return h.buffers.take_handshake()
}

// handshake_record_keys returns an independent copy of the cached handshake generation
// for the record layer to install. The handle is opaque and caller-owned: drain it with
// take_client() / take_server(), which move each pair out, and wipe() whatever is left,
// so no copy of the key material escapes unscrubbed (§7.5). The initial phase has no
// record keys and no accessor either, so asking for it is not expressible rather than
// refused.
pub fn (h &TLSHandshake) handshake_record_keys() !HandshakeRecordKeys {
	if !h.hsk_keys.ready() {
		return error('handshake: handshake traffic keys unavailable (available after ServerHello, dropped by zeroize_handshake_secrets())')
	}
	return h.hsk_keys.copies()
}

// application_record_keys returns an independent copy of the cached application
// generation — the pair a KeyUpdate re-keys — under the same ownership rule as
// handshake_record_keys(): the taker scrubs what it reads and wipes the rest.
pub fn (h &TLSHandshake) application_record_keys() !ApplicationRecordKeys {
	if !h.app_keys.ready() {
		return error('handshake: application traffic keys unavailable before the server Finished')
	}
	return h.app_keys.copies()
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

// fail_and_zeroize_secrets marks the handshake failed and wipes TLS secrets and
// all cached record keys. It does not close the TCP connection.
pub fn (mut h TLSHandshake) fail_and_zeroize_secrets() {
	h.HandshakeCore.fail_and_zeroize_secrets()
	h.wipe_record_keys()
}

// zeroize_traffic_secrets_at destroys the traffic secrets for one encryption level
// plus that level's cached record keys; valid only after .connected (core guard)
// and the initial level is refused. Module-private: adapters call the phase-named
// zeroize_handshake_secrets() / zeroize_application_secrets() below.
fn (mut h TLSHandshake) zeroize_traffic_secrets_at(level EncryptionLevel) ! {
	h.HandshakeCore.zeroize_traffic_secrets_at(level)!
	h.wipe_record_keys_at(level)
}

// zeroize_handshake_secrets drops the handshake traffic secrets and this facade's
// cached handshake record keys once the record adapter no longer needs them (§7.5).
pub fn (mut h TLSHandshake) zeroize_handshake_secrets() ! {
	h.zeroize_traffic_secrets_at(.handshake)!
}

// zeroize_application_secrets drops the application traffic secrets and this
// facade's cached application record keys — the terminal teardown at close() (§7.5).
pub fn (mut h TLSHandshake) zeroize_application_secrets() ! {
	h.zeroize_traffic_secrets_at(.application)!
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
fn (mut h TLSHandshake) sync_hsk_keys() ! {
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
fn (mut h TLSHandshake) sync_app_keys() ! {
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
// corresponding handshake or application traffic secrets.
fn (mut h TLSHandshake) sync_record_keys() ! {
	h.sync_hsk_keys()!
	h.sync_app_keys()!
}

// wipe_record_keys_at zeroes one level's cached record keys (facade half of the
// zeroize_traffic_secrets_at override). wipe() is the same scrub the secret fields
// use — zero the bytes, then drop the handle — applied to a whole generation; the
// initial level never has cached keys.
fn (mut h TLSHandshake) wipe_record_keys_at(level EncryptionLevel) {
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
fn (mut h TLSHandshake) wipe_record_keys() {
	h.wipe_record_keys_at(.handshake)
	h.wipe_record_keys_at(.application)
}
