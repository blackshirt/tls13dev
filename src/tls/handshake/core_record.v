// Copyright (c) 2026 blackshirt.
//
// core_record.v holds the TLS-record side of the unified HandshakeCore: the record keys
// derived on demand from the retained traffic secrets, the TLS KeyUpdate ratchet, and the
// record-side backlog hooks.
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

// take_buffered_handshake_bytes moves whatever consume_msgs_at() left buffered at
// .connected (legal only per RFC 8446 §4.6.1 coalescing) to the record adapter,
// zeroizing the core's copy (§7.5).
pub fn (mut h HandshakeCore) take_buffered_handshake_bytes() ![]u8 {
	if h.is_quic {
		return error('handshake: take_buffered_handshake_bytes() is TLS-record-only (QUIC reassembles its own CRYPTO stream)')
	}
	return h.buffers.take_handshake()
}

// handshake_traffic_keys derives the handshake-phase record-key generation on demand
// from the retained handshake traffic secrets and returns it for the record layer to
// install. Each call yields a fresh, caller-owned generation: drain it with take_client_keypair()
// / take_server_keypair(), which move each pair out, and wipe() whatever is left, so no copy of
// the key material escapes unscrubbed (§7.5). The initial phase has no record keys and no
// accessor either, so asking for it is not expressible rather than refused.
pub fn (h &HandshakeCore) handshake_traffic_keys() !TrafficKeys {
	if h.is_quic {
		return error('handshake: handshake_traffic_keys() is TLS-record-only (QUIC derives packet keys from peer_handshake_secrets())')
	}
	if h.c_hsk_tsec.len == 0 || h.s_hsk_tsec.len == 0 {
		return error('handshake: handshake traffic keys unavailable (available after ServerHello, dropped by zeroize_handshake_secrets())')
	}
	ck := derive_traffic_key(h.hash_algo, h.c_hsk_tsec, h.key_len)!
	ci := derive_traffic_iv(h.hash_algo, h.c_hsk_tsec, aead_nonce_len)!
	sk := derive_traffic_key(h.hash_algo, h.s_hsk_tsec, h.key_len)!
	si := derive_traffic_iv(h.hash_algo, h.s_hsk_tsec, aead_nonce_len)!
	return TrafficKeys{
		client: KeyPair{
			key: ck
			iv:  ci
		}
		server: KeyPair{
			key: sk
			iv:  si
		}
	}
}

// application_traffic_keys derives the application-phase generation — the pair a
// KeyUpdate re-keys — on demand from the retained application traffic secrets, under the
// same ownership rule as handshake_traffic_keys(): the taker scrubs what it reads and
// wipes the rest.
pub fn (h &HandshakeCore) application_traffic_keys() !TrafficKeys {
	if h.is_quic {
		return error('handshake: application_traffic_keys() is TLS-record-only (QUIC derives packet keys from peer_application_secrets())')
	}
	if h.c_app_tsec.len == 0 || h.s_app_tsec.len == 0 {
		return error('handshake: application traffic keys unavailable before the server Finished')
	}
	ck := derive_traffic_key(h.hash_algo, h.c_app_tsec, h.key_len)!
	ci := derive_traffic_iv(h.hash_algo, h.c_app_tsec, aead_nonce_len)!
	sk := derive_traffic_key(h.hash_algo, h.s_app_tsec, h.key_len)!
	si := derive_traffic_iv(h.hash_algo, h.s_app_tsec, aead_nonce_len)!
	return TrafficKeys{
		client: KeyPair{
			key: ck
			iv:  ci
		}
		server: KeyPair{
			key: sk
			iv:  si
		}
	}
}

// update_traffic_keys ratchets one direction's application traffic secret around a
// TLS KeyUpdate (RFC 8446 §7.2); TLS-record-only, and valid only once connected.
// is_server_leg selects the server→client read leg (true, after receiving) vs the
// client→server write leg (false, before sending). Only the secret is stored:
// application_traffic_keys() re-derives the record-key generation from it on the next
// call, so the two legs never update asymmetrically and no superseded key handle is
// left to scrub.
pub fn (mut h HandshakeCore) update_traffic_keys(is_server_leg bool) ! {
	if h.is_quic {
		return error('handshake: update_traffic_keys() is TLS-record-only (QUIC key updates live in the packet layer)')
	}
	side := if is_server_leg { 'server' } else { 'client' }
	if h.state() != .connected {
		return error('handshake: cannot update ${side} application traffic keys before the handshake is connected (state: ${h.state()})')
	}
	secret := if is_server_leg { h.s_app_tsec } else { h.c_app_tsec }
	if secret.len == 0 {
		return error('handshake: cannot update the ${side} application traffic secret (unavailable before the server Finished, destroyed by zeroize_application_secrets())')
	}
	next_secret := derive_updated_traffic_secret(h.hash_algo, secret) or {
		h.fail_and_zeroize_secrets()
		return err
	}
	// The superseded secret is zeroed in place before its field is rebound, which is
	// what lets an adapter aliasing the old bytes observe the zeros.
	if is_server_leg {
		wipe_secret(mut h.s_app_tsec)
		h.s_app_tsec = next_secret
	} else {
		wipe_secret(mut h.c_app_tsec)
		h.c_app_tsec = next_secret
	}
}

// derive_updated_traffic_secret performs the TLS KeyUpdate "traffic upd" derivation:
// the next application traffic secret from the current one. The record key and IV are
// derived from it on demand by application_traffic_keys(), not here.
fn derive_updated_traffic_secret(hash_algo HashAlgorithm, secret []u8) ![]u8 {
	return hkdf_expand_label(hash_algo, secret, 'traffic upd', []u8{}, hash_algo.hash_len())!
}
