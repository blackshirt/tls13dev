// Copyright (c) 2026 blackshirt.
//
// secret_lifecycle.v owns wiping, zeroization and export of handshake traffic
// secrets across the core's lifecycle (RFC 8446 §1.3.1/§7.5).
module handshake

// wipe_traffic_secrets zeroes the client and server traffic secrets for one
// encryption level; the initial level has no TLS traffic secrets. It mirrors the
// level-parameterized traffic_secret_pair() accessor so reads and wipes share the
// same phase vocabulary.
fn (mut h HandshakeCore) wipe_traffic_secrets(level EncryptionLevel) {
	match level {
		.handshake {
			wipe_secret(mut h.client_hsk_traffic)
			wipe_secret(mut h.server_hsk_traffic)
		}
		.application {
			wipe_secret(mut h.client_app_traffic)
			wipe_secret(mut h.server_app_traffic)
		}
		.initial {}
	}
}

// wipe_all_secrets zeroes the key-schedule intermediate and every traffic secret.
fn (mut h HandshakeCore) wipe_all_secrets() {
	wipe_secret(mut h.handshake_secret)
	h.wipe_traffic_secrets(.handshake)
	h.wipe_traffic_secrets(.application)
}

// zeroize_traffic_secrets destroys the client and server traffic secrets for one
// encryption level (and, on the record facade, that level's cached record keys)
// once the adapter no longer needs them; it is valid only after .connected, and
// the initial level — which has no TLS traffic secrets — is refused (RFC 8446 §7.5).
pub fn (mut h HandshakeCore) zeroize_traffic_secrets(level EncryptionLevel) ! {
	match level {
		.initial {
			return error('handshake: initial level has no traffic secrets to zeroize')
		}
		.handshake, .application {
			if h.state != .connected {
				return error('handshake: zeroize_traffic_secrets(${level}) is only valid once the handshake reaches .connected (state: ${h.state})')
			}
			h.wipe_traffic_secrets(level)
		}
	}
}

// traffic_secret_pair returns copies of the client and server traffic secrets
// for one encryption level; the initial level has no TLS traffic secrets.
fn (h &HandshakeCore) traffic_secret_pair(level EncryptionLevel) !([]u8, []u8) {
	match level {
		.initial {
			return error('handshake: initial level has no traffic secrets')
		}
		.handshake {
			if h.client_hsk_traffic.len == 0 || h.server_hsk_traffic.len == 0 {
				return error('handshake: handshake traffic secrets unavailable (available after ServerHello, dropped by zeroize_traffic_secrets(.handshake))')
			}
			return h.client_hsk_traffic.clone(), h.server_hsk_traffic.clone()
		}
		.application {
			if h.client_app_traffic.len == 0 || h.server_app_traffic.len == 0 {
				return error('handshake: application traffic secrets unavailable before the server Finished')
			}
			return h.client_app_traffic.clone(), h.server_app_traffic.clone()
		}
	}
}

// release_ephemeral_keys drops both ephemeral ECDHE private halves. The vlib key
// types expose no in-place wipe, so releasing the handles is the available
// destruction; fail_and_zeroize_secrets() and wipe_key_schedule_secrets() must
// release them identically (§7.5), so they share this single site.
fn (mut h HandshakeCore) release_ephemeral_keys() {
	h.priv_x25519 = unsafe { nil }
	h.priv_p256 = none
}

// fail_and_zeroize_secrets wipes derived secrets and parks the state machine
// in .failed (RFC 8446 §1.3.1/§7.5).
pub fn (mut h HandshakeCore) fail_and_zeroize_secrets() {
	h.wipe_all_secrets()
	h.init_buf = []u8{}
	h.hsk_buf = []u8{}
	h.release_ephemeral_keys()
	h.state = .failed
}

// wipe_key_schedule_secrets destroys the key-schedule intermediate and the dead
// ephemeral ECDHE halves at .connected (RFC 8446 §1.3.1/§7.5); it spares the handshake traffic secrets.
fn (mut h HandshakeCore) wipe_key_schedule_secrets() {
	wipe_secret(mut h.handshake_secret)
	// Release the ephemeral private keys; compute_shared_secret, their only consumer, already ran.
	h.release_ephemeral_keys()
}
