// Copyright (c) 2026 blackshirt.
//
// secret_lifecycle.v owns wiping, zeroization and export of handshake traffic
// secrets across the core's lifecycle (RFC 8446 §1.3.1/§7.5).
module handshake

// wipe_handshake_traffic_secrets zeroes the client and server handshake traffic secrets.
fn (mut h HandshakeCore) wipe_handshake_traffic_secrets() {
	wipe_secret(mut h.client_hs_traffic)
	wipe_secret(mut h.server_hs_traffic)
}

// wipe_application_traffic_secrets zeroes the client and server application traffic secrets.
fn (mut h HandshakeCore) wipe_application_traffic_secrets() {
	wipe_secret(mut h.client_ap_traffic)
	wipe_secret(mut h.server_ap_traffic)
}

// wipe_all_secrets zeroes the key-schedule intermediate and every traffic secret.
fn (mut h HandshakeCore) wipe_all_secrets() {
	wipe_secret(mut h.handshake_secret)
	h.wipe_handshake_traffic_secrets()
	h.wipe_application_traffic_secrets()
}

// zeroize_handshake_traffic_secrets destroys the handshake traffic secrets once
// the adapter no longer needs them (RFC 8446 §7.5).
pub fn (mut h HandshakeCore) zeroize_handshake_traffic_secrets() ! {
	if h.state != .connected {
		return error('handshake: zeroize_handshake_traffic_secrets() runs only once the handshake reached .connected (state: ${h.state})')
	}
	h.wipe_handshake_traffic_secrets()
}

// traffic_secret_pair returns copies of the client and server traffic secrets
// for one encryption level; the initial level has no TLS traffic secrets.
fn (h &HandshakeCore) traffic_secret_pair(level EncryptionLevel) !([]u8, []u8) {
	match level {
		.initial {
			return error('handshake: initial level has no traffic secrets')
		}
		.handshake {
			if h.client_hs_traffic.len == 0 || h.server_hs_traffic.len == 0 {
				return error('handshake: handshake traffic secrets unavailable (available after ServerHello, dropped by zeroize_handshake_traffic_secrets)')
			}
			return h.client_hs_traffic.clone(), h.server_hs_traffic.clone()
		}
		.application {
			if h.client_ap_traffic.len == 0 || h.server_ap_traffic.len == 0 {
				return error('handshake: application traffic secrets unavailable before the server Finished')
			}
			return h.client_ap_traffic.clone(), h.server_ap_traffic.clone()
		}
	}
}

// fail_and_destroy_secrets wipes derived secrets and parks the state machine
// in .failed (RFC 8446 §1.3.1/§7.5).
pub fn (mut h HandshakeCore) fail_and_destroy_secrets() {
	h.wipe_all_secrets()
	h.plaintext_reassembly = []u8{}
	h.hs_reassembly = []u8{}
	h.priv_x25519 = unsafe { nil }
	h.priv_p256 = none
	h.state = .failed
}

// zeroize_handshake_secrets destroys the key-schedule intermediate and the dead
// ephemeral ECDHE halves at .connected (RFC 8446 §1.3.1/§7.5); it spares the handshake traffic secrets.
fn (mut h HandshakeCore) zeroize_handshake_secrets() {
	wipe_secret(mut h.handshake_secret)
	// Release the ephemeral private keys; compute_shared_secret, their only consumer, already ran.
	h.priv_x25519 = unsafe { nil }
	h.priv_p256 = none
}

// zeroize_app_secrets destroys the application traffic secrets once the
// connection is finished (RFC 8446 §1.3.1/§7.5).
pub fn (mut h HandshakeCore) zeroize_app_secrets() {
	h.wipe_application_traffic_secrets()
}
