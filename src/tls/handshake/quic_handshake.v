// Copyright (c) 2026 blackshirt.
//
// QuicHandshake is the QUIC adapter facade over shared TLS handshake
// semantics. QUIC derives packet protection from the exported traffic secrets,
// so the raw-secret accessors peer_handshake_secrets() / peer_application_secrets()
// live here: the record facade caches flat record-key fields instead and has no
// caller for them.
module handshake

// QuicHandshake exposes only operations needed by a QUIC adapter.
@[noinit]
pub struct QuicHandshake {
	HandshakeCore
}

// new_quic_handshake creates a QUIC handshaker. HandshakeOptions fields can
// be supplied as optional named arguments after server_name.
pub fn new_quic_handshake(server_name string, options HandshakeOptions) !QuicHandshake {
	return QuicHandshake{
		HandshakeCore: new_handshake_core(server_name, options, true)!
	}
}

// Curated forwarders. HandshakeCore is an internal type and all its methods are
// module-private, so nothing reaches QUIC through embedded-field promotion; the
// engine sees only these entry points, each delegating to the core by an
// explicit qualified call (never h.X(), which would resolve back to the
// forwarder and recurse). The phase-named secret/teardown accessors, plus
// peer_transport_parameters/hello_retry_request_received below, stay QUIC-only
// seams; the EncryptionLevel the private bodies route on never crosses here.

// state reports the handshake position; the engine polls it to know when the
// handshake completed.
pub fn (h &QuicHandshake) state() HandshakeState {
	return h.HandshakeCore.state()
}

// negotiated_alpn returns the ALPN protocol the server picked ('' when none).
pub fn (h &QuicHandshake) negotiated_alpn() string {
	return h.HandshakeCore.negotiated_alpn()
}

// negotiated_cipher_suite reports the suite selected by the server in ServerHello.
pub fn (h &QuicHandshake) negotiated_cipher_suite() CipherSuite {
	return h.HandshakeCore.negotiated_cipher_suite()
}

// failure_alert returns the alert the adapter surfaces when the handshake dies (§6).
pub fn (h &QuicHandshake) failure_alert() AlertDescription {
	return h.HandshakeCore.failure_alert()
}

// available_secret_phases reports which traffic-secret phases the core holds.
pub fn (h &QuicHandshake) available_secret_phases() SecretPhases {
	return h.HandshakeCore.available_secret_phases()
}

// create_client_hello generates the initial ClientHello bytes (RFC 8446 App. D.4).
pub fn (mut h QuicHandshake) create_client_hello() ![]u8 {
	return h.HandshakeCore.create_client_hello()!
}

// receive_msgs_at_level feeds CRYPTO-stream bytes at one level and returns the
// outbound messages they complete; QUIC drives the core drain directly, since
// TLSHandshake.receive_msgs_at_level adds the TLS-only record-key sync on top.
// Module-private: the engine uses the phase-named receive_initial_bytes() /
// receive_handshake_bytes() below.
fn (mut h QuicHandshake) receive_msgs_at_level(level EncryptionLevel, bytes []u8) ![]HandshakeMessage {
	return h.HandshakeCore.receive_msgs_at_level(level, bytes)!
}

// receive_initial_bytes feeds Initial-packet CRYPTO bytes (pre-ServerHello).
pub fn (mut h QuicHandshake) receive_initial_bytes(bytes []u8) ![]HandshakeMessage {
	return h.receive_msgs_at_level(.initial, bytes)!
}

// receive_handshake_bytes feeds Handshake-packet CRYPTO bytes, protected by the
// handshake traffic keys.
pub fn (mut h QuicHandshake) receive_handshake_bytes(bytes []u8) ![]HandshakeMessage {
	return h.receive_msgs_at_level(.handshake, bytes)!
}

// zeroize_traffic_secrets_at destroys one level's traffic secrets after use (§7.5).
// Module-private: the engine calls the phase-named forwarders below.
fn (mut h QuicHandshake) zeroize_traffic_secrets_at(level EncryptionLevel) ! {
	h.HandshakeCore.zeroize_traffic_secrets_at(level)!
}

// zeroize_handshake_secrets releases the handshake traffic secrets once the engine
// has finished using the Handshake packet keys (RFC 8446 §7.5, RFC 9001 §4.9.2).
pub fn (mut h QuicHandshake) zeroize_handshake_secrets() ! {
	h.zeroize_traffic_secrets_at(.handshake)!
}

// zeroize_application_secrets releases the application traffic secrets — the
// terminal teardown at close() (§7.5).
pub fn (mut h QuicHandshake) zeroize_application_secrets() ! {
	h.zeroize_traffic_secrets_at(.application)!
}

// fail_and_zeroize_secrets wipes every secret and parks the machine in .failed (§7.5).
pub fn (mut h QuicHandshake) fail_and_zeroize_secrets() {
	h.HandshakeCore.fail_and_zeroize_secrets()
}

// peer_traffic_secrets_at returns copies of the client and server traffic secrets
// for one encryption level; the initial level has no TLS traffic secrets. Module-
// private QUIC seam: the engine expands the two secrets into RFC 9001 §5.1 packet
// keys through the phase-named peer_handshake_secrets() / peer_application_secrets()
// below, and the TLS record path never reads raw secrets — TLSHandshake serves
// handshake_record_keys() / application_record_keys() from its phase-typed cached key
// handles instead.
fn (h &QuicHandshake) peer_traffic_secrets_at(level EncryptionLevel) !([]u8, []u8) {
	if level == .initial {
		return error('handshake: initial level has no traffic secrets')
	}
	mut c := []u8{}
	mut s := []u8{}
	match level {
		.initial {}
		.handshake {
			c = h.c_hsk_tsec.clone()
			s = h.s_hsk_tsec.clone()
		}
		.application {
			c = h.c_app_tsec.clone()
			s = h.s_app_tsec.clone()
		}
	}
	if c.len == 0 || s.len == 0 {
		if level == .handshake {
			return error('handshake: handshake traffic secrets unavailable (available after ServerHello, dropped by zeroize_handshake_secrets())')
		}
		return error('handshake: application traffic secrets unavailable before the server Finished')
	}
	return c, s
}

// peer_handshake_secrets returns the (client, server) handshake traffic secrets the
// engine expands into Handshake packet keys (RFC 9001 §5.1).
pub fn (h &QuicHandshake) peer_handshake_secrets() !([]u8, []u8) {
	c, s := h.peer_traffic_secrets_at(.handshake)!
	return c, s
}

// peer_application_secrets returns the (client, server) application traffic secrets
// the engine expands into 1-RTT packet keys (RFC 9001 §5.1).
pub fn (h &QuicHandshake) peer_application_secrets() !([]u8, []u8) {
	c, s := h.peer_traffic_secrets_at(.application)!
	return c, s
}

// peer_transport_parameters returns the raw bytes of the server's
// quic_transport_parameters extension, captured from EncryptedExtensions once the
// server sends it. TLS never interprets them: the QUIC adapter decodes the
// id/length/value triplets (RFC 9000 §7.3). Returns none before EncryptedExtensions
// arrives.
pub fn (h &QuicHandshake) peer_transport_parameters() ?[]u8 {
	params := h.quic_params or { return none }
	return params.clone()
}

// hello_retry_request_received reports whether the core has already accepted a
// HelloRetryRequest. TLS itself has no further use for the flag once it has
// built the retry ClientHello, but a QUIC adapter must: the retry is sent under a
// different destination connection ID, and Initial protection is a function of
// that ID, so the adapter's Initial keys go stale here (RFC 9001 §5.5).
pub fn (h &QuicHandshake) hello_retry_request_received() bool {
	return h.hrr_cipher_suite != none
}
