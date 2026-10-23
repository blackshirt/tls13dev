// Copyright (c) 2026 blackshirt.
//
// state_machine.v owns the shared TLS 1.3 client handshake state, public accessors,
// reassembly, dispatch and secret lifecycle. The ServerHello transition lives in
// server_hello_flow.v, ephemeral ECDHE in key_exchange.v, and encrypted-flight
// processing in encrypted_flight.v. Transport-neutral: no record, cipher, socket,
// or packet-level concept belongs here.
//
// Public transport facades live in tls_handshake.v and quic_handshake.v.
module handshake

import crypto.ecdsa
import crypto.rand
import x.crypto.curve25519
import tls.pki

// HandshakeState tracks client progress; the wait_* order mirrors the fixed
// post-ServerHello flight (RFC 8446 §1/§4.1), each handler asserting its state.
pub enum HandshakeState {
	start                     // nothing sent yet; create_client_hello moves us out of here
	wait_server_hello         // ClientHello sent; awaiting ServerHello or HelloRetryRequest
	wait_encrypted_extensions // ServerHello accepted and handshake keys installed
	wait_certificate_request  // EncryptedExtensions accepted; a CertificateRequest may follow before the Certificate (§4.3.2/§4.4.1)
	wait_certificate          // EncryptedExtensions accepted (ALPN/SNI checks done); awaiting the server Certificate
	wait_certificate_verify   // server chain parsed and hostname/chain validated
	wait_server_finished      // CertificateVerify verified against the leaf key
	connected                 // server Finished verified; application data may flow
	failed                    // terminal error; no further handshake messages are accepted
}

// HandshakeMessage is one outbound handshake message, unframed: level tags its
// TLS protection phase, and msg holds the wire bytes, header included.
@[noinit]
pub struct HandshakeMessage {
	level EncryptionLevel // protection phase for the message
	msg   []u8            // complete handshake message bytes, including the header
}

// level returns the TLS protection phase this message belongs to.
pub fn (m &HandshakeMessage) level() EncryptionLevel {
	return m.level
}

// msg returns the complete handshake message bytes (4-byte header included).
pub fn (m &HandshakeMessage) msg() []u8 {
	return m.msg
}

// new_handshake_message builds a validated outbound message for the core.
fn new_handshake_message(level EncryptionLevel, msg []u8) !HandshakeMessage {
	_, _ := split_handshake_message(msg)!
	return HandshakeMessage{
		level: level
		msg:   msg
	}
}

// EncryptionLevel names TLS protection phases shared by handshake messages
// and traffic-secret access, independent of transport packet or record levels.
pub enum EncryptionLevel {
	initial     // handshake messages sent before handshake keys are available
	handshake   // messages protected with handshake traffic keys
	application // data protected with application traffic keys
}

// HandshakeCore owns shared TLS 1.3 handshake state and behavior.
@[noinit]
struct HandshakeCore {
mut:
	// ClientHello settings and key exchange state.
	config        ClientHelloConfig // settings used to build or retry the ClientHello
	ecdhe_group   NamedGroup        // key exchange group used for the shared secret
	priv_x25519   &curve25519.PrivateKey = unsafe { nil } // client's X25519 private key, if used
	priv_p256     ?ecdsa.PrivateKey // client's P-256 private key, if used
	client_hello1 []u8              // first ClientHello, kept in case the server requests a retry

	// Transcript and negotiated cipher suite.
	transcript   Transcript               // hash of handshake messages exchanged so far
	hash_algo    HashAlgorithm            // hash algorithm used for this handshake
	cipher_suite CipherSuite              // cipher suite selected by the server
	key_len      int                      // encryption key length for the selected cipher suite
	quic_params  ?QuicTransportParameters // server transport parameters received in EncryptedExtensions

	// Traffic secrets used to protect handshake and application data.
	handshake_secret  []u8 // secret used to derive handshake traffic keys
	client_hs_traffic []u8 // key material for client handshake messages
	server_hs_traffic []u8 // key material for server handshake messages
	client_ap_traffic []u8 // key material for client application data
	server_ap_traffic []u8 // key material for server application data

	// Incoming handshake bytes that do not yet form a complete message.
	plaintext_reassembly []u8 // initial-level bytes not yet forming a complete message
	hs_reassembly        []u8 // handshake-level bytes not yet forming a complete message

	// Peer certificate validation and client certificate response state.
	validator       pki.Validator     // checks the server's certificate and hostname
	server_certs    []pki.Certificate // certificates received from the server, leaf first
	request_context []u8              // context to include in the client's certificate response

	// Handshake retry and outcome.
	hrr_received     bool           // whether the server has requested a ClientHello retry
	hrr_cipher_suite ?CipherSuite   // cipher suite chosen in the retry request, if any
	state            HandshakeState // current stage of the handshake
	negotiated_alpn  string         // protocol chosen by the server, or empty if none
	fail_alert       AlertDescription = .internal_error // alert to report if the handshake fails
}

// new_handshake_core creates shared state from the server name and complete
// handshake options, including ALPN and certificate validation.
fn new_handshake_core(server_name string, options HandshakeOptions, is_quic bool) !HandshakeCore {
	validate_handshake_options(options)!
	validator := options.validator or {
		pki.default_validator()!
	}
	// Pin random/session id at construction so HRR reuses them byte-identically (§4.1.4).
	session_id := if options.legacy_session_id.len > 0 {
		options.legacy_session_id.clone()
	} else {
		rand.bytes(legacy_session_id_len)!
	}
	random := if options.random.len > 0 {
		options.random.clone()
	} else {
		rand.bytes(client_hello_random_len)!
	}

	mut core := HandshakeCore{
		state:                .start
		config:               ClientHelloConfig{
			server_name:           server_name
			alpn:                  options.alpn.clone()
			session_id:            session_id
			random:                random
			cipher_suites:         options.cipher_suites.clone()
			supported_groups:      options.supported_groups.clone()
			signature_algorithms:  options.signature_algorithms.clone()
			is_quic:               is_quic
			quic_transport_params: if is_quic {
				options.quic_transport_params
			} else {
				none
			}
		}
		transcript:           new_transcript(.sha256)
		hash_algo:            .sha256
		key_len:              16
		validator:            validator
		plaintext_reassembly: []u8{cap: 4096}
		hs_reassembly:        []u8{cap: 4096}
	}
	core.generate_key_share(options.key_share_group)!
	core.config.client_share = KeyShareEntry{
		group:        options.key_share_group
		key_exchange: core.public_share_bytes()!
	}
	return core
}

// state reports current handshake progress; adapters poll it to know
// when the handshake completed and which messages are still legal on the wire.
pub fn (h &HandshakeCore) state() HandshakeState {
	return h.state
}

// negotiated_alpn returns the ALPN protocol the server picked ('' when none).
pub fn (h &HandshakeCore) negotiated_alpn() string {
	return h.negotiated_alpn
}

// failure_alert returns the alert description an adapter should surface when
// this handshake dies (RFC 8446 §6).
pub fn (h &HandshakeCore) failure_alert() AlertDescription {
	return h.fail_alert
}

fn (mut h HandshakeCore) fail(alert AlertDescription, message string) IError {
	h.fail_alert = alert
	return error(message)
}

// create_client_hello generates the initial ClientHello, advances to
// .wait_server_hello and returns the raw bytes to hash and frame (RFC 8446 App. D.4).
pub fn (mut h HandshakeCore) create_client_hello() ![]u8 {
	// A second call would replay the first ClientHello into the transcript and corrupt every later hash; the retry ClientHello has its own path via receive().
	if h.state != .start {
		return error('handshake: create_client_hello() only runs once (state: ${h.state}); the retry ClientHello is produced by receive() during HelloRetryRequest handling')
	}
	_, full_client_hello := build_client_hello(h.config)!
	h.client_hello1 = full_client_hello.clone()
	h.transcript.update(full_client_hello)

	h.state = .wait_server_hello
	return full_client_hello
}

// check_reassembly_bound enforces the maximum buffered size at a level; one
// receive can coalesce a consumed message with an oversized tail.
fn (mut h HandshakeCore) check_reassembly_bound(level EncryptionLevel) ! {
	match level {
		.initial {
			if h.plaintext_reassembly.len > 4 + max_handshake_message_len {
				return h.fail(.decode_error, 'handshake: initial-level reassembly exceeds ${max_handshake_message_len} bytes without completing a message')
			}
		}
		.handshake {
			// Late retransmits at .connected skip the drain loop, so the cap is the backstop.
			if h.hs_reassembly.len > 4 + max_handshake_message_len {
				return h.fail(.decode_error, 'handshake: Handshake-level reassembly exceeds ${max_handshake_message_len} bytes without completing a message')
			}
		}
		.application {}
	}
}

// receive processes bytes using the encryption-level reassembly buffers owned
// by the selected transport facade, returning any outbound messages triggered.
pub fn (mut h HandshakeCore) receive(level EncryptionLevel, bytes []u8) ![]HandshakeMessage {
	if h.state == .start {
		return error('handshake: receive() before create_client_hello() — no ClientHello has been sent yet')
	}
	if h.state == .failed {
		return error('handshake: state machine has failed; receive() refuses further messages')
	}
	match level {
		.initial {
			if h.state != .wait_server_hello {
				return error('handshake: initial handshake bytes are only expected while awaiting ServerHello (state: ${h.state})')
			}
			h.plaintext_reassembly << bytes
			out := h.drain_plaintext() or {
				h.fail_and_destroy_secrets()
				return err
			}
			h.check_reassembly_bound(level) or {
				h.fail_and_destroy_secrets()
				return err
			}
			return out
		}
		.handshake {
			h.hs_reassembly << bytes
			out := h.drain_handshake() or {
				h.fail_and_destroy_secrets()
				return err
			}
			h.check_reassembly_bound(level) or {
				h.fail_and_destroy_secrets()
				return err
			}
			return out
		}
		.application {
			return error('handshake: receive() does not accept application-level bytes')
		}
	}
}

// drain_plaintext consumes the complete ServerHello/HelloRetryRequest from the
// initial-level buffer; framing-boundary checks remain adapter policy.
fn (mut h HandshakeCore) drain_plaintext() ![]HandshakeMessage {
	mut out := []HandshakeMessage{}
	for h.state == .wait_server_hello {
		msg := next_passthrough_message(mut h.plaintext_reassembly)!
		if msg.len == 0 {
			break // header or body still incomplete
		}
		out << h.handle_server_hello_message(msg)!
		if h.state != .wait_server_hello {
			break // ServerHello consumed (or failed); an HRR rearms the wait
		}
	}
	return out
}

// drain_handshake consumes the encrypted flight — EE, optional CertificateRequest,
// Certificate, CertificateVerify, and Finished — until the buffer runs dry
// or the handshake ends.
fn (mut h HandshakeCore) drain_handshake() ![]HandshakeMessage {
	mut out := []HandshakeMessage{}
	for h.state != .connected && h.state != .failed {
		msg := next_passthrough_message(mut h.hs_reassembly)!
		if msg.len == 0 {
			break
		}
		out << h.handle_handshake_message(msg)!
	}
	return out
}

// unconsumed_bytes reports bytes retained after complete TLS messages are consumed.
fn (h &HandshakeCore) unconsumed_bytes(level EncryptionLevel) int {
	return match level {
		.initial { h.plaintext_reassembly.len }
		.handshake { h.hs_reassembly.len }
		.application { 0 }
	}
}

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

// negotiated_cipher_suite reports the suite selected by the server in ServerHello.
pub fn (h &HandshakeCore) negotiated_cipher_suite() CipherSuite {
	return h.cipher_suite
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

// handle_handshake_message processes one complete encrypted-flight message:
// EE, optional CertificateRequest, Certificate, CertificateVerify, or Finished.
fn (mut h HandshakeCore) handle_handshake_message(full_msg []u8) ![]HandshakeMessage {
	// The message is complete by construction (reassembly framed it by its own header), so peel type/length and split the body off.
	msg_type, body := split_handshake_message(full_msg)!

	match msg_type {
		.encrypted_extensions { return h.handle_encrypted_extensions(full_msg, body) }
		.certificate_request { return h.handle_certificate_request(full_msg, body) }
		.certificate { return h.handle_certificate(full_msg, body) }
		.certificate_verify { return h.handle_certificate_verify(full_msg, body) }
		.finished { return h.handle_finished(full_msg, body) }
		else {
			return h.fail(.unexpected_message, 'handshake: unexpected handshake message ${msg_type}')
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
