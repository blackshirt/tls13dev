// Copyright (c) 2026 blackshirt.
//
// state_machine.v defines the transport-neutral handshake core shared by both
// adapters: the state and message vocabulary types, the HandshakeCore struct and its
// constructor, the state cursor accessors, and the terminal-failure primitives. Its
// methods attach to HandshakeCore; inbound reassembly lives in reassembly.v, the
// receive/dispatch routing and the ServerHello/HelloRetryRequest and encrypted-flight
// transitions in flight.v, ECDHE and the derived-secret lifecycle in key_exchange.v and
// key_schedule.v, and transport-specific behavior stays on the facades
// (tls_handshake.v, quic_handshake.v), never promoted from here.
module handshake

import crypto.ecdsa
import crypto.rand
import tls.pki
import x.crypto.curve25519

// HandshakeState is the client handshake state machine, mirroring the client
// states of RFC 8446 Appendix A.1 (the all-caps RFC names carry no formal meaning,
// so they are rendered in snake_case here); `failed` is an implementation terminal
// the RFC does not define.
pub enum HandshakeState {
	start         // RFC START: nothing sent yet; create_client_hello moves us out of here
	wait_sh       // RFC WAIT_SH: ClientHello sent; awaiting ServerHello or HelloRetryRequest
	wait_ee       // RFC WAIT_EE: ServerHello accepted; awaiting EncryptedExtensions
	wait_cert_cr  // RFC WAIT_CERT_CR: awaiting CertificateRequest or Certificate
	wait_cert     // RFC WAIT_CERT: awaiting Certificate
	wait_cv       // RFC WAIT_CV: awaiting CertificateVerify
	wait_finished // RFC WAIT_FINISHED: awaiting Finished
	connected     // RFC CONNECTED: server Finished verified; application data may flow
	failed        // implementation terminal; no further handshake messages are accepted
}

// HandshakeMessage is one outbound handshake message, unframed: level tags its
// TLS protection phase, and msg holds the wire bytes, header included.
@[noinit]
pub struct HandshakeMessage {
	level EncryptionLevel // protection phase for the message
	msg   []u8            // complete handshake message bytes, including the header
}

// is_initial reports whether this outbound message belongs to the pre-ServerHello
// (plaintext) phase; a false result means it is protected by handshake keys. It is
// the only phase fact adapters need in order to pick a transmit queue — the phase
// itself is a module-private EncryptionLevel, so it is not exposed as an accessor.
pub fn (m &HandshakeMessage) is_initial() bool {
	return m.level == .initial
}

// msg returns the complete handshake message bytes (4-byte header included).
pub fn (m &HandshakeMessage) msg() []u8 {
	return m.msg
}

// bytes is an alias for msg(), returning the complete handshake message bytes.
pub fn (m &HandshakeMessage) bytes() []u8 {
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
// Module-private: adapters reach each phase through the facades' phase-named
// methods, so the phase vocabulary stays an implementation detail.
enum EncryptionLevel {
	initial     // handshake messages sent before handshake keys are available
	handshake   // messages protected with handshake traffic keys
	application // data protected with application traffic keys
}

// HandshakeOptions configures the shared TLS handshake, including peer
// validation, ALPN, and the ClientHello preferences offered by the client.
@[params]
pub struct HandshakeOptions {
pub:
	// alpn is the preference-ordered list of application protocols to offer.
	alpn []string
	// validator verifies the server's certificate chain and hostname; omitted
	// options use the system root CA bundle.
	validator ?pki.Validator
	// key_share_group is the group used for the initial ECDHE share.
	key_share_group NamedGroup = .x25519
	// supported_groups is preference-ordered; empty uses X25519 then P-256.
	supported_groups []NamedGroup
	// cipher_suites is preference-ordered; empty uses the built-in TLS 1.3 suites.
	cipher_suites []CipherSuite
	// signature_algorithms is preference-ordered; empty uses the built-in list.
	signature_algorithms []SignatureScheme
	// legacy_session_id is the ClientHello session id echoed in ServerHello.
	legacy_session_id []u8
	// random is the ClientHello random; with legacy_session_id it lets a test vector
	// pin a deterministic handshake.
	random []u8
pub mut:
	// quic_transport_params is the encoded content of the TLS
	// quic_transport_parameters extension (RFC 9001 §8.2), copied through without
	// interpretation: the adapter above encodes and decodes it.
	quic_transport_params []u8
}

// with_validator returns a copy of the options with the given validator, preserving
// every other setting. Adapters use it to resolve trust configuration before handing
// the options to a constructor without copying fields by hand.
pub fn (o HandshakeOptions) with_validator(validator pki.Validator) HandshakeOptions {
	return HandshakeOptions{
		alpn:                  o.alpn.clone()
		validator:             validator
		key_share_group:       o.key_share_group
		supported_groups:      o.supported_groups.clone()
		cipher_suites:         o.cipher_suites.clone()
		signature_algorithms:  o.signature_algorithms.clone()
		legacy_session_id:     o.legacy_session_id.clone()
		random:                o.random.clone()
		quic_transport_params: o.quic_transport_params
	}
}

// HandshakeCore owns shared TLS 1.3 handshake state and behavior.
@[noinit]
struct HandshakeCore {
mut:
	// ClientHello settings and key exchange state.
	config      ClientHelloConfig // settings used to build or retry the ClientHello
	ecdhe_group NamedGroup        // key exchange group used for the shared secret
	priv_x25519 &curve25519.PrivateKey = unsafe { nil } // client's X25519 private key, if used
	priv_p256   ?ecdsa.PrivateKey // client's P-256 private key, if used

	// Transcript and negotiated cipher suite.
	transcript   Transcript    // hash of handshake messages exchanged so far
	hash_algo    HashAlgorithm // hash algorithm used for this handshake
	cipher_suite CipherSuite   // cipher suite selected by the server
	key_len      int           // encryption key length for the selected cipher suite
	quic_params  ?[]u8         // server transport parameters received in EncryptedExtensions, kept as opaque bytes for the QUIC adapter

	// Key-schedule material used to protect handshake and application data.
	handshake_secret []u8 // secret used to derive handshake traffic keys
	c_hsk_tsec       []u8 // client handshake traffic secret
	c_app_tsec       []u8 // client application traffic secret
	s_hsk_tsec       []u8 // server handshake traffic secret
	s_app_tsec       []u8 // server application traffic secret

	// Incoming handshake bytes that do not yet form complete messages.
	buffers ReassemblyBuffers // the initial- and handshake-phase streams, keyed by phase

	// Peer certificate validation and client certificate response state.
	validator    pki.Validator     // checks the server's certificate and hostname
	server_certs []pki.Certificate // certificates received from the server, leaf first

	// Handshake retry and outcome.
	hrr_cipher_suite ?CipherSuite   // suite from the retry request; presence marks a retry
	state            HandshakeState // position in the client state machine (RFC 8446 App. A.1)
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
	// session_id.len has been checked in validate_handshake_options
	session_id := if options.legacy_session_id.len > 0 {
		options.legacy_session_id.clone()
	} else {
		rand.bytes(legacy_session_id_len)!
	}
	// random.len has been checked in validate_handshake_options
	random := if options.random.len > 0 {
		options.random.clone()
	} else {
		rand.bytes(client_hello_random_len)!
	}

	mut core := HandshakeCore{
		state:      .start
		config:     ClientHelloConfig{
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
		transcript: new_transcript(.sha256)
		hash_algo:  .sha256
		key_len:    16
		validator:  validator
		buffers:    new_reassembly_buffers()
	}
	core.generate_key_share(options.key_share_group)!
	core.config.client_share = KeyShareEntry{
		group:        options.key_share_group
		key_exchange: core.public_share_bytes()!
	}
	return core
}

// state reports the client's position in the RFC 8446 Appendix A.1 handshake
// state machine; adapters poll it to know when the handshake completed and which
// messages are still legal on the wire. Module-private like every HandshakeCore
// method: callers reach it only through each facade's curated pub forwarder,
// never through embedded-field promotion.
fn (h &HandshakeCore) state() HandshakeState {
	return h.state
}

// in_flight reports whether the current state lies inside the encrypted server
// flight, the window in which handshake-level bytes are legal.
fn (h &HandshakeCore) in_flight() bool {
	return match h.state {
		.wait_ee, .wait_cert_cr, .wait_cert, .wait_cv, .wait_finished { true }
		else { false }
	}
}

// negotiated_alpn returns the ALPN protocol the server picked ('' when none).
fn (h &HandshakeCore) negotiated_alpn() string {
	return h.negotiated_alpn
}

// negotiated_cipher_suite reports the suite selected by the server in ServerHello.
fn (h &HandshakeCore) negotiated_cipher_suite() CipherSuite {
	return h.cipher_suite
}

// failure_alert returns the alert description an adapter should surface when
// this handshake dies (RFC 8446 §6).
fn (h &HandshakeCore) failure_alert() AlertDescription {
	return h.fail_alert
}

// classify_failure is the single terminal-failure primitive for the core: it pins
// the alert the adapter must surface, zeroes every derived secret, parks the
// machine in .failed, and returns the IError to propagate (RFC 8446 §7.5), so a
// call site cannot record an alert and forget to zeroize. Idempotent, so outer
// teardown safety nets stay harmless.
fn (mut h HandshakeCore) classify_failure(alert AlertDescription, message string) IError {
	h.fail_alert = alert
	h.fail_and_zeroize_secrets()
	return error(message)
}

// fail_with classifies a propagated error without each call site repeating the
// err.msg() unwrap.
fn (mut h HandshakeCore) fail_with(alert AlertDescription, err IError) IError {
	return h.classify_failure(alert, err.msg())
}

// update_transcript appends one message to the running transcript, converting the
// total-size bound into the alert-classified failure the state machine reports.
fn (mut h HandshakeCore) update_transcript(msg []u8) ! {
	h.transcript.update(msg) or {
		return h.fail_with(.decode_error, err)
	}
}

// create_client_hello generates the initial ClientHello, advances to
// .wait_sh and returns the raw bytes to hash and frame (RFC 8446 App. D.4).
fn (mut h HandshakeCore) create_client_hello() ![]u8 {
	// A second call would replay the first ClientHello into the transcript and
	// corrupt every later hash; the retry ClientHello has its own path, produced
	// while a HelloRetryRequest is fed.
	if h.state != .start {
		return error('handshake: create_client_hello() only runs once (state: ${h.state()}); the retry ClientHello is produced while a HelloRetryRequest is fed')
	}
	_, full_client_hello := build_client_hello(h.config)!
	h.update_transcript(full_client_hello)!

	h.state = .wait_sh
	return full_client_hello
}
