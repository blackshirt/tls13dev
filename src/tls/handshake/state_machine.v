// Copyright (c) 2026 blackshirt.
//
// state_machine.v owns the shared TLS 1.3 client handshake state, public accessors,
// reassembly and dispatch, plus the facade-shared HandshakeOptions. The ServerHello
// transition lives in server_hello_flow.v,
// ephemeral ECDHE in key_exchange.v, encrypted-flight processing in encrypted_flight.v,
// and secret wiping/zeroization in secret_lifecycle.v. Transport-neutral: no record,
// cipher, socket, or packet-level concept belongs here.
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
	// legacy_session_id and random are for deterministic test vectors only.
	legacy_session_id []u8
	random            []u8
pub mut:
	// quic_transport_params is the already-encoded content of the TLS
	// quic_transport_parameters extension (RFC 9001 §8.2), sent only by the QUIC
	// handshake facade. TLS copies these bytes in and stores them back out
	// without interpreting them: transport parameters are QUIC's own vocabulary,
	// so the adapter above encodes and decodes them.
	quic_transport_params []u8
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
	transcript   Transcript    // hash of handshake messages exchanged so far
	hash_algo    HashAlgorithm // hash algorithm used for this handshake
	cipher_suite CipherSuite   // cipher suite selected by the server
	key_len      int           // encryption key length for the selected cipher suite
	quic_params  ?[]u8         // server transport parameters received in EncryptedExtensions, kept as opaque bytes for the QUIC adapter

	// Traffic secrets used to protect handshake and application data.
	handshake_secret   []u8 // secret used to derive handshake traffic keys
	client_hsk_traffic []u8 // key material for client handshake messages
	server_hsk_traffic []u8 // key material for server handshake messages
	client_app_traffic []u8 // key material for client application data
	server_app_traffic []u8 // key material for server application data

	// Incoming handshake bytes that do not yet form a complete message.
	init_buf []u8 // initial-level bytes not yet forming a complete message
	hsk_buf  []u8 // handshake-level bytes not yet forming a complete message

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

// reassembly_buf_cap is the initial per-level reassembly allocation; the hard bound
// a hostile peer must never exceed is enforced inline in receive_msgs_at_level
// against max_handshake_message_len.
const reassembly_buf_cap = 4096

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
		init_buf:   []u8{cap: reassembly_buf_cap}
		hsk_buf:    []u8{cap: reassembly_buf_cap}
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

// update_transcript appends one message to the running transcript, converting the
// total-size bound into the alert-classified failure the state machine reports.
fn (mut h HandshakeCore) update_transcript(msg []u8) ! {
	h.transcript.update(msg) or {
		return h.fail(.decode_error, err.msg())
	}
}

// create_client_hello generates the initial ClientHello, advances to
// .wait_server_hello and returns the raw bytes to hash and frame (RFC 8446 App. D.4).
pub fn (mut h HandshakeCore) create_client_hello() ![]u8 {
	// A second call would replay the first ClientHello into the transcript and corrupt every later hash; the retry ClientHello has its own path via receive_msgs_at_level().
	if h.state != .start {
		return error('handshake: create_client_hello() only runs once (state: ${h.state}); the retry ClientHello is produced by receive_msgs_at_level() during HelloRetryRequest handling')
	}
	_, full_client_hello := build_client_hello(h.config)!
	h.client_hello1 = full_client_hello.clone()
	h.update_transcript(full_client_hello)!

	h.state = .wait_server_hello
	return full_client_hello
}

// receive_msgs_at_level processes bytes using the encryption-level reassembly buffers
// owned by the selected transport facade, returning any outbound messages triggered.
// Initial-level input is accepted only while awaiting ServerHello; handshake-level
// input is accepted only between ServerHello and Finished. Phase misuse is rejected
// without consuming bytes or changing state.
pub fn (mut h HandshakeCore) receive_msgs_at_level(level EncryptionLevel, bytes []u8) ![]HandshakeMessage {
	if h.state == .start {
		return error('handshake: receive_msgs_at_level() before create_client_hello() — no ClientHello has been sent yet')
	}
	if h.state == .failed {
		return error('handshake: state machine has failed; receive_msgs_at_level() refuses further messages')
	}
	match level {
		.initial {
			if h.state != .wait_server_hello {
				return error('handshake: initial handshake bytes are only expected while awaiting ServerHello (state: ${h.state})')
			}
			return h.append_and_drain(level, bytes)
		}
		.handshake {
			if h.state != .wait_encrypted_extensions && h.state != .wait_certificate_request
				&& h.state != .wait_certificate && h.state != .wait_certificate_verify
				&& h.state != .wait_server_finished {
				return error('handshake: handshake-level bytes are only expected after ServerHello and before Finished (state: ${h.state})')
			}
			return h.append_and_drain(level, bytes)
		}
		.application {
			return error('handshake: receive_msgs_at_level() does not accept application-level bytes')
		}
	}
}

// append_and_drain bounds each append before allocating, while still allowing a
// transport to deliver multiple complete messages in one call.
fn (mut h HandshakeCore) append_and_drain(level EncryptionLevel, bytes []u8) ![]HandshakeMessage {
	mut out := []HandshakeMessage{}
	mut offset := 0
	limit := handshake_header_len + max_handshake_message_len
	for {
		buffer_len := if level == .initial {
			h.init_buf.len
		} else {
			h.hsk_buf.len
		}
		available := limit - buffer_len
		if offset < bytes.len && available == 0 {
			alert := if level == .initial { 'initial-level' } else { 'handshake-level' }
			err := h.fail(.decode_error, 'handshake: ${alert} reassembly exceeds ${max_handshake_message_len} bytes without completing a message')
			h.fail_and_zeroize_secrets()
			return err
		}
		take := if bytes.len - offset > available { available } else { bytes.len - offset }
		if take > 0 {
			if level == .initial {
				h.init_buf << bytes[offset..offset + take]
			} else {
				h.hsk_buf << bytes[offset..offset + take]
			}
			offset += take
		}
		messages := if level == .initial {
			h.drain_initial() or {
				h.fail_and_zeroize_secrets()
				return err
			}
		} else {
			h.drain_handshake() or {
				h.fail_and_zeroize_secrets()
				return err
			}
		}
		out << messages
		if offset == bytes.len {
			break
		}
	}
	return out
}

// drain_initial consumes the complete ServerHello/HelloRetryRequest from the
// initial-level buffer; framing-boundary checks remain adapter policy.
fn (mut h HandshakeCore) drain_initial() ![]HandshakeMessage {
	mut out := []HandshakeMessage{}
	for h.state == .wait_server_hello {
		msg := next_recordless_message(mut h.init_buf)!
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
		msg := next_recordless_message(mut h.hsk_buf)!
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
		.initial { h.init_buf.len }
		.handshake { h.hsk_buf.len }
		.application { 0 }
	}
}

// negotiated_cipher_suite reports the suite selected by the server in ServerHello.
pub fn (h &HandshakeCore) negotiated_cipher_suite() CipherSuite {
	return h.cipher_suite
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
