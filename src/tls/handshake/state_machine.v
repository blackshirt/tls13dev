// Copyright (c) 2026 blackshirt.
//
// state_machine.v owns the entire transport-neutral handshake core shared by
// both adapters: client state, public accessors, reassembly and dispatch, the
// facade-shared HandshakeOptions, the ServerHello/HelloRetryRequest transition,
// encrypted-flight processing, ephemeral ECDHE, and the secret lifecycle (all
// in the sections below). Transport-specific methods are defined on their
// facade — tls_handshake.v and quic_handshake.v — never promoted from here.
// Message codecs, the transcript, and the key schedule keep their own files.
module handshake

import crypto.ecdsa
import crypto.rand
import crypto.subtle
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
	// quic_transport_params is the encoded content of the TLS
	// quic_transport_parameters extension (RFC 9001 §8.2), copied through without
	// interpretation: the adapter above encodes and decodes it.
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

// SecretPhases reports which traffic-secret phases the core currently holds
// (derived, not yet zeroized, both directions present). Transport-neutral: it lets
// adapters install record or packet keys when the material actually exists instead
// of re-deriving readiness from HandshakeState.
pub struct SecretPhases {
pub:
	handshake   bool // client+server handshake traffic secrets available
	application bool // client+server application traffic secrets available
}

// available_secret_phases reports the current key-material readiness.
pub fn (h &HandshakeCore) available_secret_phases() SecretPhases {
	return SecretPhases{
		handshake:   h.client_hsk_traffic.len > 0 && h.server_hsk_traffic.len > 0
		application: h.client_app_traffic.len > 0 && h.server_app_traffic.len > 0
	}
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

// update_transcript appends one message to the running transcript, converting the
// total-size bound into the alert-classified failure the state machine reports.
fn (mut h HandshakeCore) update_transcript(msg []u8) ! {
	h.transcript.update(msg) or {
		return h.classify_failure(.decode_error, err.msg())
	}
}

// create_client_hello generates the initial ClientHello, advances to
// .wait_server_hello and returns the raw bytes to hash and frame (RFC 8446 App. D.4).
pub fn (mut h HandshakeCore) create_client_hello() ![]u8 {
	// A second call would replay the first ClientHello into the transcript and
	// corrupt every later hash; the retry ClientHello has its own path via
	// receive_msgs_at_level().
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
// transport to deliver multiple complete messages in one call. Inner failures
// already tear down via classify_failure; the fail_and_zeroize_secrets() safety
// nets below catch anything else — teardown is idempotent.
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
			return h.classify_failure(.decode_error, 'handshake: ${alert} reassembly exceeds ${max_handshake_message_len} bytes without completing a message')
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
		msg := next_recordless_message(mut h.init_buf) or {
			return h.classify_failure(.decode_error, err.msg())
		}
		if msg.len == 0 {
			break // header or body still incomplete
		}
		out_msgs := h.handle_server_hello_message(msg) or {
			return err // classified inside the ServerHello handler
		}
		out << out_msgs
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
		msg := next_recordless_message(mut h.hsk_buf) or {
			return h.classify_failure(.decode_error, err.msg())
		}
		if msg.len == 0 {
			break
		}
		out_msgs := h.handle_handshake_message(msg) or {
			return err // classified inside the encrypted-flight handlers
		}
		out << out_msgs
	}
	return out
}

// negotiated_cipher_suite reports the suite selected by the server in ServerHello.
pub fn (h &HandshakeCore) negotiated_cipher_suite() CipherSuite {
	return h.cipher_suite
}

// handle_handshake_message processes one complete encrypted-flight message:
// EE, optional CertificateRequest, Certificate, CertificateVerify, or Finished.
fn (mut h HandshakeCore) handle_handshake_message(full_msg []u8) ![]HandshakeMessage {
	// The message is complete by construction (reassembly framed it by its own
	// header), so peel type/length and split the body off.
	msg_type, body := split_handshake_message(full_msg) or {
		return h.classify_failure(.decode_error, err.msg())
	}

	match msg_type {
		.encrypted_extensions { return h.handle_encrypted_extensions(full_msg, body) }
		.certificate_request { return h.handle_certificate_request(full_msg, body) }
		.certificate { return h.handle_certificate(full_msg, body) }
		.certificate_verify { return h.handle_certificate_verify(full_msg, body) }
		.finished { return h.handle_finished(full_msg, body) }
		else {
			return h.classify_failure(.unexpected_message, 'handshake: unexpected handshake message ${msg_type}')
		}
	}
}

// ─── Ephemeral ECDHE key exchange (RFC 8446 §4.2.8) ───

// generate_key_share creates a fresh ephemeral private key for the requested group.
fn (mut h HandshakeCore) generate_key_share(group NamedGroup) ! {
	h.ecdhe_group = group
	// Only the key for the selected group stays live.
	h.priv_x25519 = unsafe { nil }
	h.priv_p256 = none
	match group {
		.x25519 {
			h.priv_x25519 = curve25519.PrivateKey.new()!
		}
		.secp256r1 {
			h.priv_p256 = ecdsa.PrivateKey.new(nid: .prime256v1)!
		}
	}
}

// public_share_bytes serializes the public half of the current ephemeral key in
// the wire form its group mandates (RFC 8446 §4.2.8.2).
fn (mut h HandshakeCore) public_share_bytes() ![]u8 {
	match h.ecdhe_group {
		.x25519 {
			pub_key := h.priv_x25519.public_key()!
			return pub_key.bytes()!
		}
		.secp256r1 {
			priv := h.priv_p256 or { return error('handshake: missing P-256 private key') }
			pub_key := priv.public_key()!
			return pub_key.uncompressed_bytes()!
		}
	}
}

// The three small-order X25519 shared-secret results of RFC 7748 §6.1, in the
// little-endian wire encoding: the identity, u = 1, and u = p-1 = 2^255-20.
const x25519_secret_zero = [u8(0), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

const x25519_secret_one = [u8(1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

const x25519_secret_p_minus_1 = [u8(0xec), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]

// is_x25519_small_order reports whether a finished X25519 shared secret landed
// in one of the three small-order results (RFC 7748 §6.1); reject all three.
@[direct_array_access]
fn is_x25519_small_order(secret []u8) bool {
	if subtle.constant_time_compare(secret, x25519_secret_zero) == 1 {
		return true
	}
	if subtle.constant_time_compare(secret, x25519_secret_one) == 1 {
		return true
	}
	return subtle.constant_time_compare(secret, x25519_secret_p_minus_1) == 1
}

// compute_shared_secret performs the ECDHE exchange against the server's key
// share, returning the raw shared secret that seeds the key schedule.
fn (mut h HandshakeCore) compute_shared_secret(server_share KeyShareEntry) ![]u8 {
	// §4.2.8.2 fixes key_exchange size per group; gate it here so a wrong size
	// yields a named protocol error.
	expected_len := expected_share_len(server_share.group)
	if server_share.key_exchange.len != expected_len {
		return h.classify_failure(.illegal_parameter, 'handshake: ${server_share.group} key_share is ${server_share.key_exchange.len} bytes, expected ${expected_len}')
	}
	match server_share.group {
		.x25519 {
			if h.priv_x25519 == unsafe { nil } {
				return error('handshake: missing X25519 private key')
			}
			// §4.2.8.2 & RFC 7748 §6.1: an all-zero peer u-coordinate would yield an
			// all-zero secret; gate before the backend.
			if subtle.constant_time_compare(server_share.key_exchange, []u8{len: 32, init: 0}) == 1 {
				return h.classify_failure(.illegal_parameter, 'handshake: computed X25519 shared secret is all-zero value (illegal_parameter)')
			}
			// The backend runs its own low-order and zero-result checks, so a
			// small-order contribution can fail inside the scalar multiplication and
			// never reach the result comparison below. Classify every failure of this
			// exchange as the peer's fault: RFC 8446 §4.2.8.2 makes a bad key_share
			// illegal_parameter, and pinning it keeps the sent alert off internal_error.
			secret := h.priv_x25519.x25519(server_share.key_exchange) or {
				return h.classify_failure(.illegal_parameter, 'handshake: X25519 key_share is a small-order contribution (illegal_parameter)')
			}
			// Defense in depth: reject every small-order result, not just the all-zero one.
			if is_x25519_small_order(secret) {
				return h.classify_failure(.illegal_parameter, 'handshake: computed X25519 shared secret is a small-order value (illegal_parameter)')
			}
			return secret
		}
		.secp256r1 {
			// Only the uncompressed encoding is legal in TLS 1.3 (§4.2.8.2); compressed shares start 0x02/0x03.
			// A malformed share is the sender's fault, so it must pin the alert.
			if server_share.key_exchange[0] != 0x04 {
				return h.classify_failure(.illegal_parameter, 'handshake: P-256 key_share is not an uncompressed point (0x04 prefix)')
			}
			// 0x04 || 0^32 || 0^32 encodes the point at infinity: the exchange would
			// contribute nothing to the secret. Reject the identity encoding itself,
			// deterministically, instead of trusting the backend to refuse it.
			if subtle.constant_time_compare(server_share.key_exchange[1..server_share.key_exchange.len],
				[]u8{len: 64, init: 0}) == 1 {
				return h.classify_failure(.illegal_parameter, 'handshake: P-256 key_share is the point at infinity (illegal_parameter)')
			}
			priv := h.priv_p256 or { return error('handshake: missing P-256 private key') }
			// A point that does not decode is the sender's fault too, so pin the alert
			// instead of letting a backend message surface as internal_error.
			peer := ecdsa.PublicKey.from_uncompressed_bytes(server_share.key_exchange,
				nid: .prime256v1
			) or {
				return h.classify_failure(.illegal_parameter, 'handshake: P-256 key_share is not a valid uncompressed point on the curve (illegal_parameter)')
			}
			secret := priv.derive_shared_secret(peer) or {
				return h.classify_failure(.internal_error, 'handshake: P-256 ECDH operation failed')
			}
			if subtle.constant_time_compare(secret, []u8{len: secret.len, init: 0}) == 1 {
				return h.classify_failure(.illegal_parameter, 'handshake: computed P-256 shared secret is all-zero value (illegal_parameter)')
			}
			return secret
		}
	}
	// Unreachable: the match above is exhaustive over NamedGroup.
	return error('handshake: unsupported key_share group ${server_share.group}')
}

// ─── ServerHello / HelloRetryRequest transition (RFC 8446 §4.1.3/§4.1.4) ───

// handle_server_hello_message consumes one complete initial-level ServerHello
// or HelloRetryRequest and returns the follow-up messages (RFC 8446 §4.1.3).
fn (mut h HandshakeCore) handle_server_hello_message(sh_msg []u8) ![]HandshakeMessage {
	if h.state != .wait_server_hello {
		// Strict ordering: a ServerHello is only legal while we await it (§4.4.1).
		return h.classify_failure(.unexpected_message, 'handshake: unexpected ServerHello in state ${h.state}')
	}

	// Peel the 4-byte handshake header (type || 3-byte length) to bound the body (§4).
	msg_type, body := split_handshake_message(sh_msg) or {
		return h.classify_failure(.decode_error, err.msg())
	}
	if msg_type != .server_hello {
		// HelloRetryRequest reuses the ServerHello type value (2) and is told apart
		// only by the sentinel random (§4.1.3).
		return h.classify_failure(.unexpected_message, 'handshake: expected ServerHello (2), got ${msg_type}')
	}
	// Transport framing boundaries are enforced by adapters; reassembly hands this
	// method one complete handshake message.
	// §4.1.3 field decode plus the §4.2 extension allowlist.
	sh := parse_server_hello(body) or {
		return h.classify_failure(.decode_error, err.msg())
	}
	// Re-frame header + body so the transcript covers the exact wire layout.
	full_sh_msg := wrap_handshake_message(.server_hello, body)

	if sh.is_hello_retry_req {
		return h.handle_hello_retry_request(sh, full_sh_msg)
	}

	// Normal ServerHello: validate echoed fields and that a key share was selected
	// for our group; (EC)DHE cannot proceed without one.
	sh.validate(&h.config) or { return h.classify_failure(.illegal_parameter, err.msg()) }
	// §4.1.4: after a HelloRetryRequest the ServerHello suite must match the HRR's.
	if hrr_suite := h.hrr_cipher_suite {
		if hrr_suite != sh.cipher_suite {
			return h.classify_failure(.illegal_parameter, 'handshake: ServerHello cipher suite ${sh.cipher_suite} differs from HelloRetryRequest suite ${hrr_suite} (illegal_parameter)')
		}
	}
	if !sh.has_key_share {
		return h.classify_failure(.illegal_parameter, 'handshake: ServerHello missing key_share extension')
	}
	if sh.server_share.group != h.ecdhe_group {
		return h.classify_failure(.illegal_parameter, 'handshake: ServerHello key_share group ${sh.server_share.group} does not match offered group ${h.ecdhe_group}')
	}

	// The suite fixes both hash and key length; set them before deriving secrets.
	h.cipher_suite = sh.cipher_suite
	h.key_len = suite_key_len(sh.cipher_suite)
	h.set_hash_algo(suite_hash_algo(sh.cipher_suite))
	h.update_transcript(full_sh_msg)!

	// §7.1 handshake phase: derive the Handshake Secret and the client/server handshake traffic secrets.
	mut shared_secret := h.compute_shared_secret(sh.server_share)!
	defer {
		wipe_secret(mut shared_secret)
	}

	// The handshake secret is retained because the Master Secret derives from it.
	th_ch_sh := h.transcript.current_hash()
	hs := derive_hs_secrets(h.hash_algo, shared_secret, th_ch_sh)!
	h.handshake_secret = hs.handshake_secret
	h.client_hsk_traffic = hs.client_traffic
	h.server_hsk_traffic = hs.server_traffic

	h.state = .wait_encrypted_extensions
	return []HandshakeMessage{}
}

// handle_hello_retry_request validates a HelloRetryRequest, rewrites the
// transcript, and returns the retried ClientHello (RFC 8446 §4.1.4).
fn (mut h HandshakeCore) handle_hello_retry_request(sh ServerHello, full_sh_msg []u8) ![]HandshakeMessage {
	// §4.1.4: validate shared fields, reject a second HelloRetryRequest, and
	// require that the request actually changes something.
	sh.validate(&h.config) or { return h.classify_failure(.illegal_parameter, err.msg()) }
	if h.hrr_received {
		return h.classify_failure(.unexpected_message, 'handshake: received second HelloRetryRequest (unexpected_message)')
	}

	if !sh.has_key_share && sh.cookie.len == 0 {
		return h.classify_failure(.illegal_parameter, 'handshake: HelloRetryRequest would not change the ClientHello (illegal_parameter)')
	}
	if sh.has_key_share {
		// The requested group must be offered and differ from the one already sent a key share for (§4.2.8).
		if sh.server_share.group !in offered_groups(&h.config) {
			return h.classify_failure(.illegal_parameter, 'handshake: HelloRetryRequest requested unoffered group ${sh.server_share.group} (illegal_parameter)')
		}
		if sh.server_share.group == h.config.client_share.group {
			return h.classify_failure(.illegal_parameter, 'handshake: HelloRetryRequest reselected the already-offered group ${sh.server_share.group} (illegal_parameter)')
		}
	}

	h.hrr_received = true
	// §4.1.4: the final ServerHello must reuse this cipher suite.
	h.hrr_cipher_suite = sh.cipher_suite
	// §4.4.1: the message_hash uses the HRR suite's hash, so switch before applying the HRR.
	h.set_hash_algo(suite_hash_algo(sh.cipher_suite))
	h.transcript.apply_hello_retry_request(h.client_hello1, full_sh_msg)

	return h.build_second_client_hello(sh.has_key_share, sh.server_share.group, sh.cookie)!
}

// set_hash_algo adopts the negotiated suite's hash, rebuilding the transcript
// around it while keeping accumulated messages. A no-op when already matching.
fn (mut h HandshakeCore) set_hash_algo(algo HashAlgorithm) {
	if h.hash_algo == algo {
		return // already on the target digest — the common SHA-256 case, no rebuild
	}
	// The Transcript keeps raw messages, not a rolling digest, so a hash change
	// means reconstructing it around the new hash.
	h.hash_algo = algo
	h.transcript = Transcript{
		hash_algo: algo
		messages:  h.transcript.messages.clone()
	}
}

// build_second_client_hello builds the ClientHello retried after a
// HelloRetryRequest: identical to the first except key_share and cookie
// (RFC 8446 §4.1.2), level-tagged .initial.
fn (mut h HandshakeCore) build_second_client_hello(change_group bool, group NamedGroup, cookie []u8) ![]HandshakeMessage {
	if change_group {
		h.generate_key_share(group)!
		h.config.client_share = KeyShareEntry{
			group:        group
			key_exchange: h.public_share_bytes()!
		}
	}
	// A cookie-only HelloRetryRequest keeps the original key share; the cookie is
	// echoed verbatim (§4.1.4/§4.2.2).
	h.config.cookie = cookie
	_, full_ch2 := build_client_hello(h.config)!
	// Hash the retry into the already message_hash-rewritten transcript so the
	// Finished MAC covers the retried flight (§4.4.1).
	h.update_transcript(full_ch2)!

	h.state = .wait_server_hello // rearm: the server now answers with the real ServerHello
	return [new_handshake_message(.initial, full_ch2)!]
}

// ─── Encrypted flight: EE, Certificate, CertificateVerify, Finished (§4.3–§4.4) ───

// handle_encrypted_extensions records ALPN and QUIC transport parameters.
fn (mut h HandshakeCore) handle_encrypted_extensions(full_msg []u8, body []u8) ![]HandshakeMessage {
	if h.state != .wait_encrypted_extensions {
		return h.classify_failure(.unexpected_message, 'handshake: unexpected EncryptedExtensions')
	}
	alpn, transport_parameters := parse_encrypted_extensions_for_transport(body,
		h.config.is_quic) or {
		return h.classify_failure(.decode_error, err.msg())
	}
	// RFC 7301 §3.1: the server must pick from the offered list; an unoffered value
	// could steer the application protocol below us. `in` is exact element
	// membership — a substring test would let a hostile pick like "1.1" pass
	// against the offer "http/1.1".
	if alpn != '' && !(alpn in h.config.alpn) {
		return h.classify_failure(.illegal_parameter, 'handshake: server selected ALPN "${alpn}" not offered by client')
	}
	h.negotiated_alpn = alpn
	h.quic_params = transport_parameters
	h.update_transcript(full_msg)!
	h.state = .wait_certificate_request
	return []HandshakeMessage{}
}

// handle_certificate_request answers a server request with an empty Certificate.
fn (mut h HandshakeCore) handle_certificate_request(full_msg []u8, body []u8) ![]HandshakeMessage {
	// §4.3.2: the server wants client authentication; this client holds no
	// credential and acknowledges with an empty Certificate (§4.4.2).
	if h.state != .wait_certificate_request {
		return h.classify_failure(.unexpected_message, 'handshake: unexpected CertificateRequest')
	}
	req := parse_certificate_request(body) or {
		return h.classify_failure(.decode_error, err.msg())
	}
	h.update_transcript(full_msg)!
	h.request_context = req.request_context
	h.state = .wait_certificate

	// The empty Certificate-response (§4.4.2) enters the transcript BEFORE the
	// server's flight is verified, so the server Finished covers our response.
	response := build_empty_certificate(h.request_context)
	h.update_transcript(response)!
	return [new_handshake_message(.handshake, response)!]
}

// handle_certificate parses and validates the server certificate chain.
fn (mut h HandshakeCore) handle_certificate(full_msg []u8, body []u8) ![]HandshakeMessage {
	// §4.4.1: the server Certificate follows EncryptedExtensions directly, or a
	// CertificateRequest may sit before it; accept both orders.
	if h.state != .wait_certificate_request && h.state != .wait_certificate {
		return h.classify_failure(.unexpected_message, 'handshake: unexpected Certificate')
	}
	cert_ders := parse_certificate_message(body) or {
		return h.classify_failure(.decode_error, err.msg())
	}
	h.update_transcript(full_msg)!

	h.server_certs = []pki.Certificate{}
	for der in cert_ders {
		cert := pki.parse_certificate(der) or {
			return h.classify_failure(.decode_error, err.msg())
		}
		h.server_certs << cert
	}
	h.validator.verify_certificate_chain(h.server_certs, h.config.server_name) or {
		return h.classify_failure(.bad_certificate, err.msg())
	}
	h.state = .wait_certificate_verify
	return []HandshakeMessage{}
}

// handle_certificate_verify checks the server's signature over the transcript.
fn (mut h HandshakeCore) handle_certificate_verify(full_msg []u8, body []u8) ![]HandshakeMessage {
	if h.state != .wait_certificate_verify {
		return h.classify_failure(.unexpected_message, 'handshake: unexpected CertificateVerify')
	}
	cv := parse_certificate_verify(body) or {
		return h.classify_failure(.decode_error, err.msg())
	}
	signed_content := certificate_verify_signed_content(h.transcript.current_hash())
	h.update_transcript(full_msg)!

	if h.server_certs.len == 0 {
		return h.classify_failure(.decode_error, 'handshake: missing server certificate for verification')
	}
	verify_certificate_verify(leaf_key(h.server_certs[0]), cv, signed_content) or {
		return h.classify_failure(.decrypt_error, err.msg())
	}
	h.state = .wait_server_finished
	return []HandshakeMessage{}
}

// handle_finished verifies the server Finished and emits the client Finished.
fn (mut h HandshakeCore) handle_finished(full_msg []u8, body []u8) ![]HandshakeMessage {
	if h.state != .wait_server_finished {
		return h.classify_failure(.unexpected_message, 'handshake: unexpected Finished message')
	}
	// Verify the server Finished over the transcript up to but excluding this message.
	server_verify_data := parse_finished(body, h.hash_algo.hash_len()) or {
		return h.classify_failure(.decode_error, err.msg())
	}
	th_before_sfin := h.transcript.current_hash()

	expected_verify_data := compute_finished_verify_data(h.hash_algo, h.server_hsk_traffic, th_before_sfin)!
	// Constant-time compare: verify_data is a MAC over the transcript, and a naive
	// compare would leak a byte-by-byte Finished forgery.
	if subtle.constant_time_compare(server_verify_data, expected_verify_data) != 1 {
		return h.classify_failure(.decrypt_error, 'handshake: server Finished verify_data mismatch')
	}
	h.update_transcript(full_msg)!

	// Advance the key schedule to the application phase: Master Secret, then the
	// application traffic secrets bound to the transcript including server Finished.
	th_sfin := h.transcript.current_hash()
	ap := derive_app_secrets(h.hash_algo, h.handshake_secret, th_sfin)!
	h.client_app_traffic = ap.client_traffic
	h.server_app_traffic = ap.server_traffic

	// The client Finished uses the handshake traffic secret over the transcript now
	// including server Finished, sent under the (still active) handshake keys.
	client_verify_data := compute_finished_verify_data(h.hash_algo, h.client_hsk_traffic, th_sfin)!
	client_fin_msg := build_finished(client_verify_data)
	h.update_transcript(client_fin_msg)!

	// RFC 8446 §4.6.1/§4.5.5.1 let the server coalesce NewSessionTicket (type 4)
	// or KeyUpdate (type 24) behind its Finished; those stay buffered for the
	// adapter's take_buffered_handshake_bytes. Any other leader is flight garbage.
	if h.hsk_buf.len > 0 {
		leading := h.hsk_buf[0]
		if leading != u8(4) && leading != u8(24) {
			return h.classify_failure(.decode_error, 'handshake: unexpected trailing data after server Finished in handshake flight')
		}
	}

	h.state = .connected
	// Forward-secrecy cleanup: every ephemeral/handshake secret consumed to reach
	// this point is now dead (RFC 8446 §7.5 / §1.3.1).
	h.wipe_key_schedule_secrets()
	// Hand the raw client Finished to the transport, which encrypts it under the
	// still-active handshake keys.
	return [new_handshake_message(.handshake, client_fin_msg)!]
}

// ─── Secret lifecycle: wiping and zeroization (RFC 8446 §1.3.1/§7.5) ───

// wipe_traffic_secrets zeroes the client and server traffic secrets for one
// encryption level; the initial level has no TLS traffic secrets. It mirrors the
// QUIC-side peer_traffic_secrets() accessor (quic_handshake.v) so reads and
// wipes share the same phase vocabulary.
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
// ephemeral ECDHE halves at .connected (RFC 8446 §1.3.1/§7.5); it spares the
// handshake traffic secrets.
fn (mut h HandshakeCore) wipe_key_schedule_secrets() {
	wipe_secret(mut h.handshake_secret)
	// Release the ephemeral private keys; compute_shared_secret, their only consumer, already ran.
	h.release_ephemeral_keys()
}
