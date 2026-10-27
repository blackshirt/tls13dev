// Copyright (c) 2026 blackshirt.
//
// state_machine.v owns the entire transport-neutral handshake core shared by
// both adapters: client state, public accessors, reassembly and dispatch, the
// facade-shared HandshakeOptions, the ServerHello/HelloRetryRequest transition,
// and encrypted-flight processing.
// Ephemeral ECDHE lives in key_exchange.v and the derived-secret holders with
// their lifecycle in key_schedule.v, both as methods on this core.
// Transport-specific methods are defined on their
// facade — tls_handshake.v and quic_handshake.v — never promoted from here.
// Message codecs, the transcript, and the key schedule keep their own files.
module handshake

import crypto.ecdsa
import crypto.rand
import crypto.subtle
import tls.pki
import x.crypto.curve25519

//  Types: state, messages, options, and the core state struct

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
	buffers ReassemblyBuffers

	// Peer certificate validation and client certificate response state.
	validator    pki.Validator     // checks the server's certificate and hostname
	server_certs []pki.Certificate // certificates received from the server, leaf first

	// Handshake retry and outcome.
	hrr_cipher_suite ?CipherSuite   // suite from the retry request; presence marks a retry
	state            HandshakeState // position in the client state machine (RFC 8446 App. A.1)
	negotiated_alpn  string         // protocol chosen by the server, or empty if none
	fail_alert       AlertDescription = .internal_error // alert to report if the handshake fails
}

// reassembly_buf_cap is the initial per-level reassembly allocation; the hard bound
// a hostile peer must never exceed is enforced inline in receive_msgs_at_level
// against max_handshake_message_len.
const reassembly_buf_cap = 4096

// ReassemblyBuffers holds the initial- and handshake-level byte streams that do
// not yet form complete messages. Application-level bytes never reach the core.
struct ReassemblyBuffers {
mut:
	initial   []u8
	handshake []u8
}

// new_reassembly_buffers allocates both level buffers with the standard capacity.
fn new_reassembly_buffers() ReassemblyBuffers {
	return ReassemblyBuffers{
		initial:   []u8{cap: reassembly_buf_cap}
		handshake: []u8{cap: reassembly_buf_cap}
	}
}

// len reports the unconsumed byte count at one level.
fn (b &ReassemblyBuffers) len(level EncryptionLevel) int {
	return match level {
		.initial { b.initial.len }
		.handshake { b.handshake.len }
		.application { 0 }
	}
}

// append adds bytes to one level's reassembly buffer.
fn (mut b ReassemblyBuffers) append(level EncryptionLevel, bytes []u8) {
	match level {
		.initial { b.initial << bytes }
		.handshake { b.handshake << bytes }
		.application {}
	}
}

// handshake_leader returns the first buffered handshake-level byte, if any.
fn (b &ReassemblyBuffers) handshake_leader() ?u8 {
	if b.handshake.len == 0 {
		return none
	}
	return b.handshake[0]
}

// next_message extracts one complete framed message from one level's buffer.
fn (mut b ReassemblyBuffers) next_message(level EncryptionLevel) ![]u8 {
	match level {
		.initial { return next_recordless_message(mut b.initial) }
		.handshake { return next_recordless_message(mut b.handshake) }
		.application { return []u8{} }
	}
}

// take_handshake clones, zeroes and removes the handshake-level buffer, returning its bytes.
fn (mut b ReassemblyBuffers) take_handshake() []u8 {
	taken := b.handshake.clone()
	for i in 0 .. b.handshake.len {
		b.handshake[i] = 0
	}
	b.handshake = []u8{}
	return taken
}

// clear_all drops both level buffers on terminal failure.
fn (mut b ReassemblyBuffers) clear_all() {
	b.initial = []u8{}
	b.handshake = []u8{}
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
		state:      HandshakeState.start
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
// messages are still legal on the wire.
pub fn (h &HandshakeCore) state() HandshakeState {
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
pub fn (h &HandshakeCore) negotiated_alpn() string {
	return h.negotiated_alpn
}

// negotiated_cipher_suite reports the suite selected by the server in ServerHello.
pub fn (h &HandshakeCore) negotiated_cipher_suite() CipherSuite {
	return h.cipher_suite
}

// failure_alert returns the alert description an adapter should surface when
// this handshake dies (RFC 8446 §6).
pub fn (h &HandshakeCore) failure_alert() AlertDescription {
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
pub fn (mut h HandshakeCore) create_client_hello() ![]u8 {
	// A second call would replay the first ClientHello into the transcript and
	// corrupt every later hash; the retry ClientHello has its own path via
	// receive_msgs_at_level().
	if h.state != HandshakeState.start {
		return error('handshake: create_client_hello() only runs once (state: ${h.state()}); the retry ClientHello is produced by receive_msgs_at_level() during HelloRetryRequest handling')
	}
	_, full_client_hello := build_client_hello(h.config)!
	h.update_transcript(full_client_hello)!

	h.state = .wait_sh
	return full_client_hello
}

// receive_msgs_at_level processes bytes using the encryption-level reassembly buffers
// owned by the selected transport facade, returning any outbound messages triggered.
// Initial-level input is accepted only while awaiting ServerHello; handshake-level
// input is accepted only between ServerHello and Finished. Phase misuse is rejected
// without consuming bytes or changing state.
pub fn (mut h HandshakeCore) receive_msgs_at_level(level EncryptionLevel, bytes []u8) ![]HandshakeMessage {
	if h.state == HandshakeState.start {
		return error('handshake: receive_msgs_at_level() before create_client_hello() — no ClientHello has been sent yet')
	}
	if h.state == HandshakeState.failed {
		return error('handshake: state machine has failed; receive_msgs_at_level() refuses further messages')
	}
	if level == .application {
		return error('handshake: receive_msgs_at_level() does not accept application-level bytes')
	}
	if !h.level_is_open(level) {
		msg := if level == .handshake {
			'handshake: handshake-level bytes are only expected after ServerHello and before Finished (state: ${h.state()})'
		} else {
			'handshake: initial handshake bytes are only expected while awaiting ServerHello (state: ${h.state()})'
		}
		return error(msg)
	}
	return h.append_and_drain(level, bytes)
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
		available := limit - h.buffers.len(level)
		if offset < bytes.len && available == 0 {
			alert := if level == .initial { 'initial-level' } else { 'handshake-level' }
			return h.classify_failure(.decode_error, 'handshake: ${alert} reassembly exceeds ${max_handshake_message_len} bytes without completing a message')
		}
		take := if bytes.len - offset > available { available } else { bytes.len - offset }
		if take > 0 {
			h.buffers.append(level, bytes[offset..offset + take])
			offset += take
		}
		messages := h.drain(level) or {
			h.fail_and_zeroize_secrets()
			return err
		}
		out << messages
		if offset == bytes.len {
			break
		}
	}
	return out
}

// level_is_open reports whether one level's buffer is legal for the current state;
// receive_msgs_at_level and drain() share it as the single phase-legality rule.
fn (h &HandshakeCore) level_is_open(level EncryptionLevel) bool {
	return match level {
		.initial { h.state == .wait_sh }
		.handshake { h.in_flight() }
		.application { false }
	}
}

// drain consumes every complete message one level's buffer currently holds.
// Framing-boundary checks remain adapter policy.
fn (mut h HandshakeCore) drain(level EncryptionLevel) ![]HandshakeMessage {
	mut out := []HandshakeMessage{}
	for h.level_is_open(level) {
		msg := h.buffers.next_message(level) or {
			return h.fail_with(.decode_error, err)
		}
		if msg.len == 0 {
			break // header or body still incomplete
		}
		out_msgs := if level == .initial {
			h.handle_server_hello_message(msg) or { return err }
		} else {
			h.handle_handshake_message(msg) or { return err }
		}
		out << out_msgs
	}
	return out
}

// accepts_handshake_message is the single ordering check for the encrypted
// flight: it names the message types legal in the current state, so each handler
// only parses and transitions.
fn (h &HandshakeCore) accepts_handshake_message(msg_type HandshakeType) bool {
	return match h.state {
		.wait_ee { msg_type == .encrypted_extensions }
		.wait_cert_cr {
			msg_type == .certificate_request || msg_type == .certificate
		}
		.wait_cert { msg_type == .certificate }
		.wait_cv { msg_type == .certificate_verify }
		.wait_finished { msg_type == .finished }
		else { false }
	}
}

// unexpected_handshake_message preserves the per-message wording adapters and
// tests rely on when ordering rejects a message.
fn unexpected_handshake_message(msg_type HandshakeType) string {
	return match msg_type {
		.encrypted_extensions { 'handshake: unexpected EncryptedExtensions' }
		.certificate_request { 'handshake: unexpected CertificateRequest' }
		.certificate { 'handshake: unexpected Certificate' }
		.certificate_verify { 'handshake: unexpected CertificateVerify' }
		.finished { 'handshake: unexpected Finished message' }
		else { 'handshake: unexpected handshake message ${msg_type}' }
	}
}

// handle_handshake_message processes one complete encrypted-flight message:
// EE, optional CertificateRequest, Certificate, CertificateVerify, or Finished.
fn (mut h HandshakeCore) handle_handshake_message(full_msg []u8) ![]HandshakeMessage {
	// The message is complete by construction (reassembly framed it by its own
	// header), so peel type/length and split the body off.
	msg_type, body := split_handshake_message(full_msg) or {
		return h.fail_with(.decode_error, err)
	}
	if !h.accepts_handshake_message(msg_type) {
		return h.classify_failure(.unexpected_message, unexpected_handshake_message(msg_type))
	}

	match msg_type {
		.encrypted_extensions { return h.handle_encrypted_extensions(full_msg, body) }
		.certificate_request { return h.handle_certificate_request(full_msg, body) }
		.certificate { return h.handle_certificate(full_msg, body) }
		.certificate_verify { return h.handle_certificate_verify(full_msg, body) }
		.finished { return h.handle_finished(full_msg, body) }
		else {
			return h.classify_failure(.unexpected_message, unexpected_handshake_message(msg_type))
		}
	}
}

//  ServerHello / HelloRetryRequest transition (RFC 8446 §4.1.3/§4.1.4)

// handle_server_hello_message consumes one complete initial-level ServerHello
// or HelloRetryRequest and returns the follow-up messages (RFC 8446 §4.1.3).
fn (mut h HandshakeCore) handle_server_hello_message(sh_msg []u8) ![]HandshakeMessage {
	if h.state != .wait_sh {
		// Strict ordering: a ServerHello is only legal while we await it (§4.4.1).
		return h.classify_failure(.unexpected_message, 'handshake: unexpected ServerHello in state ${h.state()}')
	}

	// Peel the 4-byte handshake header (type || 3-byte length) to bound the body (§4).
	msg_type, body := split_handshake_message(sh_msg) or {
		return h.fail_with(.decode_error, err)
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
		return h.fail_with(.decode_error, err)
	}
	// Re-frame header + body so the transcript covers the exact wire layout.
	full_sh_msg := wrap_handshake_message(.server_hello, body)

	if sh.is_hello_retry_req {
		return h.handle_hello_retry_request(sh, full_sh_msg)
	}

	// Normal ServerHello: validate echoed fields and that a key share was selected
	// for our group; (EC)DHE cannot proceed without one.
	sh.validate(&h.config) or { return h.fail_with(.illegal_parameter, err) }
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
	// Derive the retained Handshake Secret first, then expand each direction's traffic
	// secret from it; all three land in locals before moving to the core's flat fields.
	// The Handshake Secret is retained (stored to h.handshake_secret below), so it
	// cannot be defer-wiped — a defer would zero the shared buffer the field still
	// needs. Instead each expansion wipes it on its own error path, before any field
	// owns it, so the split's cross-function value never leaks even if HKDF fails.
	mut hs_secret := derive_handshake_secret(h.hash_algo, shared_secret)!
	c_hs := derive_client_hs_secret(h.hash_algo, hs_secret, th_ch_sh) or {
		wipe_secret(mut hs_secret)
		return err
	}
	s_hs := derive_server_hs_secret(h.hash_algo, hs_secret, th_ch_sh) or {
		wipe_secret(mut hs_secret)
		return err
	}
	h.handshake_secret = hs_secret
	h.c_hsk_tsec = c_hs
	h.s_hsk_tsec = s_hs

	h.state = .wait_ee
	return []HandshakeMessage{}
}

// handle_hello_retry_request validates a HelloRetryRequest, rewrites the
// transcript, and returns the retried ClientHello (RFC 8446 §4.1.4).
fn (mut h HandshakeCore) handle_hello_retry_request(sh ServerHello, full_sh_msg []u8) ![]HandshakeMessage {
	// §4.1.4: validate shared fields, reject a second HelloRetryRequest, and
	// require that the request actually changes something.
	sh.validate(&h.config) or { return h.fail_with(.illegal_parameter, err) }
	if h.hrr_cipher_suite != none {
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

	// §4.1.4: the final ServerHello must reuse this cipher suite; presence also
	// marks that a retry has already been accepted.
	h.hrr_cipher_suite = sh.cipher_suite
	// §4.4.1: the message_hash uses the HRR suite's hash, so switch before applying the HRR.
	h.set_hash_algo(suite_hash_algo(sh.cipher_suite))
	h.transcript.apply_hello_retry_request(full_sh_msg)

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

	h.state = .wait_sh // rearm: the server now answers with the real ServerHello
	return [new_handshake_message(.initial, full_ch2)!]
}

//  Encrypted flight: EE, Certificate, CertificateVerify, Finished (§4.3–§4.4)

// handle_encrypted_extensions records ALPN and QUIC transport parameters.
fn (mut h HandshakeCore) handle_encrypted_extensions(full_msg []u8, body []u8) ![]HandshakeMessage {
	alpn, transport_parameters := parse_encrypted_extensions_for_transport(body,
		h.config.is_quic) or {
		return h.fail_with(.decode_error, err)
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
	h.state = .wait_cert_cr
	return []HandshakeMessage{}
}

// handle_certificate_request answers a server request with an empty Certificate.
fn (mut h HandshakeCore) handle_certificate_request(full_msg []u8, body []u8) ![]HandshakeMessage {
	// §4.3.2: the server wants client authentication; this client holds no
	// credential and acknowledges with an empty Certificate (§4.4.2).
	req := parse_certificate_request(body) or {
		return h.fail_with(.decode_error, err)
	}
	h.update_transcript(full_msg)!
	h.state = .wait_cert

	// The empty Certificate-response (§4.4.2) enters the transcript BEFORE the
	// server's flight is verified, so the server Finished covers our response.
	response := build_empty_certificate(req.request_context)
	h.update_transcript(response)!
	return [new_handshake_message(.handshake, response)!]
}

// handle_certificate parses and validates the server certificate chain.
fn (mut h HandshakeCore) handle_certificate(full_msg []u8, body []u8) ![]HandshakeMessage {
	// §4.4.1: the server Certificate follows EncryptedExtensions directly, or a
	// CertificateRequest may sit before it; accepts_handshake_message allows both.
	cert_ders := parse_certificate_message(body) or {
		return h.fail_with(.decode_error, err)
	}
	h.update_transcript(full_msg)!

	h.server_certs = []pki.Certificate{}
	for der in cert_ders {
		cert := pki.parse_certificate(der) or {
			return h.fail_with(.decode_error, err)
		}
		h.server_certs << cert
	}
	h.validator.verify_certificate_chain(h.server_certs, h.config.server_name) or {
		return h.fail_with(.bad_certificate, err)
	}
	h.state = .wait_cv
	return []HandshakeMessage{}
}

// handle_certificate_verify checks the server's signature over the transcript.
fn (mut h HandshakeCore) handle_certificate_verify(full_msg []u8, body []u8) ![]HandshakeMessage {
	cv := parse_certificate_verify(body) or {
		return h.fail_with(.decode_error, err)
	}
	signed_content := certificate_verify_signed_content(h.transcript.current_hash())
	h.update_transcript(full_msg)!

	if h.server_certs.len == 0 {
		return h.classify_failure(.decode_error, 'handshake: missing server certificate for verification')
	}
	verify_certificate_verify(leaf_key(h.server_certs[0]), cv, signed_content) or {
		return h.fail_with(.decrypt_error, err)
	}
	h.state = .wait_finished
	return []HandshakeMessage{}
}

// handle_finished verifies the server Finished and emits the client Finished.
fn (mut h HandshakeCore) handle_finished(full_msg []u8, body []u8) ![]HandshakeMessage {
	// Verify the server Finished over the transcript up to but excluding this message.
	server_verify_data := parse_finished(body, h.hash_algo.hash_len()) or {
		return h.fail_with(.decode_error, err)
	}
	th_before_sfin := h.transcript.current_hash()

	expected_verify_data := compute_finished_verify_data(h.hash_algo, h.s_hsk_tsec,
		th_before_sfin)!
	// Constant-time compare: verify_data is a MAC over the transcript, and a naive
	// compare would leak a byte-by-byte Finished forgery.
	if subtle.constant_time_compare(server_verify_data, expected_verify_data) != 1 {
		return h.classify_failure(.decrypt_error, 'handshake: server Finished verify_data mismatch')
	}
	h.update_transcript(full_msg)!

	// Advance the key schedule to the application phase: Master Secret, then the
	// application traffic secrets bound to the transcript including server Finished.
	th_sfin := h.transcript.current_hash()
	mut master_secret := derive_master_secret(h.hash_algo, h.handshake_secret)!
	// The Master Secret now crosses into the caller, so defer wipes it on every exit
	// path — including an error from the two expansions below — so it cannot leak.
	defer { wipe_secret(mut master_secret) }
	c_ap := derive_client_app_secret(h.hash_algo, master_secret, th_sfin)!
	s_ap := derive_server_app_secret(h.hash_algo, master_secret, th_sfin)!
	// §7.5: erase as soon as no longer required; the defer above is idempotent, so this
	// early wipe just shortens the happy-path lifetime. The Master Secret is never
	// stored — KeyUpdate (§7.2) chains from the traffic secrets alone.
	wipe_secret(mut master_secret)
	h.c_app_tsec = c_ap
	h.s_app_tsec = s_ap

	// The client Finished uses the handshake traffic secret over the transcript now
	// including server Finished, sent under the (still active) handshake keys.
	client_verify_data := compute_finished_verify_data(h.hash_algo, h.c_hsk_tsec,
		th_sfin)!
	client_fin_msg := build_finished(client_verify_data)
	h.update_transcript(client_fin_msg)!

	// RFC 8446 §4.6.1/§4.5.5.1 let the server coalesce NewSessionTicket (type 4)
	// or KeyUpdate (type 24) behind its Finished; those stay buffered for the
	// adapter's take_buffered_handshake_bytes. Any other leader is flight garbage.
	if leading := h.buffers.handshake_leader() {
		if leading != u8(4) && leading != u8(24) {
			return h.classify_failure(.decode_error, 'handshake: unexpected trailing data after server Finished in handshake flight')
		}
	}

	h.state = HandshakeState.connected
	// Forward-secrecy cleanup: every ephemeral/handshake secret consumed to reach
	// this point is now dead (RFC 8446 §7.5 / §1.3.1).
	h.wipe_key_schedule_secrets()
	// Hand the raw client Finished to the transport, which encrypts it under the
	// still-active handshake keys.
	return [new_handshake_message(.handshake, client_fin_msg)!]
}
