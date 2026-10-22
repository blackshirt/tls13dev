// Copyright (c) 2026 blackshirt.
//
// state_machine.v sequences the TLS 1.3 client handshake of RFC 8446, driving
// messages.v, aead.v, the §7.1 key schedule (handshake_keys.v) and the
// server-signature check (certificate_verify.v). Transport-neutral: it owns no
// record, cipher or socket concept, only level-tagged bytes (RFC 9001 §4.1).
//
// Public transport facades live in record_handshaker.v and quic_handshaker.v;
// this file owns the shared handshake state machine.
module handshake

import crypto.ecdsa
import crypto.rand
import crypto.subtle
import x.crypto.curve25519
import tls.pki
import tls.wire

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
// encryption level (RFC 9001 §4.1), msg holds the wire bytes, header included.
@[noinit]
pub struct HandshakeMessage {
	level SecretLevel
	msg   []u8
}

// level returns the encryption level this message belongs to.
pub fn (m &HandshakeMessage) level() SecretLevel {
	return m.level
}

// msg returns the complete handshake message bytes (4-byte header included).
pub fn (m &HandshakeMessage) msg() []u8 {
	return m.msg
}

// new_handshake_message builds a HandshakeMessage for producers outside this
// module; msg must be exactly one complete handshake message (RFC 8446 §4).
pub fn new_handshake_message(level SecretLevel, msg []u8) !HandshakeMessage {
	mut r := wire.new_reader(msg)
	_, length := parse_handshake_header(mut r)!
	if r.remaining() != length {
		return error('handshake: handshake message header declares ${length} body bytes, message carries ${r.remaining()}')
	}
	return HandshakeMessage{
		level: level
		msg:   msg
	}
}

// SecretLevel names a QUIC encryption level (RFC 9001 §4.1): each level has its
// own CRYPTO stream and traffic secrets; the TCP transport uses .handshake only.
pub enum SecretLevel {
	initial
	handshake
	application
}

// HandshakeCore owns shared TLS 1.3 handshake state and behavior.
@[noinit]
struct HandshakeCore {
mut:
	config            ClientHelloConfig // inputs echoed/replayed when rebuilding the second ClientHello
	transcript        Transcript        // running hash of all handshake messages (RFC 8446 §4.4.1)
	hash_algo         HashAlgorithm     // hash of the negotiated suite; drives every key derivation
	cipher_suite      CipherSuite       // suite selected by the server in ServerHello
	key_len           int               // AEAD key length of that suite (16 or 32 bytes)
	ecdhe_group       NamedGroup        // group of our key share; may change on HelloRetryRequest
	priv_x25519       &curve25519.PrivateKey = unsafe { nil } // private half of the X25519 share
	priv_p256         ?ecdsa.PrivateKey // private half of the P-256 share, set when that group is used
	client_hello1     []u8              // full first ClientHello, kept for the HRR message_hash substitution (§4.4.1)
	handshake_secret  []u8              // Early Secret → Handshake Secret stage (§7.1)
	client_hs_traffic []u8              // client handshake traffic secret (§7.1)
	server_hs_traffic []u8              // server handshake traffic secret (§7.1)
	// Traffic secrets are shared by record and QUIC adapters.
	client_ap_traffic []u8 // client application traffic secret (§7.1), kept for KeyUpdate
	server_ap_traffic []u8 // server application traffic secret (§7.1), kept for KeyUpdate
	// TLS handshake streams are protocol state shared by the core's message
	// processing, independent of the transport facade that owns this core.
	initial_reassembly []u8
	hs_reassembly      []u8
	validator          pki.Validator     // trust anchors + hostname policy, injected at construction
	server_certs       []pki.Certificate // chain sent by the server, leaf first, once Certificate is parsed
	request_context    []u8              // certificate_request_context echoed from a server CertificateRequest (§4.3.2); drives the empty client Certificate (§4.4.2)
	hrr_received       bool              // set after a HelloRetryRequest so the second CH is validated as such
	hrr_cipher_suite   ?CipherSuite      // suite selected in the HelloRetryRequest; the final ServerHello must reuse it (§4.1.4)
	// Progress and outcome fields adapters poll; surfaced through state() and negotiated_alpn() rather than made public directly.
	state           HandshakeState
	negotiated_alpn string // server's ALPN pick, '' if none; the RFC 7301 §3.1 check guarantees it was one of config.alpn
	// fail_alert is the alert description an adapter should surface when this handshake dies; §6 makes internal_error a legal catch-all, and the sites that can classify their failure precisely overwrite it.
	fail_alert AlertDescription = .internal_error
}

// new_handshake_core creates shared state offering an X25519 key share
// (RFC 8446 §9.1), with certificate validation policy injected by the caller.
fn new_handshake_core(server_name string, alpn []string, validator pki.Validator) !HandshakeCore {
	// TLS 1.3 has no separate key-exchange round trip: the public share must ride in the initial ClientHello (§4.2.8).
	mut priv_key := curve25519.PrivateKey.new()! // fresh 32-byte X25519 scalar
	pub_key := priv_key.public_key()!
	raw_pub := pub_key.bytes()! // 32-byte encoding placed verbatim in key_exchange
	// Pin the session id and random now: the retry ClientHello must reproduce them byte-identically (§4.1.4).
	session_id := rand.bytes(legacy_session_id_len)! // 32 bytes for middlebox compatibility (App. D.4)
	random := rand.bytes(client_hello_random_len)!

	// Assemble the initial hello with an X25519 key share; the cookie stays empty until a HelloRetryRequest supplies one.
	cfg := ClientHelloConfig{
		server_name:  server_name
		alpn:         alpn
		client_share: KeyShareEntry{
			group:        .x25519
			key_exchange: raw_pub
		}
		session_id:   session_id
		random:       random
	}

	return HandshakeCore{
		state:              .start
		config:             cfg
		transcript:         new_transcript(.sha256)
		hash_algo:          .sha256
		key_len:            16
		ecdhe_group:        .x25519
		priv_x25519:        priv_key
		validator:          validator
		initial_reassembly: []u8{cap: 4096}
		hs_reassembly:      []u8{cap: 4096}
	}
}

// state reports current handshake progress; the TCP adapter polls it to know
// when the handshake completed and which messages are still legal on the wire.
pub fn (h &HandshakeCore) state() HandshakeState {
	return h.state
}

// negotiated_alpn returns the ALPN protocol the server picked ('' when none).
pub fn (h &HandshakeCore) negotiated_alpn() string {
	return h.negotiated_alpn
}

// failure_alert returns the alert description an adapter should surface when
// this handshake dies (RFC 8446 §6); QUIC maps it with quic_connection_error (§4.8).
pub fn (h &HandshakeCore) failure_alert() AlertDescription {
	return h.fail_alert
}

// create_client_hello generates the initial ClientHello, advances to
// .wait_server_hello and returns the raw bytes to hash and frame (RFC 8446 App. D.4).
pub fn (mut h HandshakeCore) create_client_hello() ![]u8 {
	// A second call would replay the first ClientHello into the transcript and corrupt every later hash; the retry ClientHello has its own path via receive().
	if h.state != .start {
		return error('handshake: create_client_hello() only runs once (state: ${h.state}); the retry ClientHello is produced by receive() during HelloRetryRequest handling')
	}
	// Pin random/session id now: §4.1.4 requires the retry ClientHello to be identical except key_share/cookie (§4.1.3 compares the echo).
	if h.config.session_id.len == 0 {
		h.config.session_id = rand.bytes(legacy_session_id_len)!
	}
	if h.config.random.len != client_hello_random_len {
		h.config.random = rand.bytes(client_hello_random_len)!
	}
	_, full_client_hello := build_client_hello(h.config)!
	h.client_hello1 = full_client_hello.clone()
	h.transcript.update(full_client_hello)

	h.state = .wait_server_hello
	return full_client_hello
}

// handle_server_hello_message consumes one complete Initial-level ServerHello
// or HelloRetryRequest and returns the follow-up messages (RFC 8446 §4.1.3).
fn (mut h HandshakeCore) handle_server_hello_message(sh_msg []u8) ![]HandshakeMessage {
	if h.state != .wait_server_hello {
		// Strict ordering: a ServerHello is only legal while we await it (§4.4.1).
		h.fail_alert = .unexpected_message
		return error('handshake: unexpected ServerHello in state ${h.state}')
	}

	// Peel the 4-byte handshake header (type || 3-byte length) to bound the body (§4).
	mut r := wire.new_reader(sh_msg)
	msg_type, length := parse_handshake_header(mut r)!
	if msg_type != .server_hello {
		// HelloRetryRequest reuses the ServerHello type value (2) and is told apart only by the sentinel random (§4.1.3).
		h.fail_alert = .unexpected_message
		return error('handshake: expected ServerHello (2), got ${msg_type}')
	}
	body := r.read_bytes(length)! // body only; the header is re-added for the transcript
	// §5.1's record-boundary rule is deliberately not checked here: reassembly already handed over exactly one complete handshake message, and QUIC has no record boundaries at all; the TCP adapter enforces it via record_unconsumed_bytes().
	sh := parse_server_hello(body)! // §4.1.3 field decode plus the §4.2 extension allowlist
	// Re-frame header + body so the transcript covers the exact wire layout.
	full_sh_msg := wrap_handshake_message(.server_hello, body)

	if sh.is_hello_retry_req {
		// §4.1.4: validate shared fields, reject a second HelloRetryRequest, and require that the request actually changes something.
		sh.validate(&h.config) or {
			h.fail_alert = .illegal_parameter
			return err
		}
		if h.hrr_received {
			h.fail_alert = .unexpected_message
			return error('handshake: received second HelloRetryRequest (unexpected_message)')
		}

		if !sh.has_key_share && sh.cookie.len == 0 {
			h.fail_alert = .illegal_parameter
			return error('handshake: HelloRetryRequest would not change the ClientHello (illegal_parameter)')
		}
		if sh.has_key_share {
			// The requested group must be offered and differ from the one already sent a key share for (§4.2.8).
			if !is_supported_group(sh.server_share.group) {
				h.fail_alert = .illegal_parameter
				return error('handshake: HelloRetryRequest requested unsupported group ${sh.server_share.group} (illegal_parameter)')
			}
			if sh.server_share.group == h.config.client_share.group {
				h.fail_alert = .illegal_parameter
				return error('handshake: HelloRetryRequest reselected the already-offered group ${sh.server_share.group} (illegal_parameter)')
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

	// Normal ServerHello: validate echoed fields and that a key share was selected for our group; (EC)DHE cannot proceed without one.
	sh.validate(&h.config) or {
		h.fail_alert = .illegal_parameter
		return err
	}
	// §4.1.4: after a HelloRetryRequest the ServerHello suite must match the HRR's.
	if hrr_suite := h.hrr_cipher_suite {
		if hrr_suite != sh.cipher_suite {
			h.fail_alert = .illegal_parameter
			return error('handshake: ServerHello cipher suite ${sh.cipher_suite} differs from HelloRetryRequest suite ${hrr_suite} (illegal_parameter)')
		}
	}
	if !sh.has_key_share {
		h.fail_alert = .illegal_parameter
		return error('handshake: ServerHello missing key_share extension')
	}
	if sh.server_share.group != h.ecdhe_group {
		h.fail_alert = .illegal_parameter
		return error('handshake: ServerHello key_share group ${sh.server_share.group} does not match offered group ${h.ecdhe_group}')
	}

	// The suite fixes both hash and key length; set them before deriving secrets.
	h.cipher_suite = sh.cipher_suite
	h.key_len = suite_key_len(sh.cipher_suite)
	h.set_hash_algo(suite_hash_algo(sh.cipher_suite))
	h.transcript.update(full_sh_msg)

	// §7.1 handshake phase: derive the Handshake Secret and the client/server handshake traffic secrets.
	shared_secret := h.compute_shared_secret(sh.server_share)!

	// The handshake secret is retained because the Master Secret derives from it.
	th_ch_sh := h.transcript.current_hash()
	hs := derive_hs_secrets(h.hash_algo, shared_secret, th_ch_sh)!
	h.handshake_secret = hs.handshake_secret
	h.client_hs_traffic = hs.client_traffic
	h.server_hs_traffic = hs.server_traffic

	h.state = .wait_encrypted_extensions
	return []HandshakeMessage{}
}

// set_hash_algo adopts the negotiated suite's hash, rebuilding the transcript
// around it while keeping accumulated messages. A no-op when already matching.
fn (mut h HandshakeCore) set_hash_algo(algo HashAlgorithm) {
	if h.hash_algo == algo {
		return // already on the target digest — the common SHA-256 case, no rebuild
	}
	// The Transcript keeps raw messages, not a rolling digest, so a hash change means reconstructing it around the new hash.
	h.hash_algo = algo
	h.transcript = Transcript{
		hash_algo: algo
		messages:  h.transcript.messages.clone()
	}
}

// build_second_client_hello builds the ClientHello retried after a
// HelloRetryRequest: identical to the first except key_share and cookie (RFC 8446 §4.1.2), level-tagged .initial.
fn (mut h HandshakeCore) build_second_client_hello(change_group bool, group NamedGroup, cookie []u8) ![]HandshakeMessage {
	if change_group {
		h.generate_key_share(group)!
		h.config.client_share = KeyShareEntry{
			group:        group
			key_exchange: h.public_share_bytes()!
		}
	}
	// A cookie-only HelloRetryRequest keeps the original key share; the cookie is echoed verbatim (§4.1.4/§4.2.2).
	h.config.cookie = cookie
	_, full_ch2 := build_client_hello(h.config)!
	// Hash the retry into the already message_hash-rewritten transcript so the Finished MAC covers the retried flight (§4.4.1).
	h.transcript.update(full_ch2)

	h.state = .wait_server_hello // rearm: the server now answers with the real ServerHello
	return [new_handshake_message(.initial, full_ch2)!]
}

// generate_key_share creates a fresh ephemeral private key for the requested group.
fn (mut h HandshakeCore) generate_key_share(group NamedGroup) ! {
	h.ecdhe_group = group
	match group {
		.x25519 {
			h.priv_x25519 = curve25519.PrivateKey.new()!
			h.priv_p256 = none
		}
		.secp256r1 {
			h.priv_p256 = ecdsa.PrivateKey.new(nid: .prime256v1)!
			// priv_x25519 is left populated: dispatch routes on ecdhe_group, so a stale X25519 key is unreachable.
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
	// §4.2.8.2 fixes key_exchange size per group; gate it here so a wrong size yields a named protocol error.
	expected_len := match server_share.group {
		.x25519 { 32 }
		.secp256r1 { 65 } // 0x04 || X || Y uncompressed point
	}
	if server_share.key_exchange.len != expected_len {
		h.fail_alert = .illegal_parameter
		return error('handshake: ${server_share.group} key_share is ${server_share.key_exchange.len} bytes, expected ${expected_len}')
	}
	match server_share.group {
		.x25519 {
			if h.priv_x25519 == unsafe { nil } {
				return error('handshake: missing X25519 private key')
			}
			// §4.2.8.2 & RFC 7748 §6.1: an all-zero peer u-coordinate would yield an all-zero secret; gate before the backend.
			if subtle.constant_time_compare(server_share.key_exchange, []u8{len: 32, init: 0}) == 1 {
				h.fail_alert = .illegal_parameter
				return error('handshake: computed X25519 shared secret is all-zero value (illegal_parameter)')
			}
			secret := h.priv_x25519.x25519(server_share.key_exchange)!
			// Defense in depth: reject every small-order result, not just the all-zero one.
			if is_x25519_small_order(secret) {
				h.fail_alert = .illegal_parameter
				return error('handshake: computed X25519 shared secret is a small-order value (illegal_parameter)')
			}
			return secret
		}
		.secp256r1 {
			// Only the uncompressed encoding is legal in TLS 1.3 (§4.2.8.2); compressed shares start 0x02/0x03.
			if server_share.key_exchange[0] != 0x04 {
				return error('handshake: P-256 key_share is not an uncompressed point (0x04 prefix)')
			}
			priv := h.priv_p256 or { return error('handshake: missing P-256 private key') }
			peer := ecdsa.PublicKey.from_uncompressed_bytes(server_share.key_exchange,
				nid: .prime256v1
			)!
			secret := priv.derive_shared_secret(peer)!
			if subtle.constant_time_compare(secret, []u8{len: secret.len, init: 0}) == 1 {
				h.fail_alert = .illegal_parameter
				return error('handshake: computed P-256 shared secret is all-zero value (illegal_parameter)')
			}
			return secret
		}
	}
	// Unreachable: the match above is exhaustive over NamedGroup.
	return error('handshake: unsupported key_share group ${server_share.group}')
}

// receive processes bytes using the encryption-level reassembly buffers owned
// by the selected transport facade, returning any outbound messages triggered.
pub fn (mut h HandshakeCore) receive(level SecretLevel, bytes []u8) ![]HandshakeMessage {
	if h.state == .start {
		return error('handshake: receive() before create_client_hello() — no ClientHello has been sent yet')
	}
	if h.state == .failed {
		return error('handshake: state machine has failed; receive() refuses further messages')
	}
	match level {
		.initial {
			if h.state != .wait_server_hello {
				return error('handshake: Initial-level bytes are only expected while awaiting ServerHello (state: ${h.state})')
			}
			h.initial_reassembly << bytes
			out := h.drain_initial() or {
				h.abort()
				return err
			}
			// One receive may coalesce a consumed ServerHello with an oversized tail the loop no longer reaches; bound it even where drain cannot.
			if h.initial_reassembly.len > 4 + max_handshake_message_len {
				h.fail_alert = .decode_error
				h.abort()
				return error('handshake: Initial-level reassembly exceeds ${max_handshake_message_len} bytes without completing a message')
			}
			return out
		}
		.handshake {
			h.hs_reassembly << bytes
			out := h.drain_handshake() or {
				h.abort()
				return err
			}
			// Same bound for the Handshake level: late retransmits at .connected skip the drain loop, so the cap is the backstop.
			if h.hs_reassembly.len > 4 + max_handshake_message_len {
				h.fail_alert = .decode_error
				h.abort()
				return error('handshake: Handshake-level reassembly exceeds ${max_handshake_message_len} bytes without completing a message')
			}
			return out
		}
		.application {
			return error('handshake: application-level bytes are post-handshake traffic; parse them with handle_post_handshake (RFC 8446 §4.6)')
		}
	}
}

// drain_initial consumes the complete ServerHello/HelloRetryRequest from the
// Initial-level buffer; leftover bytes are the adapter's concern (record_unconsumed_bytes).
fn (mut h HandshakeCore) drain_initial() ![]HandshakeMessage {
	mut out := []HandshakeMessage{}
	for h.state == .wait_server_hello {
		msg := next_passthrough_message(mut h.initial_reassembly)!
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

// drain_handshake consumes the complete messages of the encrypted flight —
// EE → Cert → CV → Finished — until the buffer runs dry or the handshake ends.
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
fn (h &HandshakeCore) unconsumed_bytes(level SecretLevel) int {
	return match level {
		.initial { h.initial_reassembly.len }
		.handshake { h.hs_reassembly.len }
		.application { 0 }
	}
}

// on_handshake_confirmed destroys the handshake-stage traffic secrets; run it
// only once the handshake is confirmed (RFC 9001 §4.1.2/§4.9.2).
pub fn (mut h HandshakeCore) on_handshake_confirmed() ! {
	if h.state != .connected {
		return error('handshake: on_handshake_confirmed() runs only once the handshake reached .connected (state: ${h.state})')
	}
	for i in 0 .. h.client_hs_traffic.len {
		h.client_hs_traffic[i] = 0
	}
	for i in 0 .. h.server_hs_traffic.len {
		h.server_hs_traffic[i] = 0
	}
	h.client_hs_traffic = []u8{}
	h.server_hs_traffic = []u8{}
}

// quic_traffic_secrets returns (client, server) clones of the §7.1 traffic
// secrets for one level, to expand under the RFC 9001 §5.1 labels; .initial is refused.
pub fn (h &HandshakeCore) quic_traffic_secrets(level SecretLevel) !([]u8, []u8) {
	match level {
		.initial {
			return error('handshake: initial secrets derive from the QUIC destination connection ID (RFC 9001 §5.2), not the TLS key schedule')
		}
		.handshake {
			if h.client_hs_traffic.len == 0 || h.server_hs_traffic.len == 0 {
				return error('handshake: handshake traffic secrets unavailable (available after ServerHello, dropped by on_handshake_confirmed)')
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

// negotiated_cipher_suite reports the suite the server selected in ServerHello,
// so the TCP adapter can build its AEAD from record_traffic_keys().
pub fn (h &HandshakeCore) negotiated_cipher_suite() CipherSuite {
	return h.cipher_suite
}

// handle_handshake_message processes one complete message of the encrypted
// flight — EE → Certificate → CertificateVerify → Finished — from receive().
fn (mut h HandshakeCore) handle_handshake_message(full_msg []u8) ![]HandshakeMessage {
	// The message is complete by construction (reassembly framed it by its own header), so peel type/length and split the body off.
	mut r := wire.new_reader(full_msg)
	msg_type, length := parse_handshake_header(mut r)!
	body := r.read_bytes(length)!

	match msg_type {
		.encrypted_extensions {
			if h.state != .wait_encrypted_extensions {
				h.fail_alert = .unexpected_message
				return error('handshake: unexpected EncryptedExtensions')
			}
			alpn := parse_encrypted_extensions(body)!
			// RFC 7301 §3.1: the server must pick from the offered list; an unoffered value could steer the application protocol below us.
			if alpn != '' && !h.config.alpn.contains(alpn) {
				h.fail_alert = .illegal_parameter
				return error('handshake: server selected ALPN "${alpn}" not offered by client')
			}
			h.negotiated_alpn = alpn
			h.transcript.update(full_msg)
			h.state = .wait_certificate_request
		}
		.certificate_request {
			// §4.3.2: the server wants client authentication; this client holds no credential and acknowledges with an empty Certificate (§4.4.2).
			if h.state != .wait_certificate_request {
				h.fail_alert = .unexpected_message
				return error('handshake: unexpected CertificateRequest')
			}
			req := parse_certificate_request(body)!
			h.transcript.update(full_msg)
			h.request_context = req.request_context
			h.state = .wait_certificate

			// The empty Certificate-response (§4.4.2) enters the transcript BEFORE the server's flight is verified, so the server Finished covers our response.
			response := build_empty_certificate(h.request_context)
			h.transcript.update(response)
			return [new_handshake_message(.handshake, response)!]
		}
		.certificate {
			// §4.4.1: the server Certificate follows EncryptedExtensions directly, or a CertificateRequest may sit before it; accept both orders.
			if h.state != .wait_certificate_request && h.state != .wait_certificate {
				h.fail_alert = .unexpected_message
				return error('handshake: unexpected Certificate')
			}
			cert_ders := parse_certificate_message(body)!
			h.transcript.update(full_msg)

			h.server_certs = []pki.Certificate{}
			for der in cert_ders {
				h.server_certs << pki.parse_certificate(der)!
			}
			h.validator.verify_certificate_chain(h.server_certs, h.config.server_name) or {
				h.fail_alert = .bad_certificate
				return err
			}
			h.state = .wait_certificate_verify
		}
		.certificate_verify {
			if h.state != .wait_certificate_verify {
				h.fail_alert = .unexpected_message
				return error('handshake: unexpected CertificateVerify')
			}
			cv := parse_certificate_verify(body)!
			signed_content := certificate_verify_signed_content(h.transcript.current_hash())
			h.transcript.update(full_msg)

			if h.server_certs.len == 0 {
				h.fail_alert = .decode_error
				return error('handshake: missing server certificate for verification')
			}
			verify_certificate_verify(leaf_key(h.server_certs[0]), cv, signed_content) or {
				h.fail_alert = .decrypt_error
				return err
			}
			h.state = .wait_server_finished
		}
		.finished {
			if h.state != .wait_server_finished {
				h.fail_alert = .unexpected_message
				return error('handshake: unexpected Finished message')
			}
			// Verify the server Finished over the transcript up to but excluding this message.
			server_verify_data := parse_finished(body, h.hash_algo.hash_len())!
			th_before_sfin := h.transcript.current_hash()

			expected_verify_data := compute_finished_verify_data(h.hash_algo, h.server_hs_traffic, th_before_sfin)!
			// Constant-time compare: verify_data is a MAC over the transcript, and a naive compare would leak a byte-by-byte Finished forgery.
			if subtle.constant_time_compare(server_verify_data, expected_verify_data) != 1 {
				h.fail_alert = .decrypt_error
				return error('handshake: server Finished verify_data mismatch')
			}
			h.transcript.update(full_msg)

			// Advance the key schedule to the application phase: Master Secret, then the application traffic secrets bound to the transcript including server Finished.
			th_sfin := h.transcript.current_hash()
			ap := derive_app_secrets(h.hash_algo, h.handshake_secret, th_sfin)!
			h.client_ap_traffic = ap.client_traffic
			h.server_ap_traffic = ap.server_traffic

			// The client Finished uses the handshake traffic secret over the transcript now including server Finished, sent under the (still active) handshake keys.
			client_verify_data := compute_finished_verify_data(h.hash_algo, h.client_hs_traffic, th_sfin)!
			client_fin_msg := build_finished(client_verify_data)
			h.transcript.update(client_fin_msg)

			if h.hs_reassembly.len > 0 {
				h.fail_alert = .decode_error
				return error('handshake: unexpected trailing data after server Finished in handshake flight')
			}

			h.state = .connected
			// Forward-secrecy cleanup: every ephemeral/handshake secret consumed to reach this point is now dead (RFC 8446 §7.5 / §1.3.1).
			h.zeroize_handshake_secrets()
			// Hand the raw client Finished to the transport, which encrypts it under the still-active handshake keys.
			return [new_handshake_message(.handshake, client_fin_msg)!]
		}
		else {
			h.fail_alert = .unexpected_message
			return error('handshake: unexpected handshake message ${msg_type}')
		}
	}
	return []HandshakeMessage{}
}

// abort destroys every secret derived so far and parks the state machine in
// .failed (RFC 8446 §1.3.1/§7.5); the only legal way for an adapter to reach .failed.
pub fn (mut h HandshakeCore) abort() {
	for i in 0 .. h.handshake_secret.len {
		h.handshake_secret[i] = 0
	}
	h.handshake_secret = []u8{}
	for i in 0 .. h.client_hs_traffic.len {
		h.client_hs_traffic[i] = 0
	}
	h.client_hs_traffic = []u8{}
	for i in 0 .. h.server_hs_traffic.len {
		h.server_hs_traffic[i] = 0
	}
	h.server_hs_traffic = []u8{}
	// Defensive: application secrets cannot exist before .connected, but the wipe keeps abort() a single choke point.
	for i in 0 .. h.client_ap_traffic.len {
		h.client_ap_traffic[i] = 0
	}
	h.client_ap_traffic = []u8{}
	for i in 0 .. h.server_ap_traffic.len {
		h.server_ap_traffic[i] = 0
	}
	h.server_ap_traffic = []u8{}
	h.initial_reassembly = []u8{}
	h.hs_reassembly = []u8{}
	h.priv_x25519 = unsafe { nil }
	h.priv_p256 = none
	h.state = .failed
}

// zeroize_handshake_secrets destroys the key-schedule intermediate and the dead
// ephemeral ECDHE halves at .connected (RFC 8446 §1.3.1/§7.5); it spares the handshake traffic secrets.
fn (mut h HandshakeCore) zeroize_handshake_secrets() {
	// Scrub the buffer in place before releasing it: reassignment alone would hand the allocator the original bytes untouched.
	for i in 0 .. h.handshake_secret.len {
		h.handshake_secret[i] = 0
	}
	h.handshake_secret = []u8{}
	// Release the ephemeral private keys; compute_shared_secret, their only consumer, already ran.
	h.priv_x25519 = unsafe { nil }
	h.priv_p256 = none
}

// zeroize_app_secrets destroys the application traffic secrets once the
// connection is finished (RFC 8446 §1.3.1/§7.5).
pub fn (mut h HandshakeCore) zeroize_app_secrets() {
	for i in 0 .. h.client_ap_traffic.len {
		h.client_ap_traffic[i] = 0
	}
	for i in 0 .. h.server_ap_traffic.len {
		h.server_ap_traffic[i] = 0
	}
	h.client_ap_traffic = []u8{}
	h.server_ap_traffic = []u8{}
}
