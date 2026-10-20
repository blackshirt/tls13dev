// Copyright (c) 2026 blackshirt.
//
// state_machine.v sequences the TLS 1.3 client handshake of RFC 8446, driving the
// message codec (messages.v), AEAD primitives (aead.v), §7.1 key schedule
// (handshake_keys.v) and server-signature check (certificate_verify.v). It is
// transport-neutral: the core consumes and emits only level-tagged handshake
// bytes through feed(); record framing, AEAD record protection and alert routing
// belong to the adapters — tls's conn.v / tcp_transport.v wrap messages into TLS
// records over TCP, while a QUIC adapter (RFC 9001) feeds per-level CRYPTO
// streams and pulls keys out through traffic_keys/exported_secrets. The pub API
// below is exactly that adapter contract; nothing else in this module crosses
// the boundary.
module handshake

import crypto.ecdsa
import crypto.rand
import crypto.subtle
import x.crypto.curve25519
import tls.pki
import tls.wire

// ─── How QUIC support is implemented ────────────────────────────────────────
// Not a separate code path: an engine imports tls.handshake (+ tls.pki for
// trust anchors), never tls, and drives the same pub contract named above.
// The whole integration is the loop below — no records, cipher states, or
// sockets anywhere in it:
//
//  1. Construct — new_client_handshake(server_name, alpn, validator), exactly
//     as conn.v does. Initial packet keys are NOT part of the TLS key
//     schedule: QUIC derives them from the destination connection ID
//     (RFC 9001 §5.2), which is why traffic_keys(.initial) and
//     exported_secrets(.initial) refuse — that derivation belongs to the
//     engine, below this layer.
//  2. Outbound — create_client_hello() yields the first ClientHello;
//     feed() later returns the level-tagged follow-ups (retry ClientHello at
//     .initial, client Finished at .handshake). Each HandshakeMessage.msg is
//     a complete handshake message (4-byte header included) to place verbatim
//     into a CRYPTO frame at that level. No dummy ChangeCipherSpec is ever
//     produced: that is TCP middlebox compatibility only (RFC 8446 App. D.4),
//     and QUIC packets are already opaque (RFC 9001 §4.1.3).
//  3. Inbound — strip QUIC packet protection yourself, concatenate each
//     encryption level's CRYPTO frames into that level's byte stream, and
//     hand the bytes to feed(.initial | .handshake). Within a level the
//     stream is self-framed handshake messages (RFC 9001 §4);
//     next_passthrough_message (passthrough.v) is the core's own reassembly
//     helper and is deliberately reusable engine-side.
//  4. Traffic keys — after ServerHello, either consume traffic_keys() (the
//     raw §7.1 TrafficKeys) or, as packet protection normally needs, take
//     exported_secrets() and expand the "quic key" / "quic iv" / "quic hp"
//     labels over them with the pub hkdf_expand_label (RFC 9001 §5.1; the
//     header-protection key comes from "quic hp"). The core installs no
//     AEAD anywhere — every protection state is rebuilt engine-side.
//  5. Confirmation — call confirm_handshake() only once the handshake is
//     confirmed (HANDSHAKE_DONE or a 1-RTT acknowledgment, RFC 9001 §4.1.2),
//     NOT at client-Finished time like the TCP adapter: a peer may keep
//     sending at Handshake level until confirmation, so the cached handshake
//     keys must survive until then (they are discarded at §4.9.2).
//  6. Alerts — never ride CRYPTO frames (RFC 9001 §4.1.3): map a received
//     AlertDescription with quic_connection_error() (0x100 + description,
//     RFC 9001 §4.8) and raise a CONNECTION_CLOSE of type 0x1c yourself.
//  7. Key update — QUIC replaces TLS KeyUpdate entirely with its own Key
//     Phase mechanism (RFC 9001 §6): an endpoint MUST NOT send a TLS
//     KeyUpdate and MUST treat a received one as a connection error
//     (0x010a, unexpected_message-equivalent). The next generation of 1-RTT
//     secrets is therefore derived engine-side as
//     HKDF-Expand-Label(secret, "quic ku", "", Hash.length) (§6.1) — not via
//     update_read/write_traffic_keys(), whose "traffic upd" label is the TLS
//     record path's; the header-protection key never updates.
//  8. Post-handshake — feed(.application) refuses by contract: over QUIC TLS
//     application data is never carried (RFC 9001 §4.1.3). NewSessionTicket
//     arrives on the 1-RTT CRYPTO stream after the handshake (RFC 9001
//     §4.5); reassemble it with next_passthrough_message and decode with the
//     pub parse_new_session_ticket codec (RFC 8446 §4.6.1) — the same pair
//     the TCP adapter's handle_post_handshake consumes. A KeyUpdate on that
//     stream is a connection error, per item 7.
//
// The TCP adapter (conn.v/tcp_transport.v) is this loop's TLS-shaped twin:
// one ordered record stream instead of three CRYPTO streams, records instead
// of packets, "traffic upd" KeyUpdate instead of Key Phase.

// HandshakeState tracks client progress. The wait_* order mirrors the fixed
// post-ServerHello server flight (EncryptedExtensions → Certificate →
// CertificateVerify → Finished, RFC 8446 §1/§4.1); each handler asserts its
// state before parsing, so an out-of-order message is a protocol violation.
pub enum HandshakeState {
	start                     // nothing sent yet; create_client_hello moves us out of here
	wait_server_hello         // ClientHello sent; awaiting ServerHello or HelloRetryRequest
	wait_encrypted_extensions // ServerHello accepted and handshake keys installed
	wait_certificate_request  // EncryptedExtensions accepted; a CertificateRequest may (optionally) follow before the Certificate (§4.3.2/§4.4.1)
	wait_certificate          // EncryptedExtensions (and any CertificateRequest) accepted (ALPN/SNI checks done); awaiting the server Certificate
	wait_certificate_verify   // server chain parsed and hostname/chain validated
	wait_server_finished      // CertificateVerify verified against the leaf key
	connected                 // server Finished verified; application data may flow
	failed                    // terminal error; no further handshake messages are accepted
}

// HandshakeMessage is one outbound handshake message the core produces, before
// any transport frames or encrypts it. level names the encryption level its
// bytes belong to (RFC 9001 §4.1): the retry ClientHello rides .initial, the
// client Finished rides .handshake; msg is the wire bytes — the full handshake
// message, 4-byte header included, exactly as it must be hashed and put on the
// wire. The TCP adapter maps every level onto its single record stream.
// Instances come from feed() or new_handshake_message(); @[noinit] keeps other
// modules from pairing a valid 4-byte header with a body that does not match it.
@[noinit]
pub struct HandshakeMessage {
pub mut:
	level SecretLevel
	msg   []u8
}

// new_handshake_message builds a HandshakeMessage for producers outside this
// module (tests, or a future adapter synthesizing its own bytes). msg must be
// exactly one complete handshake message — the 4-byte header plus the body its
// declared length covers, nothing trailing (RFC 8446 §4) — so the struct
// literal's freedom to ship a truncated or padded message behind a well-formed
// header does not survive the @[noinit] gate.
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
// own CRYPTO stream and its own traffic secrets. The TCP transport has one
// ordered stream and always uses .handshake.
pub enum SecretLevel {
	initial
	handshake
	application
}

// ClientHandshake orchestrates the TLS 1.3 client handshake state machine.
// The pub methods below are the adapter contract; every field stays private so
// adapters go through the seam (state()/negotiated_alpn() surface the two the
// TCP Conn polls).
@[noinit]
pub struct ClientHandshake {
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
	// The reusable state is the traffic secrets (RFC 8446 §7.2 rekeying); the
	// TrafficKeys derived from them are cached only so adapters can pull
	// per-direction keys through traffic_keys() and build their own AEAD/packet
	// state. The core holds no cipher state of its own — transport protection
	// is the adapter's concern.
	client_ap_traffic []u8        // client application traffic secret (§7.1), kept for KeyUpdate
	server_ap_traffic []u8        // server application traffic secret (§7.1), kept for KeyUpdate
	client_hs_keys    TrafficKeys // cached client handshake keys, handed out by traffic_keys(.handshake)
	server_hs_keys    TrafficKeys // cached server handshake keys, handed out by traffic_keys(.handshake)
	client_app_keys   TrafficKeys // cached client application keys, handed out by traffic_keys(.application)
	server_app_keys   TrafficKeys // cached server application keys, handed out by traffic_keys(.application)
	// Handshake messages may be split across records (or, over QUIC, across many
	// CRYPTO frames) and coalesced within one (RFC 8446 §5.2), so inbound bytes
	// accumulate per encryption level for reassembly, mirroring the distinct
	// CRYPTO streams of RFC 9001 §4.1: Initial-level bytes carry the ServerHello
	// or HelloRetryRequest, Handshake-level bytes carry the encrypted flight.
	initial_reassembly []u8
	hs_reassembly      []u8
	validator          pki.Validator     // trust anchors + hostname policy, injected at construction
	server_certs       []pki.Certificate // chain sent by the server, leaf first, once Certificate is parsed
	request_context    []u8              // certificate_request_context echoed from a server CertificateRequest (§4.3.2); drives the empty client Certificate (§4.4.2)
	hrr_received       bool              // set after a HelloRetryRequest so the second CH is validated as such
	hrr_cipher_suite   ?CipherSuite      // suite selected in the HelloRetryRequest; the final ServerHello must reuse it (§4.1.4)
	// Progress and outcome fields adapters poll; surfaced through state() and
	// negotiated_alpn() rather than made public directly.
	state           HandshakeState
	negotiated_alpn string // server's ALPN pick, '' if none; the RFC 7301 §3.1 check guarantees it was one of config.alpn
	// fail_alert is the alert description an adapter should surface to the peer
	// when this handshake dies. RFC 8446 §6 makes internal_error a legal
	// catch-all, so the default suffices; the sites that can classify their
	// failure precisely (unexpected_message, illegal_parameter, decrypt_error,
	// bad_certificate, ...) overwrite it before the error bubbles out.
	fail_alert AlertDescription = .internal_error
}

// new_client_handshake creates a ClientHandshake offering an X25519 key share —
// mandatory to implement (§9.1) and movable to P-256 via HelloRetryRequest. The
// initial hash/key lengths (SHA-256/AES-128) are provisional, overwritten by the
// server's suite selection. The validator is constructor-injected: it is only
// consulted when feed() reaches the Certificate message, but the core needs it
// mid-feed and cannot take it per call without splitting the reassembly loop.
pub fn new_client_handshake(server_name string, alpn []string, validator pki.Validator) !ClientHandshake {
	// Generate the X25519 key pair up front: TLS 1.3 has no separate key-exchange
	// round trip, so the public share must ride in the initial ClientHello (§4.2.8).
	mut priv_key := curve25519.PrivateKey.new()! // fresh 32-byte X25519 scalar
	pub_key := priv_key.public_key()! // base-point multiplication of the scalar
	raw_pub := pub_key.bytes()! // 32-byte encoding placed verbatim in key_exchange
	// Draw the session id and ClientHello.random now and pin them in config: the
	// retry ClientHello must reproduce them byte-identically (§4.1.4), and the
	// echo check compares against config.session_id (§4.1.3).
	session_id := rand.bytes(legacy_session_id_len)! // 32 bytes for middlebox compatibility (App. D.4)
	random := rand.bytes(client_hello_random_len)! // 32-byte ClientHello.random

	// Assemble the initial hello with an X25519 key share; cookie stays empty
	// until a HelloRetryRequest supplies one.
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

	return ClientHandshake{
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
pub fn (h &ClientHandshake) state() HandshakeState {
	return h.state
}

// negotiated_alpn returns the ALPN protocol the server picked ('' when none);
// the adapter surfaces it to the application after the handshake succeeded.
pub fn (h &ClientHandshake) negotiated_alpn() string {
	return h.negotiated_alpn
}

// failure_alert returns the alert description an adapter should surface to the
// peer when this handshake dies (RFC 8446 §6). The default is internal_error,
// which §6 makes a legal catch-all for any internal failure; the sites that
// can classify their failure precisely overwrite the field before the error
// bubbles out. A QUIC adapter maps the description to a CRYPTO_ERROR
// connection-close code via AlertDescription.quic_connection_error (§4.8).
pub fn (h &ClientHandshake) failure_alert() AlertDescription {
	return h.fail_alert
}

// create_client_hello generates the initial ClientHello message and advances to
// .wait_server_hello. It returns the raw handshake message bytes (header + body,
// exactly what goes into the transcript); framing into a TLS record and the
// middlebox-compatibility dummy ChangeCipherSpec are the TCP transport's job
// (RFC 8446 App. D.4), so the core stays transport-neutral.
pub fn (mut h ClientHandshake) create_client_hello() ![]u8 {
	// A second call would replay the first ClientHello into the transcript a
	// second time and silently corrupt every later hash; the retry ClientHello
	// has its own path (build_second_client_hello, driven by HelloRetryRequest
	// handling in feed()), so this entry point is single-shot.
	if h.state != .start {
		return error('handshake: create_client_hello() only runs once (state: ${h.state}); the retry ClientHello is produced by feed() during HelloRetryRequest handling')
	}
	// Pin random/session id now: build_client_hello would otherwise draw fresh
	// ones per call, and §4.1.4 requires the retry ClientHello to be identical
	// except key_share/cookie (while §4.1.3 compares the echo to config.session_id).
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

// handle_server_hello_message consumes one complete Initial-level handshake
// message — ServerHello or HelloRetryRequest — delivered through feed(). On HRR
// it returns the follow-up message (the retry ClientHello at .initial, unframed
// and CCS-free — the transport adds those); on a normal ServerHello it returns
// an empty list after caching the handshake TrafficKeys for the adapter to
// build its own record/packet protection from.
fn (mut h ClientHandshake) handle_server_hello_message(sh_msg []u8) ![]HandshakeMessage {
	if h.state != .wait_server_hello {
		// Strict ordering: a ServerHello is only legal while we await it; reject
		// out-of-turn messages before parsing (§4.4.1).
		h.fail_alert = .unexpected_message
		return error('handshake: unexpected ServerHello in state ${h.state}')
	}

	// Peel the 4-byte handshake header (type || 3-byte length) to confirm the
	// message type and bound the body (§4).
	mut r := wire.new_reader(sh_msg)
	msg_type, length := parse_handshake_header(mut r)!
	if msg_type != .server_hello {
		// HelloRetryRequest reuses the ServerHello type value (2) and is told
		// apart only by the sentinel random later in the parser (§4.1.3).
		h.fail_alert = .unexpected_message
		return error('handshake: expected ServerHello (2), got ${msg_type}')
	}
	body := r.read_bytes(length)! // body only; the header is re-added for the transcript below
	// RFC 8446 §5.1's record-boundary rule for the ServerHello is deliberately
	// not checked here: reassembly already handed over exactly one complete
	// handshake message (its own 4-byte header length), which is the
	// transport-neutral invariant, and QUIC has no record boundaries at all. The
	// TCP adapter enforces the per-record boundary itself via buffered_bytes().
	sh := parse_server_hello(body)! // §4.1.3 field decode plus the §4.2 extension allowlist
	// Re-frame header + body so the transcript covers the exact wire layout.
	full_sh_msg := wrap_handshake_message(.server_hello, body)

	if sh.is_hello_retry_req {
		// §4.1.4: validate shared fields, reject a second HelloRetryRequest, and
		// require that the request actually changes something.
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
			// The requested group must be offered and differ from the one already
			// sent a key share for (RFC 8446 §4.2.8).
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
		// §4.4.1: the message_hash uses the HRR suite's hash, so switch before
		// applying the HRR.
		h.set_hash_algo(suite_hash_algo(sh.cipher_suite))
		h.transcript.apply_hello_retry_request(h.client_hello1, full_sh_msg)

		return h.build_second_client_hello(sh.has_key_share, sh.server_share.group, sh.cookie)!
	}

	// Normal ServerHello: validate echoed fields and that a key share was
	// selected for our group; (EC)DHE cannot proceed without one.
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

	// §7.1 handshake phase: derive the Handshake Secret and the client/server
	// handshake traffic secrets from the ECDHE shared secret.
	shared_secret := h.compute_shared_secret(sh.server_share)!

	// The handshake secret is retained because the Master Secret derives from it;
	// the traffic secrets feed the handshake keys below.
	th_ch_sh := h.transcript.current_hash()
	hs := derive_hs_secrets(h.hash_algo, shared_secret, th_ch_sh)!
	h.handshake_secret = hs.handshake_secret
	h.client_hs_traffic = hs.client_traffic
	h.server_hs_traffic = hs.server_traffic

	// Each traffic secret expands into an AEAD key and IV; both directions are
	// cached so the adapter can instantiate its own cipher/packet keys from
	// traffic_keys(.handshake) — the core never builds a protection state.
	client_hs_keys := derive_traffic_keys(h.hash_algo, h.client_hs_traffic, h.key_len, aead_nonce_len)!
	server_hs_keys := derive_traffic_keys(h.hash_algo, h.server_hs_traffic, h.key_len, aead_nonce_len)!

	h.server_hs_keys = server_hs_keys
	h.client_hs_keys = client_hs_keys

	h.state = .wait_encrypted_extensions
	return []HandshakeMessage{}
}

// set_hash_algo adopts the negotiated suite's hash, rebuilding the transcript
// around it while keeping accumulated messages. A no-op when already matching.
fn (mut h ClientHandshake) set_hash_algo(algo HashAlgorithm) {
	if h.hash_algo == algo {
		return // already on the target digest — the common SHA-256 case, no rebuild
	}
	// The Transcript keeps the algorithm plus raw messages, not a rolling digest,
	// so a hash change means reconstructing it around the new hash — otherwise
	// derived secrets would keep using the initial SHA-256 and diverge from the
	// server's.
	h.hash_algo = algo
	h.transcript = Transcript{
		hash_algo: algo
		messages:  h.transcript.messages.clone()
	}
}

// build_second_client_hello builds the ClientHello retried after a
// HelloRetryRequest: identical to the first except key_share (when a new group
// was requested) and cookie (when supplied) — RFC 8446 §4.1.2. Like
// create_client_hello it returns the raw message, level-tagged .initial (over
// QUIC the retry rides the Initial CRYPTO stream, RFC 9001 §4.1.3); the
// transport frames it and repeats the dummy CCS only on the TCP path.
fn (mut h ClientHandshake) build_second_client_hello(change_group bool, group NamedGroup, cookie []u8) ![]HandshakeMessage {
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
	h.transcript.update(full_ch2)

	h.state = .wait_server_hello // rearm: the server now answers with the real ServerHello
	return [new_handshake_message(.initial, full_ch2)!]
}

// generate_key_share creates a fresh ephemeral private key for the requested group.
fn (mut h ClientHandshake) generate_key_share(group NamedGroup) ! {
	h.ecdhe_group = group
	match group {
		.x25519 {
			h.priv_x25519 = curve25519.PrivateKey.new()!
			h.priv_p256 = none
		}
		.secp256r1 {
			h.priv_p256 = ecdsa.PrivateKey.new(nid: .prime256v1)!
			// priv_x25519 is left populated: dispatch routes on ecdhe_group, so a
			// stale X25519 key is unreachable.
		}
	}
}

// public_share_bytes serializes the public half of the current ephemeral key in
// the wire form its group mandates (§4.2.8.2): raw 32 bytes for X25519, an
// uncompressed 0x04||X||Y point for P-256.
fn (mut h ClientHandshake) public_share_bytes() ![]u8 {
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
// little-endian wire encoding so they can be compared byte-for-byte against a
// raw secret: the identity, u = 1, and u = p-1 = 2^255-20 (0xec, thirty 0xff
// octets, then a top byte of 0x7f).
const x25519_secret_zero = [u8(0), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

const x25519_secret_one = [u8(1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

const x25519_secret_p_minus_1 = [u8(0xec), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]

// is_x25519_small_order reports whether a finished X25519 shared secret landed
// in one of the three small-order results (see the constants above). Peer
// points of order 2 or 4 (u = 1 and u = p-1) do not multiply to zero but still
// produce a predictable secret, so callers must reject all three, not just the
// identity.
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
fn (mut h ClientHandshake) compute_shared_secret(server_share KeyShareEntry) ![]u8 {
	// §4.2.8.2 fixes key_exchange size per group; gate it here so a wrong size
	// yields a named protocol error rather than a backend panic or opaque error.
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
			// §4.2.8.2 & RFC 7748 §6.1: an all-zero peer u-coordinate is the
			// small-order identity and would yield an all-zero secret; gate before
			// the backend so the abort carries our named protocol error.
			if subtle.constant_time_compare(server_share.key_exchange, []u8{len: 32, init: 0}) == 1 {
				h.fail_alert = .illegal_parameter
				return error('handshake: computed X25519 shared secret is all-zero value (illegal_parameter)')
			}
			secret := h.priv_x25519.x25519(server_share.key_exchange)!
			// Defense in depth: reject every small-order result, not just the
			// all-zero one (see is_x25519_small_order).
			if is_x25519_small_order(secret) {
				h.fail_alert = .illegal_parameter
				return error('handshake: computed X25519 shared secret is a small-order value (illegal_parameter)')
			}
			return secret
		}
		.secp256r1 {
			// Only the uncompressed encoding is legal in TLS 1.3 (§4.2.8.2);
			// compressed shares start 0x02/0x03.
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

// feed is the single inbound entry point of the core: the adapter hands over
// handshake bytes as they arrived at their encryption level — ServerHello and
// HelloRetryRequest plaintext at .initial, the encrypted flight after
// decrypting it (TCP) or straight off the CRYPTO stream (QUIC) at .handshake.
// Bytes append to that level's reassembly buffer and every complete message is
// consumed immediately, dispatching by state. It returns the outbound messages
// the peer's bytes triggered (retry ClientHello at .initial, client Finished at
// .handshake). Decryption is never seen here; alert routing belongs to the
// adapter, which is why over QUIC alerts need no CRYPTO path at all (they
// become CRYPTO_ERROR connection-close codes, RFC 9001 §4.8).
// Contract misuse — feeding before create_client_hello(), Initial bytes outside
// the ServerHello wait, or anything once the state machine has failed — is
// refused with the state untouched so the caller can correct its sequencing.
// Errors while parsing peer bytes instead set the terminal .failed state, and
// each level's reassembly buffer is held to one maximum-size message plus its
// header, so no input pattern can grow it without bound.
pub fn (mut h ClientHandshake) feed(level SecretLevel, bytes []u8) ![]HandshakeMessage {
	if h.state == .start {
		return error('handshake: feed() before create_client_hello() — no ClientHello has been sent yet')
	}
	if h.state == .failed {
		return error('handshake: state machine has failed; feed() refuses further messages')
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
			// One feed may coalesce a consumed ServerHello with an oversized tail
			// the loop no longer reaches; bound it even where drain cannot.
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
			// Same bound for the Handshake level: late retransmits at .connected
			// skip the drain loop, so the cap is the backstop.
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

// drain_initial consumes complete ServerHello/HelloRetryRequest messages from
// the Initial-level buffer. Only one is ever legal — after a normal ServerHello
// the stream switches to .handshake bytes — so the loop stops as soon as the
// wait ends; bytes left over are the adapter's boundary concern, surfaced via
// buffered_bytes(.initial).
fn (mut h ClientHandshake) drain_initial() ![]HandshakeMessage {
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

// drain_handshake consumes complete messages of the encrypted flight — EE →
// Cert → CV → Finished — from the Handshake-level buffer until it runs dry or
// the handshake completes.
fn (mut h ClientHandshake) drain_handshake() ![]HandshakeMessage {
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

// traffic_keys returns the (client, server) TrafficKeys cached for one
// encryption level. Adapters instantiate their own protection from them — the
// TCP Conn builds its record AEAD states, a QUIC engine expands the same
// secrets under the RFC 9001 §5.1 "quic key"/"quic iv"/"quic hp" labels.
// .initial keys derive from the destination connection ID (§5.2), not the TLS
// schedule, so they are refused. Handshake-level keys survive until
// confirm_handshake().
pub fn (h &ClientHandshake) traffic_keys(level SecretLevel) !(TrafficKeys, TrafficKeys) {
	match level {
		.initial {
			return error('handshake: initial keys derive from the QUIC destination connection ID (RFC 9001 §5.2), not the TLS key schedule')
		}
		.handshake {
			if h.client_hs_keys.key.len == 0 || h.server_hs_keys.key.len == 0 {
				return error('handshake: handshake traffic keys unavailable (available after ServerHello, dropped by confirm_handshake)')
			}
			return clone_traffic_keys(h.client_hs_keys), clone_traffic_keys(h.server_hs_keys)
		}
		.application {
			if h.client_app_keys.key.len == 0 || h.server_app_keys.key.len == 0 {
				return error('handshake: application traffic keys unavailable before the server Finished')
			}
			return clone_traffic_keys(h.client_app_keys), clone_traffic_keys(h.server_app_keys)
		}
	}
}

// clone_traffic_keys copies one direction's key/iv buffers so callers never
// alias the core's cached material. Aliasing would matter twice: an adapter
// mutating its copy would corrupt the core's state, and the core wipes the
// superseded generation in place during a KeyUpdate ratchet — which would
// otherwise destroy keys the adapter is still encrypting with.
fn clone_traffic_keys(k TrafficKeys) TrafficKeys {
	return TrafficKeys{
		key: k.key.clone()
		iv:  k.iv.clone()
	}
}

// buffered_bytes reports the incomplete bytes parked in one level's reassembly
// buffer. The TCP adapter uses it for the RFC 8446 §5.1 ServerHello
// record-boundary rule (the rule is meaningless over QUIC, which is why the
// core does not own it): after feeding a plaintext record that carried the
// ServerHello, anything still buffered means the record coalesced more than one
// handshake message or truncated it, and must be rejected.
pub fn (h &ClientHandshake) buffered_bytes(level SecretLevel) int {
	return match level {
		.initial {
			h.initial_reassembly.len
		}
		.handshake {
			h.hs_reassembly.len
		}
		.application {
			0
		}
	}
}

// confirm_handshake tells the core the adapter no longer protects any traffic at
// the handshake level, so the handshake-stage traffic secrets and cached keys
// can be destroyed. The TCP Conn calls it right after sending its Finished;
// a QUIC engine must call it only once the handshake is confirmed per RFC 9001
// §4.1.2/§4.9.2, since a peer may still send at Handshake level until then —
// that is why zeroize_handshake_secrets() (which runs at .connected) deliberately
// stops short of this material. Until .connected the transport still needs
// those keys to encrypt the client Finished, so an early call is refused
// instead of stranding the handshake.
pub fn (mut h ClientHandshake) confirm_handshake() ! {
	if h.state != .connected {
		return error('handshake: confirm_handshake() runs only once the handshake reached .connected (state: ${h.state})')
	}
	for i in 0 .. h.client_hs_traffic.len {
		h.client_hs_traffic[i] = 0
	}
	for i in 0 .. h.server_hs_traffic.len {
		h.server_hs_traffic[i] = 0
	}
	h.client_hs_traffic = []u8{}
	h.server_hs_traffic = []u8{}
	wipe_traffic_keys(mut h.client_hs_keys)
	wipe_traffic_keys(mut h.server_hs_keys)
}

// exported_secrets returns (client, server) clones of the §7.1 traffic secrets
// for one encryption level, so a QUIC engine can expand them under the RFC 9001
// §5.1 "quic key" / "quic iv" / "quic hp" labels — secrets cross this boundary,
// not TrafficKeys. Handshake-stage secrets and keys are deliberately retained
// past .connected until confirm_handshake(), because a QUIC peer may still send
// at Handshake level until the handshake is confirmed (RFC 9001 §4.1.2);
// application secrets live from the server Finished until close.
// .initial derives from the destination connection ID (§5.2), not the TLS
// schedule, and is rejected.
pub fn (h &ClientHandshake) exported_secrets(level SecretLevel) !([]u8, []u8) {
	match level {
		.initial {
			return error('handshake: initial secrets derive from the QUIC destination connection ID (RFC 9001 §5.2), not the TLS key schedule')
		}
		.handshake {
			if h.client_hs_traffic.len == 0 || h.server_hs_traffic.len == 0 {
				return error('handshake: handshake traffic secrets unavailable (available after ServerHello, dropped by confirm_handshake)')
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
// so the TCP adapter can instantiate the matching AEAD when it builds record
// ciphers from traffic_keys(). A QUIC adapter derives packet keys from the
// level secrets instead and never needs the suite identity itself.
pub fn (h &ClientHandshake) negotiated_cipher_suite() CipherSuite {
	return h.cipher_suite
}

// handle_handshake_message processes one complete message of the encrypted
// flight — EncryptedExtensions → Certificate → CertificateVerify → Finished —
// that feed()'s reassembly delivered. It returns the raw client Finished,
// level-tagged .handshake, when the handshake completes (the transport frames
// and encrypts it), or an empty list otherwise.
fn (mut h ClientHandshake) handle_handshake_message(full_msg []u8) ![]HandshakeMessage {
	// The message is complete by construction (reassembly framed it by its own
	// header), so peel type/length and split the body straight off it.
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
			// RFC 7301 §3.1: the server must pick from the offered list (or send
			// no ALPN); an unoffered value could silently steer the application
			// protocol below us.
			if alpn != '' && !h.config.alpn.contains(alpn) {
				h.fail_alert = .illegal_parameter
				return error('handshake: server selected ALPN "${alpn}" not offered by client')
			}
			h.negotiated_alpn = alpn
			h.transcript.update(full_msg)
			h.state = .wait_certificate_request
		}
		.certificate_request {
			// §4.3.2: CertificateRequest is the first server-flight message that
			// indicates the server wants client authentication. This client holds
			// no credential, so it must still acknowledge the request with an
			// empty Certificate (§4.4.2) rather than ignore it or fail.
			if h.state != .wait_certificate_request {
				h.fail_alert = .unexpected_message
				return error('handshake: unexpected CertificateRequest')
			}
			req := parse_certificate_request(body)!
			h.transcript.update(full_msg)
			h.request_context = req.request_context
			h.state = .wait_certificate

			// The empty Certificate-response (RFC 8446 §4.4.2) enters the
			// transcript BEFORE the server's Certificate/CertificateVerify/
			// Finished are verified, so the server Finished is computed over the
			// transcript that already includes our response.
			response := build_empty_certificate(h.request_context)
			h.transcript.update(response)
			return [new_handshake_message(.handshake, response)!]
		}
		.certificate {
			// §4.4.1: the server Certificate follows EncryptedExtensions directly,
			// or a CertificateRequest may sit before it (client authentication);
			// accept both orders.
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
			// Verify the server Finished over the transcript up to but
			// excluding this message, using the server handshake traffic secret.
			server_verify_data := parse_finished(body, h.hash_algo.hash_len())!
			th_before_sfin := h.transcript.current_hash()

			expected_verify_data := compute_finished_verify_data(h.hash_algo, h.server_hs_traffic, th_before_sfin)!
			// Constant-time compare: verify_data is a MAC over the transcript,
			// and a naive compare would leak a byte-by-byte Finished forgery.
			if subtle.constant_time_compare(server_verify_data, expected_verify_data) != 1 {
				h.fail_alert = .decrypt_error
				return error('handshake: server Finished verify_data mismatch')
			}
			h.transcript.update(full_msg)

			// Advance the key schedule to the application phase: Master Secret,
			// then the application traffic secrets bound to the transcript
			// including server Finished.
			th_sfin := h.transcript.current_hash()
			ap := derive_app_secrets(h.hash_algo, h.handshake_secret, th_sfin)!
			h.client_ap_traffic = ap.client_traffic
			h.server_ap_traffic = ap.server_traffic

			client_app_keys := derive_traffic_keys(h.hash_algo, h.client_ap_traffic, h.key_len, aead_nonce_len)!
			server_app_keys := derive_traffic_keys(h.hash_algo, h.server_ap_traffic, h.key_len, aead_nonce_len)!

			// The client Finished uses the handshake traffic secret over the
			// transcript now including server Finished, sent under the (still
			// active) handshake keys.
			client_verify_data := compute_finished_verify_data(h.hash_algo, h.client_hs_traffic, th_sfin)!
			client_fin_msg := build_finished(client_verify_data)
			h.transcript.update(client_fin_msg)

			// Cache the application TrafficKeys for the adapter to install its own
			// transport protection from via traffic_keys(.application). The
			// handshake-level keys/secrets stay intact until confirm_handshake(),
			// because the transport must still encrypt the client Finished under
			// them (and a QUIC peer may keep sending at Handshake level).
			h.server_app_keys = server_app_keys
			h.client_app_keys = client_app_keys

			if h.hs_reassembly.len > 0 {
				h.fail_alert = .decode_error
				return error('handshake: unexpected trailing data after server Finished in handshake flight')
			}

			h.state = .connected
			// Forward-secrecy cleanup: every ephemeral/handshake secret consumed
			// to reach this point is now dead, so destroy it here rather than keep
			// it resident for the whole connection (RFC 8446 §7.5 / §1.3.1).
			h.zeroize_handshake_secrets()
			// Hand the raw client Finished to the transport, which encrypts it
			// under the still-active handshake keys.
			return [new_handshake_message(.handshake, client_fin_msg)!]
		}
		else {
			h.fail_alert = .unexpected_message
			return error('handshake: unexpected handshake message ${msg_type}')
		}
	}
	return []HandshakeMessage{}
}

// update_read_traffic_keys ratchets the server application traffic secret to its
// next generation (TLS KeyUpdate, RFC 8446 §7.2) and refreshes the cached read
// TrafficKeys. It never installs a cipher: the adapter rebuilds its own read
// protection from traffic_keys(.application) afterward. This is the TLS record
// path only — over QUIC a received TLS KeyUpdate is a connection error
// (RFC 9001 §6) and the engine ratchets with the "quic ku" label itself.
// A secret that does not exist — no server Finished yet, or already destroyed
// by zeroize_app_secrets — refuses the ratchet rather than being expanded
// into junk keys.
pub fn (mut h ClientHandshake) update_read_traffic_keys() ! {
	// Ratchet the secret forward: new_secret = HKDF-Expand-Label(old, "traffic
	// upd", "", Hash) (§7.2); overwriting the old secret is the forward-security
	// property KeyUpdate exists to deliver.
	if h.server_ap_traffic.len == 0 {
		return error('handshake: cannot ratchet the server application traffic secret (unavailable before the server Finished, destroyed by zeroize_app_secrets)')
	}
	// Advance first, then destroy the superseded generation in place: the old
	// secret and the keys derived from it must not survive the ratchet in freed
	// storage, which is the whole point of KeyUpdate's forward secrecy.
	new_secret := hkdf_expand_label(h.hash_algo, h.server_ap_traffic, 'traffic upd', []u8{}, h.hash_algo.hash_len())!
	for i in 0 .. h.server_ap_traffic.len {
		h.server_ap_traffic[i] = 0
	}
	h.server_ap_traffic = new_secret
	wipe_traffic_keys(mut h.server_app_keys)
	h.server_app_keys = derive_traffic_keys(h.hash_algo, h.server_ap_traffic, h.key_len, aead_nonce_len)!
}

// update_write_traffic_keys ratchets the client application traffic secret to its
// next generation (TLS KeyUpdate, RFC 8446 §7.2) and refreshes the cached write
// TrafficKeys, mirroring update_read_traffic_keys. §4.6.3 still requires the
// KeyUpdate notice to go out under the old keys, so callers update after sending
// and then rebuild their write protection — the TCP adapter restarts its record
// sequence number at 0 (§5.3). Like its read twin this is the TLS record path
// only: QUIC forbids TLS KeyUpdate entirely (RFC 9001 §6) and updates packet
// keys with its own Key Phase mechanism below this layer. Like its read twin
// it refuses when the secret does not exist (before the server Finished, or
// after zeroize_app_secrets), so an empty secret is never expanded.
pub fn (mut h ClientHandshake) update_write_traffic_keys() ! {
	if h.client_ap_traffic.len == 0 {
		return error('handshake: cannot ratchet the client application traffic secret (unavailable before the server Finished, destroyed by zeroize_app_secrets)')
	}
	// Same supersession rule as the read side: compute the next generation from
	// the old secret, then wipe the old secret and its cached keys before the
	// replacement lands.
	new_secret := hkdf_expand_label(h.hash_algo, h.client_ap_traffic, 'traffic upd', []u8{}, h.hash_algo.hash_len())!
	for i in 0 .. h.client_ap_traffic.len {
		h.client_ap_traffic[i] = 0
	}
	h.client_ap_traffic = new_secret
	wipe_traffic_keys(mut h.client_app_keys)
	h.client_app_keys = derive_traffic_keys(h.hash_algo, h.client_ap_traffic, h.key_len, aead_nonce_len)!
}

// abort destroys every secret the handshake has derived so far and parks the
// state machine in the terminal .failed state. RFC 8446 §1.3.1/§7.5 require
// destroying key material the moment it is known dead; a failed handshake
// kills the Handshake Secret, the traffic secrets, and the cached TrafficKeys
// immediately instead of leaving them resident until the caller drops the
// object. It is the failure-path twin of the success-choke-point wipes and is
// the only legal way for an adapter to reach .failed. The ephemeral ECDHE
// private halves are released exactly the way zeroize_handshake_secrets
// releases them: after the (possibly failed) shared-secret computation they
// are dead either way, and the vlib key types expose no in-place wipe.
pub fn (mut h ClientHandshake) abort() {
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
	wipe_traffic_keys(mut h.client_hs_keys)
	wipe_traffic_keys(mut h.server_hs_keys)
	// Defensive: application secrets cannot exist before .connected, but the
	// wipe is cheap and keeps abort() a single choke point for adapters that
	// call it from post-handshake failure paths too.
	for i in 0 .. h.client_ap_traffic.len {
		h.client_ap_traffic[i] = 0
	}
	h.client_ap_traffic = []u8{}
	for i in 0 .. h.server_ap_traffic.len {
		h.server_ap_traffic[i] = 0
	}
	h.server_ap_traffic = []u8{}
	wipe_traffic_keys(mut h.client_app_keys)
	wipe_traffic_keys(mut h.server_app_keys)
	h.priv_x25519 = unsafe { nil }
	h.priv_p256 = none
	h.state = .failed
}

// zeroize_handshake_secrets destroys the key-schedule intermediate and the
// ephemeral ECDHE private halves that are provably dead once the handshake
// completes. RFC 8446 §1.3.1/§7.5: without destroying this material a later
// memory compromise could still recover the secrets that decrypt PAST traffic,
// which is exactly what forward secrecy is meant to prevent. It runs at the
// single success choke point (.connected). It deliberately does NOT touch the
// handshake traffic secrets or cached handshake TrafficKeys — a QUIC adapter may
// still protect packets at Handshake level until the handshake is confirmed, so
// those survive until confirm_handshake() (RFC 9001 §4.1.2/§4.9.2). KeyUpdate
// ratchets only *_ap_traffic, never the values cleared here.
fn (mut h ClientHandshake) zeroize_handshake_secrets() {
	// Scrub the buffer in place before releasing it: merely reassigning the slice
	// hands the allocator the original bytes untouched, so the wipe has to precede
	// the drop. Best-effort against optimizer dead-store elimination, but the
	// reference release below always takes effect.
	for i in 0 .. h.handshake_secret.len {
		h.handshake_secret[i] = 0
	}
	h.handshake_secret = []u8{}
	// Release the ephemeral private keys; compute_shared_secret (their only
	// consumer) ran during ServerHello processing, so nothing reads them again.
	h.priv_x25519 = unsafe { nil }
	h.priv_p256 = none
}

// zeroize_app_secrets destroys the application traffic secrets once the
// connection is finished. They are the last retained material from which the
// keys protecting application data can be re-derived, so keeping them past
// teardown would let a later memory compromise decrypt recorded traffic
// and undo the app-phase forward secrecy the handshake zeroization above is
// meant to establish (RFC 8446 §1.3.1/§7.5). The cached TrafficKeys derived
// from them are wiped for the same reason — §7.5 says forget the secret
// values *and* the keys — while the adapter's live record cipher is a
// separate instantiation it may still need to send close_notify. After this,
// read/write refuse (closed) and traffic_keys/exported_secrets no longer
// hand out the dead material; KeyUpdate ratcheting is refused by its own
// guard, reachable only while the connection is still open.
pub fn (mut h ClientHandshake) zeroize_app_secrets() {
	for i in 0 .. h.client_ap_traffic.len {
		h.client_ap_traffic[i] = 0
	}
	for i in 0 .. h.server_ap_traffic.len {
		h.server_ap_traffic[i] = 0
	}
	h.client_ap_traffic = []u8{}
	h.server_ap_traffic = []u8{}
	wipe_traffic_keys(mut h.client_app_keys)
	wipe_traffic_keys(mut h.server_app_keys)
}

// wipe_traffic_keys zeroes a cached TrafficKeys byte by byte before releasing
// it: reassignment alone would hand the allocator the key material intact, the
// same reason zeroize_handshake_secrets wipes in place first. Best-effort
// against optimizer dead-store elimination, but the release always takes effect.
fn wipe_traffic_keys(mut keys TrafficKeys) {
	for i in 0 .. keys.key.len {
		keys.key[i] = 0
	}
	for i in 0 .. keys.iv.len {
		keys.iv[i] = 0
	}
	keys = TrafficKeys{}
}
