// Copyright (c) 2026 blackshirt.
//
// state_machine.v sequences the TLS 1.3 client handshake of RFC 8446, driving the
// message codec (messages.v), AEAD primitives (aead.v), §7.1 key schedule
// (handshake_keys.v) and server-signature check (certificate_verify.v). It is
// transport-neutral: the core emits raw handshake messages and the transport
// (conn.v / tcp_transport.v) frames them into TLS records over TCP; the record
// module's QUIC passthrough helpers (record.v, RFC 9001 §4) are the alternate
// framing a future QUIC adapter would reuse.
module tls

import crypto.ecdsa
import crypto.rand
import crypto.subtle
import x.crypto.curve25519

// HandshakeState tracks client progress. The wait_* order mirrors the fixed
// post-ServerHello server flight (EncryptedExtensions → Certificate →
// CertificateVerify → Finished, RFC 8446 §1/§4.1); each handler asserts its
// state before parsing, so an out-of-order message is a protocol violation.
enum HandshakeState {
	start                     // nothing sent yet; create_client_hello moves us out of here
	wait_server_hello         // ClientHello sent; awaiting ServerHello or HelloRetryRequest
	wait_encrypted_extensions // ServerHello accepted and handshake keys installed
	wait_certificate          // EncryptedExtensions accepted (ALPN/SNI checks done)
	wait_certificate_verify   // server chain parsed and hostname/chain validated
	wait_server_finished      // CertificateVerify verified against the leaf key
	connected                 // server Finished verified; application data may flow
	failed                    // terminal error; no further handshake messages are accepted
}

// RawHandshakeMessage is one outbound handshake message the core produces,
// before any transport frames or encrypts it. content_type is the TLS content
// type it must travel under (.handshake for every message the core emits
// today); msg is the wire bytes — the full handshake message, 4-byte header
// included, exactly as it must be hashed and put on the wire.
struct RawHandshakeMessage {
mut:
	content_type ContentType
	msg          []u8
}

// ClientHandshake orchestrates the TLS 1.3 client handshake state machine.
@[noinit]
struct ClientHandshake {
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
	// Traffic keys live only inside the RecordCipherStates below; the reusable
	// state is the traffic secrets (RFC 8446 §7.2 rekeying).
	client_ap_traffic []u8              // client application traffic secret (§7.1), kept for KeyUpdate
	server_ap_traffic []u8              // server application traffic secret (§7.1), kept for KeyUpdate
	server_hs_cipher  RecordCipherState // AEAD state for records the server sends under handshake keys
	client_hs_cipher  RecordCipherState // AEAD state for records we send under handshake keys
	// Handshake messages may be split across records or coalesced within one
	// (RFC 8446 §5.2), so decrypted plaintext accumulates here for reassembly.
	reassembly_buf   []u8
	server_certs     []Certificate // chain sent by the server, leaf first, once Certificate is parsed
	hrr_received     bool          // set after a HelloRetryRequest so the second CH is validated as such
	hrr_cipher_suite ?CipherSuite  // suite selected in the HelloRetryRequest; the final ServerHello must reuse it (§4.1.4)
	// These fields are read by conn.v; all remain internal to the tls module.
	state             HandshakeState
	negotiated_alpn   string             // server's ALPN pick, '' if none; the RFC 7301 §3.1 check guarantees it was one of config.alpn
	server_app_cipher RecordCipherState  // AEAD state for records the server sends under app keys
	client_app_cipher RecordCipherState  // AEAD state for records we send under app keys
	session_tickets   []NewSessionTicket // tickets received post-handshake; currently collected, not resumable
}

// new_client_handshake creates a ClientHandshake offering an X25519 key share —
// mandatory to implement (§9.1) and movable to P-256 via HelloRetryRequest. The
// initial hash/key lengths (SHA-256/AES-128) are provisional, overwritten by the
// server's suite selection.
fn new_client_handshake(server_name string, alpn []string) !ClientHandshake {
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
		state:          .start
		config:         cfg
		transcript:     new_transcript(.sha256)
		hash_algo:      .sha256
		key_len:        16
		ecdhe_group:    .x25519
		priv_x25519:    priv_key
		reassembly_buf: []u8{cap: 4096}
	}
}

// create_client_hello generates the initial ClientHello message and advances to
// .wait_server_hello. It returns the raw handshake message bytes (header + body,
// exactly what goes into the transcript); framing into a TLS record and the
// middlebox-compatibility dummy ChangeCipherSpec are the TCP transport's job
// (RFC 8446 App. D.4), so the core stays transport-neutral.
fn (mut h ClientHandshake) create_client_hello() ![]u8 {
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

// process_server_hello parses ServerHello or HelloRetryRequest from the raw
// handshake message bytes the transport handed over (the ServerHello travels in
// the clear, so no decryption precedes it). On HRR it returns the follow-up
// message (the retry ClientHello, unframed and CCS-free — the transport adds
// those); on a normal ServerHello it returns an empty list after installing the
// handshake keys.
fn (mut h ClientHandshake) process_server_hello(sh_msg []u8) !([]RawHandshakeMessage, ServerHello) {
	if h.state != .wait_server_hello {
		// Strict ordering: a ServerHello is only legal while we await it; reject
		// out-of-turn messages before parsing (§4.4.1).
		return error('handshake: unexpected ServerHello in state ${h.state}')
	}

	// Peel the 4-byte handshake header (type || 3-byte length) to confirm the
	// message type and bound the body (§4).
	mut r := new_reader(sh_msg)
	msg_type, length := parse_handshake_header(mut r)!
	if msg_type != .server_hello {
		// HelloRetryRequest reuses the ServerHello type value (2) and is told
		// apart only by the sentinel random later in the parser (§4.1.3).
		return error('handshake: expected ServerHello (2), got ${msg_type}')
	}
	body := r.read_bytes(length)! // body only; the header is re-added for the transcript below
	// RFC 8446 §5.1: a handshake message immediately preceding a key change (the
	// ServerHello) MUST align with a record boundary. Extra bytes coalesced after
	// it in the same record would be silently dropped (and any following flight
	// would then be mis-framed), so reject them as unexpected_message.
	if r.remaining() != 0 {
		return error('handshake: trailing data after ServerHello in the same record (unexpected_message)')
	}
	sh := parse_server_hello(body)! // §4.1.3 field decode plus the §4.2 extension allowlist
	// Re-frame header + body so the transcript covers the exact wire layout.
	full_sh_msg := wrap_handshake_message(.server_hello, body)

	if sh.is_hello_retry_req {
		// §4.1.4: validate shared fields, reject a second HelloRetryRequest, and
		// require that the request actually changes something.
		sh.validate(&h.config)!
		if h.hrr_received {
			return error('handshake: received second HelloRetryRequest (unexpected_message)')
		}

		if !sh.has_key_share && sh.cookie.len == 0 {
			return error('handshake: HelloRetryRequest would not change the ClientHello (illegal_parameter)')
		}
		if sh.has_key_share {
			// The requested group must be offered and differ from the one already
			// sent a key share for (RFC 8446 §4.2.8).
			if !is_supported_group(sh.server_share.group) {
				return error('handshake: HelloRetryRequest requested unsupported group ${sh.server_share.group} (illegal_parameter)')
			}
			if sh.server_share.group == h.config.client_share.group {
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

		followups := h.build_second_client_hello(sh.has_key_share, sh.server_share.group, sh.cookie)!
		return followups, sh
	}

	// Normal ServerHello: validate echoed fields and that a key share was
	// selected for our group; (EC)DHE cannot proceed without one.
	sh.validate(&h.config)!
	// §4.1.4: after a HelloRetryRequest the ServerHello suite must match the HRR's.
	if hrr_suite := h.hrr_cipher_suite {
		if hrr_suite != sh.cipher_suite {
			return error('handshake: ServerHello cipher suite ${sh.cipher_suite} differs from HelloRetryRequest suite ${hrr_suite} (illegal_parameter)')
		}
	}
	if !sh.has_key_share {
		return error('handshake: ServerHello missing key_share extension')
	}
	if sh.server_share.group != h.ecdhe_group {
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

	// Each traffic secret expands into an AEAD key and IV; the keys exist only as
	// locals feeding new_cipher.
	client_hs_keys := derive_traffic_keys(h.hash_algo, h.client_hs_traffic, h.key_len, aead_nonce_len)!
	server_hs_keys := derive_traffic_keys(h.hash_algo, h.server_hs_traffic, h.key_len, aead_nonce_len)!

	h.server_hs_cipher = h.new_cipher(server_hs_keys)!
	h.client_hs_cipher = h.new_cipher(client_hs_keys)!

	h.state = .wait_encrypted_extensions
	return []RawHandshakeMessage{}, sh
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

// new_cipher instantiates the negotiated suite's AEAD under the given keys and
// wraps it in a fresh record cipher state. Sequence numbers restart at 0 for
// each key generation (§5.3), so KeyUpdate builds a new state instead of
// mutating the old one.
fn (h &ClientHandshake) new_cipher(keys TrafficKeys) !RecordCipherState {
	aead := new_aead_for_suite(h.cipher_suite, keys.key)!
	return new_record_cipher_state(aead, keys.iv)!
}

// build_second_client_hello builds the ClientHello retried after a
// HelloRetryRequest: identical to the first except key_share (when a new group
// was requested) and cookie (when supplied) — RFC 8446 §4.1.2. Like
// create_client_hello it returns the raw message; the transport frames it and
// repeats the dummy CCS only on the TCP path.
fn (mut h ClientHandshake) build_second_client_hello(change_group bool, group NamedGroup, cookie []u8) ![]RawHandshakeMessage {
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
	return [RawHandshakeMessage{
		content_type: .handshake
		msg:          full_ch2
	}]
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
				return error('handshake: computed X25519 shared secret is all-zero value (illegal_parameter)')
			}
			secret := h.priv_x25519.x25519(server_share.key_exchange)!
			// Defense in depth: reject every small-order result, not just the
			// all-zero one (see is_x25519_small_order).
			if is_x25519_small_order(secret) {
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
				return error('handshake: computed P-256 shared secret is all-zero value (illegal_parameter)')
			}
			return secret
		}
	}
	// Unreachable: the match above is exhaustive over NamedGroup.
	return error('handshake: unsupported key_share group ${server_share.group}')
}

// feed_encrypted_record decrypts a handshake-phase record into the reassembly buffer.
fn (mut h ClientHandshake) feed_encrypted_record(rec Record) ! {
	// Decrypt under the server handshake keys; the true content type lies inside
	// the inner plaintext (§5.1/§5.2).
	decrypted := h.server_hs_cipher.decrypt_record(rec)!
	if decrypted.content_type == .alert {
		// RFC 8446 §6: after the ServerHello the server may surface a fatal alert
		// under the handshake keys (e.g. decrypt_error, certificate_required,
		// illegal_parameter). Decode and preserve its code instead of dropping it
		// as a generic content-type mismatch.
		peer_alert := parse_alert(decrypted.plaintext)!
		if peer_alert.description == .close_notify {
			return error('handshake: peer sent close_notify during handshake')
		}
		return error('handshake: received alert ${peer_alert.description} during handshake')
	}
	if decrypted.content_type != .handshake {
		// Only handshake is otherwise legal in this phase; anything else violates §5.6.
		return error('handshake: unexpected content type in handshake phase: ${decrypted.content_type}')
	}
	// Accumulate plaintext; process_reassembled_messages joins fragments that span
	// records and splits several messages coalesced into one (§5.2).
	h.reassembly_buf << decrypted.plaintext
}

// process_reassembled_messages processes EncryptedExtensions → Certificate →
// CertificateVerify → Finished. Returns the raw client Finished message when the
// handshake completes (the transport frames and encrypts it), or an empty list
// when more data is needed.
fn (mut h ClientHandshake) process_reassembled_messages(validator &Validator) ![]RawHandshakeMessage {
	// Loop over the reassembly buffer consuming one complete message at a time; a
	// partial message means more records are needed, so return and wait.
	for {
		if h.reassembly_buf.len < 4 {
			return []RawHandshakeMessage{} // need the 4-byte handshake header
		}
		mut r := new_reader(h.reassembly_buf)
		msg_type, length := parse_handshake_header(mut r)!
		// Reject an oversized declared length before buffering any more fragments
		// toward it — the cap must bite at the header, not at completion.
		if length > max_handshake_message_len {
			return error('handshake: handshake message length ${length} exceeds maximum ${max_handshake_message_len} (unexpected_message)')
		}
		if h.reassembly_buf.len < 4 + length {
			return []RawHandshakeMessage{} // body not fully received yet
		}

		// Consume the whole message: full_msg (header + body) is hashed into the
		// transcript, while body is the parsed payload.
		body := r.read_bytes(length)!
		full_msg := h.reassembly_buf[..4 + length].clone()
		h.reassembly_buf = h.reassembly_buf[4 + length..].clone()

		match msg_type {
			.encrypted_extensions {
				if h.state != .wait_encrypted_extensions {
					return error('handshake: unexpected EncryptedExtensions')
				}
				alpn := parse_encrypted_extensions(body)!
				// RFC 7301 §3.1: the server must pick from the offered list (or send
				// no ALPN); an unoffered value could silently steer the application
				// protocol below us.
				if alpn != '' && !h.config.alpn.contains(alpn) {
					return error('handshake: server selected ALPN "${alpn}" not offered by client')
				}
				h.negotiated_alpn = alpn
				h.transcript.update(full_msg)
				h.state = .wait_certificate
			}
			.certificate {
				if h.state != .wait_certificate {
					return error('handshake: unexpected Certificate')
				}
				cert_ders := parse_certificate_message(body)!
				h.transcript.update(full_msg)

				h.server_certs = []Certificate{}
				for der in cert_ders {
					h.server_certs << parse_certificate(der)!
				}
				validator.verify_certificate_chain(h.server_certs, h.config.server_name)!
				h.state = .wait_certificate_verify
			}
			.certificate_verify {
				if h.state != .wait_certificate_verify {
					return error('handshake: unexpected CertificateVerify')
				}
				cv := parse_certificate_verify(body)!
				signed_content := certificate_verify_signed_content(h.transcript.current_hash())
				h.transcript.update(full_msg)

				if h.server_certs.len == 0 {
					return error('handshake: missing server certificate for verification')
				}
				verify_certificate_verify(h.server_certs[0], cv, signed_content)!
				h.state = .wait_server_finished
			}
			.finished {
				if h.state != .wait_server_finished {
					return error('handshake: unexpected Finished message')
				}
				// Verify the server Finished over the transcript up to but
				// excluding this message, using the server handshake traffic secret.
				server_verify_data := parse_finished(body)!
				th_before_sfin := h.transcript.current_hash()

				expected_verify_data := compute_finished_verify_data(h.hash_algo, h.server_hs_traffic, th_before_sfin)!
				// Constant-time compare: verify_data is a MAC over the transcript,
				// and a naive compare would leak a byte-by-byte Finished forgery.
				if subtle.constant_time_compare(server_verify_data, expected_verify_data) != 1 {
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

				// Switch the application record ciphers into place for post-handshake
				// traffic. The handshake write cipher is left intact so the transport
				// can still encrypt the client Finished under it.
				h.server_app_cipher = h.new_cipher(server_app_keys)!
				h.client_app_cipher = h.new_cipher(client_app_keys)!

				if h.reassembly_buf.len > 0 {
					return error('handshake: unexpected trailing data after server Finished in handshake flight')
				}

				h.state = .connected
				// Forward-secrecy cleanup: every ephemeral/handshake secret consumed
				// to reach this point is now dead, so destroy it here rather than keep
				// it resident for the whole connection (RFC 8446 §7.5 / §1.3.1).
				h.zeroize_handshake_secrets()
				// Hand the raw client Finished to the transport, which encrypts it
				// under the still-active handshake keys.
				return [RawHandshakeMessage{
					content_type: .handshake
					msg:          client_fin_msg
				}]
			}
			else {
				return error('handshake: unexpected handshake message ${msg_type}')
			}
		}
	}
	return []RawHandshakeMessage{}
}

// update_read_traffic_keys ratchets the server application traffic secret to its
// next generation (KeyUpdate, RFC 8446 §7.2) and swaps in the new read cipher.
fn (mut h ClientHandshake) update_read_traffic_keys() ! {
	// Ratchet the secret forward: new_secret = HKDF-Expand-Label(old, "traffic
	// upd", "", Hash) (§7.2); overwriting the old secret is the forward-security
	// property KeyUpdate exists to deliver.
	h.server_ap_traffic = hkdf_expand_label(h.hash_algo, h.server_ap_traffic, 'traffic upd', []u8{}, h.hash_algo.hash_len())!
	new_keys := derive_traffic_keys(h.hash_algo, h.server_ap_traffic, h.key_len, aead_nonce_len)!
	h.server_app_cipher = h.new_cipher(new_keys)! // fresh state restarts the record sequence number at 0 (§5.3)
}

// update_write_traffic_keys ratchets the client application traffic secret to its
// next generation (KeyUpdate, RFC 8446 §7.2) and swaps in the new write cipher.
fn (mut h ClientHandshake) update_write_traffic_keys() ! {
	// Symmetric to update_read_traffic_keys, but §4.6.3 requires the KeyUpdate
	// notice to go out under the old keys first, so callers update after sending.
	h.client_ap_traffic = hkdf_expand_label(h.hash_algo, h.client_ap_traffic, 'traffic upd', []u8{}, h.hash_algo.hash_len())!
	new_keys := derive_traffic_keys(h.hash_algo, h.client_ap_traffic, h.key_len, aead_nonce_len)!
	h.client_app_cipher = h.new_cipher(new_keys)! // fresh state restarts the record sequence number at 0 (§5.3)
}

// zeroize_handshake_secrets destroys the key-schedule inputs and the ephemeral
// ECDHE private halves that are provably dead once the handshake completes.
// RFC 8446 §1.3.1/§7.5: without destroying this material a later memory
// compromise could still recover the secrets that decrypt PAST traffic, which is
// exactly what forward secrecy is meant to prevent. It runs at the single
// success choke point (.connected) because the application traffic secrets and
// instantiated record ciphers already capture everything still needed; KeyUpdate
// ratchets only *_ap_traffic, never the handshake-stage values cleared here.
fn (mut h ClientHandshake) zeroize_handshake_secrets() {
	// Scrub each buffer in place before releasing it: merely reassigning the
	// slice hands the allocator the original bytes untouched, so the wipe has to
	// precede the drop. Best-effort against optimizer dead-store elimination, but
	// the reference releases below always take effect.
	for i in 0 .. h.handshake_secret.len {
		h.handshake_secret[i] = 0
	}
	for i in 0 .. h.client_hs_traffic.len {
		h.client_hs_traffic[i] = 0
	}
	for i in 0 .. h.server_hs_traffic.len {
		h.server_hs_traffic[i] = 0
	}
	h.handshake_secret = []u8{}
	h.client_hs_traffic = []u8{}
	h.server_hs_traffic = []u8{}
	// Release the ephemeral private keys; compute_shared_secret (their only
	// consumer) ran during ServerHello processing, so nothing reads them again.
	h.priv_x25519 = unsafe { nil }
	h.priv_p256 = none
}

// zeroize_app_secrets destroys the application traffic secrets once the
// connection is finished. They are the last retained material from which the
// record keys protecting application data can be re-derived, so keeping them
// past teardown would let a later memory compromise decrypt recorded traffic
// and undo the app-phase forward secrecy the handshake zeroization above is
// meant to establish (RFC 8446 §1.3.1/§7.5). The live record ciphers keep their
// own instantiated keys, so this only closes the secret-recovery path; it is
// safe because read/write refuse once closed and KeyUpdate ratcheting is the
// sole reader, reachable only while the connection is still open.
fn (mut h ClientHandshake) zeroize_app_secrets() {
	for i in 0 .. h.client_ap_traffic.len {
		h.client_ap_traffic[i] = 0
	}
	for i in 0 .. h.server_ap_traffic.len {
		h.server_ap_traffic[i] = 0
	}
	h.client_ap_traffic = []u8{}
	h.server_ap_traffic = []u8{}
}
