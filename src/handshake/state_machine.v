// module handshake implements the TLS 1.3 client protocol machinery per RFC
// 8446: messages.v encodes/decodes each handshake message (including the §4.2
// extension framing, placement policy, and ServerHello semantic checks),
// aead.v supplies the AEAD primitives, key_schedule.v holds the pure §7.1
// secret derivations, certificate_verify.v checks the server signature, and
// state_machine.v drives the message flow and wires those pieces together.
// conn.v in the client module owns the socket; this module is pure protocol
// state.
module handshake

import crypto.ecdsa
import crypto.rand
import crypto.subtle
import x.crypto.curve25519
import wire
import record
import kdf
import pki

// HandshakeState tracks the progression of a TLS 1.3 client handshake.
// The wait_* order mirrors the fixed server flight after ServerHello
// (EncryptedExtensions → Certificate → CertificateVerify → Finished, RFC 8446 §1/
// §4.1): a message arriving out of order is a protocol violation, which is why
// each handler asserts its state before parsing.
pub enum HandshakeState {
	start                     // nothing sent yet; create_client_hello moves us out of here
	wait_server_hello         // ClientHello sent; awaiting ServerHello or HelloRetryRequest
	wait_encrypted_extensions // ServerHello accepted and handshake keys installed
	wait_certificate          // EncryptedExtensions accepted (ALPN/SNI checks done)
	wait_certificate_verify   // server chain parsed and hostname/chain validated
	wait_server_finished      // CertificateVerify verified against the leaf key
	connected                 // server Finished verified; application data may flow
	failed                    // terminal error; no further handshake messages are accepted
}

// ClientHandshake orchestrates the TLS 1.3 client handshake state machine.
pub struct ClientHandshake {
mut:
	config            ClientHelloConfig // inputs echoed/replayed when rebuilding the second ClientHello
	transcript        kdf.Transcript    // running hash of all handshake messages (RFC 8446 §4.4.1)
	hash_algo         kdf.HashAlgorithm // hash of the negotiated suite; drives every key derivation
	cipher_suite      CipherSuite       // suite selected by the server in ServerHello
	key_len           int               // AEAD key length of that suite (16 or 32 bytes)
	ecdhe_group       NamedGroup        // group of our key share; may change on HelloRetryRequest
	priv_x25519       &curve25519.PrivateKey = unsafe { nil } // private half of the X25519 share
	priv_p256         ?ecdsa.PrivateKey // private half of the P-256 share, set when that group is used
	client_hello1     []u8              // full first ClientHello, kept for the HRR message_hash substitution (§4.4.1)
	handshake_secret  []u8              // Early Secret → Handshake Secret stage (§7.1)
	client_hs_traffic []u8              // client handshake traffic secret (§7.1)
	server_hs_traffic []u8              // server handshake traffic secret (§7.1)
	// Traffic keys are never stored: they are derived into locals and live on
	// only inside the RecordCipherStates below, which are the sole consumers —
	// the reusable state is the traffic *secrets* (next fields + ap_traffic),
	// per RFC 8446 §7.2 rekeying.
	client_ap_traffic []u8                     // client application traffic secret (§7.1), kept for KeyUpdate
	server_ap_traffic []u8                     // server application traffic secret (§7.1), kept for KeyUpdate
	server_hs_cipher  record.RecordCipherState // AEAD state for records the server sends under handshake keys
	client_hs_cipher  record.RecordCipherState // AEAD state for records we send under handshake keys
	// Handshake messages may be split across records or coalesced within one
	// (RFC 8446 §5.2), so decrypted plaintext accumulates here and complete
	// messages are consumed from the front as they become available.
	reassembly_buf   []u8
	server_certs     []pki.Certificate // chain sent by the server, leaf first, once Certificate is parsed
	hrr_received     bool              // set after a HelloRetryRequest so the second CH is validated as such
	hrr_cipher_suite ?CipherSuite      // suite selected in the HelloRetryRequest; the final ServerHello must reuse it (§4.1.4)
pub mut:
	// Only the members conn.v actually reads stay public; everything above is
	// handshake-internal and hidden from the client module.
	state             HandshakeState
	negotiated_alpn   string                   // server's ALPN pick, '' if none; the RFC 7301 §3.1 check guarantees it was one of config.alpn
	server_app_cipher record.RecordCipherState // AEAD state for records the server sends under app keys
	client_app_cipher record.RecordCipherState // AEAD state for records we send under app keys
	session_tickets   []NewSessionTicket       // tickets received post-handshake; currently collected, not resumable
}

// new_client_handshake creates a new ClientHandshake with an X25519 key share.
// X25519 is the default first offer because it is mandatory to implement in TLS
// 1.3 (RFC 8446 §9.1); a HelloRetryRequest can still move us to P-256 later.
// The hash/key lengths start at the SHA-256/AES-128 values and are only
// provisional: the server's cipher suite selection overwrites them before any
// derivation that matters. The 32-byte session_id satisfies the middlebox
// compatibility recommendation (RFC 8446 App. D.4).
pub fn new_client_handshake(server_name string, alpn []string) !ClientHandshake {
	// Generate the ephemeral X25519 key pair up front so the very first ClientHello
	// can already carry a key_share: TLS 1.3 has no separate key-exchange round
	// trip, so the public share must ride in the initial hello (§4.2.8).
	mut priv_key := curve25519.PrivateKey.new()! // fresh 32-byte X25519 scalar
	pub_key := priv_key.public_key()! // base-point multiplication of the scalar
	raw_pub := pub_key.bytes()! // 32-byte encoding placed verbatim in key_exchange
	// Draw the two randoms that must stay stable for the whole connection: the
	// legacy session id (echoed by the server, re-used after an HRR) and
	// ClientHello.random. Keeping them in config lets the retry hello reproduce
	// them byte-identically, as §4.1.4 requires.
	session_id := rand.bytes(legacy_session_id_len)! // 32 bytes for middlebox compatibility (App. D.4)
	random := rand.bytes(client_hello_random_len)! // 32-byte ClientHello.random

	// Assemble the initial hello inputs. The key-share group is pinned to X25519
	// — mandatory to implement (§9.1) — and cookie is left empty until a
	// HelloRetryRequest supplies one; cipher_suites defaults elsewhere to the three
	// TLS 1.3 AEAD suites.
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
		transcript:     kdf.new_transcript(.sha256)
		hash_algo:      .sha256
		key_len:        16
		ecdhe_group:    .x25519
		priv_x25519:    priv_key
		reassembly_buf: []u8{cap: 4096}
	}
}

// create_client_hello generates the initial ClientHello record and dummy ChangeCipherSpec.
pub fn (mut h ClientHandshake) create_client_hello() !([]record.Record, []u8) {
	// Pin the random/session id NOW instead of letting build_client_hello draw
	// fresh ones per call: the legacy_session_id_echo check compares the server's
	// echo against config.session_id (§4.1.3), and after an HRR §4.1.4 requires
	// the second ClientHello to be identical except key_share/cookie. Without
	// pinning, an HRR against a real server could never validate and the retry
	// hello would silently differ in fields the spec freezes.
	if h.config.session_id.len == 0 {
		h.config.session_id = rand.bytes(legacy_session_id_len)!
	}
	if h.config.random.len != client_hello_random_len {
		h.config.random = rand.bytes(client_hello_random_len)!
	}
	_, full_client_hello := build_client_hello(h.config)!
	h.client_hello1 = full_client_hello.clone()
	h.transcript.update(full_client_hello)

	ch_rec := record.new_record(.handshake, full_client_hello)
	// A dummy ChangeCipherSpec is sent after the ClientHello for middlebox
	// compatibility (RFC 8446 App. D.4); servers must tolerate and ignore it.
	ccs_rec := record.change_cipher_spec()

	h.state = .wait_server_hello
	return [ch_rec, ccs_rec], full_client_hello
}

// process_server_hello parses ServerHello or HelloRetryRequest.
// On HRR it returns follow-up records (second ClientHello + CCS).
// On a normal ServerHello it returns an empty record list after deriving HS keys.
pub fn (mut h ClientHandshake) process_server_hello(sh_record record.Record) !([]record.Record, ServerHello) {
	if h.state != .wait_server_hello {
		// Strict ordering: a ServerHello/HelloRetryRequest is only legal while we
		// are waiting for it. Any other state means the peer delivered a message out
		// of turn (§4.4.1), so reject before parsing rather than acting on a possible
		// reordering/truncation attack.
		return error('handshake: unexpected ServerHello in state ${h.state}')
	}

	// Peel the 4-byte handshake header (type || 3-byte length) off the record
	// payload. We read it here to both confirm the message type and know exactly
	// how many bytes form the body that parse_server_hello then decodes (§4).
	mut r := wire.new_reader(sh_record.payload)
	msg_type, length := parse_handshake_header(mut r)!
	if msg_type != .server_hello {
		// HelloRetryRequest reuses the ServerHello type value (2) and is told apart
		// only by the sentinel random later in the parser; anything other than 2 is
		// unexpected in this slot (§4.1.3).
		return error('handshake: expected ServerHello (2), got ${msg_type}')
	}
	body := r.read_bytes(length)! // body only; the header is re-added for the transcript below
	sh := parse_server_hello(body)! // §4.1.3 field decode plus the §4.2 extension allowlist
	// Re-frame header + body for the transcript: hashing must cover the exact
	// 4-byte-message-type || 3-byte-length || body layout sent on the wire, and
	// wrap_handshake_message reproduces it byte-identically from the parsed body.
	full_sh_msg := wrap_handshake_message(.server_hello, body)

	if sh.is_hello_retry_req {
		// RFC 8446 §4.1.4: validate the shared ServerHello fields, reject a second
		// HelloRetryRequest, and require that the request actually changes something.
		sh.validate(&h.config)!
		if h.hrr_received {
			return error('handshake: received second HelloRetryRequest (unexpected_message)')
		}

		if !sh.has_key_share && sh.cookie.len == 0 {
			return error('handshake: HelloRetryRequest would not change the ClientHello (illegal_parameter)')
		}
		if sh.has_key_share {
			// The requested group must be one we offer and must differ from the
			// group we already sent a key share for (RFC 8446 §4.2.8).
			if !is_supported_group(sh.server_share.group) {
				return error('handshake: HelloRetryRequest requested unsupported group ${sh.server_share.group} (illegal_parameter)')
			}
			if sh.server_share.group == h.config.client_share.group {
				return error('handshake: HelloRetryRequest reselected the already-offered group ${sh.server_share.group} (illegal_parameter)')
			}
		}

		h.hrr_received = true
		// RFC 8446 §4.1.4: the final ServerHello MUST select this same cipher
		// suite; remember it so the ServerHello handler can enforce that.
		h.hrr_cipher_suite = sh.cipher_suite
		// RFC 8446 §4.4.1: the synthetic message_hash replacing ClientHello1 must
		// use the hash from the HRR's cipher suite — update now before applying HRR.
		h.set_hash_algo(suite_hash_algo(sh.cipher_suite))
		h.transcript.apply_hello_retry_request(h.client_hello1, full_sh_msg)

		followups := h.build_second_client_hello(sh.has_key_share, sh.server_share.group, sh.cookie)!
		return followups, sh
	}

	// Normal ServerHello. Validate the echoed fields and that the server selected
	// a key share for the group we offered; with only (EC)DHE key exchange a
	// missing key_share leaves us unable to derive the handshake keys.
	sh.validate(&h.config)!
	// RFC 8446 §4.1.4: after a HelloRetryRequest the ServerHello cipher suite
	// must match the one the HRR selected, otherwise abort with illegal_parameter.
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

	// The cipher suite fixes both the hash and the key length, so set them on the
	// transcript before deriving any secrets.
	h.cipher_suite = sh.cipher_suite
	h.key_len = suite_key_len(sh.cipher_suite)
	h.set_hash_algo(suite_hash_algo(sh.cipher_suite))
	h.transcript.update(full_sh_msg)

	// RFC 8446 §7.1 key schedule (handshake phase). Starting from the ECDHE
	// shared secret, derive the handshake secret and the client/server handshake
	// traffic secrets, then expand each into an AEAD key + IV.
	shared_secret := h.compute_shared_secret(sh.server_share)!

	// The handshake secret is retained because the Master Secret (application
	// phase, after server Finished) derives from it; the traffic secrets feed the
	// handshake write keys below.
	th_ch_sh := h.transcript.current_hash()
	hs := derive_hs_secrets(h.hash_algo, shared_secret, th_ch_sh)!
	h.handshake_secret = hs.handshake_secret
	h.client_hs_traffic = hs.client_traffic
	h.server_hs_traffic = hs.server_traffic

	// Each traffic secret expands into the record-layer AEAD write key and IV;
	// the keys themselves exist only as locals feeding new_cipher.
	client_hs_keys := kdf.derive_traffic_keys(h.hash_algo, h.client_hs_traffic, h.key_len, record.aead_nonce_len)!
	server_hs_keys := kdf.derive_traffic_keys(h.hash_algo, h.server_hs_traffic, h.key_len, record.aead_nonce_len)!

	h.server_hs_cipher = h.new_cipher(server_hs_keys)!
	h.client_hs_cipher = h.new_cipher(client_hs_keys)!

	h.state = .wait_encrypted_extensions
	return []record.Record{}, sh
}

// set_hash_algo adopts the negotiated suite's hash: the Transcript only stores
// the algo alongside raw messages, so switching rebuilds it around the new hash
// while keeping everything accumulated so far. A no-op when the suite's hash
// already matches (the initial SHA-256 default).
fn (mut h ClientHandshake) set_hash_algo(algo kdf.HashAlgorithm) {
	if h.hash_algo == algo {
		return // already on the target digest — the common SHA-256 case, no rebuild
	}
	// The Transcript persists only the algorithm plus the raw messages, not a
	// rolling digest, so adopting a suite with a different hash (SHA-384 for
	// AES-256-GCM) means reconstructing it around the new algorithm while carrying
	// every byte accumulated so far — otherwise the running hash would keep using
	// the initial SHA-256 default and every derived secret would diverge from the
	// server's.
	h.hash_algo = algo
	h.transcript = kdf.Transcript{
		hash_algo: algo
		messages:  h.transcript.messages.clone()
	}
}

// new_cipher instantiates the negotiated suite's AEAD under the given traffic
// keys and wraps it in a fresh record cipher state (sequence numbers restart at
// 0 for every new key generation — RFC 8446 §5.3 — which is why rekeying via
// KeyUpdate builds a new state instead of mutating the old one).
fn (h &ClientHandshake) new_cipher(keys kdf.TrafficKeys) !record.RecordCipherState {
	aead := new_aead_for_suite(h.cipher_suite, keys.key)!
	return record.new_record_cipher_state(aead, keys.iv)!
}

// build_second_client_hello constructs the ClientHello sent in response to a
// HelloRetryRequest. The retried ClientHello must be identical to the first
// except that the key_share is replaced when a new group was requested and the
// cookie is echoed when one was supplied (RFC 8446 §4.1.2).
fn (mut h ClientHandshake) build_second_client_hello(change_group bool, group NamedGroup, cookie []u8) ![]record.Record {
	if change_group {
		h.generate_key_share(group)!
		h.config.client_share = KeyShareEntry{
			group:        group
			key_exchange: h.public_share_bytes()!
		}
	}
	// A cookie-only HelloRetryRequest keeps the original key share unchanged.
	// Stash the server's cookie verbatim so build_client_hello echoes it back as
	// the cookie extension; every other field of the retried hello must stay
	// byte-identical to the first except for key_share/cookie (§4.1.4/§4.2.2).
	h.config.cookie = cookie
	_, full_ch2 := build_client_hello(h.config)!
	// Hash the new hello into the already message_hash-rewritten transcript so the
	// eventual Finished MAC covers the retried flight rather than ClientHello1
	// (§4.4.1).
	h.transcript.update(full_ch2)

	ch_rec := record.new_record(.handshake, full_ch2)
	ccs_rec := record.change_cipher_spec() // repeat the dummy CCS for middlebox compatibility (App. D.4)
	h.state = .wait_server_hello // rearm: the server now answers with the real ServerHello
	return [ch_rec, ccs_rec]
}

// generate_key_share creates a fresh ephemeral private key for the requested
// group. Used when responding to a HelloRetryRequest for a different group.
fn (mut h ClientHandshake) generate_key_share(group NamedGroup) ! {
	h.ecdhe_group = group
	match group {
		.x25519 {
			h.priv_x25519 = curve25519.PrivateKey.new()!
			h.priv_p256 = none
		}
		.secp256r1 {
			h.priv_p256 = ecdsa.PrivateKey.new(nid: .prime256v1)!
			// priv_x25519 is intentionally left populated: every later dispatch
			// (public_share_bytes/compute_shared_secret) routes on ecdhe_group, so a
			// stale X25519 key is unreachable — clearing it would only hide bugs,
			// not prevent them.
		}
	}
}

// public_share_bytes serializes the public half of the current ephemeral key in
// the wire form its group mandates for the key_share extension: raw 32 bytes
// for X25519, an uncompressed 0x04||X||Y point for P-256 (RFC 8446 §4.2.8.2).
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

// compute_shared_secret performs the ECDHE exchange against the server's key
// share, returning the raw shared secret that seeds the key schedule.
fn (mut h ClientHandshake) compute_shared_secret(server_share KeyShareEntry) ![]u8 {
	// RFC 8446 §4.2.8.2 fixes the key_exchange size per group. Gate it here so a
	// wrong size fails with a named protocol error instead of whatever panic or
	// opaque library error the crypto backend would produce (they differ per
	// group and per platform, which is exactly what a hostile share exploits).
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
			// RFC 8446 §4.2.8.2 & RFC 7748 §6.1: an all-zero peer u-coordinate is
			// the small-order subgroup identity, so scalar multiplication would
			// yield an all-zero shared secret (small-subgroup attack). Gate it
			// before the backend, which rejects the same input with an opaque
			// library error, so the abort carries our named protocol error.
			if subtle.constant_time_compare(server_share.key_exchange, []u8{len: 32, init: 0}) == 1 {
				return error('handshake: computed X25519 shared secret is all-zero value (illegal_parameter)')
			}
			secret := h.priv_x25519.x25519(server_share.key_exchange)!
			// Defence in depth: a non-zero peer point in the same small subgroup
			// also multiplies to zero, so re-check the backend's result.
			if subtle.constant_time_compare(secret, []u8{len: 32, init: 0}) == 1 {
				return error('handshake: computed X25519 shared secret is all-zero value (illegal_parameter)')
			}
			return secret
		}
		.secp256r1 {
			// Only the uncompressed encoding is legal in TLS 1.3 (§4.2.8.2);
			// compressed shares start 0x02/0x03 and would be a different (here:
			// unsupported) point encoding, so name the framing problem explicitly.
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
	// Unreachable: the match above is exhaustive over NamedGroup and every arm
	// returns or errors.
	return error('handshake: unsupported key_share group ${server_share.group}')
}

// feed_encrypted_record decrypts a handshake-phase record into the reassembly buffer.
pub fn (mut h ClientHandshake) feed_encrypted_record(rec record.Record) ! {
	// Decrypt under the server's handshake traffic keys: everything the server
	// sends after ServerHello is protected, so a plaintext handshake record never
	// appears again — the true message type lives inside the inner plaintext
	// (§5.1/§5.2).
	decrypted := h.server_hs_cipher.decrypt_record(rec)!
	if decrypted.content_type != .handshake {
		// In this phase the only legal inner content type is handshake; an
		// application_data or alert here is a protocol violation (§5.6), so abort
		// rather than mis-routing it into the transcript.
		return error('handshake: unexpected content type in handshake phase: ${decrypted.content_type}')
	}
	// Accumulate the recovered plaintext; process_reassembled_messages later walks
	// this buffer, joining message fragments that span records and splitting
	// several messages coalesced into one (§5.2).
	h.reassembly_buf << decrypted.plaintext
}

// process_reassembled_messages processes EncryptedExtensions → Certificate →
// CertificateVerify → Finished. Returns [client_finished] when the handshake
// completes, or an empty list when more encrypted data is needed.
pub fn (mut h ClientHandshake) process_reassembled_messages(validator &pki.Validator) ![]record.Record {
	// Handshake messages may span several records, so loop over the reassembly
	// buffer consuming one complete message at a time. A partial message means
	// more records are needed, so return and wait for the next feed.
	for {
		if h.reassembly_buf.len < 4 {
			return []record.Record{} // need the 4-byte handshake header
		}
		mut r := wire.new_reader(h.reassembly_buf)
		msg_type, length := parse_handshake_header(mut r)!
		if h.reassembly_buf.len < 4 + length {
			return []record.Record{} // body not fully received yet
		}

		// Consume the whole message; `full_msg` is what gets hashed into the
		// transcript (header + body), while `body` is the parsed payload.
		body := r.read_bytes(length)!
		full_msg := h.reassembly_buf[..4 + length].clone()
		h.reassembly_buf = h.reassembly_buf[4 + length..].clone()

		match msg_type {
			.encrypted_extensions {
				if h.state != .wait_encrypted_extensions {
					return error('handshake: unexpected EncryptedExtensions')
				}
				alpn := parse_encrypted_extensions(body)!
				// RFC 7301 §3.1: the server must pick a protocol from the client's
				// offered list (or send no ALPN at all). Without this check an
				// on-path attacker could silently steer the application protocol
				// below us with an unoffered ALPN value in EncryptedExtensions.
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
				cert_ders := parse_certificate(body)!
				h.transcript.update(full_msg)

				h.server_certs = []pki.Certificate{}
				for der in cert_ders {
					h.server_certs << pki.parse_certificate(der)!
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
				// Verify the server's Finished using the handshake traffic
				// secret and the transcript up to (but excluding) this message.
				server_verify_data := parse_finished(body)!
				th_before_sfin := h.transcript.current_hash()

				expected_verify_data := kdf.compute_finished_verify_data(h.hash_algo, h.server_hs_traffic, th_before_sfin)!
				// Constant-time comparison: verify_data is effectively a MAC over the
				// transcript, and a naive byte comparison leaks match length through
				// timing, letting an on-path attacker forge Finished byte-by-byte.
				if subtle.constant_time_compare(server_verify_data, expected_verify_data) != 1 {
					return error('handshake: server Finished verify_data mismatch')
				}
				h.transcript.update(full_msg)

				// With the server Finished verified, advance the key schedule to
				// the application phase: Master Secret, then the application
				// traffic secrets bound to the transcript including server Finished.
				th_sfin := h.transcript.current_hash()
				ap := derive_app_secrets(h.hash_algo, h.handshake_secret, th_sfin)!
				h.client_ap_traffic = ap.client_traffic
				h.server_ap_traffic = ap.server_traffic

				client_app_keys := kdf.derive_traffic_keys(h.hash_algo, h.client_ap_traffic, h.key_len, record.aead_nonce_len)!
				server_app_keys := kdf.derive_traffic_keys(h.hash_algo, h.server_ap_traffic, h.key_len, record.aead_nonce_len)!

				// The client Finished is computed with the handshake traffic
				// secret over the transcript that now includes server Finished,
				// then sent encrypted under the (still active) handshake keys.
				client_verify_data := kdf.compute_finished_verify_data(h.hash_algo, h.client_hs_traffic, th_sfin)!
				client_fin_msg := build_finished(client_verify_data)
				h.transcript.update(client_fin_msg)

				client_fin_rec := h.client_hs_cipher.encrypt_record(.handshake, client_fin_msg)!

				// Switch the application record ciphers into place for post-handshake traffic.
				h.server_app_cipher = h.new_cipher(server_app_keys)!
				h.client_app_cipher = h.new_cipher(client_app_keys)!

				if h.reassembly_buf.len > 0 {
					return error('handshake: unexpected trailing data after server Finished in handshake flight')
				}

				h.state = .connected
				return [client_fin_rec]
			}
			else {
				return error('handshake: unexpected handshake message ${msg_type}')
			}
		}
	}
	return []record.Record{}
}

// update_read_traffic_keys ratchets the server application traffic secret to its
// next generation (KeyUpdate, RFC 8446 §7.2) and swaps in the new read cipher.
pub fn (mut h ClientHandshake) update_read_traffic_keys() ! {
	// Ratchet the server's application traffic secret forward before deriving the
	// next read keys: new_secret = HKDF-Expand-Label(old, "traffic upd", "", Hash)
	// (§7.2). Overwriting the old secret means prior keys can no longer open newer
	// records — the forward-security property KeyUpdate exists to deliver.
	h.server_ap_traffic = kdf.hkdf_expand_label(h.hash_algo, h.server_ap_traffic, 'traffic upd', []u8{}, h.hash_algo.hash_len())!
	new_keys := kdf.derive_traffic_keys(h.hash_algo, h.server_ap_traffic, h.key_len, record.aead_nonce_len)!
	h.server_app_cipher = h.new_cipher(new_keys)! // fresh state restarts the record sequence number at 0 (§5.3)
}

// update_write_traffic_keys ratchets the client application traffic secret to its
// next generation (KeyUpdate, RFC 8446 §7.2) and swaps in the new write cipher.
pub fn (mut h ClientHandshake) update_write_traffic_keys() ! {
	// Symmetric to update_read_traffic_keys but for our outgoing direction, and
	// subject to a stricter ordering rule (§4.6.3): a KeyUpdate response must be
	// sent under the OLD write keys, so the caller only invokes this AFTER that
	// message goes out. Ratchet the secret, re-expand key+IV, and install a fresh
	// cipher whose sequence number restarts at 0 to avoid nonce reuse (§5.3).
	h.client_ap_traffic = kdf.hkdf_expand_label(h.hash_algo, h.client_ap_traffic, 'traffic upd', []u8{}, h.hash_algo.hash_len())!
	new_keys := kdf.derive_traffic_keys(h.hash_algo, h.client_ap_traffic, h.key_len, record.aead_nonce_len)!
	h.client_app_cipher = h.new_cipher(new_keys)!
}
