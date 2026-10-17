// Copyright (c) 2026 blackshirt.
// SPDX-License-Identifier: MIT
//
// The handshake module implements the TLS 1.3 client protocol machinery of RFC
// 8446: message codec (messages.v), AEAD primitives (aead.v), §7.1 key schedule
// (key_schedule.v), server-signature check (certificate_verify.v), and the
// message-flow state machine (state_machine.v). The client module owns the socket.
module handshake

import crypto.ecdsa
import crypto.rand
import crypto.subtle
import x.crypto.curve25519
import wire
import record
import kdf
import pki

// HandshakeState tracks client progress. The wait_* order mirrors the fixed
// post-ServerHello server flight (EncryptedExtensions → Certificate →
// CertificateVerify → Finished, RFC 8446 §1/§4.1); each handler asserts its
// state before parsing, so an out-of-order message is a protocol violation.
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
	// Traffic keys live only inside the RecordCipherStates below; the reusable
	// state is the traffic secrets (RFC 8446 §7.2 rekeying).
	client_ap_traffic []u8                     // client application traffic secret (§7.1), kept for KeyUpdate
	server_ap_traffic []u8                     // server application traffic secret (§7.1), kept for KeyUpdate
	server_hs_cipher  record.RecordCipherState // AEAD state for records the server sends under handshake keys
	client_hs_cipher  record.RecordCipherState // AEAD state for records we send under handshake keys
	// Handshake messages may be split across records or coalesced within one
	// (RFC 8446 §5.2), so decrypted plaintext accumulates here for reassembly.
	reassembly_buf   []u8
	server_certs     []pki.Certificate // chain sent by the server, leaf first, once Certificate is parsed
	hrr_received     bool              // set after a HelloRetryRequest so the second CH is validated as such
	hrr_cipher_suite ?CipherSuite      // suite selected in the HelloRetryRequest; the final ServerHello must reuse it (§4.1.4)
pub mut:
	// Only members conn.v reads stay public; the rest are handshake-internal.
	state             HandshakeState
	negotiated_alpn   string                   // server's ALPN pick, '' if none; the RFC 7301 §3.1 check guarantees it was one of config.alpn
	server_app_cipher record.RecordCipherState // AEAD state for records the server sends under app keys
	client_app_cipher record.RecordCipherState // AEAD state for records we send under app keys
	session_tickets   []NewSessionTicket       // tickets received post-handshake; currently collected, not resumable
}

// new_client_handshake creates a ClientHandshake offering an X25519 key share —
// mandatory to implement (§9.1) and movable to P-256 via HelloRetryRequest. The
// initial hash/key lengths (SHA-256/AES-128) are provisional, overwritten by the
// server's suite selection.
pub fn new_client_handshake(server_name string, alpn []string) !ClientHandshake {
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

	ch_rec := record.new_record(.handshake, full_client_hello)
	// Dummy ChangeCipherSpec for middlebox compatibility (RFC 8446 App. D.4);
	// servers must tolerate and ignore it.
	ccs_rec := record.change_cipher_spec()

	h.state = .wait_server_hello
	return [ch_rec, ccs_rec], full_client_hello
}

// process_server_hello parses ServerHello or HelloRetryRequest. On HRR it
// returns the follow-up records (second ClientHello + CCS); on a normal
// ServerHello it returns an empty list after deriving the handshake keys.
pub fn (mut h ClientHandshake) process_server_hello(sh_record record.Record) !([]record.Record, ServerHello) {
	if h.state != .wait_server_hello {
		// Strict ordering: a ServerHello is only legal while we await it; reject
		// out-of-turn messages before parsing (§4.4.1).
		return error('handshake: unexpected ServerHello in state ${h.state}')
	}

	// Peel the 4-byte handshake header (type || 3-byte length) to confirm the
	// message type and bound the body (§4).
	mut r := wire.new_reader(sh_record.payload)
	msg_type, length := parse_handshake_header(mut r)!
	if msg_type != .server_hello {
		// HelloRetryRequest reuses the ServerHello type value (2) and is told
		// apart only by the sentinel random later in the parser (§4.1.3).
		return error('handshake: expected ServerHello (2), got ${msg_type}')
	}
	body := r.read_bytes(length)! // body only; the header is re-added for the transcript below
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
	client_hs_keys := kdf.derive_traffic_keys(h.hash_algo, h.client_hs_traffic, h.key_len, record.aead_nonce_len)!
	server_hs_keys := kdf.derive_traffic_keys(h.hash_algo, h.server_hs_traffic, h.key_len, record.aead_nonce_len)!

	h.server_hs_cipher = h.new_cipher(server_hs_keys)!
	h.client_hs_cipher = h.new_cipher(client_hs_keys)!

	h.state = .wait_encrypted_extensions
	return []record.Record{}, sh
}

// set_hash_algo adopts the negotiated suite's hash, rebuilding the transcript
// around it while keeping accumulated messages. A no-op when already matching.
fn (mut h ClientHandshake) set_hash_algo(algo kdf.HashAlgorithm) {
	if h.hash_algo == algo {
		return // already on the target digest — the common SHA-256 case, no rebuild
	}
	// The Transcript keeps the algorithm plus raw messages, not a rolling digest,
	// so a hash change means reconstructing it around the new hash — otherwise
	// derived secrets would keep using the initial SHA-256 and diverge from the
	// server's.
	h.hash_algo = algo
	h.transcript = kdf.Transcript{
		hash_algo: algo
		messages:  h.transcript.messages.clone()
	}
}

// new_cipher instantiates the negotiated suite's AEAD under the given keys and
// wraps it in a fresh record cipher state. Sequence numbers restart at 0 for
// each key generation (§5.3), so KeyUpdate builds a new state instead of
// mutating the old one.
fn (h &ClientHandshake) new_cipher(keys kdf.TrafficKeys) !record.RecordCipherState {
	aead := new_aead_for_suite(h.cipher_suite, keys.key)!
	return record.new_record_cipher_state(aead, keys.iv)!
}

// build_second_client_hello builds the ClientHello retried after a
// HelloRetryRequest: identical to the first except key_share (when a new group
// was requested) and cookie (when supplied) — RFC 8446 §4.1.2.
fn (mut h ClientHandshake) build_second_client_hello(change_group bool, group NamedGroup, cookie []u8) ![]record.Record {
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

	ch_rec := record.new_record(.handshake, full_ch2)
	ccs_rec := record.change_cipher_spec() // repeat the dummy CCS for middlebox compatibility (App. D.4)
	h.state = .wait_server_hello // rearm: the server now answers with the real ServerHello
	return [ch_rec, ccs_rec]
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
			// Defense in depth: a non-zero peer point in the same small subgroup
			// also multiplies to zero, so re-check the backend's result.
			if subtle.constant_time_compare(secret, []u8{len: 32, init: 0}) == 1 {
				return error('handshake: computed X25519 shared secret is all-zero value (illegal_parameter)')
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
pub fn (mut h ClientHandshake) feed_encrypted_record(rec record.Record) ! {
	// Decrypt under the server handshake keys; the true content type lies inside
	// the inner plaintext (§5.1/§5.2).
	decrypted := h.server_hs_cipher.decrypt_record(rec)!
	if decrypted.content_type != .handshake {
		// Only handshake is legal in this phase; anything else violates §5.6.
		return error('handshake: unexpected content type in handshake phase: ${decrypted.content_type}')
	}
	// Accumulate plaintext; process_reassembled_messages joins fragments that span
	// records and splits several messages coalesced into one (§5.2).
	h.reassembly_buf << decrypted.plaintext
}

// process_reassembled_messages processes EncryptedExtensions → Certificate →
// CertificateVerify → Finished. Returns [client_finished] when the handshake
// completes, or an empty list when more encrypted data is needed.
pub fn (mut h ClientHandshake) process_reassembled_messages(validator &pki.Validator) ![]record.Record {
	// Loop over the reassembly buffer consuming one complete message at a time; a
	// partial message means more records are needed, so return and wait.
	for {
		if h.reassembly_buf.len < 4 {
			return []record.Record{} // need the 4-byte handshake header
		}
		mut r := wire.new_reader(h.reassembly_buf)
		msg_type, length := parse_handshake_header(mut r)!
		if h.reassembly_buf.len < 4 + length {
			return []record.Record{} // body not fully received yet
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
				// Verify the server Finished over the transcript up to but
				// excluding this message, using the server handshake traffic secret.
				server_verify_data := parse_finished(body)!
				th_before_sfin := h.transcript.current_hash()

				expected_verify_data := kdf.compute_finished_verify_data(h.hash_algo, h.server_hs_traffic, th_before_sfin)!
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

				client_app_keys := kdf.derive_traffic_keys(h.hash_algo, h.client_ap_traffic, h.key_len, record.aead_nonce_len)!
				server_app_keys := kdf.derive_traffic_keys(h.hash_algo, h.server_ap_traffic, h.key_len, record.aead_nonce_len)!

				// The client Finished uses the handshake traffic secret over the
				// transcript now including server Finished, sent under the (still
				// active) handshake keys.
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
	// Ratchet the secret forward: new_secret = HKDF-Expand-Label(old, "traffic
	// upd", "", Hash) (§7.2); overwriting the old secret is the forward-security
	// property KeyUpdate exists to deliver.
	h.server_ap_traffic = kdf.hkdf_expand_label(h.hash_algo, h.server_ap_traffic, 'traffic upd', []u8{}, h.hash_algo.hash_len())!
	new_keys := kdf.derive_traffic_keys(h.hash_algo, h.server_ap_traffic, h.key_len, record.aead_nonce_len)!
	h.server_app_cipher = h.new_cipher(new_keys)! // fresh state restarts the record sequence number at 0 (§5.3)
}

// update_write_traffic_keys ratchets the client application traffic secret to its
// next generation (KeyUpdate, RFC 8446 §7.2) and swaps in the new write cipher.
pub fn (mut h ClientHandshake) update_write_traffic_keys() ! {
	// Symmetric to update_read_traffic_keys, but §4.6.3 requires a KeyUpdate
	// response to be sent under the OLD write keys, so callers invoke this only
	// after that message goes out.
	h.client_ap_traffic = kdf.hkdf_expand_label(h.hash_algo, h.client_ap_traffic, 'traffic upd', []u8{}, h.hash_algo.hash_len())!
	new_keys := kdf.derive_traffic_keys(h.hash_algo, h.client_ap_traffic, h.key_len, record.aead_nonce_len)!
	h.client_app_cipher = h.new_cipher(new_keys)!
}
