// module handshake implements the TLS 1.3 client protocol machinery per RFC
// 8446: messages.v encodes/decodes each handshake message (including the §4.2
// extension framing and placement policy), aead.v supplies the AEAD primitives
// that protect handshake and application records, and state_machine.v drives
// the message flow, key-schedule integration, and CertificateVerify checks.
// conn.v in the client module owns the socket; this module is pure protocol
// state.
module handshake

import crypto.ecdsa
import crypto.ed25519
import crypto.rand
import crypto.sha512
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
pub mut:
	state             HandshakeState
	config            ClientHelloConfig // inputs echoed/replayed when rebuilding the second ClientHello
	transcript        kdf.Transcript    // running hash of all handshake messages (RFC 8446 §4.4.1)
	hash_algo         kdf.HashAlgorithm // hash of the negotiated suite; drives every key derivation
	cipher_suite      CipherSuite       // suite selected by the server in ServerHello
	key_len           int               // AEAD key length of that suite (16 or 32 bytes)
	ecdhe_group       NamedGroup        // group of our key share; may change on HelloRetryRequest
	priv_x25519       &curve25519.PrivateKey = unsafe { nil } // private half of the X25519 share
	priv_p256         ?ecdsa.PrivateKey        // private half of the P-256 share, set when that group is used
	client_hello1     []u8                     // full first ClientHello, kept for the HRR message_hash substitution (§4.4.1)
	handshake_secret  []u8                     // Early Secret → Handshake Secret stage (§7.1)
	client_hs_traffic []u8                     // client handshake traffic secret (§7.1)
	server_hs_traffic []u8                     // server handshake traffic secret (§7.1)
	client_hs_keys    kdf.TrafficKeys          // client write keys derived from client_hs_traffic
	server_hs_keys    kdf.TrafficKeys          // server write keys derived from server_hs_traffic
	client_app_keys   kdf.TrafficKeys          // client write keys for application data
	server_app_keys   kdf.TrafficKeys          // server write keys for application data
	client_ap_traffic []u8                     // client application traffic secret (§7.1), kept for KeyUpdate
	server_ap_traffic []u8                     // server application traffic secret (§7.1), kept for KeyUpdate
	server_hs_cipher  record.RecordCipherState // AEAD state for records the server sends under handshake keys
	client_hs_cipher  record.RecordCipherState // AEAD state for records we send under handshake keys
	server_app_cipher record.RecordCipherState // AEAD state for records the server sends under app keys
	client_app_cipher record.RecordCipherState // AEAD state for records we send under app keys
	// Handshake messages may be split across records or coalesced within one
	// (RFC 8446 §5.2), so decrypted plaintext accumulates here and complete
	// messages are consumed from the front as they become available.
	reassembly_buf   []u8
	server_certs     []pki.Certificate  // chain sent by the server, leaf first, once Certificate is parsed
	negotiated_alpn  string             // server's ALPN pick, '' if none; the RFC 7301 §3.1 check guarantees it was one of config.alpn
	session_tickets  []NewSessionTicket // tickets received post-handshake; currently collected, not resumable
	hrr_received     bool               // set after a HelloRetryRequest so the second CH is validated as such
	hrr_cipher_suite ?CipherSuite       // suite selected in the HelloRetryRequest; the final ServerHello must reuse it (§4.1.4)
}

// new_client_handshake creates a new ClientHandshake with an X25519 key share.
// X25519 is the default first offer because it is mandatory to implement in TLS
// 1.3 (RFC 8446 §9.1); a HelloRetryRequest can still move us to P-256 later.
// The hash/key lengths start at the SHA-256/AES-128 values and are only
// provisional: the server's cipher suite selection overwrites them before any
// derivation that matters. The 32-byte session_id satisfies the middlebox
// compatibility recommendation (RFC 8446 App. D.4).
pub fn new_client_handshake(server_name string, alpn []string) !ClientHandshake {
	mut priv_key := curve25519.PrivateKey.new()!
	pub_key := priv_key.public_key()!
	raw_pub := pub_key.bytes()!
	session_id := rand.bytes(legacy_session_id_len)!
	random := rand.bytes(client_hello_random_len)!

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
		return error('handshake: unexpected ServerHello in state ${h.state}')
	}

	mut r := wire.new_reader(sh_record.payload)
	msg_type, length := parse_handshake_header(mut r)!
	if msg_type != .server_hello {
		return error('handshake: expected ServerHello (2), got ${msg_type}')
	}
	body := r.read_bytes(length)!
	sh := parse_server_hello(body)!
	// Re-frame header + body for the transcript: hashing must cover the exact
	// 4-byte-message-type || 3-byte-length || body layout sent on the wire, and
	// wrap_handshake_message reproduces it byte-identically from the parsed body.
	full_sh_msg := wrap_handshake_message(.server_hello, body)

	if sh.is_hello_retry_req {
		// RFC 8446 §4.1.4: validate the shared ServerHello fields, reject a second
		// HelloRetryRequest, and require that the request actually changes something.
		h.validate_server_hello_common(sh)!
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
	h.validate_server_hello_common(sh)!
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

	// Early Secret = HKDF-Extract(0, 0). Without a PSK the IKM is empty, but it
	// is still mixed in via Derive-Secret so the schedule matches the RFC.
	early_secret := kdf.hkdf_extract(h.hash_algo, []u8{}, []u8{len: h.hash_algo.hash_len()})
	derived_early := kdf.derive_secret(h.hash_algo, early_secret, 'derived', kdf.empty_transcript_hash(h.hash_algo))!
	// Handshake Secret = HKDF-Extract(Derive-Secret(Early, "derived"), ECDHE)
	h.handshake_secret = kdf.hkdf_extract(h.hash_algo, derived_early, shared_secret)

	// Handshake traffic secrets are bound to the transcript through ServerHello.
	th_ch_sh := h.transcript.current_hash()
	h.client_hs_traffic = kdf.derive_secret(h.hash_algo, h.handshake_secret, 'c hs traffic', th_ch_sh)!
	h.server_hs_traffic = kdf.derive_secret(h.hash_algo, h.handshake_secret, 's hs traffic', th_ch_sh)!

	// Each traffic secret expands into the record-layer AEAD write key and IV.
	h.client_hs_keys = kdf.derive_traffic_keys(h.hash_algo, h.client_hs_traffic, h.key_len, record.aead_nonce_len)!
	h.server_hs_keys = kdf.derive_traffic_keys(h.hash_algo, h.server_hs_traffic, h.key_len, record.aead_nonce_len)!

	h.server_hs_cipher = h.new_cipher(h.server_hs_keys)!
	h.client_hs_cipher = h.new_cipher(h.client_hs_keys)!

	h.state = .wait_encrypted_extensions
	return []record.Record{}, sh
}

// validate_server_hello_common performs the ServerHello/HelloRetryRequest checks
// that do not depend on the message variant (RFC 8446 §4.1.3): the echoed legacy
// session ID must match the ClientHello, and the selected cipher suite must have
// been offered by the client.
fn (h &ClientHandshake) validate_server_hello_common(sh ServerHello) ! {
	if sh.session_id_echo != h.config.session_id {
		return error('handshake: legacy_session_id_echo does not match ClientHello (illegal_parameter)')
	}
	if !h.is_offered_cipher_suite(sh.cipher_suite) {
		return error('handshake: server selected unoffered cipher suite ${sh.cipher_suite} (illegal_parameter)')
	}
}

// is_offered_cipher_suite reports whether the client advertised the suite.
fn (h &ClientHandshake) is_offered_cipher_suite(cs CipherSuite) bool {
	for offered in h.offered_cipher_suites() {
		if offered == cs {
			return true
		}
	}
	return false
}

// offered_cipher_suites returns the suites sent in the ClientHello: the explicit
// configuration if present, otherwise the built-in default list.
fn (h &ClientHandshake) offered_cipher_suites() []CipherSuite {
	if h.config.cipher_suites.len > 0 {
		return h.config.cipher_suites
	}
	return default_cipher_suites()
}

// is_supported_group reports whether the client advertised support for a group in
// its supported_groups extension (see build_client_hello).
fn is_supported_group(g NamedGroup) bool {
	return g == .x25519 || g == .secp256r1
}

// set_hash_algo adopts the negotiated suite's hash: the Transcript only stores
// the algo alongside raw messages, so switching rebuilds it around the new hash
// while keeping everything accumulated so far. A no-op when the suite's hash
// already matches (the initial SHA-256 default).
fn (mut h ClientHandshake) set_hash_algo(algo kdf.HashAlgorithm) {
	if h.hash_algo == algo {
		return
	}
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
	h.config.cookie = cookie
	_, full_ch2 := build_client_hello(h.config)!
	h.transcript.update(full_ch2)

	ch_rec := record.new_record(.handshake, full_ch2)
	ccs_rec := record.change_cipher_spec()
	h.state = .wait_server_hello
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
			return h.priv_x25519.x25519(server_share.key_exchange)!
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
			return priv.derive_shared_secret(peer)!
		}
	}
	// Unreachable: the match above is exhaustive over NamedGroup and every arm
	// returns or errors.
	return error('handshake: unsupported key_share group ${server_share.group}')
}

// feed_encrypted_record decrypts a handshake-phase record into the reassembly buffer.
pub fn (mut h ClientHandshake) feed_encrypted_record(rec record.Record) ! {
	decrypted := h.server_hs_cipher.decrypt_record(rec)!
	if decrypted.content_type != .handshake {
		return error('handshake: unexpected content type in handshake phase: ${decrypted.content_type}')
	}
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
				derived_hs := kdf.derive_secret(h.hash_algo, h.handshake_secret, 'derived', kdf.empty_transcript_hash(h.hash_algo))!
				master_secret := kdf.hkdf_extract(h.hash_algo, derived_hs, []u8{len: h.hash_algo.hash_len()})

				th_sfin := h.transcript.current_hash()
				h.client_ap_traffic = kdf.derive_secret(h.hash_algo, master_secret, 'c ap traffic', th_sfin)!
				h.server_ap_traffic = kdf.derive_secret(h.hash_algo, master_secret, 's ap traffic', th_sfin)!

				h.client_app_keys = kdf.derive_traffic_keys(h.hash_algo, h.client_ap_traffic, h.key_len, record.aead_nonce_len)!
				h.server_app_keys = kdf.derive_traffic_keys(h.hash_algo, h.server_ap_traffic, h.key_len, record.aead_nonce_len)!

				// The client Finished is computed with the handshake traffic
				// secret over the transcript that now includes server Finished,
				// then sent encrypted under the (still active) handshake keys.
				client_verify_data := kdf.compute_finished_verify_data(h.hash_algo, h.client_hs_traffic, th_sfin)!
				client_fin_msg := build_finished(client_verify_data)
				h.transcript.update(client_fin_msg)

				client_fin_rec := h.client_hs_cipher.encrypt_record(.handshake, client_fin_msg)!

				// Switch the application record ciphers into place for post-handshake traffic.
				h.server_app_cipher = h.new_cipher(h.server_app_keys)!
				h.client_app_cipher = h.new_cipher(h.client_app_keys)!

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

// hash_for_digest returns Hash(data) for the named digest ("sha256"/"sha384"/"sha512").
fn hash_for_digest(digest_type string, data []u8) []u8 {
	return match digest_type {
		'sha256' { kdf.HashAlgorithm.sha256.compute_hash(data) }
		'sha384' { kdf.HashAlgorithm.sha384.compute_hash(data) }
		else { sha512.sum512(data) }
	}
}

// verify_certificate_verify checks the server's CertificateVerify signature
// against the leaf certificate's public key over the §4.4.3 signed content
// (see certificate_verify_signed_content). Note the digest split: RSA branches
// hash the content first and verify a digest, while ECDSA/Ed25519 verify APIs
// take the raw message and hash internally per their own scheme (EdDSA is pure
// — the key, not the hash, is what binds the signature).
fn verify_certificate_verify(leaf pki.Certificate, cv ParsedCertificateVerify, signed_content []u8) ! {
	match cv.algorithm {
		.rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 {
			rsa_key := leaf.rsa_public_key or { return error('handshake: missing RSA public key') }
			digest_type := match cv.algorithm {
				.rsa_pss_rsae_sha256 { 'sha256' }
				.rsa_pss_rsae_sha384 { 'sha384' }
				else { 'sha512' }
			}
			hash := hash_for_digest(digest_type, signed_content)
			ok := rsa_key.verify_pss(digest_type, hash, cv.signature)!
			if !ok {
				return error('handshake: RSA-PSS ${digest_type} CertificateVerify failed')
			}
		}
		.rsa_pkcs1_sha256 {
			rsa_key := leaf.rsa_public_key or { return error('handshake: missing RSA public key') }
			hash := kdf.HashAlgorithm.sha256.compute_hash(signed_content)
			ok := rsa_key.verify_pkcs1_v1_5('sha256', hash, cv.signature)!
			if !ok {
				return error('handshake: RSA-PKCS1 SHA-256 CertificateVerify failed')
			}
		}
		.ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384 {
			pubkey := leaf.ecdsa_public_key()!
			ok := pubkey.verify(signed_content, cv.signature)!
			if !ok {
				return error('handshake: ECDSA CertificateVerify failed (${cv.algorithm})')
			}
		}
		.ed25519 {
			if leaf.public_key_raw.len != ed25519.public_key_size {
				return error('handshake: invalid Ed25519 public key length')
			}
			ok := ed25519.verify(ed25519.PublicKey(leaf.public_key_raw), signed_content, cv.signature)!
			if !ok {
				return error('handshake: Ed25519 CertificateVerify failed')
			}
		}
	}
}

// update_read_traffic_keys ratchets the server application traffic secret to its
// next generation (KeyUpdate, RFC 8446 §7.2) and swaps in the new read cipher.
pub fn (mut h ClientHandshake) update_read_traffic_keys() ! {
	h.server_ap_traffic = kdf.hkdf_expand_label(h.hash_algo, h.server_ap_traffic, 'traffic upd', []u8{}, h.hash_algo.hash_len())!
	h.server_app_keys = kdf.derive_traffic_keys(h.hash_algo, h.server_ap_traffic, h.key_len, record.aead_nonce_len)!
	h.server_app_cipher = h.new_cipher(h.server_app_keys)!
}

// update_write_traffic_keys ratchets the client application traffic secret to its
// next generation (KeyUpdate, RFC 8446 §7.2) and swaps in the new write cipher.
pub fn (mut h ClientHandshake) update_write_traffic_keys() ! {
	h.client_ap_traffic = kdf.hkdf_expand_label(h.hash_algo, h.client_ap_traffic, 'traffic upd', []u8{}, h.hash_algo.hash_len())!
	h.client_app_keys = kdf.derive_traffic_keys(h.hash_algo, h.client_ap_traffic, h.key_len, record.aead_nonce_len)!
	h.client_app_cipher = h.new_cipher(h.client_app_keys)!
}
