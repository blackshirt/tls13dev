// Copyright (c) 2026 blackshirt.
//
// server_hello_flow.v handles the ServerHello / HelloRetryRequest transition,
// including transcript rewrites and the retried ClientHello (RFC 8446 §4.1.4).
module handshake

// handle_server_hello_message consumes one complete initial-level ServerHello
// or HelloRetryRequest and returns the follow-up messages (RFC 8446 §4.1.3).
fn (mut h HandshakeCore) handle_server_hello_message(sh_msg []u8) ![]HandshakeMessage {
	if h.state != .wait_server_hello {
		// Strict ordering: a ServerHello is only legal while we await it (§4.4.1).
		return h.fail(.unexpected_message, 'handshake: unexpected ServerHello in state ${h.state}')
	}

	// Peel the 4-byte handshake header (type || 3-byte length) to bound the body (§4).
	msg_type, body := split_handshake_message(sh_msg)!
	if msg_type != .server_hello {
		// HelloRetryRequest reuses the ServerHello type value (2) and is told apart only by the sentinel random (§4.1.3).
		return h.fail(.unexpected_message, 'handshake: expected ServerHello (2), got ${msg_type}')
	}
	// Transport framing boundaries are enforced by adapters; reassembly hands this method one complete handshake message.
	sh := parse_server_hello(body)! // §4.1.3 field decode plus the §4.2 extension allowlist
	// Re-frame header + body so the transcript covers the exact wire layout.
	full_sh_msg := wrap_handshake_message(.server_hello, body)

	if sh.is_hello_retry_req {
		return h.handle_hello_retry_request(sh, full_sh_msg)
	}

	// Normal ServerHello: validate echoed fields and that a key share was selected for our group; (EC)DHE cannot proceed without one.
	sh.validate(&h.config) or { return h.fail(.illegal_parameter, err.msg()) }
	// §4.1.4: after a HelloRetryRequest the ServerHello suite must match the HRR's.
	if hrr_suite := h.hrr_cipher_suite {
		if hrr_suite != sh.cipher_suite {
			return h.fail(.illegal_parameter, 'handshake: ServerHello cipher suite ${sh.cipher_suite} differs from HelloRetryRequest suite ${hrr_suite} (illegal_parameter)')
		}
	}
	if !sh.has_key_share {
		return h.fail(.illegal_parameter, 'handshake: ServerHello missing key_share extension')
	}
	if sh.server_share.group != h.ecdhe_group {
		return h.fail(.illegal_parameter, 'handshake: ServerHello key_share group ${sh.server_share.group} does not match offered group ${h.ecdhe_group}')
	}

	// The suite fixes both hash and key length; set them before deriving secrets.
	h.cipher_suite = sh.cipher_suite
	h.key_len = suite_key_len(sh.cipher_suite)
	h.set_hash_algo(suite_hash_algo(sh.cipher_suite))
	h.update_transcript(full_sh_msg)!

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

// handle_hello_retry_request validates a HelloRetryRequest, rewrites the
// transcript, and returns the retried ClientHello (RFC 8446 §4.1.4).
fn (mut h HandshakeCore) handle_hello_retry_request(sh ServerHello, full_sh_msg []u8) ![]HandshakeMessage {
	// §4.1.4: validate shared fields, reject a second HelloRetryRequest, and require that the request actually changes something.
	sh.validate(&h.config) or { return h.fail(.illegal_parameter, err.msg()) }
	if h.hrr_received {
		return h.fail(.unexpected_message, 'handshake: received second HelloRetryRequest (unexpected_message)')
	}

	if !sh.has_key_share && sh.cookie.len == 0 {
		return h.fail(.illegal_parameter, 'handshake: HelloRetryRequest would not change the ClientHello (illegal_parameter)')
	}
	if sh.has_key_share {
		// The requested group must be offered and differ from the one already sent a key share for (§4.2.8).
		if sh.server_share.group !in offered_groups(&h.config) {
			return h.fail(.illegal_parameter, 'handshake: HelloRetryRequest requested unoffered group ${sh.server_share.group} (illegal_parameter)')
		}
		if sh.server_share.group == h.config.client_share.group {
			return h.fail(.illegal_parameter, 'handshake: HelloRetryRequest reselected the already-offered group ${sh.server_share.group} (illegal_parameter)')
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
	h.update_transcript(full_ch2)!

	h.state = .wait_server_hello // rearm: the server now answers with the real ServerHello
	return [new_handshake_message(.initial, full_ch2)!]
}
