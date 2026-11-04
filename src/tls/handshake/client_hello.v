// Copyright (c) 2026 blackshirt.
//
// client_hello.v validates ClientHello options and builds the RFC 8446 §4.1.2
// ClientHello from the configured capabilities.
module handshake

import crypto.rand
import tls.pki
import tls.wire

// default_supported_groups returns the group preference order used when none is
// configured — the full supported set, whose single source is
// supported_named_groups in messages.v.
fn default_supported_groups() []NamedGroup {
	return supported_named_groups
}

// default_signature_algorithms returns the scheme preference order used when none
// is configured — the full supported set, whose single source is
// supported_signature_schemes in messages.v.
fn default_signature_algorithms() []SignatureScheme {
	return supported_signature_schemes
}

// offered_supported_groups returns the configured groups or their defaults.
fn offered_supported_groups(groups []NamedGroup) []NamedGroup {
	return if groups.len > 0 { groups } else { default_supported_groups() }
}

// validate_handshake_options rejects values that cannot be encoded, that this stack
// cannot implement, or that would create ambiguous ClientHello capability lists.
fn validate_handshake_options(options HandshakeOptions) ! {
	mut alpn_list_len := 0
	for protocol in options.alpn {
		if protocol.len == 0 {
			return error('handshake: ALPN protocol names must not be empty')
		}
		if protocol.len > 255 {
			return error('handshake: ALPN protocol name exceeds 255 bytes')
		}
		alpn_list_len += 1 + protocol.len
		if alpn_list_len > 65533 {
			return error('handshake: encoded ALPN extension exceeds 65535 bytes')
		}
	}
	groups := offered_supported_groups(options.supported_groups)
	mut seen_groups := []NamedGroup{}
	for group in groups {
		if !is_supported_group(group) {
			return error('handshake: unsupported configured group ${group}')
		}
		if group in seen_groups {
			return error('handshake: duplicate configured group ${group}')
		}
		seen_groups << group
	}
	if options.key_share_group !in groups {
		return error('handshake: initial key_share_group ${options.key_share_group} must be included in supported_groups')
	}
	if options.cipher_suites.len > 0 {
		mut seen_suites := []CipherSuite{}
		for suite in options.cipher_suites {
			// Membership, not just uniqueness: a raw-cast unimplementable suite would
			// be advertised and could echo-match the server's choice; dedup then
			// bounds the list at 3 entries.
			if !is_supported_cipher_suite(suite) {
				return error('handshake: unsupported configured cipher suite ${suite}')
			}
			if suite in seen_suites {
				return error('handshake: duplicate configured cipher suite ${suite}')
			}
			seen_suites << suite
		}
	}
	if options.signature_algorithms.len > 0 {
		mut seen_schemes := []SignatureScheme{}
		for scheme in options.signature_algorithms {
			// A client must only offer schemes its verifier can check; membership +
			// the duplicate scan bounds the list at 7 entries.
			if !is_supported_signature_scheme(scheme) {
				return error('handshake: unsupported configured signature scheme ${scheme}')
			}
			if scheme in seen_schemes {
				return error('handshake: duplicate configured signature scheme ${scheme}')
			}
			seen_schemes << scheme
		}
	}
	// Validate PSKs: each must have a non-empty identity and key, and no duplicate
	// identities (RFC 8446 §4.2.9 forbids duplicate identities in the list).
	if options.psks.len > 0 {
		mut seen_ids := [][]u8{}
		for psk in options.psks {
			if psk.identity.len == 0 {
				return error('handshake: PSK identity must not be empty')
			}
			if psk.key.len == 0 {
				return error('handshake: PSK key must not be empty')
			}
			if psk.identity in seen_ids {
				return error('handshake: duplicate PSK identity (illegal_parameter)')
			}
			seen_ids << psk.identity.clone()
		}
	}
	// RFC 8446 §4.1.2: legacy_session_id MUST NOT exceed 32 bytes; shorter values are
	// legal and echo-checked by equality. Unset applies the App. D.4 default of 32
	// fresh random bytes.
	if options.legacy_session_id.len > legacy_session_id_len {
		return error('handshake: configured legacy_session_id exceeds ${legacy_session_id_len} bytes')
	}
	if options.random.len > 0 && options.random.len != client_hello_random_len {
		return error('handshake: configured ClientHello.random must be exactly ${client_hello_random_len} bytes')
	}
}

// default_cipher_suites returns the suite list offered when the caller configures
// none — the full supported set, whose single source (including the ChaCha20-first
// software-AEAD rationale) is supported_cipher_suites in messages.v.
fn default_cipher_suites() []CipherSuite {
	return supported_cipher_suites
}

// ClientHelloConfig holds the parameters used to build a ClientHello.
struct ClientHelloConfig {
mut:
	// Server identity and application protocol.
	// Host name sent to the server for SNI; empty omits the extension.
	server_name string
	// Application protocols offered to the server, in preference order.
	alpn []string

	// Key exchange and cryptographic capabilities.
	// Client's key-exchange group and public key share.
	client_share KeyShareEntry
	// TLS cipher suites offered to the server.
	cipher_suites []CipherSuite
	// Key-exchange groups supported by the client.
	supported_groups []NamedGroup
	// Signature algorithms the client supports.
	signature_algorithms []SignatureScheme
	// Pre-shared keys the client may offer (RFC 8446 §4.2.9).
	psks []Psk
	// binder_transcript is the raw handshake-message transcript preceding this
	// ClientHello. It is empty for the first ClientHello and holds
	// message_hash(ClientHello1) || HelloRetryRequest for the retry, so PSK
	// binders cover the complete transcript (RFC 8446 §4.2.9/§4.4.1).
	binder_transcript []u8
	// binder_hash_algo pins the hash used for binder computation. It is unset
	// for the first ClientHello (the first offered suite's hash applies) and is
	// set to the HelloRetryRequest suite's hash for the retried ClientHello.
	binder_hash_algo ?HashAlgorithm

	// ClientHello values reused or echoed during HelloRetryRequest.
	// Legacy session ID sent in the ClientHello and reused after a retry.
	session_id []u8
	// ClientHello random value; generated if empty.
	random []u8
	// Cookie received in HelloRetryRequest and echoed in the retry ClientHello.
	cookie []u8

	// QUIC-specific settings.
	// Whether this ClientHello is for a QUIC connection.
	is_quic bool
	// quic_transport_params is the already-encoded extension content, built by
	// the QUIC adapter; it is required when is_quic is true.
	quic_transport_params ?[]u8
}

// offered_cipher_suites returns the configured suites or the built-in defaults.
fn offered_cipher_suites(cfg &ClientHelloConfig) []CipherSuite {
	if cfg.cipher_suites.len > 0 {
		return cfg.cipher_suites
	}
	return default_cipher_suites()
}

// offered_groups returns the configured supported groups or the defaults.
fn offered_groups(cfg &ClientHelloConfig) []NamedGroup {
	return offered_supported_groups(cfg.supported_groups)
}

// offered_signature_algorithms returns the configured schemes or the defaults.
fn offered_signature_algorithms(cfg &ClientHelloConfig) []SignatureScheme {
	if cfg.signature_algorithms.len > 0 {
		return cfg.signature_algorithms
	}
	return default_signature_algorithms()
}

// build_client_hello generates the ClientHello of RFC 8446 §4.1.2, returning the
// message body followed by the full handshake message (header + body).
fn build_client_hello(cfg ClientHelloConfig) !([]u8, []u8) {
	// A direct ClientHelloConfig caller bypasses validate_handshake_options, so the
	// framing primitive enforces the sizes itself: §4.1.2 caps legacy_session_id at
	// 32 bytes (0 means "generate fresh random", the App. D.4 default), while Random
	// is a fixed 32-byte field, so a configured value must be exactly 32.
	if cfg.session_id.len > legacy_session_id_len {
		return error('handshake: ClientHello legacy_session_id exceeds ${legacy_session_id_len} bytes')
	}
	if cfg.random.len != 0 && cfg.random.len != client_hello_random_len {
		return error('handshake: ClientHello random must be exactly ${client_hello_random_len} bytes')
	}
	// QUIC does not use middlebox compatibility mode, so its legacy_session_id is
	// empty and is never generated here (RFC 9001 §8.4).
	if cfg.is_quic && cfg.session_id.len > 0 {
		return error('handshake: QUIC ClientHello legacy_session_id must be empty (RFC 9001 §8.4)')
	}
	mut body := wire.new_writer(512)

	// Legacy version 0x0303 (TLS 1.2) pinned for middleboxes; the real version
	// comes from supported_versions (§4.2.1).
	body.write_u16(0x0303)

	// An explicit cfg.random replays RFC test vectors; real handshakes leave it empty (§4.1.4).
	random_bytes := if cfg.random.len == client_hello_random_len {
		cfg.random.clone()
	} else {
		rand.bytes(client_hello_random_len)!
	}
	body.write_bytes(random_bytes)

	// Legacy session id for middlebox compatibility (App. D.4); echoed in
	// ServerHello for the legacy_session_id_echo check.
	session_id := if cfg.is_quic || cfg.session_id.len > 0 {
		cfg.session_id.clone()
	} else {
		rand.bytes(legacy_session_id_len)!
	}
	body.write_vector_u8(session_id)!

	suites := offered_cipher_suites(&cfg)
	mut cs_writer := wire.new_writer(suites.len * 2)
	for cs in suites {
		cs_writer.write_u16(u16(cs))
	}
	body.write_vector_u16(cs_writer.bytes())!

	// Legacy compression methods: clients must offer only the null method (§4.2).
	body.write_vector_u8([u8(0x00)])!

	// Build all non-PSK extension bytes first. PSK extensions are appended last
	// after a two-pass binder computation (§4.2.9): pass 1 builds the extension
	// with empty binders to compute the ClientHello handshake hash, pass 2 fills
	// in real binders. We track non-PSK extensions as raw bytes so we can
	// concatenate them with either binder pass without truncating a Writer.
	mut non_psk_exts := []u8{}

	// SNI host_name is a DNS name; omit it for IP literals (RFC 6066 §3).
	if cfg.server_name.len > 0 && !pki.is_ip_literal(cfg.server_name) {
		mut sni_w := wire.new_writer(cfg.server_name.len + 5)
		mut snl_w := wire.new_writer(cfg.server_name.len + 3)
		snl_w.write_u8(0x00) // HostName type
		snl_w.write_vector_u16(cfg.server_name.bytes())!
		sni_w.write_vector_u16(snl_w.bytes())!
		mut ext_w := wire.new_writer(sni_w.len() + 4)
		write_extension(mut ext_w, .server_name, sni_w.bytes())!
		non_psk_exts << ext_w.bytes()
	}

	// supported_versions (RFC 8446 §4.2.1)
	{
		mut sv_w := wire.new_writer(3)
		sv_w.write_vector_u8([u8(0x03), 0x04])! // TLS 1.3
		mut ext_w := wire.new_writer(sv_w.len() + 4)
		write_extension(mut ext_w, .supported_versions, sv_w.bytes())!
		non_psk_exts << ext_w.bytes()
	}

	// supported_groups (RFC 8446 §4.2.7)
	{
		groups := offered_groups(&cfg)
		mut groups_w := wire.new_writer(groups.len * 2)
		for group in groups {
			groups_w.write_u16(u16(group))
		}
		mut sg_w := wire.new_writer(groups_w.len() + 2)
		sg_w.write_vector_u16(groups_w.bytes())!
		mut ext_w := wire.new_writer(sg_w.len() + 4)
		write_extension(mut ext_w, .supported_groups, sg_w.bytes())!
		non_psk_exts << ext_w.bytes()
	}

	// signature_algorithms (RFC 8446 §4.2.3)
	{
		schemes := offered_signature_algorithms(&cfg)
		mut slist_w := wire.new_writer(schemes.len * 2)
		for s in schemes {
			slist_w.write_u16(u16(s))
		}
		mut sa_w := wire.new_writer(slist_w.len() + 2)
		sa_w.write_vector_u16(slist_w.bytes())!
		mut ext_w := wire.new_writer(sa_w.len() + 4)
		write_extension(mut ext_w, .signature_algorithms, sa_w.bytes())!
		non_psk_exts << ext_w.bytes()
	}

	// key_share (RFC 8446 §4.2.8): a u16 vector of group (u16) plus
	// u16-length-prefixed key_exchange entries.
	{
		// The client's own share gets the same gates compute_shared_secret applies
		// to the peer's: a direct ClientHelloConfig builder bypasses
		// validate_handshake_options, so the framing primitive refuses a malformed
		// or unoffered key_share rather than putting it on the wire (§4.2.8).
		if cfg.client_share.group !in offered_groups(&cfg) {
			return error('handshake: ClientHello key_share group ${cfg.client_share.group} is not in supported_groups')
		}
		if cfg.client_share.key_exchange.len != key_exchange_len(cfg.client_share.group) {
			return error('handshake: ClientHello ${cfg.client_share.group} key_share is ${cfg.client_share.key_exchange.len} bytes, expected ${key_exchange_len(cfg.client_share.group)}')
		}
		if cfg.client_share.group == .secp256r1 && cfg.client_share.key_exchange[0] != 0x04 {
			return error('handshake: ClientHello secp256r1 key_share is not a 0x04-prefixed uncompressed point')
		}
		mut entry_w := wire.new_writer(cfg.client_share.key_exchange.len + 4)
		entry_w.write_u16(u16(cfg.client_share.group))
		entry_w.write_vector_u16(cfg.client_share.key_exchange)!
		mut ks_w := wire.new_writer(entry_w.len() + 2)
		ks_w.write_vector_u16(entry_w.bytes())!
		mut ext_w := wire.new_writer(ks_w.len() + 4)
		write_extension(mut ext_w, .key_share, ks_w.bytes())!
		non_psk_exts << ext_w.bytes()
	}

	// ALPN (RFC 7301)
	if cfg.alpn.len > 0 {
		mut protocols_w := wire.new_writer(30)
		for p in cfg.alpn {
			protocols_w.write_vector_u8(p.bytes())!
		}
		mut alpn_w := wire.new_writer(protocols_w.len() + 2)
		alpn_w.write_vector_u16(protocols_w.bytes())!
		mut ext_w := wire.new_writer(alpn_w.len() + 4)
		write_extension(mut ext_w, .alpn, alpn_w.bytes())!
		non_psk_exts << ext_w.bytes()
	}

	// QUIC transport parameters are carried in ClientHello (RFC 9001 §8.2). TLS is
	// a courier for these bytes: it frames and sends whatever the adapter encoded,
	// without inspecting the value - even a malformed list is the peer's adapter to
	// reject, not this handshake's.
	if cfg.is_quic {
		params := cfg.quic_transport_params or {
			return error('handshake: QUIC ClientHello is missing transport parameters')
		}
		mut ext_w := wire.new_writer(params.len + 4)
		write_extension(mut ext_w, .quic_transport_parameters, params)!
		non_psk_exts << ext_w.bytes()
	}

	// cookie (RFC 8446 §4.2.2) — echoed after HelloRetryRequest
	if cfg.cookie.len > 0 {
		mut cookie_w := wire.new_writer(cfg.cookie.len + 2)
		cookie_w.write_vector_u16(cfg.cookie)!
		mut ext_w := wire.new_writer(cookie_w.len() + 4)
		write_extension(mut ext_w, .cookie, cookie_w.bytes())!
		non_psk_exts << ext_w.bytes()
	}

	// Build the full extensions block, with PSK extensions last: §4.2.9 requires
	// pre_shared_key to be the final extension in the ClientHello.
	mut ext_bytes := non_psk_exts.clone()
	if cfg.psks.len > 0 {
		// psk_key_exchange_modes: advertise only psk_dhe_ke (forward secrecy).
		mut kem := build_psk_key_exchange_modes_extension()!
		mut kem_ext_w := wire.new_writer(4 + kem.len)
		write_extension(mut kem_ext_w, .psk_key_exchange_modes, kem)!
		ext_bytes << kem_ext_w.bytes()

		// Convert Psk identities to PskIdentity wire values, preserving the
		// caller-supplied obfuscated ticket age (§4.2.9).
		mut psk_ids := []PskIdentity{cap: cfg.psks.len}
		for psk in cfg.psks {
			psk_ids << PskIdentity{
				identity:              psk.identity
				obfuscated_ticket_age: psk.obfuscated_ticket_age
			}
		}
		ids_bytes := build_pre_shared_key_identities(psk_ids)!

		// Determine the hash for binder computation from the first offered
		// ciphersuite, unless a retry pinned it to the HRR suite (RFC 8446 §4.2.9).
		binder_hash := cfg.binder_hash_algo or {
			suite_hash_algo(offered_cipher_suites(&cfg)[0])
		}
		hash_len := binder_hash.hash_len()

		// Binder entries are Hash.length bytes; build a placeholder with those
		// lengths so the truncated ClientHello carries the same length fields as
		// the final message (RFC 8446 §4.2.9).
		mut placeholder_binders := []PskBinderEntry{cap: cfg.psks.len}
		for _ in 0 .. cfg.psks.len {
			placeholder_binders << PskBinderEntry{ binder: []u8{len: hash_len} }
		}
		binders_bytes := build_pre_shared_key_binders(placeholder_binders)!
		psk_body_len := ids_bytes.len + binders_bytes.len
		if psk_body_len > 0xffff {
			return error('handshake: pre_shared_key extension body exceeds 65535 bytes')
		}
		exts_len := ext_bytes.len + 4 + psk_body_len
		if exts_len > 0xffff {
			return error('handshake: ClientHello extensions exceed 65535 bytes')
		}

		// The binder transcript is the ClientHello truncated immediately before
		// the binders vector, with every length field set as if binders were
		// present, including the 4-byte handshake header and any prior HRR
		// transcript (RFC 8446 §4.2.9/§4.4.1).
		mut partial := wire.new_writer(4 + body.len() + 2 + ext_bytes.len + 4 + ids_bytes.len)
		partial.write_u8(u8(HandshakeType.client_hello))
		partial.write_u24(u32(body.len() + 2 + exts_len))
		partial.write_bytes(body.bytes())
		partial.write_u16(u16(exts_len))
		partial.write_bytes(ext_bytes)
		partial.write_u16(u16(ExtensionType.pre_shared_key))
		partial.write_u16(u16(psk_body_len))
		partial.write_bytes(ids_bytes)

		mut binder_transcript := cfg.binder_transcript.clone()
		binder_transcript << partial.bytes()
		client_hello_hash := binder_hash.compute_hash(binder_transcript)

		// Compute one binder per PSK, each bound to its own Early Secret and
		// binder label (RFC 8446 §4.2.9/§7.1).
		mut binders := []PskBinderEntry{cap: cfg.psks.len}
		for psk in cfg.psks {
			binder := compute_psk_binder(binder_hash, psk.key, psk_binder_label(psk),
				client_hello_hash)!
			binders << PskBinderEntry{ binder: binder }
		}

		psk_ext := build_pre_shared_key_extension(psk_ids, binders)!
		mut psk_ext_w := wire.new_writer(psk_ext.len + 4)
		write_extension(mut psk_ext_w, .pre_shared_key, psk_ext)!
		ext_bytes << psk_ext_w.bytes()
	}

	body.write_vector_u16(ext_bytes)! or {
		return err
	}

	body_bytes := body.bytes()
	full_msg := wrap_handshake_message(.client_hello, body_bytes)
	return body_bytes, full_msg
}
