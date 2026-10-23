// Copyright (c) 2026 blackshirt.
//
// messages.v encodes and decodes the RFC 8446 §4 handshake structures — ClientHello,
// ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished and the
// extension blocks — using the wire reader/writer for framing arithmetic.
module handshake

import crypto.rand
import tls.pki
import tls.wire

// HandshakeType identifies TLS 1.3 handshake messages (RFC 8446 §4).
pub enum HandshakeType as u8 {
	client_hello         = 1
	server_hello         = 2
	new_session_ticket   = 4
	end_of_early_data    = 5 // 0-RTT; recognized but not implemented
	encrypted_extensions = 8
	certificate          = 11
	certificate_request  = 13 // server→client auth; not implemented by this client
	certificate_verify   = 15
	finished             = 20
	key_update           = 24
	// Synthetic: after a HelloRetryRequest, ClientHello1 becomes a message_hash (RFC 8446 §4.4.1).
	message_hash         = 254
}

// handshake_type_from_u8 decodes a 1-byte handshake message type.
fn handshake_type_from_u8(b u8) !HandshakeType {
	return match b {
		1 { .client_hello }
		2 { .server_hello }
		4 { .new_session_ticket }
		5 { .end_of_early_data }
		8 { .encrypted_extensions }
		11 { .certificate }
		13 { .certificate_request }
		15 { .certificate_verify }
		20 { .finished }
		24 { .key_update }
		254 { .message_hash }
		else { error('handshake: unknown HandshakeType ${b}') }
	}
}

// ExtensionType represents TLS 1.3 extension codes (RFC 8446 §4.2), assigned by
// the IANA TLS ExtensionType Registry.
enum ExtensionType as u16 {
	// server_name carries SNI in ClientHello, echoed empty in EncryptedExtensions (RFC 6066 §3).
	server_name               = 0
	supported_groups          = 10
	signature_algorithms      = 13
	alpn                      = 16
	supported_versions        = 43
	cookie                    = 44
	key_share                 = 51
	quic_transport_parameters = 57
	// RFC 5746 §4.1, not an RFC 8446 extension: TLS 1.3 servers carry it in EncryptedExtensions even when unoffered.
	renegotiation_info        = 65281 // 0xff01
}

// NamedGroup defines key exchange groups (RFC 8446 §4.2.7); only the two mandatory
// ECDHE groups are supported.
pub enum NamedGroup as u16 {
	secp256r1 = 0x0017
	x25519    = 0x001d
}

// SignatureScheme defines cryptographic signature algorithms (RFC 8446 §4.2.3).
pub enum SignatureScheme as u16 {
	rsa_pkcs1_sha256       = 0x0401
	ecdsa_secp256r1_sha256 = 0x0403
	ecdsa_secp384r1_sha384 = 0x0503
	rsa_pss_rsae_sha256    = 0x0804
	rsa_pss_rsae_sha384    = 0x0805
	rsa_pss_rsae_sha512    = 0x0806
	ed25519                = 0x0807
}

const default_supported_groups = [NamedGroup.x25519, .secp256r1]

const default_signature_algorithms = [
	SignatureScheme.rsa_pss_rsae_sha256,
	.rsa_pss_rsae_sha384,
	.rsa_pss_rsae_sha512,
	.ecdsa_secp256r1_sha256,
	.ecdsa_secp384r1_sha384,
	.ed25519,
	.rsa_pkcs1_sha256,
]

fn offered_supported_groups(groups []NamedGroup) []NamedGroup {
	return if groups.len > 0 { groups } else { default_supported_groups }
}

fn offered_signature_algorithms(schemes []SignatureScheme) []SignatureScheme {
	return if schemes.len > 0 { schemes } else { default_signature_algorithms }
}

fn validate_handshake_options(options HandshakeOptions) ! {
	groups := offered_supported_groups(options.supported_groups)
	if groups.len == 0 {
		return error('handshake: supported_groups must not be empty')
	}
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
			if suite in seen_suites {
				return error('handshake: duplicate configured cipher suite ${suite}')
			}
			seen_suites << suite
		}
	}
	if options.signature_algorithms.len > 0 {
		mut seen_schemes := []SignatureScheme{}
		for scheme in options.signature_algorithms {
			if scheme in seen_schemes {
				return error('handshake: duplicate configured signature scheme ${scheme}')
			}
			seen_schemes << scheme
		}
	}
	if options.legacy_session_id.len > legacy_session_id_len {
		return error('handshake: configured legacy_session_id exceeds ${legacy_session_id_len} bytes')
	}
	if options.random.len > 0 && options.random.len != client_hello_random_len {
		return error('handshake: configured ClientHello.random must be exactly ${client_hello_random_len} bytes')
	}
}

// CipherSuite defines TLS 1.3 cipher suites (RFC 8446 §B.4).
pub enum CipherSuite as u16 {
	tls_aes_128_gcm_sha256       = 0x1301
	tls_aes_256_gcm_sha384       = 0x1302
	tls_chacha20_poly1305_sha256 = 0x1303
}

// default_cipher_suites returns the suite list offered when the caller configures none.
// ChaCha20-Poly1305 leads because the AEAD backend is software-only.
fn default_cipher_suites() []CipherSuite {
	return [
		CipherSuite.tls_chacha20_poly1305_sha256,
		CipherSuite.tls_aes_128_gcm_sha256,
		CipherSuite.tls_aes_256_gcm_sha384,
	]
}

// cipher_suite_from_u16 decodes a 2-byte cipher suite code (RFC 8446 §B.4).
fn cipher_suite_from_u16(raw u16) !CipherSuite {
	return match raw {
		0x1301 { .tls_aes_128_gcm_sha256 }
		0x1302 { .tls_aes_256_gcm_sha384 }
		0x1303 { .tls_chacha20_poly1305_sha256 }
		else { error('handshake: unsupported cipher suite 0x${raw:04x}') }
	}
}

// signature_scheme_from_u16 decodes a 2-byte SignatureScheme code (RFC 8446 §4.2.3).
fn signature_scheme_from_u16(raw u16) !SignatureScheme {
	return match raw {
		0x0401 { .rsa_pkcs1_sha256 }
		0x0403 { .ecdsa_secp256r1_sha256 }
		0x0503 { .ecdsa_secp384r1_sha384 }
		0x0804 { .rsa_pss_rsae_sha256 }
		0x0805 { .rsa_pss_rsae_sha384 }
		0x0806 { .rsa_pss_rsae_sha512 }
		0x0807 { .ed25519 }
		else { error('handshake: unsupported signature scheme 0x${raw:04x}') }
	}
}

// client_hello_random_len is the fixed ClientHello.random size (RFC 8446 §4.1.2).
const client_hello_random_len = 32

// legacy_session_id_len is the 32-byte legacy session id for middlebox compatibility (RFC 8446 App. D.4).
const legacy_session_id_len = 32

// KeyShareEntry holds a group and public key share (RFC 8446 §4.2.8).
struct KeyShareEntry {
mut:
	group        NamedGroup // negotiated group the key belongs to
	key_exchange []u8       // X25519 32-byte share, or P-256 uncompressed point (0x04 || X || Y)
}

// hello_retry_request_random is the HRR sentinel random (RFC 8446 §4.1.3); an HRR is
// a ServerHello, so only this fixed value tells them apart.
const hello_retry_request_random = [u8(0xcf), 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d,
	0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e,
	0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c]

// ServerHello holds the parsed ServerHello/HelloRetryRequest fields the client acts on.
// Extension extraction obeys the §4.2 placement allowlist; semantic checks live on validate.
struct ServerHello {
mut:
	session_id_echo []u8          // legacy_session_id echoed from the ClientHello (middlebox compatibility)
	cipher_suite    CipherSuite   // suite selected by the server
	server_share    KeyShareEntry // server's ECDHE public share
	// is_hello_retry_req is set solely by the §4.1.3 sentinel-random comparison; an HRR parses into this struct.
	is_hello_retry_req bool
	// has_key_share reports whether a key_share was present; for an HRR it separates a group change from a cookie-only request.
	has_key_share bool
	// cookie holds the cookie value from a HelloRetryRequest, empty otherwise.
	cookie []u8
}

// ParsedCertificateVerify holds the parsed CertificateVerify handshake message.
struct ParsedCertificateVerify {
mut:
	algorithm SignatureScheme // scheme the server signed with, must be usable for the leaf key
	signature []u8            // raw signature bytes over the transcript-derived content
}

// wrap_handshake_message frames a handshake body with its 1-byte HandshakeType
// and 3-byte big-endian length.
fn wrap_handshake_message(typ HandshakeType, body []u8) []u8 {
	mut w := wire.new_writer(4 + body.len)
	w.write_u8(u8(typ))
	w.write_u24(u32(body.len))
	w.write_bytes(body)
	return w.bytes()
}

// write_extension appends a 2-byte extension type plus 2-byte-length-prefixed data.
// It does not de-duplicate: §4.2 forbids repeats and the parser enforces that.
fn write_extension(mut w wire.Writer, typ ExtensionType, data []u8) ! {
	w.write_u16(u16(typ))
	w.write_vector_u16(data)!
}

// named_group_from_u16 converts the 16-bit group identifier to NamedGroup.
fn named_group_from_u16(raw u16) !NamedGroup {
	return match raw {
		0x0017 { .secp256r1 }
		0x001d { .x25519 }
		else { error('handshake: unsupported group 0x${raw:04x}') }
	}
}

// WireExtension is a raw, undecoded type/value pair from an extensions block (RFC 8446 §4.2).
struct WireExtension {
mut:
	typ  u16
	data []u8 // extension_data, already length-bounded by the framing read
}

// parse_extensions decodes an extensions block of [u16 type][u16 length][data].
// Duplicate types are rejected: §4.2 forbids repeats. Unknown types are returned verbatim.
fn parse_extensions(ext_bytes []u8) ![]WireExtension {
	mut r := wire.new_reader(ext_bytes)
	mut out := []WireExtension{}
	mut seen_types := []u16{}
	for r.remaining() > 0 {
		typ := r.read_u16()!
		data := r.read_vector_u16()!
		for seen_type in seen_types {
			if seen_type == typ {
				return error('handshake: duplicate extension type 0x${typ:04x} in extensions block')
			}
		}
		seen_types << typ
		out << WireExtension{
			typ:  typ
			data: data
		}
	}
	return out
}

// parse_handshake_header reads the 4-byte handshake header from a reader.
// Pub so adapters can dispatch post-handshake messages through the core's framing.
pub fn parse_handshake_header(mut r wire.Reader) !(HandshakeType, int) {
	if r.remaining() < 4 {
		return error('handshake: message header truncated')
	}
	raw_type := r.read_u8()!
	typ := handshake_type_from_u8(raw_type)!
	length := int(r.read_u24()!)
	return typ, length
}

// ClientHelloConfig holds the parameters used to build a ClientHello.
struct ClientHelloConfig {
mut:
	// server_name is sent in the SNI extension; empty omits it.
	server_name string
	// alpn is the ordered list of application protocols offered (§4.2.1).
	alpn []string
	// client_share is the single key_share offered (§4.2.8).
	client_share KeyShareEntry
	// session_id is echoed across HelloRetryRequest; generated if empty and pinned back for §4.1.4 reuse.
	session_id []u8
	// random is the ClientHello.random, generated if empty; an explicit value replays RFC test vectors.
	random []u8
	// cookie is echoed from HelloRetryRequest when present.
	cookie []u8
	// cipher_suites defaults to the three TLS 1.3 AEAD suites when empty.
	cipher_suites []CipherSuite
	// supported_groups and signature_algorithms use defaults when empty.
	supported_groups          []NamedGroup
	signature_algorithms      []SignatureScheme
	quic_transport_parameters ?QuicTransportParameters
}

const quic_transport_parameter_initial_source_connection_id = u64(0x0f)

fn encode_quic_varint(value u64) ![]u8 {
	if value < (1 << 6) {
		return [u8(value)]
	}
	if value < (1 << 14) {
		return [u8(value >> 8) | 0x40, u8(value & 0xff)]
	}
	if value < (1 << 30) {
		return [
			u8(value >> 24) | 0x80,
			u8((value >> 16) & 0xff),
			u8((value >> 8) & 0xff),
			u8(value & 0xff),
		]
	}
	if value < (u64(1) << 62) {
		return [
			u8(value >> 56) | 0xc0,
			u8((value >> 48) & 0xff),
			u8((value >> 40) & 0xff),
			u8((value >> 32) & 0xff),
			u8((value >> 24) & 0xff),
			u8((value >> 16) & 0xff),
			u8((value >> 8) & 0xff),
			u8(value & 0xff),
		]
	}
	return error('handshake: QUIC transport parameter value exceeds 2^62-1')
}

fn decode_quic_varint(data []u8) !(u64, int) {
	if data.len == 0 {
		return error('handshake: truncated QUIC transport parameter')
	}
	n := 1 << (data[0] >> 6)
	if data.len < n {
		return error('handshake: truncated QUIC transport parameter varint')
	}
	mut value := u64(data[0] & 0x3f)
	for i in 1 .. n {
		value = (value << 8) | u64(data[i])
	}
	return value, n
}

fn encode_quic_transport_parameters(params QuicTransportParameters) ![]u8 {
	if params.initial_source_connection_id.len > 20 {
		return error('handshake: QUIC initial_source_connection_id exceeds 20 bytes')
	}
	mut out := encode_quic_varint(quic_transport_parameter_initial_source_connection_id)!
	out << encode_quic_varint(u64(params.initial_source_connection_id.len))!
	out << params.initial_source_connection_id
	return out
}

fn parse_quic_transport_parameters(data []u8) !QuicTransportParameters {
	mut off := 0
	mut has_source_connection_id := false
	mut source_connection_id := []u8{}
	mut seen_ids := []u64{}
	for off < data.len {
		id, id_len := decode_quic_varint(data[off..])!
		off += id_len
		length, length_len := decode_quic_varint(data[off..])!
		off += length_len
		if length > u64(data.len - off) {
			return error('handshake: truncated QUIC transport parameter value')
		}
		for seen_id in seen_ids {
			if seen_id == id {
				return error('handshake: duplicate QUIC transport parameter ${id}')
			}
		}
		seen_ids << id
		value := data[off..off + int(length)]
		off += int(length)
		if id == quic_transport_parameter_initial_source_connection_id {
			if value.len > 20 {
				return error('handshake: QUIC initial_source_connection_id exceeds 20 bytes')
			}
			source_connection_id = value.clone()
			has_source_connection_id = true
		}
	}
	if !has_source_connection_id {
		return error('handshake: QUIC transport parameters missing initial_source_connection_id')
	}
	return QuicTransportParameters{
		initial_source_connection_id: source_connection_id
	}
}

// offered_cipher_suites returns the suites a client sends in its ClientHello:
// the explicit configuration if present, otherwise the built-in default list.
fn offered_cipher_suites(cfg &ClientHelloConfig) []CipherSuite {
	if cfg.cipher_suites.len > 0 {
		return cfg.cipher_suites
	}
	return default_cipher_suites()
}

fn offered_groups(cfg &ClientHelloConfig) []NamedGroup {
	return offered_supported_groups(cfg.supported_groups)
}

// validate performs the ServerHello/HelloRetryRequest checks independent of the message
// variant (RFC 8446 §4.1.3): the echoed session id must match and the suite must be offered.
fn (sh ServerHello) validate(cfg &ClientHelloConfig) ! {
	// A session-id mismatch means the hello we answer is not the one we sent (illegal_parameter).
	if sh.session_id_echo != cfg.session_id {
		return error('handshake: legacy_session_id_echo does not match ClientHello (illegal_parameter)')
	}
	// An unoffered suite would let an attacker downgrade us to one the state machine never configured.
	if !sh.is_offered_cipher_suite(cfg) {
		return error('handshake: server selected unoffered cipher suite ${sh.cipher_suite} (illegal_parameter)')
	}
}

// is_offered_cipher_suite reports whether the client advertised the suite.
fn (sh ServerHello) is_offered_cipher_suite(cfg &ClientHelloConfig) bool {
	// Linear scan: the offered list is at most the three TLS 1.3 AEAD suites.
	for offered in offered_cipher_suites(cfg) {
		if offered == sh.cipher_suite {
			return true
		}
	}
	return false
}

// build_client_hello generates the ClientHello of RFC 8446 §4.1.2, returning the
// message body followed by the full handshake message (header + body).
fn build_client_hello(cfg ClientHelloConfig) !([]u8, []u8) {
	validate_handshake_options(HandshakeOptions{
		key_share_group:      cfg.client_share.group
		supported_groups:     cfg.supported_groups
		cipher_suites:        cfg.cipher_suites
		signature_algorithms: cfg.signature_algorithms
		legacy_session_id:    cfg.session_id
		random:               cfg.random
	})!
	mut body := wire.new_writer(512)

	// Legacy version 0x0303 (TLS 1.2) pinned for middleboxes; the real version comes from supported_versions (§4.2.1).
	body.write_u16(0x0303)

	// An explicit cfg.random replays RFC test vectors; real handshakes leave it empty (§4.1.4).
	random_bytes := if cfg.random.len == client_hello_random_len {
		cfg.random.clone()
	} else {
		rand.bytes(client_hello_random_len)!
	}
	body.write_bytes(random_bytes)

	// Legacy session id for middlebox compatibility (App. D.4); echoed in ServerHello for the legacy_session_id_echo check.
	session_id := if cfg.session_id.len > 0 {
		cfg.session_id.clone()
	} else {
		rand.bytes(legacy_session_id_len)!
	}
	body.write_vector_u8(session_id)!

	suites := if cfg.cipher_suites.len > 0 {
		cfg.cipher_suites.clone()
	} else {
		default_cipher_suites()
	}
	mut cs_writer := wire.new_writer(suites.len * 2)
	for cs in suites {
		cs_writer.write_u16(u16(cs))
	}
	body.write_vector_u16(cs_writer.bytes())!

	// Legacy compression methods: clients must offer only the null method (§4.2).
	body.write_vector_u8([u8(0x00)])!

	mut ext_writer := wire.new_writer(256)

	// server_name (SNI, RFC 6066 §3): literal IP addresses are forbidden.
	if cfg.server_name.len > 0 && !pki.is_ip_literal(cfg.server_name) {
		mut sni_w := wire.new_writer(cfg.server_name.len + 5)
		// Two nested u16 vectors per RFC 6066 §3: ServerNameList and the host_name length.
		mut snl_w := wire.new_writer(cfg.server_name.len + 3)
		snl_w.write_u8(0x00) // HostName type
		snl_w.write_vector_u16(cfg.server_name.bytes())!
		sni_w.write_vector_u16(snl_w.bytes())!

		write_extension(mut ext_writer, .server_name, sni_w.bytes())!
	}

	// supported_versions (RFC 8446 §4.2.1)
	{
		mut sv_w := wire.new_writer(3)
		sv_w.write_vector_u8([u8(0x03), 0x04])! // TLS 1.3
		write_extension(mut ext_writer, .supported_versions, sv_w.bytes())!
	}

	// supported_groups (RFC 8446 §4.2.7)
	{
		groups := offered_groups(&cfg)
		mut sg_w := wire.new_writer(groups.len * 2 + 2)
		mut groups_w := wire.new_writer(groups.len * 2)
		for group in groups {
			groups_w.write_u16(u16(group))
		}
		sg_w.write_vector_u16(groups_w.bytes())!

		write_extension(mut ext_writer, .supported_groups, sg_w.bytes())!
	}

	// signature_algorithms (RFC 8446 §4.2.3)
	{
		schemes := if cfg.signature_algorithms.len > 0 {
			cfg.signature_algorithms
		} else {
			default_signature_algorithms
		}
		mut sa_w := wire.new_writer(schemes.len * 2 + 2)
		mut slist_w := wire.new_writer(schemes.len * 2)
		for s in schemes {
			slist_w.write_u16(u16(s))
		}
		sa_w.write_vector_u16(slist_w.bytes())!

		write_extension(mut ext_writer, .signature_algorithms, sa_w.bytes())!
	}

	// key_share (RFC 8446 §4.2.8): a u16 vector of group (u16) plus u16-length-prefixed key_exchange entries.
	{
		mut ks_w := wire.new_writer(cfg.client_share.key_exchange.len + 6)
		mut entry_w := wire.new_writer(cfg.client_share.key_exchange.len + 4)
		entry_w.write_u16(u16(cfg.client_share.group))
		entry_w.write_vector_u16(cfg.client_share.key_exchange)!
		ks_w.write_vector_u16(entry_w.bytes())!

		write_extension(mut ext_writer, .key_share, ks_w.bytes())!
	}

	// ALPN (RFC 7301)
	if cfg.alpn.len > 0 {
		mut alpn_w := wire.new_writer(32)
		mut protocols_w := wire.new_writer(30)
		for p in cfg.alpn {
			protocols_w.write_vector_u8(p.bytes())!
		}
		alpn_w.write_vector_u16(protocols_w.bytes())!

		write_extension(mut ext_writer, .alpn, alpn_w.bytes())!
	}

	// QUIC transport parameters are carried in ClientHello (RFC 9001 §8.2).
	if params := cfg.quic_transport_parameters {
		write_extension(mut ext_writer, .quic_transport_parameters,
			encode_quic_transport_parameters(params)!)!
	}

	// cookie (RFC 8446 §4.2.2) — echoed after HelloRetryRequest
	if cfg.cookie.len > 0 {
		mut cookie_w := wire.new_writer(cfg.cookie.len + 2)
		cookie_w.write_vector_u16(cfg.cookie)!
		write_extension(mut ext_writer, .cookie, cookie_w.bytes())!
	}

	body.write_vector_u16(ext_writer.bytes())!

	body_bytes := body.bytes()
	full_msg := wrap_handshake_message(.client_hello, body_bytes)
	return body_bytes, full_msg
}

// parse_server_hello decodes a ServerHello message body (RFC 8446 §4.1.3).
// §4.2 placement rules: only supported_versions, key_share and (HRR only) cookie may appear.
fn parse_server_hello(body []u8) !ServerHello {
	// The body follows §4.1.3's fixed field order; a length mismatch desyncs the rest and is caught here.
	mut r := wire.new_reader(body)
	// legacy_version is pinned to 0x0303 (TLS 1.2); the real version is in supported_versions (§4.2.1).
	legacy_version := r.read_u16()!
	if legacy_version != 0x0303 {
		return error('handshake: ServerHello legacy_version must be 0x0303, got 0x${legacy_version:04x}')
	}
	// random: equal to the fixed sentinel means this is a HelloRetryRequest (§4.1.3).
	random := r.read_bytes(client_hello_random_len)!
	// legacy_session_id_echo: must echo our ClientHello's session id (checked in validate).
	session_id_echo := r.read_vector_u8()!
	// cipher_suite: exactly one 2-byte suite, and one we offered (checked in validate).
	cs_raw := r.read_u16()!
	cipher_suite := cipher_suite_from_u16(cs_raw)!
	// legacy_compression_method: TLS 1.3 fixes this to the null method (0).
	compression := r.read_u8()!
	if compression != 0 {
		return error('handshake: compression method must be 0, got ${compression}')
	}

	ext_bytes := r.read_vector_u16()!

	mut selected_version := u16(0)
	mut server_share := KeyShareEntry{}
	mut has_key_share := false
	mut cookie := []u8{}
	is_hrr := random == hello_retry_request_random // §4.1.3: fixed sentinel random identifies an HRR

	exts := parse_extensions(ext_bytes)!
	for ext in exts {
		mut data_r := wire.new_reader(ext.data)

		match ext.typ {
			u16(ExtensionType.supported_versions) {
				// A bare u16 version here, not a length-prefixed vector as in ClientHello (§4.2.1).
				selected_version = data_r.read_u16()!
				if data_r.remaining() != 0 {
					return error('handshake: trailing bytes in supported_versions extension')
				}
			}
			u16(ExtensionType.key_share) {
				has_key_share = true
				if is_hrr {
					// HelloRetryRequest contains only the selected group (2 bytes, §4.1.4)
					grp := data_r.read_u16()!
					if data_r.remaining() != 0 {
						return error('handshake: trailing bytes in HelloRetryRequest key_share')
					}
					server_share = KeyShareEntry{
						group:        named_group_from_u16(grp)!
						key_exchange: []u8{}
					}
				} else {
					grp := data_r.read_u16()!
					key_ex := data_r.read_vector_u16()!
					if data_r.remaining() != 0 {
						// ServerHello carries exactly one KeyShareEntry (§4.2.8).
						return error('handshake: trailing bytes in ServerHello key_share')
					}
					server_share = KeyShareEntry{
						group:        named_group_from_u16(grp)!
						key_exchange: key_ex
					}
				}
			}
			u16(ExtensionType.cookie) {
				// §4.2: cookie appears in a ServerHello-type message only as part of an HRR.
				if !is_hrr {
					return error('handshake: cookie extension in a normal ServerHello (unsupported_extension)')
				}
				// data_r already wraps this extension's bytes; reuse it.
				cookie = data_r.read_vector_u16()!
				if cookie.len == 0 {
					return error('handshake: HelloRetryRequest cookie must be non-empty')
				}
				if data_r.remaining() != 0 {
					return error('handshake: trailing bytes in HelloRetryRequest cookie')
				}
			}
			else {
				// The §4.2 allowlist: TLS 1.2 leftovers must never reach client state.
				return error('handshake: extension 0x${ext.typ:04x} not permitted in ServerHello (unsupported_extension)')
			}
		}
	}

	// The negotiated version MUST be confirmed via supported_versions = 0x0304.
	if selected_version != 0x0304 {
		return error('handshake: ServerHello negotiated version must be 0x0304 (TLS 1.3), got 0x${selected_version:04x}')
	}

	return ServerHello{
		session_id_echo:    session_id_echo
		cipher_suite:       cipher_suite
		server_share:       server_share
		is_hello_retry_req: is_hrr
		has_key_share:      has_key_share
		cookie:             cookie
	}
}

// parse_certificate_message decodes the Certificate message body (RFC 8446 §4.4.2)
// and returns the DER-encoded chain; pki.parse_certificate decodes a single certificate.
fn parse_certificate_message(body []u8) ![][]u8 {
	mut r := wire.new_reader(body)
	req_ctx := r.read_vector_u8()!
	// §4.4.2: a server Certificate's certificate_request_context SHALL be zero length.
	if req_ctx.len > 0 {
		return error('handshake: non-empty certificate_request_context in server Certificate (illegal_parameter)')
	}
	// u24 list length: full chains can exceed 64 KiB, which a u16 could not frame.
	cert_list_bytes := r.read_vector_u24()!

	mut cert_r := wire.new_reader(cert_list_bytes)
	mut certs := [][]u8{}
	for cert_r.remaining() > 0 {
		// Reject an over-long chain before every entry is ASN.1-parsed, so a peer cannot pack thousands of tiny entries.
		if certs.len >= pki.max_cert_chain_depth {
			return error('handshake: certificate chain exceeds maximum depth ${pki.max_cert_chain_depth} (illegal_parameter)')
		}
		cert_data := cert_r.read_vector_u24()!
		cert_extensions := cert_r.read_vector_u16()!
		_ := parse_extensions(cert_extensions)!
		certs << cert_data
	}

	if certs.len == 0 {
		return error('handshake: server certificate list cannot be empty')
	}
	if r.remaining() != 0 {
		return error('handshake: trailing bytes in Certificate message (decode_error)')
	}
	return certs
}

// parse_certificate_verify decodes the CertificateVerify body (RFC 8446 §4.4.3).
fn parse_certificate_verify(body []u8) !ParsedCertificateVerify {
	mut r := wire.new_reader(body)
	algo_u16 := r.read_u16()!
	algo := signature_scheme_from_u16(algo_u16)!
	signature := r.read_vector_u16()!
	if signature.len == 0 {
		return error('handshake: empty signature in CertificateVerify (decode_error)')
	}
	if r.remaining() != 0 {
		return error('handshake: trailing bytes in CertificateVerify message (decode_error)')
	}
	return ParsedCertificateVerify{
		algorithm: algo
		signature: signature
	}
}

// certificate_verify_signed_content constructs the bytes signed in CertificateVerify
// (RFC 8446 §4.4.3): 0x20 * 64 || "TLS 1.3, server CertificateVerify" || 0x00 || transcript_hash.
fn certificate_verify_signed_content(transcript_hash []u8) []u8 {
	context_string := 'TLS 1.3, server CertificateVerify'.bytes()
	mut out := []u8{cap: 64 + context_string.len + 1 + transcript_hash.len}
	for _ in 0 .. 64 {
		out << 0x20 // 64 space octets
	}
	out << context_string
	out << 0x00
	out << transcript_hash
	return out
}

// parse_finished reads the verify_data from a Finished message (RFC 8446 §4.4.4).
// The body is exactly verify_data, so its length is fixed at Hash.length.
fn parse_finished(body []u8, hash_len int) ![]u8 {
	if body.len != hash_len {
		return error('handshake: Finished verify_data is ${body.len} bytes, expected ${hash_len} (Hash.length, RFC 8446 §4.4.4)')
	}
	return body.clone()
}

// build_finished creates a Finished handshake message carrying verify_data.
fn build_finished(verify_data []u8) []u8 {
	return wrap_handshake_message(.finished, verify_data)
}

// CertificateRequest is the decoded form of a server CertificateRequest (RFC 8446 §4.3.2);
// this client holds no certificate, so only the request context must be echoed verbatim.
struct CertificateRequest {
	request_context []u8 // echoed verbatim in the responding Certificate (§4.4.2)
}

// parse_certificate_request decodes the CertificateRequest body (RFC 8446 §4.3.2).
// The extensions must be well-formed and bounded; their content is not interpreted here.
fn parse_certificate_request(body []u8) !CertificateRequest {
	mut r := wire.new_reader(body)
	request_context := r.read_vector_u8()!
	ext_bytes := r.read_vector_u16()!
	if r.remaining() != 0 {
		return error('handshake: trailing bytes in CertificateRequest (decode_error)')
	}
	_ := parse_extensions(ext_bytes)!
	return CertificateRequest{
		request_context: request_context.clone()
	}
}

// build_empty_certificate creates an empty Certificate message (RFC 8446 §4.4.2),
// echoing the request context verbatim and framing certificate_list as u24 zero.
fn build_empty_certificate(request_context []u8) []u8 {
	mut body := []u8{cap: 1 + request_context.len + 3}
	body << u8(request_context.len)
	body << request_context
	body << [u8(0), 0, 0] // u24 certificate_list length: empty
	return wrap_handshake_message(.certificate, body)
}

// parse_encrypted_extensions decodes EncryptedExtensions (RFC 8446 §4.3.1) and
// returns the negotiated ALPN protocol (empty when none); only client-offered extensions belong here.
fn parse_encrypted_extensions(body []u8) !string {
	alpn, _ := parse_encrypted_extensions_for_transport(body, false)!
	return alpn
}

fn parse_encrypted_extensions_for_transport(body []u8, is_quic bool) !(string, ?QuicTransportParameters) {
	mut r := wire.new_reader(body)
	ext_bytes := r.read_vector_u16()!
	mut alpn := ''
	mut quic_transport_parameters := ?QuicTransportParameters(none)

	exts := parse_extensions(ext_bytes)!
	for ext in exts {
		if ext.typ == u16(ExtensionType.alpn) {
			mut data_r := wire.new_reader(ext.data)
			proto_list := data_r.read_vector_u16()!
			if data_r.remaining() != 0 {
				return error('handshake: trailing bytes after ALPN protocol_list')
			}
			mut pl_r := wire.new_reader(proto_list)
			if pl_r.remaining() == 0 {
				// RFC 7301 §3.1: an ALPN extension asserts a single protocol.
				return error('handshake: ALPN extension carried no protocol')
			}
			alpn = pl_r.read_vector_u8()!.bytestr()
			if pl_r.remaining() != 0 {
				// RFC 7301 §3.1: exactly one protocol; a second would dodge the offered-list check.
				return error('handshake: ALPN extension carried more than one protocol')
			}
		} else if ext.typ == u16(ExtensionType.server_name) {
			// RFC 8446 §4.2 / RFC 6066 §3: the SNI acknowledgment is an EMPTY server_name extension.
			if ext.data.len != 0 {
				return error('handshake: server sent a non-empty server_name in EncryptedExtensions')
			}
		} else if ext.typ == u16(ExtensionType.supported_groups) {
			// Interop carve-out: §4.2 makes supported_groups ClientHello-only, but some servers echo it; it carries no authority.
			continue
		} else if ext.typ == u16(ExtensionType.renegotiation_info) {
			// Interop carve-out: OpenSSL sends this unoffered; RFC 5746 §3.4 fixes the content to an empty renegotiated_connection.
			mut ri_r := wire.new_reader(ext.data)
			if ri_r.remaining() > 0 {
				renegotiated := ri_r.read_vector_u8()!
				if renegotiated.len != 0 || ri_r.remaining() != 0 {
					return error('handshake: renegotiation_info carried a non-empty renegotiated_connection')
				}
			}
		} else if ext.typ == u16(ExtensionType.quic_transport_parameters) {
			if !is_quic {
				return error('handshake: QUIC transport parameters received on a TLS record connection')
			}
			quic_transport_parameters = parse_quic_transport_parameters(ext.data)!
		} else {
			// §4.3.1: everything else must have been offered and belong here.
			return error('handshake: extension 0x${ext.typ:04x} in EncryptedExtensions was not offered (unsupported_extension)')
		}
	}
	if r.remaining() != 0 {
		return error('handshake: trailing bytes after EncryptedExtensions')
	}
	if is_quic && quic_transport_parameters == none {
		return error('handshake: server omitted QUIC transport parameters')
	}

	return alpn, quic_transport_parameters
}

// parse_key_update decodes a KeyUpdate body (RFC 8446 §4.6.3) and reports whether
// the sender requested that we also update our keys.
pub fn parse_key_update(body []u8) !bool {
	if body.len != 1 {
		return error('handshake: KeyUpdate body must be 1 byte')
	}
	if body[0] > 1 {
		return error('handshake: invalid KeyUpdate request_update value ${body[0]} (illegal_parameter)')
	}
	return body[0] == 1
}

// build_key_update creates a KeyUpdate handshake message carrying the §4.6.3
// request_update byte (1 = update_requested, 0 = update_not_requested).
pub fn build_key_update(request_update bool) []u8 {
	val := if request_update { u8(1) } else { u8(0) }
	return wrap_handshake_message(.key_update, [val])
}

// NewSessionTicket holds a parsed NewSessionTicket (RFC 8446 §4.6.1); its fields are
// module-private and reachable only through the accessors below.
@[noinit]
pub struct NewSessionTicket {
	ticket_lifetime u32  // seconds the ticket may be used after issuance; 0 means no support
	ticket_age_add  u32  // random value for obfuscating ticket age in early_data (§4.6.1)
	ticket_nonce    []u8 // ties the ticket to this connection's resumption master secret
	ticket          []u8 // opaque resumption token to present in a future ClientHello
}

// lifetime returns the ticket_lifetime in seconds.
pub fn (t &NewSessionTicket) lifetime() u32 {
	return t.ticket_lifetime
}

// age_add returns the ticket_age_add obfuscation value.
fn (t &NewSessionTicket) age_add() u32 {
	return t.ticket_age_add
}

// nonce returns the ticket nonce.
fn (t &NewSessionTicket) nonce() []u8 {
	return t.ticket_nonce
}

// bytes returns the opaque ticket (the resumption token) to store for a future ClientHello.
pub fn (t &NewSessionTicket) bytes() []u8 {
	return t.ticket
}

// parse_new_session_ticket decodes NewSessionTicket (RFC 8446 §4.6.1); ticket
// storage belongs to the stack above this core (RFC 9001 §4.5).
pub fn parse_new_session_ticket(body []u8) !NewSessionTicket {
	mut r := wire.new_reader(body)
	lifetime := r.read_u32()!
	// RFC 8446 §4.6.1: servers MUST NOT use a value greater than 604800 seconds.
	if lifetime > 604800 {
		return error('handshake: ticket_lifetime ${lifetime} exceeds maximum 604800 seconds (illegal_parameter)')
	}
	age_add := r.read_u32()!
	nonce := r.read_vector_u8()!
	ticket := r.read_vector_u16()!
	if ticket.len == 0 {
		return error('handshake: empty ticket in NewSessionTicket (decode_error)')
	}
	_ := r.read_vector_u16()! // extensions (max_early_data, …): unused while
	// resumption is unimplemented (see Conn.session_tickets on the tls side)
	if r.remaining() != 0 {
		// Strict framing: leftover bytes mean the ticket was misframed.
		return error('handshake: trailing bytes in NewSessionTicket (decode_error)')
	}
	return NewSessionTicket{
		ticket_lifetime: lifetime
		ticket_age_add:  age_add
		ticket_nonce:    nonce
		ticket:          ticket
	}
}
