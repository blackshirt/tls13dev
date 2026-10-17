// Copyright (c) 2026 blackshirt.
// SPDX-License-Identifier: MIT
//
// messages.v encodes and decodes the RFC 8446 §4 handshake structures — ClientHello,
// ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished and the
// extension blocks — relying on the wire reader/writer for the framing arithmetic.
module handshake

import crypto.rand
import wire

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
	// Synthetic type that never appears on the wire: after a HelloRetryRequest,
	// ClientHello1 is replaced by a message_hash in the transcript (RFC 8446 §4.4.1).
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
// the IANA TLS ExtensionType Registry and matched byte-for-byte on the wire.
enum ExtensionType as u16 {
	// server_name rides in the ClientHello as SNI and may be echoed empty in
	// EncryptedExtensions as the server's acknowledgment (RFC 6066 §3).
	server_name          = 0
	supported_groups     = 10
	signature_algorithms = 13
	alpn                 = 16
	supported_versions   = 43
	cookie               = 44
	key_share            = 51
	// RFC 5746 §4.1, not an RFC 8446 extension: TLS 1.3 servers carry it in
	// EncryptedExtensions even when unoffered (see parse_encrypted_extensions).
	renegotiation_info   = 65281 // 0xff01
}

// NamedGroup defines key exchange groups (RFC 8446 §4.2.7), from the IANA
// Supported Groups registry; only the two mandatory ECDHE groups are supported.
pub enum NamedGroup as u16 {
	secp256r1 = 0x0017
	x25519    = 0x001d
}

// SignatureScheme defines cryptographic signature algorithms (RFC 8446 §4.2.3).
enum SignatureScheme as u16 {
	rsa_pkcs1_sha256       = 0x0401
	ecdsa_secp256r1_sha256 = 0x0403
	ecdsa_secp384r1_sha384 = 0x0503
	rsa_pss_rsae_sha256    = 0x0804
	rsa_pss_rsae_sha384    = 0x0805
	rsa_pss_rsae_sha512    = 0x0806
	ed25519                = 0x0807
}

// CipherSuite defines TLS 1.3 cipher suites (RFC 8446 §B.4).
pub enum CipherSuite as u16 {
	tls_aes_128_gcm_sha256       = 0x1301
	tls_aes_256_gcm_sha384       = 0x1302
	tls_chacha20_poly1305_sha256 = 0x1303
}

// default_cipher_suites returns the suite list offered when the caller does not
// configure one (all TLS 1.3 AEAD suites we implement).
fn default_cipher_suites() []CipherSuite {
	return [
		CipherSuite.tls_aes_128_gcm_sha256,
		CipherSuite.tls_aes_256_gcm_sha384,
		CipherSuite.tls_chacha20_poly1305_sha256,
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

// legacy_session_id_len is the 32-byte legacy session id used for middlebox
// compatibility (RFC 8446 App. D.4).
const legacy_session_id_len = 32

// KeyShareEntry holds a group and public key share (RFC 8446 §4.2.8).
pub struct KeyShareEntry {
pub:
	group        NamedGroup // negotiated group the key belongs to
	key_exchange []u8       // X25519 32-byte share, or P-256 uncompressed point (0x04 || X || Y)
}

// HelloRetryRequest sentinel random string (RFC 8446 §4.1.3).
// HRR is syntactically a ServerHello (same msg_type 2) and is identified only
// by this fixed random value, so the message type alone cannot distinguish them.
const hello_retry_request_random = [32]u8[
	0xcf,
	0x21,
	0xad,
	0x74,
	0xe5,
	0x9a,
	0x61,
	0x11,
	0xbe,
	0x1d,
	0x8c,
	0x02,
	0x1e,
	0x65,
	0xb8,
	0x91,
	0xc2,
	0xa2,
	0x11,
	0x16,
	0x7a,
	0xbb,
	0x8c,
	0x5e,
	0x07,
	0x9e,
	0x09,
	0xe2,
	0xc8,
	0xa8,
	0x33,
	0x9c,
]

// ServerHello holds the parsed ServerHello/HelloRetryRequest fields the client
// acts on. Extension extraction obeys the §4.2 placement allowlist; semantic
// checks live on the type itself (validate); key-schedule effects are the state
// machine's job.
pub struct ServerHello {
pub:
	session_id_echo []u8          // legacy_session_id echoed from the ClientHello (middlebox compatibility)
	cipher_suite    CipherSuite   // suite selected by the server
	server_share    KeyShareEntry // server's ECDHE public share
	// is_hello_retry_req is set solely by the §4.1.3 sentinel-random comparison;
	// an HRR parses into this same struct because the wire layout is identical.
	is_hello_retry_req bool
	// has_key_share reports whether a key_share extension was present. For an HRR
	// it distinguishes a group-change request from a cookie-only request.
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

// write_extension appends a TLS extension: 2-byte type followed by the
// 2-byte-length-prefixed data. It does not de-duplicate — build_client_hello
// writes each extension at most once, and §4.2 forbids repeats (the parser
// enforces that).
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

// WireExtension is a raw type/value pair from an extensions block (RFC 8446 §4.2).
// The value stays undecoded: interpretation differs per message and call site.
struct WireExtension {
pub:
	typ  u16
	data []u8 // extension_data, already length-bounded by the framing read
}

// parse_extensions decodes an extensions block: repeated
// [u16 extension_type][u16 length][extension_data]. A duplicated extension type
// is rejected, since §4.2 forbids repeats and a later instance could otherwise
// overwrite a validated value. Unknown types are returned verbatim.
fn parse_extensions(ext_bytes []u8) ![]WireExtension {
	mut r := wire.new_reader(ext_bytes)
	mut out := []WireExtension{}
	mut seen_types := []u16{}
	for r.remaining() > 0 {
		typ := r.read_u16()!
		data := r.read_vector_u16()!
		for s in seen_types {
			if s == typ {
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

// parse_handshake_header reads the 4-byte header from a reader.
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
	// session_id is echoed across HelloRetryRequest; generated if empty (the
	// state machine pins the generated value back into config for §4.1.4 reuse).
	session_id []u8
	// random is the ClientHello.random; generated (and pinned into config) if
	// empty — an explicit value exists solely to replay RFC test vectors.
	random []u8
	// cookie is echoed from HelloRetryRequest when present.
	cookie []u8
	// cipher_suites defaults to the three TLS 1.3 AEAD suites when empty.
	cipher_suites []CipherSuite
}

// offered_cipher_suites returns the suites a client sends in its ClientHello:
// the explicit configuration if present, otherwise the built-in default list.
fn offered_cipher_suites(cfg &ClientHelloConfig) []CipherSuite {
	if cfg.cipher_suites.len > 0 {
		return cfg.cipher_suites
	}
	return default_cipher_suites()
}

// validate performs the ServerHello/HelloRetryRequest checks that do not depend
// on the message variant (RFC 8446 §4.1.3): the echoed legacy session ID must
// match the ClientHello, and the selected cipher suite must have been offered.
fn (sh ServerHello) validate(cfg &ClientHelloConfig) ! {
	// A session-id mismatch means the hello we answer is not the one we sent — a
	// renegotiation/off-path injection signal (illegal_parameter).
	if sh.session_id_echo != cfg.session_id {
		return error('handshake: legacy_session_id_echo does not match ClientHello (illegal_parameter)')
	}
	// The server must pick a suite we offered; an unoffered choice would let an
	// attacker downgrade us to a suite the state machine never configured.
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

// is_ip_literal reports whether host is an IPv4 or IPv6 address.
// Per RFC 6066 §3, literal IP addresses are not permitted in SNI HostName.
fn is_ip_literal(host string) bool {
	h := host.trim_space()
	if h.len == 0 {
		return false
	}
	if h.contains(':') {
		return true
	}
	parts := h.split('.')
	if parts.len == 4 {
		for p in parts {
			if p.len == 0 || p.len > 3 {
				return false
			}
			for c in p {
				if c < `0` || c > `9` {
					return false
				}
			}
			val := p.int()
			if val < 0 || val > 255 {
				return false
			}
		}
		return true
	}
	return false
}

// build_client_hello generates the ClientHello of RFC 8446 §4.1.2, returning the
// message body followed by the full handshake message (header + body).
fn build_client_hello(cfg ClientHelloConfig) !([]u8, []u8) {
	mut body := wire.new_writer(512)

	// Legacy version 0x0303 (TLS 1.2): TLS 1.3 pins this field so version-sensitive
	// middleboxes keep parsing; the real version is negotiated via the
	// supported_versions extension (§4.2.1).
	body.write_u16(0x0303)

	// Random: an explicit cfg.random replays RFC test vectors byte-for-byte; real
	// handshakes leave it empty so the state machine pre-generates and pins the
	// value for HRR reuse (§4.1.4).
	random_bytes := if cfg.random.len == client_hello_random_len {
		cfg.random.clone()
	} else {
		rand.bytes(client_hello_random_len)!
	}
	body.write_bytes(random_bytes)

	// Legacy session id for middlebox compatibility (App. D.4); its only real
	// job is to be echoed in ServerHello for the legacy_session_id_echo check.
	session_id := if cfg.session_id.len > 0 {
		cfg.session_id.clone()
	} else {
		rand.bytes(legacy_session_id_len)!
	}
	body.write_vector_u8(session_id)!

	// Cipher Suites
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

	// Extensions
	mut ext_writer := wire.new_writer(256)

	// server_name (SNI, RFC 6066 §3): literal IP addresses are forbidden.
	if cfg.server_name.len > 0 && !is_ip_literal(cfg.server_name) {
		mut sni_w := wire.new_writer(cfg.server_name.len + 5)
		// Two nested u16 vectors per RFC 6066 §3: ServerNameList and, inside it,
		// the per-entry host_name length.
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
		mut sg_w := wire.new_writer(5)
		mut groups_w := wire.new_writer(4)
		groups_w.write_u16(u16(NamedGroup.x25519))
		groups_w.write_u16(u16(NamedGroup.secp256r1))
		sg_w.write_vector_u16(groups_w.bytes())!

		write_extension(mut ext_writer, .supported_groups, sg_w.bytes())!
	}

	// signature_algorithms (RFC 8446 §4.2.3)
	{
		schemes := [
			u16(SignatureScheme.rsa_pss_rsae_sha256),
			u16(SignatureScheme.rsa_pss_rsae_sha384),
			u16(SignatureScheme.rsa_pss_rsae_sha512),
			u16(SignatureScheme.ecdsa_secp256r1_sha256),
			u16(SignatureScheme.ecdsa_secp384r1_sha384),
			u16(SignatureScheme.ed25519),
			u16(SignatureScheme.rsa_pkcs1_sha256),
		]
		mut sa_w := wire.new_writer(schemes.len * 2 + 2)
		mut slist_w := wire.new_writer(schemes.len * 2)
		for s in schemes {
			slist_w.write_u16(s)
		}
		sa_w.write_vector_u16(slist_w.bytes())!

		write_extension(mut ext_writer, .signature_algorithms, sa_w.bytes())!
	}

	// key_share (RFC 8446 §4.2.8): client_shares is a u16 vector of entries, each
	// a group (u16) plus a u16-length-prefixed key_exchange.
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
// Enforces the §4.2 extension placement rules: only supported_versions,
// key_share, and (HelloRetryRequest only) cookie may appear; anything else
// aborts instead of silently steering client state.
fn parse_server_hello(body []u8) !ServerHello {
	// The body follows §4.1.3's fixed field order; each read advances the cursor,
	// so any reordering or length mismatch desyncs the rest and is caught here.
	mut r := wire.new_reader(body)
	// legacy_version is pinned to 0x0303 (TLS 1.2); the real version is in
	// supported_versions and is confirmed below (§4.2.1).
	legacy_version := r.read_u16()!
	if legacy_version != 0x0303 {
		return error('handshake: ServerHello legacy_version must be 0x0303, got 0x${legacy_version:04x}')
	}
	// random: equal to the fixed sentinel means this is a HelloRetryRequest (§4.1.3).
	random := r.read_bytes(client_hello_random_len)!
	// legacy_session_id_echo: must echo our ClientHello's session id (checked in validate).
	session_id_echo := r.read_vector_u8()!
	// cipher_suite: exactly one 2-byte suite, and it must be one we offered
	// (checked in validate); cipher_suite_from_u16 rejects non-TLS-1.3 codes.
	cs_raw := r.read_u16()!
	cipher_suite := cipher_suite_from_u16(cs_raw)!
	// legacy_compression_method: TLS 1.3 fixes this to the null method (0).
	compression := r.read_u8()!
	if compression != 0 {
		return error('handshake: compression method must be 0, got ${compression}')
	}

	// Extensions
	ext_bytes := r.read_vector_u16()!

	mut selected_version := u16(0)
	mut server_share := KeyShareEntry{}
	mut has_key_share := false
	mut cookie := []u8{}
	is_hrr := random == hello_retry_request_random[..] // §4.1.3: fixed sentinel random identifies an HRR

	exts := parse_extensions(ext_bytes)!
	for ext in exts {
		mut data_r := wire.new_reader(ext.data)

		match ext.typ {
			u16(ExtensionType.supported_versions) {
				// In ServerHello this extension is a bare u16 version, not a
				// length-prefixed vector as in ClientHello (§4.2.1).
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
				mut cr := wire.new_reader(ext.data)
				cookie = cr.read_vector_u16()!
				if cookie.len == 0 {
					return error('handshake: HelloRetryRequest cookie must be non-empty')
				}
				if cr.remaining() != 0 {
					return error('handshake: trailing bytes in HelloRetryRequest cookie')
				}
			}
			else {
				// The allowlist is the §4.2 one; TLS 1.2 leftovers or unoffered
				// extensions must never reach client state.
				return error('handshake: extension 0x${ext.typ:04x} not permitted in ServerHello (unsupported_extension)')
			}
		}
	}

	// TLS 1.3 hides its real version behind legacy_version=0x0303, so the
	// negotiated version MUST be confirmed via supported_versions = 0x0304.
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

// parse_certificate decodes the Certificate message body (RFC 8446 §4.4.2) and
// returns the DER-encoded certificate chain.
fn parse_certificate(body []u8) ![][]u8 {
	mut r := wire.new_reader(body)
	req_ctx := r.read_vector_u8()!
	// §4.4.2: in a server Certificate, certificate_request_context SHALL be zero
	// length; a nonzero value is illegal_parameter.
	if req_ctx.len > 0 {
		return error('handshake: non-empty certificate_request_context in server Certificate (illegal_parameter)')
	}
	// u24 list length: full chains can exceed 64 KiB, which a u16 could not frame.
	cert_list_bytes := r.read_vector_u24()!

	mut cert_r := wire.new_reader(cert_list_bytes)
	mut certs := [][]u8{}
	for cert_r.remaining() > 0 {
		cert_data := cert_r.read_vector_u24()!
		_ := cert_r.read_vector_u16()! // per-cert extensions (status_request etc.):
		// ignored, this client uses no optional cert features.
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

// certificate_verify_signed_content constructs the exact bytes signed in
// CertificateVerify (RFC 8446 §4.4.3):
//
//	content = 0x20 * 64 || "TLS 1.3, server CertificateVerify" || 0x00 || transcript_hash
//
// The 64 leading space octets fill one hash block so the signed data does not
// start with attacker-controlled content, and the context string
// domain-separates CertificateVerify from Finished so a signature valid for one
// purpose can never be replayed as the other.
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
// The body is exactly verify_data with no length prefix or other fields, so the
// slice is returned as-is.
fn parse_finished(body []u8) ![]u8 {
	return body.clone()
}

// build_finished creates a Finished handshake message carrying verify_data.
fn build_finished(verify_data []u8) []u8 {
	return wrap_handshake_message(.finished, verify_data)
}

// parse_encrypted_extensions decodes EncryptedExtensions (RFC 8446 §4.3.1) and
// returns the negotiated ALPN protocol (empty when none). Per §4.3.1 only
// client-offered extensions belong here; the tolerated echoes are the empty
// server_name SNI acknowledgment (RFC 6066 §3), the redundant supported_groups
// list, and RFC 5746 renegotiation_info (see the loop). Whether ALPN was
// actually offered is the caller's check — only the state machine knows the
// config.
fn parse_encrypted_extensions(body []u8) !string {
	mut r := wire.new_reader(body)
	ext_bytes := r.read_vector_u16()!
	mut alpn := ''

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
				// RFC 7301 §3.1: the server picks exactly one protocol; a second
				// entry could hide behind the first and dodge the offered-list check.
				return error('handshake: ALPN extension carried more than one protocol')
			}
		} else if ext.typ == u16(ExtensionType.server_name) {
			// RFC 8446 §4.2 registers server_name for EncryptedExtensions as the SNI
			// acknowledgment of RFC 6066 §3: a server that accepted our hostname
			// echoes an EMPTY server_name extension. The ack asserts nothing, so
			// require empty extension_data — a non-empty value would have the server
			// asserting a name we never chose.
			if ext.data.len != 0 {
				return error('handshake: server sent a non-empty server_name in EncryptedExtensions')
			}
		} else if ext.typ == u16(ExtensionType.supported_groups) {
			// Interop carve-out: §4.2 registers supported_groups as ClientHello-only,
			// yet some servers still echo it here. It was offered (§4.3.1's real
			// requirement) and the negotiated group is already pinned by the
			// ServerHello key_share, so the echo carries no authority — ignore it
			// rather than aborting an otherwise valid handshake.
			continue
		} else if ext.typ == u16(ExtensionType.renegotiation_info) {
			// Interop carve-out (see the enum member): OpenSSL sends this unoffered,
			// so it must not be rejected. RFC 5746 §3.4 fixes its TLS 1.3 content to
			// the empty renegotiated_connection case; a non-empty value asserts a
			// renegotiation this single-shot client never performed.
			mut ri_r := wire.new_reader(ext.data)
			if ri_r.remaining() > 0 {
				conn := ri_r.read_vector_u8()!
				if conn.len != 0 || ri_r.remaining() != 0 {
					return error('handshake: renegotiation_info carried a non-empty renegotiated_connection')
				}
			}
		} else {
			// §4.3.1: everything else must have been offered and belong here.
			return error('handshake: extension 0x${ext.typ:04x} in EncryptedExtensions was not offered (unsupported_extension)')
		}
	}
	if r.remaining() != 0 {
		return error('handshake: trailing bytes after EncryptedExtensions')
	}

	return alpn
}

// parse_key_update decodes a KeyUpdate body (RFC 8446 §4.6.3) and reports
// whether the sender requested that we also update our keys.
// Wire enum: update_not_requested(0), update_requested(1).
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

// NewSessionTicket holds a parsed NewSessionTicket (fields needed for storage).
pub struct NewSessionTicket {
pub:
	ticket_lifetime u32  // seconds the ticket may be used after issuance; 0 means no support
	ticket_age_add  u32  // random value for obfuscating ticket age in early_data (§4.6.1)
	ticket_nonce    []u8 // ties the ticket to this connection's resumption master secret
	ticket          []u8 // opaque resumption token to present in a future ClientHello
}

// parse_new_session_ticket decodes NewSessionTicket (RFC 8446 §4.6.1).
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
	// resumption is unimplemented (see ClientHandshake.session_tickets)
	return NewSessionTicket{
		ticket_lifetime: lifetime
		ticket_age_add:  age_add
		ticket_nonce:    nonce
		ticket:          ticket
	}
}
