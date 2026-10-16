module handshake

import crypto.rand
import wire

// HandshakeType identifies TLS 1.3 handshake messages (RFC 8446 §4).
pub enum HandshakeType as u8 {
	client_hello         = 1
	server_hello         = 2
	new_session_ticket   = 4
	end_of_early_data    = 5 // 0-RTT; recognised but not implemented
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
pub fn handshake_type_from_u8(b u8) !HandshakeType {
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

// ExtensionType represents TLS 1.3 extension codes (RFC 8446 §4.2).
// Values are assigned by the IANA TLS ExtensionType Registry, so they must
// match byte-for-byte for interoperability.
pub enum ExtensionType as u16 {
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

// NamedGroup defines key exchange groups (RFC 8446 §4.2.7).
// Codes come from the IANA TLS Supported Groups registry; only the two
// mandatory-to-implement ECDHE groups are supported here.
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

// CipherSuite defines TLS 1.3 cipher suites (RFC 8446 §B.4).
pub enum CipherSuite as u16 {
	tls_aes_128_gcm_sha256       = 0x1301
	tls_aes_256_gcm_sha384       = 0x1302
	tls_chacha20_poly1305_sha256 = 0x1303
}

// default_cipher_suites returns the suite list offered when the caller does not
// configure one (all TLS 1.3 AEAD suites we implement).
pub fn default_cipher_suites() []CipherSuite {
	return [
		CipherSuite.tls_aes_128_gcm_sha256,
		CipherSuite.tls_aes_256_gcm_sha384,
		CipherSuite.tls_chacha20_poly1305_sha256,
	]
}

// cipher_suite_from_u16 decodes a 2-byte cipher suite code (RFC 8446 §B.4).
pub fn cipher_suite_from_u16(raw u16) !CipherSuite {
	return match raw {
		0x1301 { .tls_aes_128_gcm_sha256 }
		0x1302 { .tls_aes_256_gcm_sha384 }
		0x1303 { .tls_chacha20_poly1305_sha256 }
		else { error('handshake: unsupported cipher suite 0x${raw:04x}') }
	}
}

// signature_scheme_from_u16 decodes a 2-byte SignatureScheme code (RFC 8446 §4.2.3).
pub fn signature_scheme_from_u16(raw u16) !SignatureScheme {
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
pub const client_hello_random_len = 32

// legacy_session_id_len is the 32-byte legacy session id used for middlebox
// compatibility (RFC 8446 App. D.4).
pub const legacy_session_id_len = 32

// KeyShareEntry holds a group and public key share (RFC 8446 §4.2.8).
pub struct KeyShareEntry {
pub:
	group        NamedGroup // negotiated group the key belongs to
	key_exchange []u8       // X25519 32-byte share, or P-256 uncompressed point (0x04 || X || Y)
}

// HelloRetryRequest sentinel random string (RFC 8446 §4.1.3).
// HRR is syntactically a ServerHello (same msg_type 2), so it is identified by
// replacing the random field with this fixed value — a client cannot rely on
// msg_type alone to branch between the two.
pub const hello_retry_request_random = [32]u8[
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
// needs to act on. Extension extraction obeys the §4.2 placement allowlist;
// semantic checks (suite supported, share usable against our offer) are the
// state machine's job, not this parser's.
pub struct ServerHello {
pub:
	session_id_echo []u8          // legacy_session_id echoed from the ClientHello (middlebox compatibility)
	cipher_suite    CipherSuite   // suite selected by the server
	server_share    KeyShareEntry // server's ECDHE public share
	// is_hello_retry_req is set solely by the §4.1.3 sentinel-random comparison;
	// an HRR parses into this same struct because the wire layout is identical.
	is_hello_retry_req bool
	// has_key_share reports whether a key_share extension was present. For a
	// HelloRetryRequest it distinguishes a group-change request from a
	// cookie-only request; for a ServerHello it should always be true.
	has_key_share bool
	// cookie holds the cookie value from HelloRetryRequest when present, empty otherwise.
	cookie []u8
}

// ParsedCertificateVerify holds the parsed CertificateVerify handshake message.
pub struct ParsedCertificateVerify {
pub:
	algorithm SignatureScheme // scheme the server signed with, must be usable for the leaf key
	signature []u8            // raw signature bytes over the transcript-derived content
}

// wrap_handshake_message frames a handshake body with its 1-byte HandshakeType
// and 3-byte big-endian length.
pub fn wrap_handshake_message(typ HandshakeType, body []u8) []u8 {
	mut w := wire.new_writer(4 + body.len)
	w.write_u8(u8(typ))
	w.write_u24(u32(body.len))
	w.write_bytes(body)
	return w.bytes()
}

// write_extension appends a TLS extension: 2-byte type followed by the
// 2-byte-length-prefixed extension data. It performs no de-duplication — safe
// only because build_client_hello writes each extension at most once by
// construction; §4.2 forbids repeats, which is why the *parser* checks them.
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

// WireExtension is a raw type/value pair from an extensions block (RFC 8446
// §4.2). The value stays undecoded: which extensions are meaningful and how to
// treat unknown ones differs per message, so framing is handled centrally while
// interpretation is left to the call site.
struct WireExtension {
pub:
	typ  u16
	data []u8 // extension_data, already length-bounded by the framing read
}

// parse_extensions decodes a whole extensions block: repeated
// [u16 extension_type][u16 length][extension_data]. It enforces §4.2's rule
// that "...MUST NOT include multiple instances of the same extension": without
// this, a duplicated supported_versions or key_share could silently overwrite
// the first occurrence after the caller believed it validated one. Unknown
// types are returned verbatim so each caller decides to ignore or reject.
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
pub struct ClientHelloConfig {
pub mut:
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

// build_client_hello generates the ClientHello of RFC 8446 §4.1.2, returning the
// message body followed by the full handshake message (header + body).
pub fn build_client_hello(cfg ClientHelloConfig) !([]u8, []u8) {
	mut body := wire.new_writer(512)

	// 1. Legacy version: 0x0303 (TLS 1.2). TLS 1.3 pins this field to 1.2 so
	// version-sensitive middleboxes keep parsing the hello; the real version is
	// negotiated exclusively through the supported_versions extension (§4.2.1).
	body.write_u16(0x0303)

	// 2. Random: client_hello_random_len bytes cryptographically secure random.
	// An explicit cfg.random exists to replay RFC test vectors byte-for-byte;
	// real handshakes leave it empty here — the state machine pre-generates and
	// pins the value so HRR retries reuse it (§4.1.4). The random seeds nothing
	// cryptographic in 1.3, but predictability would break session uniqueness.
	random_bytes := if cfg.random.len == client_hello_random_len {
		cfg.random.clone()
	} else {
		rand.bytes(client_hello_random_len)!
	}
	body.write_bytes(random_bytes)

	// 3. Legacy session ID: a random legacy_session_id_len-byte value for middlebox
	// compatibility (RFC 8446 App. D.4): servers/middleboxes treat it as a
	// session-resumption hint, and its only real job here is to be echoed in
	// ServerHello for the legacy_session_id_echo check.
	session_id := if cfg.session_id.len > 0 {
		cfg.session_id.clone()
	} else {
		rand.bytes(legacy_session_id_len)!
	}
	body.write_vector_u8(session_id)!

	// 4. Cipher Suites
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

	// 5. Legacy compression methods: RFC 8446 §4.2 requires clients to offer
	// only the null method (0x00); any compression selection from a 1.2-style
	// server is rejected during ServerHello parsing.
	body.write_vector_u8([u8(0x00)])!

	// 6. Extensions
	mut ext_writer := wire.new_writer(256)

	// Extension: server_name (SNI)
	if cfg.server_name.len > 0 {
		mut sni_w := wire.new_writer(cfg.server_name.len + 5)
		// Two nested u16 vectors per RFC 6066 §3: ServerNameList (all names) and,
		// inside it, the per-entry host_name length — easy to collapse into one by
		// mistake, which servers reject as a malformed hello.
		mut snl_w := wire.new_writer(cfg.server_name.len + 3)
		snl_w.write_u8(0x00) // HostName type
		snl_w.write_vector_u16(cfg.server_name.bytes())!
		sni_w.write_vector_u16(snl_w.bytes())!

		write_extension(mut ext_writer, .server_name, sni_w.bytes())!
	}

	// Extension: supported_versions (RFC 8446 §4.2.1)
	// (Plain scoped blocks below: they exist only to keep each extension's
	// scratch writers out of the outer namespace, nothing protocol-related.)
	{
		mut sv_w := wire.new_writer(3)
		sv_w.write_vector_u8([u8(0x03), 0x04])! // TLS 1.3
		write_extension(mut ext_writer, .supported_versions, sv_w.bytes())!
	}

	// Extension: supported_groups (RFC 8446 §4.2.7)
	{
		mut sg_w := wire.new_writer(5)
		mut groups_w := wire.new_writer(4)
		groups_w.write_u16(u16(NamedGroup.x25519))
		groups_w.write_u16(u16(NamedGroup.secp256r1))
		sg_w.write_vector_u16(groups_w.bytes())!

		write_extension(mut ext_writer, .supported_groups, sg_w.bytes())!
	}

	// Extension: signature_algorithms (RFC 8446 §4.2.3)
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

	// Extension: key_share (RFC 8446 §4.2.8)
	// client_shares is a u16 vector of entries; each entry is group (u16) plus a
	// u8-length-prefixed key_exchange — the three nesting levels are mandatory.
	{
		mut ks_w := wire.new_writer(cfg.client_share.key_exchange.len + 6)
		mut entry_w := wire.new_writer(cfg.client_share.key_exchange.len + 4)
		entry_w.write_u16(u16(cfg.client_share.group))
		entry_w.write_vector_u16(cfg.client_share.key_exchange)!
		ks_w.write_vector_u16(entry_w.bytes())!

		write_extension(mut ext_writer, .key_share, ks_w.bytes())!
	}

	// Extension: ALPN (RFC 7301)
	if cfg.alpn.len > 0 {
		mut alpn_w := wire.new_writer(32)
		mut protocols_w := wire.new_writer(30)
		for p in cfg.alpn {
			protocols_w.write_vector_u8(p.bytes())!
		}
		alpn_w.write_vector_u16(protocols_w.bytes())!

		write_extension(mut ext_writer, .alpn, alpn_w.bytes())!
	}

	// Extension: cookie (RFC 8446 §4.2.2) — echoed after HelloRetryRequest
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
pub fn parse_server_hello(body []u8) !ServerHello {
	mut r := wire.new_reader(body)
	legacy_version := r.read_u16()!
	if legacy_version != 0x0303 {
		return error('handshake: ServerHello legacy_version must be 0x0303, got 0x${legacy_version:04x}')
	}
	random := r.read_bytes(client_hello_random_len)!
	session_id_echo := r.read_vector_u8()!
	cs_raw := r.read_u16()!
	cipher_suite := cipher_suite_from_u16(cs_raw)!
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
				// Asymmetric with ClientHello: in ServerHello this extension is a bare
				// u16 version, not a length-prefixed vector (§4.2.1).
				selected_version = data_r.read_u16()!
				if data_r.remaining() != 0 {
					// Fixed 2-byte structure; leftover bytes are a malformed message
					// (§4.4), not something to tolerate past the parsed version.
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
						// ServerHello carries exactly one KeyShareEntry (§4.2.8); anything
						// beyond it is a malformed message.
						return error('handshake: trailing bytes in ServerHello key_share')
					}
					server_share = KeyShareEntry{
						group:        named_group_from_u16(grp)!
						key_exchange: key_ex
					}
				}
			}
			u16(ExtensionType.cookie) {
				// §4.2: cookie rides in a ServerHello-type message only as part of an HRR.
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
				// TLS 1.2 leftovers or unoffered extensions must never reach client
				// state — the allowlist in this match is the §4.2 one.
				return error('handshake: extension 0x${ext.typ:04x} not permitted in ServerHello (unsupported_extension)')
			}
		}
	}

	// TLS 1.3 hides its real version behind legacy_version=0x0303, so the actual
	// negotiated version MUST be confirmed via supported_versions = 0x0304 here;
	// a server that omits it or downgrades is being tampered with or is 1.2-only.
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
// returns the DER-encoded certificate chain. The request context is unused.
pub fn parse_certificate(body []u8) ![][]u8 {
	mut r := wire.new_reader(body)
	_ := r.read_vector_u8()! // request context (always empty server→client, §4.4.2)
	// u24 list length: full chains can exceed 64 KiB, which a u16 prefix could not
	// frame (§4.4.2 defines certificate_list as a vector<...>(2^24-1)).
	cert_list_bytes := r.read_vector_u24()!

	mut cert_r := wire.new_reader(cert_list_bytes)
	mut certs := [][]u8{}
	for cert_r.remaining() > 0 {
		cert_data := cert_r.read_vector_u24()!
		_ := cert_r.read_vector_u16()! // per-cert extensions (status_request etc.)
		// intentionally ignored: this client uses no optional cert features.
		certs << cert_data
	}

	if certs.len == 0 {
		return error('handshake: server certificate list cannot be empty')
	}
	return certs
}

// parse_certificate_verify decodes the CertificateVerify body (RFC 8446 §4.4.3).
pub fn parse_certificate_verify(body []u8) !ParsedCertificateVerify {
	mut r := wire.new_reader(body)
	algo_u16 := r.read_u16()!
	algo := signature_scheme_from_u16(algo_u16)!
	signature := r.read_vector_u16()!
	return ParsedCertificateVerify{
		algorithm: algo
		signature: signature
	}
}

// certificate_verify_signed_content constructs the exact bytes that are signed
// in CertificateVerify (RFC 8446 §4.4.3):
//
//	content = 0x20 * 64 || "TLS 1.3, server CertificateVerify" || 0x00 || transcript_hash
//
// Why this padding + context string exists (RFC 8446 §4.4.3):
// - The 64 leading 0x20 octets fill one SHA-256/384 block so the signed data
//   does not start with content an attacker can control, blocking prefix-based
//   hash-collision tricks against Merkle-Damgård-style constructions.
// - The context string domain-separates CertificateVerify from Finished: a
//   signature valid for one purpose can never be replayed as the other.
pub fn certificate_verify_signed_content(transcript_hash []u8) []u8 {
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

// parse_finished reads the verify_data from a Finished handshake message (RFC 8446 §4.4.4).
// The Finished body is exactly verify_data with no length prefix or other fields
// (its length is fixed at Hash.length), so the body slice is returned as-is.
pub fn parse_finished(body []u8) ![]u8 {
	return body.clone()
}

// build_finished creates a Finished handshake message carrying verify_data.
pub fn build_finished(verify_data []u8) []u8 {
	return wrap_handshake_message(.finished, verify_data)
}

// parse_encrypted_extensions decodes EncryptedExtensions (RFC 8446 §4.3.1) and
// returns the negotiated ALPN protocol (empty when none was selected). Per
// §4.3.1 only client-offered extensions belong here; the sole tolerated extra
// is RFC 5746 renegotiation_info (see the loop). Whether ALPN was actually
// offered is the caller's check — only the state machine knows the config.
pub fn parse_encrypted_extensions(body []u8) !string {
	mut r := wire.new_reader(body)
	ext_bytes := r.read_vector_u16()!
	mut alpn := ''

	exts := parse_extensions(ext_bytes)!
	for ext in exts {
		if ext.typ == u16(ExtensionType.alpn) {
			mut data_r := wire.new_reader(ext.data)
			proto_list := data_r.read_vector_u16()!
			mut pl_r := wire.new_reader(proto_list)
			if pl_r.remaining() > 0 {
				// The server must select exactly one protocol (RFC 7301 §3.1);
				// reading only the first entry treats a non-compliant multi-protocol
				// list as the server's choice without inventing validation.
				alpn = pl_r.read_vector_u8()!.bytestr()
			}
		} else if ext.typ == u16(ExtensionType.renegotiation_info) {
			// Interop carve-out (see the enum member): it asserts nothing this
			// single-shot client acts on, so tolerate and ignore rather than break
			// OpenSSL servers that send it unoffered.
		} else {
			// §4.3.1: everything else must have been offered and belong here.
			return error('handshake: extension 0x${ext.typ:04x} in EncryptedExtensions was not offered (unsupported_extension)')
		}
	}

	return alpn
}

// parse_key_update decodes a KeyUpdate body (RFC 8446 §4.6.3) and reports
// whether the sender requested that we also update our keys. Note the wire
// enum is request_update(0) / update_not_requested(1) — the *absence* of a
// byte pattern means a request, so a plain `== 1` here inverts the meaning.
pub fn parse_key_update(body []u8) !bool {
	if body.len != 1 {
		return error('handshake: KeyUpdate body must be 1 byte')
	}
	return body[0] == 0
}

// build_key_update creates a KeyUpdate handshake message carrying the §4.6.3
// update_request byte (0 = please update, 1 = no response expected).
pub fn build_key_update(request_update bool) []u8 {
	val := if request_update { u8(0) } else { u8(1) }
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
	age_add := r.read_u32()!
	nonce := r.read_vector_u8()!
	ticket := r.read_vector_u16()!
	_ := r.read_vector_u16()! // extensions (max_early_data, …): unused while
	// resumption is unimplemented (see ClientHandshake.session_tickets)
	return NewSessionTicket{
		ticket_lifetime: lifetime
		ticket_age_add:  age_add
		ticket_nonce:    nonce
		ticket:          ticket
	}
}
