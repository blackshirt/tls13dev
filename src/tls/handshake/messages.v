// Copyright (c) 2026 blackshirt.
//
// messages.v owns the shared RFC 8446 §4 handshake vocabulary — message, extension,
// group, signature-scheme and cipher-suite codes, their single-source supported lists,
// and the wire decoders and framing built on them.
module handshake

import tls.wire

// HandshakeType identifies TLS 1.3 handshake messages (RFC 8446 §4).
pub enum HandshakeType as u8 {
	client_hello         = 1
	server_hello         = 2
	new_session_ticket   = 4
	end_of_early_data    = 5 // 0-RTT; recognized but not implemented
	encrypted_extensions = 8
	certificate          = 11
	certificate_request  = 13 // server→client auth; client holds no credential, so it answers with an empty Certificate (§4.4.2)
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
	// RFC 5746 §4.1, not RFC 8446: servers may carry it in EncryptedExtensions unoffered.
	renegotiation_info        = 65281 // 0xff01
	// pre_shared_key carries PSK identities (ClientHello) or the server's
	// selected PSK index (ServerHello) (RFC 8446 §4.2.11).
	pre_shared_key            = 41
	// psk_key_exchange_modes tells the server which PSK key-exchange modes
	// the client supports (mode 1 = psk_dhe_ke, PSK with (EC)DHE) (RFC 8446 §4.2.9).
	psk_key_exchange_modes    = 45
}

// NamedGroup defines key exchange groups (RFC 8446 §4.2.7); only the two mandatory
// ECDHE groups are supported.
pub enum NamedGroup as u16 {
	secp256r1 = 0x0017
	x25519    = 0x001d
}

// supported_named_groups is the single source of the groups this stack offers,
// accepts on the wire, and performs ECDHE for; order is the default offer order.
const supported_named_groups = [NamedGroup.x25519, .secp256r1]

// is_supported_group reports whether the group is in this stack's supported set
// — the same source the wire decoder and the default offer list derive from.
fn is_supported_group(g NamedGroup) bool {
	return g in supported_named_groups
}

// named_group_from_u16 converts the 16-bit group identifier against
// supported_named_groups — the same list the offer and configuration gates use.
fn named_group_from_u16(raw u16) !NamedGroup {
	for g in supported_named_groups {
		if u16(g) == raw {
			return g
		}
	}
	return error('handshake: unsupported group 0x${raw:04x}')
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

// supported_signature_schemes is the single source of the schemes this stack
// offers, accepts on the wire, and can verify in CertificateVerify; order is the
// default offer order. A client must never offer a scheme it could not verify.
const supported_signature_schemes = [SignatureScheme.rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384,
	.rsa_pss_rsae_sha512, .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384, .ed25519,
	.rsa_pkcs1_sha256]

// is_supported_signature_scheme reports whether the scheme is in this stack's
// supported set — offerable, decodable, and verifiable by the same source, so a
// client can never offer a scheme it could not verify in CertificateVerify.
fn is_supported_signature_scheme(s SignatureScheme) bool {
	return s in supported_signature_schemes
}

// signature_scheme_from_u16 decodes a 2-byte SignatureScheme code against
// supported_signature_schemes (RFC 8446 §4.2.3) — the same list the offer and
// configuration gates use.
fn signature_scheme_from_u16(raw u16) !SignatureScheme {
	for s in supported_signature_schemes {
		if u16(s) == raw {
			return s
		}
	}
	return error('handshake: unsupported signature scheme 0x${raw:04x}')
}

// CipherSuite defines TLS 1.3 cipher suites (RFC 8446 §B.4).
pub enum CipherSuite as u16 {
	tls_aes_128_gcm_sha256       = 0x1301
	tls_aes_256_gcm_sha384       = 0x1302
	tls_chacha20_poly1305_sha256 = 0x1303
}

// supported_cipher_suites is the single source of the suites this stack offers,
// accepts on the wire, and implements (RFC 8446 §B.4); order is the default offer
// order — ChaCha20-Poly1305 leads because the AEAD backend is software-only.
const supported_cipher_suites = [CipherSuite.tls_chacha20_poly1305_sha256, .tls_aes_128_gcm_sha256,
	.tls_aes_256_gcm_sha384]

// is_supported_cipher_suite reports whether the suite is in this stack's
// supported set: offered, decoded, and implemented from one list, so
// advertisement and acceptance cannot drift apart.
fn is_supported_cipher_suite(cs CipherSuite) bool {
	return cs in supported_cipher_suites
}

// cipher_suite_from_u16 decodes a 2-byte cipher suite code against
// supported_cipher_suites (RFC 8446 §B.4), the same list the offer and
// configuration gates use.
fn cipher_suite_from_u16(raw u16) !CipherSuite {
	for cs in supported_cipher_suites {
		if u16(cs) == raw {
			return cs
		}
	}
	return error('handshake: unsupported cipher suite 0x${raw:04x}')
}

// client_hello_random_len is the fixed ClientHello.random size (RFC 8446 §4.1.2).
const client_hello_random_len = 32

// legacy_session_id_len is the cap on ClientHello.legacy_session_id (§4.1.2 MUST NOT exceed
// 32 bytes); shorter values are legal, and unset config applies the App. D.4 default of 32
// fresh random bytes for middlebox compatibility.
const legacy_session_id_len = 32

// KeyShareEntry holds a group and public key share (RFC 8446 §4.2.8).
struct KeyShareEntry {
mut:
	group        NamedGroup // negotiated group the key belongs to
	key_exchange []u8       // X25519 32-byte share, or P-256 uncompressed point (0x04 || X || Y)
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

// WireExtension is a raw, undecoded type/value pair from an extensions block (RFC 8446 §4.2).
struct WireExtension {
mut:
	typ  u16
	data []u8 // extension_data, already length-bounded by the framing read
}

// parse_extensions decodes an extensions block of [u16 type][u16 length][data].
// Duplicate types are rejected: §4.2 forbids repeats. Unknown types are returned verbatim.
@[direct_array_access]
fn parse_extensions(ext_bytes []u8) ![]WireExtension {
	mut r := wire.new_reader(ext_bytes)
	mut out := []WireExtension{}
	mut seen_types := []u16{}
	for r.remaining() > 0 {
		typ := r.read_u16()!
		data := r.read_vector_u16()!
		if typ in seen_types {
			return error('handshake: duplicate extension type 0x${typ:04x} in extensions block')
		}
		seen_types << typ
		out << WireExtension{
			typ:  typ
			data: data
		}
	}
	return out
}

// read_handshake_header reads the 4-byte handshake header from a reader.
// Pub so adapters can dispatch post-handshake messages through the core's framing.
pub fn read_handshake_header(mut r wire.Reader) !(HandshakeType, int) {
	if r.remaining() < 4 {
		return error('handshake: message header truncated')
	}
	raw_type := r.read_u8()!
	typ := handshake_type_from_u8(raw_type)!
	length := int(r.read_u24()!)
	return typ, length
}

// split_handshake_message splits a full handshake message into its header and body.
@[direct_array_access]
fn split_handshake_message(full_msg []u8) !(HandshakeType, []u8) {
	mut r := wire.new_reader(full_msg)
	msg_type, length := read_handshake_header(mut r)!
	if r.remaining() != length {
		return error('handshake: handshake message header declares ${length} body bytes, message carries ${r.remaining()}')
	}
	return msg_type, r.read_bytes(length)!
}

// PskKeyExchangeMode names the PSK key-exchange modes (RFC 8446 §4.2.9).
pub enum PskKeyExchangeMode as u8 {
	psk_ke     = 0 // PSK only, no (EC)DHE (no forward secrecy)
	psk_dhe_ke = 1 // PSK with (EC)DHE (forward secrecy)
}

// supported_psk_key_exchange_modes is the mode list this client offers:
// psk_dhe_ke only, so every PSK handshake keeps forward secrecy.
pub const supported_psk_key_exchange_modes = [PskKeyExchangeMode.psk_dhe_ke]

// PskIdentity is one offered PSK: an opaque ticket (the identity) and its
// obfuscated ticket age (ticket_age_add + age mod 2^32) (RFC 8446 §4.2.11).
pub struct PskIdentity {
mut:
	identity              []u8 // opaque PSK identity (a NewSessionTicket's ticket bytes)
	obfuscated_ticket_age u32  // ticket_age_add + age (mod 2^32), obfuscating real age
}

// Psk is a usable pre-shared key: the identity presented on the wire plus the
// key material both sides use to derive binders and the Early Secret (RFC 8446
// §7.1).
pub struct Psk {
pub mut:
	identity []u8 // opaque PSK identity (ticket bytes, sent in the ClientHello)
	key      []u8 // PSK key material (known to both client and server)
	// obfuscated_ticket_age is the ticket_age_add-obfuscated age sent for a
	// resumption PSK (RFC 8446 §4.2.11); zero is valid for a freshly issued ticket.
	obfuscated_ticket_age u32
	// external selects the "ext binder" label over the resumption default
	// "res binder" (RFC 8446 §7.1); importers of externally provisioned PSKs set it.
	external bool
	// hash_algo is the single Hash associated with this PSK (RFC 8446 §4.2.11).
	// For resumption PSKs it is the ticket connection's KDF hash; external PSKs
	// default to SHA-256 when no hash was provisioned, which is the enum zero value.
	hash_algo HashAlgorithm
}

// PskBinderEntry is one PSK binder: an HMAC over the finished binder key and the
// truncated ClientHello transcript hash (RFC 8446 §4.2.11).
pub struct PskBinderEntry {
mut:
	binder []u8
}

// build_psk_key_exchange_modes_extension encodes the psk_key_exchange_modes
// extension (RFC 8446 §4.2.9): a u8-length vector of modes.
fn build_psk_key_exchange_modes_extension() ![]u8 {
	mut body := wire.new_writer(1 + 3)
	mut modes := wire.new_writer(2)
	for m in supported_psk_key_exchange_modes {
		modes.write_u8(u8(m))
	}
	body.write_vector_u8(modes.bytes())!
	return body.bytes()
}

// build_pre_shared_key_identities encodes the identities vector of the
// pre_shared_key extension (RFC 8446 §4.2.11), including its u16 length prefix.
fn build_pre_shared_key_identities(identities []PskIdentity) ![]u8 {
	mut entries := wire.new_writer(64)
	for id in identities {
		entries.write_vector_u16(id.identity)!
		entries.write_u32(id.obfuscated_ticket_age)
	}
	mut out := wire.new_writer(entries.len() + 2)
	out.write_vector_u16(entries.bytes())!
	return out.bytes()
}

// build_pre_shared_key_binders encodes the binders vector of the
// pre_shared_key extension (RFC 8446 §4.2.11), including its u16 length prefix.
// Each PskBinderEntry is an opaque<32..255>, so its own length is one byte.
fn build_pre_shared_key_binders(binders []PskBinderEntry) ![]u8 {
	mut entries := wire.new_writer(64)
	for b in binders {
		entries.write_vector_u8(b.binder)!
	}
	mut out := wire.new_writer(entries.len() + 2)
	out.write_vector_u16(entries.bytes())!
	return out.bytes()
}

// build_pre_shared_key_extension encodes the pre_shared_key extension body
// (RFC 8446 §4.2.11): a u16-length vector of identities followed by a u16-length
// vector of binders. Binders may be empty placeholders to be filled later.
fn build_pre_shared_key_extension(identities []PskIdentity, binders []PskBinderEntry) ![]u8 {
	if identities.len != binders.len {
		return error('handshake: pre_shared_key has ${identities.len} identities but ${binders.len} binders')
	}
	ids := build_pre_shared_key_identities(identities)!
	binds := build_pre_shared_key_binders(binders)!
	mut body := wire.new_writer(ids.len + binds.len)
	body.write_bytes(ids)
	body.write_bytes(binds)
	return body.bytes()
}

// parse_server_selected_psk decodes the pre_shared_key extension body from a
// ServerHello: exactly one u16 selected identity index (RFC 8446 §4.2.11).
fn parse_server_selected_psk(ext_data []u8) !u16 {
	mut r := wire.new_reader(ext_data)
	selected := r.read_u16()!
	if r.remaining() != 0 {
		return error('handshake: trailing bytes in ServerHello pre_shared_key extension')
	}
	return selected
}
