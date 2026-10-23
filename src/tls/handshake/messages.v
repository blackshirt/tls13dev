// Copyright (c) 2026 blackshirt.
//
// messages.v owns shared RFC 8446 §4 handshake framing primitives and extension
// block decoding. Message-family codecs live in client_hello.v, server_hello.v,
// server_flight.v and post_handshake.v.
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

// CipherSuite defines TLS 1.3 cipher suites (RFC 8446 §B.4).
pub enum CipherSuite as u16 {
	tls_aes_128_gcm_sha256       = 0x1301
	tls_aes_256_gcm_sha384       = 0x1302
	tls_chacha20_poly1305_sha256 = 0x1303
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

fn split_handshake_message(full_msg []u8) !(HandshakeType, []u8) {
	mut r := wire.new_reader(full_msg)
	msg_type, length := parse_handshake_header(mut r)!
	if r.remaining() != length {
		return error('handshake: handshake message header declares ${length} body bytes, message carries ${r.remaining()}')
	}
	return msg_type, r.read_bytes(length)!
}
