// Copyright (c) 2026 blackshirt.
//
// initial_keys.v derives the QUIC Initial packet protection keys (RFC 9001
// §5.2). Unlike Handshake and 1-RTT keys, Initial keys do not come from the TLS
// key schedule — they are a fixed function of the client's original Destination
// Connection ID and the protocol's version salt, so any observer can compute
// them. They exist only to bootstrap the handshake.
//
//	initial_secret = HKDF-Extract(initial_salt, client_dcid)
//	client_in      = HKDF-Expand-Label(initial_secret, "client in", "", 32)
//	server_in      = HKDF-Expand-Label(initial_secret, "server in", "", 32)
//
// The per-direction packet key/iv/hp come from the same "quic key"/"quic iv"/
// "quic hp" expansions the engine applies at every level (§5.1); Initial always
// uses AES-128-GCM (SHA-256), so key and hp are 16 bytes and iv is 12.
module quic

import crypto.hmac
import crypto.sha256
import tls.handshake

// initial_salt_v1 is the QUIC version 1 Initial salt (RFC 9001 §5.2).
const initial_salt_v1 = [
	u8(0x38),
	0x76,
	0x2c,
	0xf7,
	0xf5,
	0x59,
	0x34,
	0xb3,
	0x4d,
	0x17,
	0x9a,
	0xe6,
	0xa4,
	0xc8,
	0x0c,
	0xad,
	0xcc,
	0xbb,
	0x7f,
	0x0a,
]

// initial_key_len and initial_iv_len are fixed for the Initial level: QUIC
// v1 mandates AES-128-GCM for Initial, so key/hp are 16 bytes and the nonce
// base is 12 (RFC 9001 §5.2).
const initial_key_len = 16
const initial_iv_len = 12

// initial_hkdf_extract runs HKDF-Extract over SHA-256 with the RFC 5869
// all-zero-salt default. The handshake module exposes HKDF-Expand-Label but not
// Extract, so the engine owns this one primitive for its transport-level keys.
fn initial_hkdf_extract(salt []u8, ikm []u8) []u8 {
	effective_salt := if salt.len == 0 { []u8{len: 32} } else { salt }
	return hmac.new(effective_salt, ikm, sha256.sum256, 64)
}

// InitialKeys holds one direction's Initial protection material: the AEAD
// packet key, the packet-number nonce base, and the header-protection key
// (RFC 9001 §5.2). The engine builds an AEAD from `key` and masks with `hp`.
pub struct InitialKeys {
pub:
	key []u8 // 16-byte AES-128-GCM key ("quic key")
	iv  []u8 // 12-byte packet-number nonce base ("quic iv")
	hp  []u8 // 16-byte header-protection key ("quic hp")
}

// derive_initial_keys computes the (client, server) Initial keys for the given
// Destination Connection ID (RFC 9001 §5.2). The DCID is the one the client put
// in its very first Initial packet; it never changes for the derivation even if
// the connection ID later does.
pub fn derive_initial_keys(client_dcid []u8) !(InitialKeys, InitialKeys) {
	if client_dcid.len == 0 {
		return error('quic: Initial key derivation needs a non-empty destination connection ID')
	}
	initial_secret := initial_hkdf_extract(initial_salt_v1, client_dcid)
	client_secret := handshake.hkdf_expand_label(.sha256, initial_secret, 'client in', []u8{},
		32)!
	server_secret := handshake.hkdf_expand_label(.sha256, initial_secret, 'server in', []u8{},
		32)!
	return expand_initial(client_secret)!, expand_initial(server_secret)!
}

// expand_initial performs the three RFC 9001 §5.1 expansions over one
// direction's initial secret.
fn expand_initial(secret []u8) !InitialKeys {
	key := handshake.hkdf_expand_label(.sha256, secret, 'quic key', []u8{}, initial_key_len)!
	iv := handshake.hkdf_expand_label(.sha256, secret, 'quic iv', []u8{}, initial_iv_len)!
	hp := handshake.hkdf_expand_label(.sha256, secret, 'quic hp', []u8{}, initial_key_len)!
	return InitialKeys{
		key: key
		iv:  iv
		hp:  hp
	}
}
