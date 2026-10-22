// Copyright (c) 2026 blackshirt.
//
// QUIC Initial packet protection key derivation (RFC 9001 §5.2).
module quic

import crypto.hmac
import crypto.sha256
import tls.handshake

// initial_salt_v1 is the QUIC v1 Initial salt (RFC 9001 §5.2).
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

// Initial level uses AES-128-GCM (RFC 9001 §5.2).
const initial_key_len = 16
const initial_iv_len = 12

// initial_hkdf_extract does HKDF-Extract (SHA-256).
fn initial_hkdf_extract(salt []u8, ikm []u8) []u8 {
	effective_salt := if salt.len == 0 { []u8{len: 32} } else { salt }
	return hmac.new(effective_salt, ikm, sha256.sum256, 64)
}

// InitialKeys holds one direction's Initial protection material (RFC 9001 §5.2).
struct InitialKeys {
	key []u8
	iv  []u8
	hp  []u8
}

// derive_initial_keys derives (client, server) Initial keys from client_dcid (RFC 9001 §5.2).
fn derive_initial_keys(client_dcid []u8) !(InitialKeys, InitialKeys) {
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

// expand_initial expands one Initial secret (RFC 9001 §5.1).
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
