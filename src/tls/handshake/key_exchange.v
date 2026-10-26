// Copyright (c) 2026 blackshirt.
//
// key_exchange.v owns the client's ephemeral ECDHE key material and the shared
// secret computation for X25519 and P-256 (RFC 8446 §4.2.8).
module handshake

import crypto.ecdsa
import crypto.subtle
import x.crypto.curve25519

// generate_key_share creates a fresh ephemeral private key for the requested group.
fn (mut h HandshakeCore) generate_key_share(group NamedGroup) ! {
	h.ecdhe_group = group
	// Only the key for the selected group stays live.
	h.priv_x25519 = unsafe { nil }
	h.priv_p256 = none
	match group {
		.x25519 {
			h.priv_x25519 = curve25519.PrivateKey.new()!
		}
		.secp256r1 {
			h.priv_p256 = ecdsa.PrivateKey.new(nid: .prime256v1)!
		}
	}
}

// public_share_bytes serializes the public half of the current ephemeral key in
// the wire form its group mandates (RFC 8446 §4.2.8.2).
fn (mut h HandshakeCore) public_share_bytes() ![]u8 {
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

// The three small-order X25519 shared-secret results of RFC 7748 §6.1, in the
// little-endian wire encoding: the identity, u = 1, and u = p-1 = 2^255-20.
const x25519_secret_zero = [u8(0), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

const x25519_secret_one = [u8(1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

const x25519_secret_p_minus_1 = [u8(0xec), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]

// is_x25519_small_order reports whether a finished X25519 shared secret landed
// in one of the three small-order results (RFC 7748 §6.1); reject all three.
@[direct_array_access]
fn is_x25519_small_order(secret []u8) bool {
	if subtle.constant_time_compare(secret, x25519_secret_zero) == 1 {
		return true
	}
	if subtle.constant_time_compare(secret, x25519_secret_one) == 1 {
		return true
	}
	return subtle.constant_time_compare(secret, x25519_secret_p_minus_1) == 1
}

// expected_share_len is the §4.2.8.2 key_exchange size per group (x25519 32;
// secp256r1 65 = 0x04||X||Y): one source for the peer gate and ClientHello builder.
fn expected_share_len(g NamedGroup) int {
	return match g {
		.x25519 { 32 }
		.secp256r1 { 65 }
	}
}

// compute_shared_secret performs the ECDHE exchange against the server's key
// share, returning the raw shared secret that seeds the key schedule.
fn (mut h HandshakeCore) compute_shared_secret(server_share KeyShareEntry) ![]u8 {
	// §4.2.8.2 fixes key_exchange size per group; gate it here so a wrong size yields a named protocol error.
	expected_len := expected_share_len(server_share.group)
	if server_share.key_exchange.len != expected_len {
		return h.classify_failure(.illegal_parameter, 'handshake: ${server_share.group} key_share is ${server_share.key_exchange.len} bytes, expected ${expected_len}')
	}
	match server_share.group {
		.x25519 {
			if h.priv_x25519 == unsafe { nil } {
				return error('handshake: missing X25519 private key')
			}
			// §4.2.8.2 & RFC 7748 §6.1: an all-zero peer u-coordinate would yield an all-zero secret; gate before the backend.
			if subtle.constant_time_compare(server_share.key_exchange, []u8{len: 32, init: 0}) == 1 {
				return h.classify_failure(.illegal_parameter, 'handshake: computed X25519 shared secret is all-zero value (illegal_parameter)')
			}
			// The backend runs its own low-order and zero-result checks, so a
			// small-order contribution can fail inside the scalar multiplication and
			// never reach the result comparison below. Classify every failure of this
			// exchange as the peer's fault: RFC 8446 §4.2.8.2 makes a bad key_share
			// illegal_parameter, and pinning it keeps the sent alert off internal_error.
			secret := h.priv_x25519.x25519(server_share.key_exchange) or {
				return h.classify_failure(.illegal_parameter, 'handshake: X25519 key_share is a small-order contribution (illegal_parameter)')
			}
			// Defense in depth: reject every small-order result, not just the all-zero one.
			if is_x25519_small_order(secret) {
				return h.classify_failure(.illegal_parameter, 'handshake: computed X25519 shared secret is a small-order value (illegal_parameter)')
			}
			return secret
		}
		.secp256r1 {
			// Only the uncompressed encoding is legal in TLS 1.3 (§4.2.8.2); compressed shares start 0x02/0x03.
			// A malformed share is the sender's fault, so it must pin the alert.
			if server_share.key_exchange[0] != 0x04 {
				return h.classify_failure(.illegal_parameter, 'handshake: P-256 key_share is not an uncompressed point (0x04 prefix)')
			}
			// 0x04 || 0^32 || 0^32 encodes the point at infinity: the exchange would
			// contribute nothing to the secret. Reject the identity encoding itself,
			// deterministically, instead of trusting the backend to refuse it.
			if subtle.constant_time_compare(server_share.key_exchange[1..server_share.key_exchange.len],
				[]u8{len: 64, init: 0}) == 1 {
				return h.classify_failure(.illegal_parameter, 'handshake: P-256 key_share is the point at infinity (illegal_parameter)')
			}
			priv := h.priv_p256 or { return error('handshake: missing P-256 private key') }
			// A point that does not decode is the sender's fault too, so pin the alert
			// instead of letting a backend message surface as internal_error.
			peer := ecdsa.PublicKey.from_uncompressed_bytes(server_share.key_exchange,
				nid: .prime256v1
			) or {
				return h.classify_failure(.illegal_parameter, 'handshake: P-256 key_share is not a valid uncompressed point on the curve (illegal_parameter)')
			}
			secret := priv.derive_shared_secret(peer) or {
				return h.classify_failure(.internal_error, 'handshake: P-256 ECDH operation failed')
			}
			if subtle.constant_time_compare(secret, []u8{len: secret.len, init: 0}) == 1 {
				return h.classify_failure(.illegal_parameter, 'handshake: computed P-256 shared secret is all-zero value (illegal_parameter)')
			}
			return secret
		}
	}
	// Unreachable: the match above is exhaustive over NamedGroup.
	return error('handshake: unsupported key_share group ${server_share.group}')
}
