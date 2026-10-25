// Copyright (c) 2026 blackshirt.
//
// Adversarial ECDHE key-share tests: compute_shared_secret must reject peer
// shares that would hand us a low-entropy or invalid shared secret —
// wrong sizes, the all-zero and small-order X25519 results (RFC 7748 §6.1),
// and compressed P-256 points (RFC 8446 §4.2.8.2).
module handshake

import crypto.subtle
import tls.pki
import x.crypto.curve25519

// empty_store_validator builds a Validator over an empty trust store; none of
// these tests reach chain verification. V compiles each _test.v file on its own,
// so this file carries its own fixture instead of reaching into a sibling suite.
fn empty_store_validator() pki.Validator {
	return pki.new_validator(pki.new_trust_store())
}

// core_with_group builds a HandshakeCore whose ephemeral share lives on the
// requested group — the exact precondition compute_shared_secret checks.
fn core_with_group(group NamedGroup) !HandshakeCore {
	return new_handshake_core('example.com', HandshakeOptions{
		validator:       empty_store_validator()
		key_share_group: group
	}, false)
}

// test_rejects_all_zero_x25519_share checks the §4.2.8.2 pre-backend gate: an
// all-zero peer u-coordinate would yield an all-zero secret and must surface as
// illegal_parameter, not a backend result.
fn test_rejects_all_zero_x25519_share() ! {
	mut h := core_with_group(.x25519)!
	mut rejected := false
	h.compute_shared_secret(KeyShareEntry{
		group:        .x25519
		key_exchange: []u8{len: 32, init: 0x00}
	}) or {
		assert err.msg().contains('all-zero')
		assert h.fail_alert == .illegal_parameter
		rejected = true
	}
	assert rejected, 'an all-zero X25519 share must be rejected'
}

// test_rejects_small_order_x25519_shares checks the RFC 7748 §6.1 results:
// peer u = 1 and u = p drive any private key to a constant secret, so both must
// be rejected even though the backend computes them without error. The shares
// are built in the little-endian wire order X25519 itself uses.
fn test_rejects_small_order_x25519_shares() ! {
	mut u_one := []u8{len: 32} // u = 1 -> the shared secret is 1
	u_one[0] = 1
	mut u_p := []u8{len: 32, init: 0xff} // u = 2^255-19, which reduces to 0 mod p
	u_p[0] = 0xed
	u_p[31] = 0x7f
	peers := [u_one, u_p]
	mut rejections := 0
	for share in peers {
		// A classified key_share rejection is terminal: classify_failure releases the
		// ephemeral private key (RFC 8446 §7.5), so each peer share must be exercised
		// against a fresh core rather than a torn-down one.
		mut h := core_with_group(.x25519)!
		mut rejected := false
		h.compute_shared_secret(KeyShareEntry{
			group:        .x25519
			key_exchange: share
		}) or {
			// u = 1 lands on the pinned small-order result; u = p is refused inside the
			// backend's scalar multiplication, which compute_shared_secret also
			// classifies as small-order. Both must pin the same alert.
			assert err.msg().contains('small-order')
			assert h.fail_alert == .illegal_parameter
			rejected = true
		}
		assert rejected, 'a small-order X25519 share must be rejected'
		if rejected {
			rejections += 1
		}
	}
	assert rejections == peers.len
}

// test_rejects_wrong_size_key_shares pins the §4.2.8.2 size gate ahead of any
// cryptographic processing.
fn test_rejects_wrong_size_key_shares() ! {
	mut h := core_with_group(.x25519)!
	mut rejected := false
	h.compute_shared_secret(KeyShareEntry{
		group:        .x25519
		key_exchange: [u8(0xaa)]
	}) or {
		assert err.msg().contains('expected 32')
		assert h.fail_alert == .illegal_parameter
		rejected = true
	}
	assert rejected, 'a mis-sized X25519 share must be rejected'

	mut h2 := core_with_group(.secp256r1)!
	rejected = false
	h2.compute_shared_secret(KeyShareEntry{
		group:        .secp256r1
		key_exchange: []u8{len: 64, init: 0x04}
	}) or {
		assert err.msg().contains('expected 65')
		assert h2.fail_alert == .illegal_parameter
		rejected = true
	}
	assert rejected, 'a mis-sized P-256 share must be rejected'
}

// test_rejects_compressed_p256_share checks that only the uncompressed 0x04
// encoding is accepted (§4.2.8.2); 0x02/0x03 compressed points are refused
// before point decoding.
fn test_rejects_compressed_p256_share() ! {
	mut h := core_with_group(.secp256r1)!
	prefixes := [u8(0x02), 0x03]
	for i in 0 .. prefixes.len {
		mut share := [prefixes[i]]
		for _ in 0 .. 64 { // the 64 affine coordinates that follow the encoding prefix
			share << u8(0x11)
		}
		assert share.len == 65, 'a compressed share must be 1+64 bytes, or the size gate fires first'
		mut rejected := false
		h.compute_shared_secret(KeyShareEntry{
			group:        .secp256r1
			key_exchange: share
		}) or {
			assert err.msg().contains('uncompressed point')
			assert h.fail_alert == .illegal_parameter
			rejected = true
		}
		assert rejected, 'a compressed P-256 share (0x${prefixes[i]:02x}) must be refused'
	}
}

// test_rejects_invalid_uncompressed_p256_share checks that a correctly sized,
// uncompressed encoding of an off-curve point is treated as a peer error.
fn test_rejects_invalid_uncompressed_p256_share() ! {
	mut h := core_with_group(.secp256r1)!
	mut share := []u8{len: 65, init: 0}
	share[0] = 0x04
	mut rejected := false
	h.compute_shared_secret(KeyShareEntry{
		group:        .secp256r1
		key_exchange: share
	}) or {
		assert h.fail_alert == .illegal_parameter
		rejected = true
	}
	assert rejected, 'an off-curve P-256 share must be rejected'
}

// test_valid_x25519_share_is_accepted guards against an over-tight rejection:
// a genuine random peer share must produce its matching shared secret.
fn test_valid_x25519_share_is_accepted() ! {
	mut h := core_with_group(.x25519)!
	peer := curve25519.PrivateKey.new()!
	peer_pub := peer.public_key()!
	share := peer_pub.bytes()!
	secret := h.compute_shared_secret(KeyShareEntry{
		group:        .x25519
		key_exchange: share
	})!
	own_pub := h.priv_x25519.public_key()!
	own_pub_bytes := own_pub.bytes()!
	expected := peer.x25519(own_pub_bytes)!
	assert subtle.constant_time_compare(secret, expected) == 1
}
