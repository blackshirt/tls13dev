// Copyright (c) 2026 blackshirt.
//
// rfc9001_test.v checks the packet layer against the RFC 9001 Appendix A test
// vectors. These are the ground truth for QUIC v1 Initial key derivation and
// packet protection: if the engine derives the same keys and reproduces the
// same protected packet bytes, the HMAC/HKDF/AEAD/header-protection wiring is
// byte-correct, independent of any handshake.
module quic

import encoding.hex

// The RFC 9001 Appendix A.1 client Destination Connection ID.
const app_a_dcid_hex = '8394c8f03e515708'

fn test_initial_key_derivation_appendix_a1() ! {
	dcid := hex.decode(app_a_dcid_hex)!
	ck, sk := derive_initial_keys(dcid)!

	// RFC 9001 Appendix A.1 expected material.
	assert hex.encode(ck.key) == '1f369613dd76d5467730efcbe3b1a22d'
	assert hex.encode(ck.iv) == 'fa044b2f42a3fd3b46fb255c'
	assert hex.encode(ck.hp) == '9f50449e04a0e810283a1e9933adedd2'

	assert hex.encode(sk.key) == 'cf3a5331653c364c88f0f379b6067e37'
	assert hex.encode(sk.iv) == '0ac1493ca1905853b0bba03e'
	assert hex.encode(sk.hp) == 'c206b8d9b9f0f37644430b490eeaa314'
}

fn test_varint_roundtrip_and_bounds() ! {
	cases := [u64(0), 1, 63, 64, 16383, 16384, 1073741823, 1073741824, max_varint]
	for v in cases {
		enc := encode_varint(v)!
		assert enc.len == varint_len(v)
		dec, n := decode_varint(enc)!
		assert dec == v
		assert n == enc.len
	}
	// 2-bit prefix selects the field width (RFC 9000 §16).
	assert encode_varint(37)! == [u8(0x25)]
	assert encode_varint(15293)! == [u8(0x7b), 0xbd]
	assert encode_varint(494878333)! == [u8(0x9d), 0x7f, 0x3e, 0x7d]
	assert encode_varint(151288809941952652)! == [
		u8(0xc2),
		0x19,
		0x7c,
		0x5e,
		0xff,
		0x14,
		0xe8,
		0x8c,
	]
}

fn test_packet_number_encoding_and_decoding() {
	// RFC 9000 Appendix A.3: a truncated 2-byte value 0x9b32 at
	// largest_pn 0xa82f30ea reconstructs to 0xa82f9b32.
	pn := decode_packet_number(0x9b32, 2, 0xa82f30ea)
	assert pn == 0xa82f9b32

	// Shortest encoding: the difference must fit in one fewer than the byte
	// count's bits.
	assert packet_number_len(0, 0) == 1
	assert packet_number_len(127, 0) == 1
	assert packet_number_len(128, 0) == 2
	assert packet_number_len(32767, 0) == 2
	assert packet_number_len(32768, 0) == 3

	enc := encode_packet_number(0xac5c, 2)!
	assert enc == [u8(0xac), 0x5c]
}

fn test_long_header_build_and_parse_roundtrip() ! {
	dcid := hex.decode('8394c8f03e515708')!
	scid := hex.decode('0102030405060708')!
	// A 30-byte payload, PN length 2, no tag (framing-only roundtrip).
	header, pn_off := build_long_header(.initial, quic_version_1, dcid, scid, []u8{}, 30, 2, 0)!
	assert pn_off == header.len
	// First byte: long form | fixed bit | Initial type (0) | pn_len-1 (1).
	assert header[0] == (long_header_form | fixed_bit | 0x01)
	// Version is big-endian 0x00000001.
	assert header[1..5] == [u8(0x00), 0x00, 0x00, 0x01]

	// The parser recovers the same framing from the prefix + a fake PN/payload.
	mut packet := header.clone()
	packet << [u8(0x00), 0x00] // placeholder PN
	packet << []u8{len: 30} // placeholder payload
	meta := long_packet_meta(packet)!
	assert meta.ptype == .initial
	assert meta.version == quic_version_1
	assert meta.dcid == dcid
	assert meta.scid == scid
	assert meta.pn_offset == pn_off
	// total = prefix + length (PN + payload).
	assert meta.total_len == pn_off + 2 + 30
}

fn test_varint_field_rejects_out_of_bounds_lengths() ! {
	// Maximal 8-byte varint lengths must be rejected before integer conversion
	// or slice arithmetic can overflow.
	if _, _ := read_varint_field([u8(0)], -1) {
		assert false
	}

	mut initial := [u8(0xc0), 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]
	initial << [u8(0xff), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
	if _ := long_packet_meta(initial) {
		assert false
	}

	mut handshake := [u8(0xe0), 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]
	handshake << [u8(0xff), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
	if _ := long_packet_meta(handshake) {
		assert false
	}
}

fn test_seal_open_roundtrip_initial() ! {
	dcid := hex.decode(app_a_dcid_hex)!
	ck, _ := derive_initial_keys(dcid)!
	// A packet the client sends is protected with the client's Initial keys, and
	// the peer that receives it unprotects with those *same* client keys
	// (RFC 9001 §5.1: protection keys are per-direction, not per-endpoint).
	mut sender := new_initial_protection(ck)!
	mut receiver := new_initial_protection(ck)!

	payload := 'hello quic crypto frame'.bytes()
	header, _ := build_long_header(.initial, quic_version_1, dcid, []u8{len: 8}, []u8{},
		payload.len, 1, sender.overhead())!
	packet := sender.seal_packet(header, 0, 1, payload)!

	// The receiver removes header protection, reads the packet number, and
	// decrypts; the sample offset depends only on the fixed prefix length.
	mut rx := packet.clone()
	pn_offset := header.len
	pn_len := receiver.unprotect(mut rx, pn_offset)!
	assert pn_len == 1
	truncated := read_truncated_pn(rx, pn_offset, pn_len)
	assert truncated == 0
	opened := receiver.decrypt_payload(rx, pn_offset, pn_len, 0)!
	assert opened == payload
}

// RFC 9001 Appendix A.5: AEAD_CHACHA20_POLY1305 short-header packet material.
const a5_key_hex = 'c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8'

const a5_iv_hex = 'e0459b3474bdd0e44a41c144'

const a5_hp_hex = '25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4'

const a5_sample_hex = '5e5cd55c41f69080575d7999c25a5bfb'

// new_a5_protection builds the Appendix A.5 ChaCha20-Poly1305 protection state from the
// fixture key, IV and header-protection constant above; every test that needs A.5 material
// reads it through this one constructor, so a typo cannot desynchronize two of them.
fn new_a5_protection() !ProtectionState {
	return new_protection(ProtectionKeys{
		key: hex.decode(a5_key_hex)!
		iv:  hex.decode(a5_iv_hex)!
		hp:  hex.decode(a5_hp_hex)!
	}, .tls_chacha20_poly1305_sha256)
}

fn test_chacha20_header_protection_mask_appendix_a5() ! {
	state := new_a5_protection()!
	// RFC 9001 §5.4.4: counter = sample[0..3] (little-endian), nonce =
	// sample[4..15], mask = ChaCha20 over five zero bytes.
	mask := state.compute_mask(hex.decode(a5_sample_hex)!)!
	assert hex.encode(mask) == 'aefefe7d03'
}

fn test_chacha20_short_header_packet_appendix_a5() ! {
	mut state := new_a5_protection()!
	// pn 654360564 on 3 bytes, a single PING frame: the AAD is the unprotected
	// header 4200bff4 and the whole packet is 21 bytes (RFC 9001 §5.3/§5.4.2).
	packet := state.seal_packet([u8(0x42)], 654360564, 3, [u8(0x01)])!
	assert hex.encode(packet) == '4cfe4189655e5cd55c41f69080575d7999c25a5bfb'
}

// test_protection_state_wipe_clears_keys checks that wipe zeroes the nonce base and
// header-protection key so a closed engine leaves no packet key material behind
// (RFC 8446 §7.5, RFC 9001 §4.9.2), and that a second wipe is a safe no-op.
fn test_protection_state_wipe_clears_keys() ! {
	mut state := new_a5_protection()!
	state.wipe()
	assert state.iv.len == 0
	assert state.hp.len == 0
	state.wipe()
	assert state.iv.len == 0
}
