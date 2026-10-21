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
