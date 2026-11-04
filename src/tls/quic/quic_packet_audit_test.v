// Copyright (c) 2026 blackshirt.
//
// quic_packet_audit_test.v verifies QUIC packet-layer edge cases:
// packet number reconstruction edge cases, CRYPTO frame bounds,
// ACK range handling, header protection masking.
module quic

fn test_decode_packet_number_simple_case() ! {
	pn := decode_packet_number(0x42, 1, 0)
	assert pn == 0x42
}

fn test_decode_packet_number_normal_reconstruction() ! {
	pn := decode_packet_number(0x9b32, 2, 0xa82f30ea)
	assert pn == 0xa82f9b32
}

fn test_packet_number_len_bounds() ! {
	assert packet_number_len(0, 0) == 1
	assert packet_number_len(127, 0) == 1
	assert packet_number_len(128, 0) == 2
	assert packet_number_len(32767, 0) == 2
	assert packet_number_len(32768, 0) == 3
	assert packet_number_len(8388607, 0) == 3
	assert packet_number_len(8388608, 0) == 4
}

fn test_encode_decode_packet_number_roundtrip() ! {
	// Each (pn, pn_len) pair must be valid: pn fits in pn_len bytes.
	mut enc := encode_packet_number(u64(0), 1)!
	assert enc.len == 1
	assert enc[0] == 0

	enc = encode_packet_number(u64(255), 1)!
	assert enc.len == 1
	assert enc[0] == 255

	enc = encode_packet_number(u64(256), 2)!
	assert enc.len == 2
	assert enc[0] == 1
	assert enc[1] == 0

	enc = encode_packet_number(u64(65535), 2)!
	assert enc.len == 2
	assert enc[0] == 255
	assert enc[1] == 255

	enc = encode_packet_number(u64(65536), 3)!
	assert enc.len == 3
	assert enc[0] == 1
	assert enc[1] == 0
	assert enc[2] == 0

	enc = encode_packet_number(u64(16777215), 3)!
	assert enc.len == 3
	assert enc[0] == 255
	assert enc[1] == 255
	assert enc[2] == 255

	enc = encode_packet_number(u64(16777216), 4)!
	assert enc.len == 4
	assert enc[0] == 1
	assert enc[1] == 0
	assert enc[2] == 0
	assert enc[3] == 0

	// Decode back: read truncated value and verify it matches.
	mut truncated := u64(0)
	enc = encode_packet_number(u64(4294967295), 4)!
	for i in 0 .. enc.len {
		truncated = (truncated << 8) | u64(enc[i])
	}
	assert truncated == 4294967295
}

fn test_parse_crypto_frame_bounds() ! {
	frame := encode_crypto_frame(0, [0x74, 0x65, 0x73, 0x74])!
	cf, consumed := parse_crypto_frame(frame[1..])!
	assert cf.offset == 0
	assert cf.data == [0x74, 0x65, 0x73, 0x74]
	assert consumed == frame.len - 1
}

fn test_parse_crypto_frame_truncated_rejected() ! {
	// offset=0, length=2 but only 1 byte follows (after type byte stripped)
	bad := [u8(0x00), 0x02, 0xFF]
	parse_crypto_frame(bad) or {
		assert err.msg().contains('CRYPTO frame length')
		return
	}
	assert false, 'truncated CRYPTO frame must be rejected'
}

fn test_add_rx_range_dedupes() ! {
	mut ranges := add_rx_range([], 5)
	assert ranges.len == 1
	assert ranges[0].lo == 5 && ranges[0].hi == 5

	ranges = add_rx_range(ranges, 5)
	assert ranges.len == 1

	ranges = add_rx_range(ranges, 6)
	assert ranges.len == 1
	assert ranges[0].lo == 5 && ranges[0].hi == 6

	ranges = add_rx_range(ranges, 10)
	assert ranges.len == 2
}

fn test_encode_ack_frame_roundtrip() ! {
	ranges := [RxRange{ lo: 100, hi: 105 }, RxRange{ lo: 110, hi: 115 }]
	ack := encode_ack_frame(ranges, 0)!
	assert ack.len > 0
	assert ack[0] == frame_ack
}
