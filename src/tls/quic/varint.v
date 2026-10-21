// Copyright (c) 2026 blackshirt.
//
// varint.v implements the QUIC variable-length integer encoding (RFC 9000 §16):
// the two most significant bits of the first byte select a 1, 2, 4, or 8-byte
// field, leaving 6, 14, 30, or 62 value bits. Packet numbers, frame lengths,
// stream offsets and connection IDs' lengths all use it.
module quic

// max_varint is the largest value a QUIC varint can carry: 2^62 - 1, the 62
// value bits of the 8-byte form (RFC 9000 §16).
pub const max_varint = u64(1 << 62) - 1

// varint_len returns how many bytes encode v: the smallest of 1/2/4/8 that fits
// (RFC 9000 §16). Values above max_varint cannot be encoded and report 0.
pub fn varint_len(v u64) int {
	if v > max_varint {
		return 0
	}
	if v < (1 << 6) {
		return 1
	}
	if v < (1 << 14) {
		return 2
	}
	if v < (1 << 30) {
		return 4
	}
	return 8
}

// encode_varint writes v in its shortest QUIC varint form (RFC 9000 §16).
pub fn encode_varint(v u64) ![]u8 {
	n := varint_len(v)
	return match n {
		1 { [u8(v)] }
		2 { [u8(v >> 8) | 0x40, u8(v & 0xff)] }
		4 {
			[
				u8(v >> 24) | 0x80,
				u8((v >> 16) & 0xff),
				u8((v >> 8) & 0xff),
				u8(v & 0xff),
			]
		}
		8 {
			[
				u8(v >> 56) | 0xc0,
				u8((v >> 48) & 0xff),
				u8((v >> 40) & 0xff),
				u8((v >> 32) & 0xff),
				u8((v >> 24) & 0xff),
				u8((v >> 16) & 0xff),
				u8((v >> 8) & 0xff),
				u8(v & 0xff),
			]
		}
		else { return error('quic: varint value ${v} exceeds 2^62-1') }
	}
}

// decode_varint reads one varint from the front of buf and returns (value,
// bytes_consumed) (RFC 9000 §16). It errors on an empty buffer; a truncated
// multi-byte field makes it read past the end, which is caught by the length
// check.
pub fn decode_varint(buf []u8) !(u64, int) {
	if buf.len == 0 {
		return error('quic: varint decode on empty buffer')
	}
	len := 1 << (buf[0] >> 6)
	if buf.len < len {
		return error('quic: truncated ${len}-byte varint (${buf.len} bytes available)')
	}
	mut v := u64(buf[0] & 0x3f)
	for i in 1 .. len {
		v = (v << 8) | u64(buf[i])
	}
	return v, len
}
