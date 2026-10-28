// Copyright (c) 2026 blackshirt.
//
// varint.v implements the QUIC variable-length integer codec (RFC 9000 §16): a
// 2-bit prefix selects a 1-, 2-, 4- or 8-byte field, capped at 2^62-1. It is the
// module's only integer encoding, shared by packets, frames and transport params.
module quic

// max_varint is the largest representable value, 2^62-1 (RFC 9000 §16).
const max_varint = u64(1 << 62) - 1

// varint_len returns the smallest 1/2/4/8-byte form for `v`, or 0 when `v`
// exceeds max_varint and therefore has no encoding (RFC 9000 §16).
fn varint_len(v u64) int {
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

// encode_varint writes `v` in the shortest form that fits, recording the field
// width in the two most-significant bits of the first byte (RFC 9000 §16).
fn encode_varint(v u64) ![]u8 {
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

// decode_varint reads the one varint at the front of `buf`, returning its value
// and the number of bytes it occupied (RFC 9000 §16). It checks only the width
// promised by the 2-bit prefix and does not re-derive the shortest form, so a
// non-minimal encoding decodes rather than failing; callers that compare decoded
// values (rather than raw bytes) are unaffected by that malleability.
fn decode_varint(buf []u8) !(u64, int) {
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
