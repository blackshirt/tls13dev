// Copyright (c) 2026 blackshirt.
//
// QUIC variable-length integer encoding (RFC 9000 §16).
module quic

// max_varint is 2^62-1 (RFC 9000 §16).
const max_varint = u64(1 << 62) - 1

// varint_len returns smallest 1/2/4/8-byte form; returns 0 if v > max_varint (RFC 9000 §16).
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

// encode_varint encodes v in shortest QUIC varint form (RFC 9000 §16).
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

// decode_varint reads one varint; returns (value, bytes_consumed) (RFC 9000 §16).
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
