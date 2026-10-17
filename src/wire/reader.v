// Copyright (c) 2026 blackshirt.
// SPDX-License-Identifier: MIT
//
// module wire provides the byte-level primitives every other module parses
// through: reader.v is a bounds-checked cursor over a message body, writer.v
// assembles length-prefixed structures. There is no TLS semantics here, only
// framing arithmetic; every out-of-bounds or oversized access is an error.
module wire

// Reader is a bounds-checked cursor over TLS wire data.
// Every read validates its length first: parsers face hostile input and must
// reject truncation or malformed framing rather than panic (RFC 8446 §4).
pub struct Reader {
	data []u8 // buffer being parsed; never mutated, only walked
pub mut:
	cursor int // next unread byte; advanced only after a successful read
}

// new_reader initializes a Reader over the given byte slice.
pub fn new_reader(data []u8) Reader {
	return Reader{
		data:   data
		cursor: 0
	}
}

// remaining returns the number of unread bytes.
pub fn (r &Reader) remaining() int {
	rem := r.data.len - r.cursor
	return if rem > 0 { rem } else { 0 }
}

// has_remaining reports whether at least `n` bytes are left, so callers can
// validate framing before committing to a read.
fn (r &Reader) has_remaining(n int) bool {
	return n >= 0 && n <= r.data.len - r.cursor
}

// ensure checks that at least `n` bytes remain, so fixed-width accessors fail
// with a framing error instead of indexing out of bounds. `what` names the item.
fn (mut r Reader) ensure(n int, what string) ! {
	if n < 0 || n > r.data.len - r.cursor {
		return error('wire.Reader: unexpected EOF reading ${what}')
	}
}

// read_u8 reads a single 8-bit unsigned integer.
pub fn (mut r Reader) read_u8() !u8 {
	r.ensure(1, 'u8')!
	b := r.data[r.cursor]
	r.cursor++
	return b
}

// read_u16 reads a 16-bit big-endian unsigned integer (RFC 8446 §2).
pub fn (mut r Reader) read_u16() !u16 {
	r.ensure(2, 'u16')!
	v := (u16(r.data[r.cursor]) << 8) | u16(r.data[r.cursor + 1])
	r.cursor += 2
	return v
}

// read_u24 reads a 24-bit big-endian unsigned integer as u32.
// TLS has no native u24, but 24-bit lengths are pervasive (§4 handshake body
// length, §4.4.2 certificate vectors), so it gets its own accessor.
pub fn (mut r Reader) read_u24() !u32 {
	r.ensure(3, 'u24')!
	v := (u32(r.data[r.cursor]) << 16) | (u32(r.data[r.cursor + 1]) << 8) | u32(r.data[r.cursor + 2])
	r.cursor += 3
	return v
}

// read_u32 reads a 32-bit big-endian unsigned integer (RFC 8446 §2).
pub fn (mut r Reader) read_u32() !u32 {
	r.ensure(4, 'u32')!
	v := (u32(r.data[r.cursor]) << 24) | (u32(r.data[r.cursor + 1]) << 16) | (u32(r.data[r.cursor + 2]) << 8) | u32(r.data[r.cursor + 3])
	r.cursor += 4
	return v
}

// read_u64 reads a 64-bit big-endian unsigned integer.
fn (mut r Reader) read_u64() !u64 {
	r.ensure(8, 'u64')!
	v := (u64(r.data[r.cursor]) << 56) | (u64(r.data[r.cursor + 1]) << 48) | (u64(r.data[r.cursor + 2]) << 40) | (u64(r.data[r.cursor + 3]) << 32) | (u64(r.data[r.cursor + 4]) << 24) | (u64(r.data[r.cursor + 5]) << 16) | (u64(r.data[r.cursor + 6]) << 8) | u64(r.data[r.cursor + 7])
	r.cursor += 8
	return v
}

// read_bytes reads exactly `n` bytes from the stream.
// The result is cloned, not a subslice: callers (e.g. record payloads) outlive
// this reader's buffer, and aliasing would let later reads overwrite it.
pub fn (mut r Reader) read_bytes(n int) ![]u8 {
	if n < 0 || n > r.data.len - r.cursor {
		return error('wire.Reader: unexpected EOF reading ${n} bytes (only ${r.remaining()} available)')
	}
	slice := r.data[r.cursor..r.cursor + n].clone()
	r.cursor += n
	return slice
}

// The read_vector_* methods decode the `opaque T<V>` vector syntax of RFC 8446
// §3: a length prefix (V = 8, 16, or 24 bits) followed by that many bytes.

// read_vector_u8 reads a vector prefixed with a 1-byte length.
pub fn (mut r Reader) read_vector_u8() ![]u8 {
	len := int(r.read_u8()!)
	return r.read_bytes(len)
}

// read_vector_u16 reads a vector prefixed with a 2-byte big-endian length.
pub fn (mut r Reader) read_vector_u16() ![]u8 {
	len := int(r.read_u16()!)
	return r.read_bytes(len)
}

// read_vector_u24 reads a vector prefixed with a 3-byte big-endian length,
// used for certificate_list chains that can exceed a u16 prefix (§4.4.2).
pub fn (mut r Reader) read_vector_u24() ![]u8 {
	len := int(r.read_u24()!)
	return r.read_bytes(len)
}
