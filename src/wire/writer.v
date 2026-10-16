module wire

import encoding.binary

// Writer appends TLS wire data to an in-memory buffer.
// TLS fixes all multi-byte integers to network byte order (big-endian,
// RFC 8446 §2), so every fixed-width writer here emits big-endian bytes
// regardless of the host's native endianness.
pub struct Writer {
pub mut:
	buf []u8 // bytes accumulated for the frame currently being built
}

// new_writer creates a new Writer with an optional preallocated capacity.
// Preallocating the exact frame size (callers know it from the payload length)
// avoids repeated grow-and-copy while appending; capacity <= 0 falls back to a
// modest default so small alerts/handshakes don't start from a 0-length array.
pub fn new_writer(capacity int) Writer {
	cap_size := if capacity > 0 { capacity } else { 128 }
	return Writer{
		buf: []u8{cap: cap_size}
	}
}

// len returns the current number of bytes written.
pub fn (w &Writer) len() int {
	return w.buf.len
}

// bytes returns a copy of the written bytes.
pub fn (w &Writer) bytes() []u8 {
	return w.buf.clone()
}

// write_u8 appends a single 8-bit unsigned integer.
pub fn (mut w Writer) write_u8(v u8) {
	w.buf << v
}

// write_u16 appends a 16-bit big-endian unsigned integer.
pub fn (mut w Writer) write_u16(v u16) {
	mut b := []u8{len: 2}
	binary.big_endian_put_u16(mut b, v)
	w.buf << b
}

// write_u24 appends a 24-bit big-endian unsigned integer (lower 3 bytes of v).
// The upper byte of v is deliberately dropped: u24 fields in TLS can never
// legitimately exceed 0xffffff, and callers pass pre-validated lengths.
pub fn (mut w Writer) write_u24(v u32) {
	w.buf << u8((v >> 16) & 0xff)
	w.buf << u8((v >> 8) & 0xff)
	w.buf << u8(v & 0xff)
}

// write_u32 appends a 32-bit big-endian unsigned integer.
pub fn (mut w Writer) write_u32(v u32) {
	mut b := []u8{len: 4}
	binary.big_endian_put_u32(mut b, v)
	w.buf << b
}

// write_u64 appends a 64-bit big-endian unsigned integer.
pub fn (mut w Writer) write_u64(v u64) {
	mut b := []u8{len: 8}
	binary.big_endian_put_u64(mut b, v)
	w.buf << b
}

// write_bytes appends raw bytes to the buffer.
pub fn (mut w Writer) write_bytes(data []u8) {
	w.buf << data
}

// The write_vector_* methods produce the `opaque T<V>` vector framing of
// RFC 8446 §3 (length prefix + bytes) that the matching Reader::read_vector_*
// accessors expect, keeping encode/decode symmetric for every call site.
// Each one validates the length against its prefix width: silently truncating
// an oversized length would corrupt the frame and desync the peer's parser.

// write_vector_u8 appends a byte slice prefixed with its 1-byte length.
pub fn (mut w Writer) write_vector_u8(data []u8) ! {
	if data.len > 0xff {
		return error('wire.Writer: data length ${data.len} exceeds u8 max (255)')
	}
	w.write_u8(u8(data.len))
	w.write_bytes(data)
}

// write_vector_u16 appends a byte slice prefixed with its 2-byte big-endian length.
pub fn (mut w Writer) write_vector_u16(data []u8) ! {
	if data.len > 0xffff {
		return error('wire.Writer: data length ${data.len} exceeds u16 max (65535)')
	}
	w.write_u16(u16(data.len))
	w.write_bytes(data)
}

// write_vector_u24 appends a byte slice prefixed with its 3-byte big-endian length.
pub fn (mut w Writer) write_vector_u24(data []u8) ! {
	if data.len > 0xffffff {
		return error('wire.Writer: data length ${data.len} exceeds u24 max (16777215)')
	}
	w.write_u24(u32(data.len))
	w.write_bytes(data)
}
