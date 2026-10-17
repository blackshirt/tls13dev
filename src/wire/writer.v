module wire

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
fn (w &Writer) len() int {
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
	// Most-significant octet first (network order, §2), so Reader::read_u16's
	// `byte0 << 8 | byte1` reconstructs the value byte for byte.
	w.buf << u8((v >> 8) & 0xff)
	w.buf << u8(v & 0xff)
}

// write_u24 appends a 24-bit big-endian unsigned integer (lower 3 bytes of v).
// The upper byte of v is deliberately dropped: u24 fields in TLS can never
// legitimately exceed 0xffffff, and callers pass pre-validated lengths.
pub fn (mut w Writer) write_u24(v u32) {
	// Three octets, most-significant kept first (shifts 16/8/0); this is the
	// encoder counterpart of read_u24 and the only way to frame a 3-byte TLS length.
	w.buf << u8((v >> 16) & 0xff)
	w.buf << u8((v >> 8) & 0xff)
	w.buf << u8(v & 0xff)
}

// write_u32 appends a 32-bit big-endian unsigned integer.
pub fn (mut w Writer) write_u32(v u32) {
	// Four octets big-endian (shifts 24/16/8/0): the top byte is emitted first so
	// the byte stream matches the MSB-first layout every read_u32 expects (§2).
	w.buf << u8((v >> 24) & 0xff)
	w.buf << u8((v >> 16) & 0xff)
	w.buf << u8((v >> 8) & 0xff)
	w.buf << u8(v & 0xff)
}

// write_u64 appends a 64-bit big-endian unsigned integer.
fn (mut w Writer) write_u64(v u64) {
	// Eight octets big-endian (shifts 56..0). Every byte is emitted, none dropped:
	// this width backs sequence-number-scale values where a lost byte would corrupt
	// the count, so it must exactly mirror read_u64.
	w.buf << u8((v >> 56) & 0xff)
	w.buf << u8((v >> 48) & 0xff)
	w.buf << u8((v >> 40) & 0xff)
	w.buf << u8((v >> 32) & 0xff)
	w.buf << u8((v >> 24) & 0xff)
	w.buf << u8((v >> 16) & 0xff)
	w.buf << u8((v >> 8) & 0xff)
	w.buf << u8(v & 0xff)
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
	// Reject an oversized payload before writing the length prefix: silently
	// truncating a >255 length into one octet would corrupt the frame and desync
	// the peer's parser, so it is an error rather than a best-effort encode.
	if data.len > 0xff {
		return error('wire.Writer: data length ${data.len} exceeds u8 max (255)')
	}
	// `opaque T<8>`: the true length as a one-octet prefix, then the bytes verbatim
	// — exactly the framing read_vector_u8 consumes (§3).
	w.write_u8(u8(data.len))
	w.write_bytes(data)
}

// write_vector_u16 appends a byte slice prefixed with its 2-byte big-endian length.
pub fn (mut w Writer) write_vector_u16(data []u8) ! {
	// Same truncation guard as the u8 form, bounded by the 2-byte prefix's range
	// (65535); exceeding it would wrap the length and corrupt downstream framing.
	if data.len > 0xffff {
		return error('wire.Writer: data length ${data.len} exceeds u16 max (65535)')
	}
	// `opaque T<16>`: big-endian u16 length then the bytes; the width covers
	// extensions, tickets, and other bodies too long for a single octet (§3).
	w.write_u16(u16(data.len))
	w.write_bytes(data)
}

// write_vector_u24 appends a byte slice prefixed with its 3-byte big-endian length.
fn (mut w Writer) write_vector_u24(data []u8) ! {
	// Truncation guard at the 3-byte prefix's ceiling (2^24-1), the largest TLS
	// vector length; anything bigger cannot be framed and is rejected outright.
	if data.len > 0xffffff {
		return error('wire.Writer: data length ${data.len} exceeds u24 max (16777215)')
	}
	// `opaque T<24>`: big-endian 3-byte length then the bytes, used for
	// certificate_list where a chain can exceed 64 KiB and so outgrows a u16
	// prefix (§4.4.2).
	w.write_u24(u32(data.len))
	w.write_bytes(data)
}
