// module wire provides the byte-level primitives every other module parses
// through: reader.v is a bounds-checked cursor over a message body, writer.v
// assembles length-prefixed structures. No TLS semantics live here — only
// framing arithmetic, with every out-of-bounds or oversized access returned as
// an error rather than a panic.
module wire

import encoding.binary

// Reader provides safe, bounds-checked deserialization of TLS wire data.
// Every read validates against the buffer length first: TLS parsers face
// hostile network input and must reject truncation/malformed framing rather
// than panic on an out-of-bounds index (RFC 8446 §4 requires malformed
// messages to be treated as a fatal decode_error alert).
pub struct Reader {
pub:
	data []u8 // full buffer being parsed; never mutated, only walked
pub mut:
	cursor int // next unread byte; advanced only after a successful read
}

// new_reader initializes a new Reader over the given byte slice.
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

// has_remaining checks if at least `n` bytes are left to read.
// Lets callers peek/validate framing (e.g. record payload length) before committing to a read.
pub fn (r &Reader) has_remaining(n int) bool {
	return r.cursor + n <= r.data.len
}

// ensure checks that at least `n` bytes remain, so the fixed-width accessors
// fail with a framing error instead of indexing out of bounds. `what` names the
// item being read for the error message.
fn (mut r Reader) ensure(n int, what string) ! {
	if r.cursor + n > r.data.len {
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

// read_u16 reads a 16-bit big-endian unsigned integer.
pub fn (mut r Reader) read_u16() !u16 {
	r.ensure(2, 'u16')!
	v := binary.big_endian_u16(r.data[r.cursor..r.cursor + 2])
	r.cursor += 2
	return v
}

// read_u24 reads a 24-bit (3 bytes) big-endian unsigned integer as u32.
// TLS has no native u24 type, but 24-bit lengths are pervasive (RFC 8446 §4:
// handshake message body length; §4.4.2: cert_data vectors inside CertificateEntry),
// so it gets its own accessor instead of three manual shifts at each call site.
pub fn (mut r Reader) read_u24() !u32 {
	r.ensure(3, 'u24')!
	v := (u32(r.data[r.cursor]) << 16) | (u32(r.data[r.cursor + 1]) << 8) | u32(r.data[r.cursor + 2])
	r.cursor += 3
	return v
}

// read_u32 reads a 32-bit big-endian unsigned integer.
pub fn (mut r Reader) read_u32() !u32 {
	r.ensure(4, 'u32')!
	v := binary.big_endian_u32(r.data[r.cursor..r.cursor + 4])
	r.cursor += 4
	return v
}

// read_u64 reads a 64-bit big-endian unsigned integer.
pub fn (mut r Reader) read_u64() !u64 {
	r.ensure(8, 'u64')!
	v := binary.big_endian_u64(r.data[r.cursor..r.cursor + 8])
	r.cursor += 8
	return v
}

// read_bytes reads exact `n` bytes from the stream.
// The result is cloned, not a subslice: callers (e.g. record payloads) often
// outlive the socket receive buffer, and aliasing it would let later reads
// mutate already-handed-over data.
pub fn (mut r Reader) read_bytes(n int) ![]u8 {
	if n < 0 {
		// Guards against attacker-controlled lengths wrapped through int casts;
		// slicing with a negative n would panic instead of erroring.
		return error('wire.Reader: negative length requested')
	}
	if r.cursor + n > r.data.len {
		return error('wire.Reader: unexpected EOF reading ${n} bytes (only ${r.remaining()} available)')
	}
	slice := r.data[r.cursor..r.cursor + n].clone()
	r.cursor += n
	return slice
}

// The read_vector_* methods implement the `opaque T<V>` vector syntax of
// RFC 8446 §3: a length prefix (V = 8, 16, or 24 bits) followed by that many
// bytes. This framing lets the parser delimit variable-length fields (session IDs,
// extensions, certificates) unambiguously without sentinels.

// read_vector_u8 reads a vector prefixed with a 1-byte length.
// Used for short fields like session_id and SNI hostnames.
pub fn (mut r Reader) read_vector_u8() ![]u8 {
	len := int(r.read_u8()!)
	return r.read_bytes(len)
}

// read_vector_u16 reads a vector prefixed with a 2-byte big-endian length.
pub fn (mut r Reader) read_vector_u16() ![]u8 {
	len := int(r.read_u16()!)
	return r.read_bytes(len)
}

// read_vector_u24 reads a vector prefixed with a 3-byte big-endian length.
pub fn (mut r Reader) read_vector_u24() ![]u8 {
	len := int(r.read_u24()!)
	return r.read_bytes(len)
}
