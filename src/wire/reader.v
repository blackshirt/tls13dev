// module wire provides the byte-level primitives every other module parses
// through: reader.v is a bounds-checked cursor over a message body, writer.v
// assembles length-prefixed structures. No TLS semantics live here — only
// framing arithmetic, with every out-of-bounds or oversized access returned as
// an error rather than a panic.
module wire

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
fn (r &Reader) has_remaining(n int) bool {
	return n >= 0 && n <= r.data.len - r.cursor
}

// ensure checks that at least `n` bytes remain, so the fixed-width accessors
// fail with a framing error instead of indexing out of bounds. `what` names the
// item being read for the error message.
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

// read_u16 reads a 16-bit big-endian unsigned integer.
pub fn (mut r Reader) read_u16() !u16 {
	// Bounds-check before touching the buffer so a truncated read surfaces as a
	// framing error, never an out-of-bounds index (§4 requires malformed input to
	// error, not panic).
	r.ensure(2, 'u16')!
	// Big-endian: the lower-address byte is the most significant, so it is shifted
	// up 8 bits and combined with the following byte (RFC 8446 §2 network order).
	v := (u16(r.data[r.cursor]) << 8) | u16(r.data[r.cursor + 1])
	r.cursor += 2 // consume both octets so the next read starts after them
	return v
}

// read_u24 reads a 24-bit (3 bytes) big-endian unsigned integer as u32.
// TLS has no native u24 type, but 24-bit lengths are pervasive (RFC 8446 §4:
// handshake message body length; §4.4.2: cert_data vectors inside CertificateEntry),
// so it gets its own accessor instead of three manual shifts at each call site.
pub fn (mut r Reader) read_u24() !u32 {
	r.ensure(3, 'u24')!
	// Three octets most-significant-first: the shifts 16/8/0 reassemble the 24-bit
	// length into a u32, because V has no native u24 yet TLS frames several
	// vectors/handshake lengths up to 2^24-1 that must not be truncated to u16.
	v := (u32(r.data[r.cursor]) << 16) | (u32(r.data[r.cursor + 1]) << 8) | u32(r.data[r.cursor + 2])
	r.cursor += 3
	return v
}

// read_u32 reads a 32-bit big-endian unsigned integer.
pub fn (mut r Reader) read_u32() !u32 {
	r.ensure(4, 'u32')!
	// Big-endian assembly: consecutive bytes land at shifts 24/16/8/0, so the byte
	// read first is the most significant — the mirror of Writer::write_u32 (§2).
	v := (u32(r.data[r.cursor]) << 24) | (u32(r.data[r.cursor + 1]) << 16) | (u32(r.data[r.cursor + 2]) << 8) | u32(r.data[r.cursor + 3])
	r.cursor += 4
	return v
}

// read_u64 reads a 64-bit big-endian unsigned integer.
fn (mut r Reader) read_u64() !u64 {
	r.ensure(8, 'u64')!
	// Eight octets most-significant-first (shifts 56..0). The full 64-bit width
	// matters here: this decodes sequence-number-scale values where dropping any
	// byte would silently corrupt the count, so every octet is OR-ed into place.
	v := (u64(r.data[r.cursor]) << 56) | (u64(r.data[r.cursor + 1]) << 48) | (u64(r.data[r.cursor + 2]) << 40) | (u64(r.data[r.cursor + 3]) << 32) | (u64(r.data[r.cursor + 4]) << 24) | (u64(r.data[r.cursor + 5]) << 16) | (u64(r.data[r.cursor + 6]) << 8) | u64(r.data[r.cursor + 7])
	r.cursor += 8
	return v
}

// read_bytes reads exact `n` bytes from the stream.
// The result is cloned, not a subslice: callers (e.g. record payloads) often
// outlive the socket receive buffer, and aliasing it would let later reads
// mutate already-handed-over data.
pub fn (mut r Reader) read_bytes(n int) ![]u8 {
	// Reject a negative count or one larger than what remains before indexing,
	// reporting how many bytes were actually available so callers can tell a short
	// record apart from a corrupt length field.
	if n < 0 || n > r.data.len - r.cursor {
		return error('wire.Reader: unexpected EOF reading ${n} bytes (only ${r.remaining()} available)')
	}
	// Clone rather than subslice: callers keep the returned bytes well past this
	// reader's buffer (record payloads staged straight from the socket recv
	// buffer), and aliasing would let a later read overwrite already-handed-off
	// plaintext.
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
	// `opaque T<8>` framing (§3): one length octet, then exactly that many bytes,
	// which the bounds-checked read_bytes then enforces against the buffer.
	len := int(r.read_u8()!)
	return r.read_bytes(len)
}

// read_vector_u16 reads a vector prefixed with a 2-byte big-endian length.
pub fn (mut r Reader) read_vector_u16() ![]u8 {
	// `opaque T<16>` framing (§3): the length is a big-endian u16, covering the
	// extensions, tickets, and per-entry bodies that can exceed a single octet.
	len := int(r.read_u16()!)
	return r.read_bytes(len)
}

// read_vector_u24 reads a vector prefixed with a 3-byte big-endian length.
pub fn (mut r Reader) read_vector_u24() ![]u8 {
	// `opaque T<24>` framing (§3): used for certificate_list, whose full chains can
	// exceed 64 KiB and therefore cannot be framed by a u16 length prefix (§4.4.2).
	len := int(r.read_u24()!)
	return r.read_bytes(len)
}
