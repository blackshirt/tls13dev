// Copyright (c) 2026 blackshirt.
//
// QUIC packet headers (RFC 9000 §17).
module quic

// Long-header form and fixed-bit flags (RFC 9000 §17).
const long_header_form = u8(0x80)
const fixed_bit = u8(0x40)

// long_header_type_mask selects the two type bits of a long header byte.
const long_header_type_mask = u8(0x30)

// PacketType is the engine-facing level of a parsed packet.
enum PacketType {
	initial
	zero_rtt
	handshake
	retry
	one_rtt
}

// first_byte_long reports if first byte is a long header (RFC 9000 §17.2).
fn first_byte_long(b u8) bool {
	return b & long_header_form != 0
}

// read_cid reads a 1-byte-length-prefixed connection ID (RFC 9000 §17.2).
fn read_cid(buf []u8, off int) !([]u8, int) {
	if off >= buf.len {
		return error('quic: truncated connection ID length')
	}
	n := int(buf[off])
	if off + 1 + n > buf.len {
		return error('quic: truncated connection ID (wanted ${n} bytes)')
	}
	return buf[off + 1..off + 1 + n], off + 1 + n
}

// read_varint_field reads a varint-length-prefixed field (RFC 9000 §17.2).
fn read_varint_field(buf []u8, off int) !([]u8, int) {
	if off < 0 || off >= buf.len {
		return error('quic: truncated varint field')
	}
	n, consumed := decode_varint(buf[off..])!
	start := off + consumed
	if n > u64(buf.len - start) {
		return error('quic: truncated varint field body (wanted ${n} bytes)')
	}
	end := start + int(n)
	return buf[start..end], end
}

// build_long_header serializes a long header prefix through the length field,
// up to but not including the packet number (RFC 9000 §17.2). The caller appends
// the (encodable) packet number, then protection. `pn_len` is written into the
// first byte. `payload_len` is the AEAD payload length and `tag_len` the AEAD
// tag length, because the Length field counts the packet number, the payload,
// *and* the tag (RFC 9000 §17.2). Returns the prefix and the byte offset where
// the PN begins.
fn build_long_header(ptype PacketType, version u32, dcid []u8, scid []u8, token []u8, payload_len int, pn_len int, tag_len int) !([]u8, int) {
	type_bits := match ptype {
		.initial { u8(0x00) }
		.zero_rtt { u8(0x10) }
		.handshake { u8(0x20) }
		.retry, .one_rtt { return error('quic: ${ptype} is not a buildable long header') }
	}
	mut out := []u8{cap: 32}
	out << long_header_form | fixed_bit | type_bits | u8((pn_len - 1) & 0x03)
	out << u8(version >> 24)
	out << u8((version >> 16) & 0xff)
	out << u8((version >> 8) & 0xff)
	out << u8(version & 0xff)
	out << u8(dcid.len)
	out << dcid
	out << u8(scid.len)
	out << scid
	if ptype == .initial {
		tok := encode_varint(u64(token.len))!
		out << tok
		out << token
	}
	length_field := encode_varint(u64(payload_len + pn_len + tag_len))!
	out << length_field
	return out, out.len
}

// build_short_header serializes a 1-RTT short header prefix through the first
// byte (RFC 9000 §17.3). The caller appends the packet number and payload.
// `key_phase` sets the Key Phase bit (bit 0x04), which the engine flips when it
// updates 1-RTT keys (§6).
fn build_short_header(dcid []u8, pn_len int, key_phase bool) []u8 {
	mut first := fixed_bit | u8((pn_len - 1) & 0x03)
	if key_phase {
		first |= 0x04
	}
	mut out := []u8{cap: 1 + dcid.len}
	out << first
	out << dcid
	return out
}

// encode_packet_number writes pn using exactly pn_len bytes, big-endian
// (RFC 9000 §17.1).
fn encode_packet_number(pn u64, pn_len int) ![]u8 {
	if pn_len < 1 || pn_len > 4 {
		return error('quic: packet number length ${pn_len} must be 1..4')
	}
	mut out := []u8{len: pn_len}
	for i in 0 .. pn_len {
		shift := (pn_len - 1 - i) * 8
		out[i] = u8((pn >> shift) & 0xff)
	}
	return out
}

// packet_number_len picks the smallest 1..4 byte encoding that carries the
// difference between pn and the largest acknowledged packet number (RFC 9000
// §17.1, "the number of bits must be at least one more than the number of
// significant bits in the difference"). `largest_acked` is 0 when nothing is
// acknowledged yet.
fn packet_number_len(pn u64, largest_acked u64) int {
	// The sender must encode at least enough bits to distinguish pn from every
	// packet the peer might still have outstanding; using the largest acked as
	// the reference is the conservative standard choice.
	diff := if pn > largest_acked { pn - largest_acked } else { 0 }
	if diff < (1 << 7) {
		return 1
	}
	if diff < (1 << 15) {
		return 2
	}
	if diff < (1 << 23) {
		return 3
	}
	return 4
}

// decode_packet_number reconstructs the full packet number from the truncated
// wire value, the number of bytes it occupied, and the largest packet number
// received so far on that level (RFC 9000 §17.1 / Appendix A.3).
fn decode_packet_number(truncated u64, pn_len int, largest_pn u64) u64 {
	pn_nbits := u64(pn_len * 8)
	pn_win := u64(1) << pn_nbits
	pn_hwin := pn_win / 2
	pn_mask := pn_win - 1
	if largest_pn == 0 {
		return truncated
	}
	expected := largest_pn + 1
	pn_floor := expected & ~pn_mask
	candidate := pn_floor | truncated
	if candidate + pn_hwin <= expected {
		return candidate + pn_win
	}
	if candidate > expected + pn_hwin && candidate >= pn_win {
		return candidate - pn_win
	}
	return candidate
}
