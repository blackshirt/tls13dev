// Copyright (c) 2026 blackshirt.
//
// packet_parse.v extracts the fixed region of a long header — everything before the
// packet number — without trusting the protected bits. Header protection (RFC 9001
// §5.4.1) masks only the first byte's low nibble and the packet number, so version,
// connection IDs, token and length are readable before deprotection, letting the
// engine locate the packet number and AEAD sample without guessing their length.
module quic

// LongPacketMeta is the framing a receiver can recover from a long header
// before removing header protection.
struct LongPacketMeta {
	ptype       PacketType
	version     u32
	dcid        []u8
	scid        []u8
	token       []u8
	pn_offset   int // byte offset where the (still-masked) packet number begins
	pn_len_hint int // PN length derived from the protected first byte's low bits
	payload_off int // byte offset where the protected payload begins
	total_len   int // pn_offset + pn_len_hint + payload length
}

// long_packet_meta parses the protection-independent framing of a long header.
// It returns the type, IDs, token, the offset of the masked packet number, and
// the total packet length derived from the length field (RFC 9000 §17.2).
fn long_packet_meta(buf []u8) !LongPacketMeta {
	if buf.len < 7 {
		return error('quic: long header too short (${buf.len} bytes)')
	}
	if !first_byte_long(buf[0]) {
		return error('quic: not a long header')
	}
	ptype := match int((buf[0] & long_header_type_mask) >> 4) {
		0 { PacketType.initial }
		1 { PacketType.zero_rtt }
		2 { PacketType.handshake }
		3 { PacketType.retry }
		else { return error('quic: bad long packet type') }
	}
	version := (u32(buf[1]) << 24) | (u32(buf[2]) << 16) | (u32(buf[3]) << 8) | u32(buf[4])
	dcid, off := read_cid(buf, 5)!
	scid, off2 := read_cid(buf, off)!
	mut token := []u8{}
	mut o := off2
	if ptype == .initial {
		token, o = read_varint_field(buf, o)!
	}
	if ptype == .retry {
		return LongPacketMeta{
			ptype:   .retry
			version: version
			dcid:    dcid.clone()
			scid:    scid.clone()
		}
	}
	// The PN length hint comes from the *protected* first byte; the real value
	// is recovered after header-protection removal, but the low two bits are
	// masked so this hint is only used to find the sample position (which does
	// not depend on pn_len).
	pn_len_hint := int(buf[0] & 0x03) + 1
	// The Length field counts the packet number plus the protected payload
	// (RFC 9000 §17.2), so the packet ends at payload_off + length.
	length, n := decode_varint(buf[o..]) or {
		return error('quic: invalid long-header packet length: ${err.msg()}')
	}
	payload_off := o + n // first byte of the packet number
	if length > u64(buf.len - payload_off) {
		return error('quic: long packet length ${length} exceeds remaining buffer ${buf.len - payload_off}')
	}
	total := payload_off + int(length)
	return LongPacketMeta{
		ptype:       ptype
		version:     version
		dcid:        dcid.clone()
		scid:        scid.clone()
		token:       token.clone()
		pn_offset:   payload_off
		pn_len_hint: pn_len_hint
		payload_off: payload_off
		total_len:   total
	}
}
