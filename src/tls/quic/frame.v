// Copyright (c) 2026 blackshirt.
//
// frame.v implements the small set of QUIC frames (RFC 9000 §19) a client needs
// to carry a handshake:
//
//   * CRYPTO (§19.6) — carries the handshake message stream, one frame per
//     encryption level, with an offset so a flight can span several packets.
//   * ACK (§19.3) — acknowledges received packets so the peer can drop its
//     recovery state. This engine only emits simple contiguous ACKs.
//   * PADDING (§19.1) — inflates a ClientHello packet to the 1200-byte minimum.
//   * CONNECTION_CLOSE (§19.19) — carries a handshake failure's alert code.
//   * HANDSHAKE_DONE (§19.20) — the server's signal that the handshake is
//     confirmed, which is the engine's cue to zeroize handshake traffic secrets.
//
// Frames a client never needs here (STREAM, flow control, Retry, NEW_TOKEN,
// etc.) are out of scope.
module quic

// frame type codes (RFC 9000 §19).
const frame_padding = u8(0x00)
const frame_ping = u8(0x01)
const frame_ack = u8(0x02)
const frame_ack_ecn = u8(0x03)
const frame_crypto = u8(0x06)
const frame_connection_close_transport = u8(0x1c)
const frame_connection_close_application = u8(0x1d)
const frame_handshake_done = u8(0x1e)

// CryptoFrame is a parsed CRYPTO frame: the handshake bytes it carries and the
// stream offset they sit at (RFC 9000 §19.6).
struct CryptoFrame {
	offset u64
	data   []u8
}

// encode_crypto_frame serializes a CRYPTO frame carrying `data` at `offset`
// (RFC 9000 §19.6).
fn encode_crypto_frame(offset u64, data []u8) ![]u8 {
	mut out := []u8{cap: data.len + 16}
	out << frame_crypto
	out << encode_varint(offset)!
	out << encode_varint(u64(data.len))!
	out << data
	return out
}

// AckFrame is a parsed ACK frame: the contiguous packet-number range a peer is
// acknowledging (RFC 9000 §19.3). Only the largest/last-range fields are
// retained — enough for this engine to know the peer's progress.
struct AckFrame {
	largest_acked u64
	ack_delay     u64
	first_range   u64
	ranges        int
}

// encode_ack_frame serializes a minimal ACK frame acknowledging the contiguous
// range [0, largest] with delay 0 and no additional ranges (RFC 9000 §19.3).
fn encode_ack_frame(largest u64, delay u64) ![]u8 {
	mut out := []u8{cap: 16}
	out << frame_ack
	out << encode_varint(largest)!
	out << encode_varint(delay)!
	out << encode_varint(0)! // ACK Range Count
	out << encode_varint(0)! // First ACK Range: everything below largest
	return out
}

// parse_ack_frame parses an ACK frame body (after the type byte)
// (RFC 9000 §19.3). It reads the count and ranges to advance correctly, but
// only exposes the contiguous high range; a client engine needs no more.
fn parse_ack_frame(body []u8) !(AckFrame, int) {
	mut off := 0
	largest, n := decode_varint(body[off..])!
	off += n
	delay, n2 := decode_varint(body[off..])!
	off += n2
	count, n3 := decode_varint(body[off..])!
	off += n3
	first_range, n4 := decode_varint(body[off..])!
	off += n4
	mut ranges := int(0)
	mut o := off
	for _ in 0 .. int(count) {
		gap, ng := decode_varint(body[o..])!
		o += ng
		range_len, nr := decode_varint(body[o..])!
		o += nr
		_ = gap
		_ = range_len
		ranges++
	}
	return AckFrame{
		largest_acked: largest
		ack_delay:     delay
		first_range:   first_range
		ranges:        ranges
	}, o
}

// parse_crypto_frame parses a CRYPTO frame body (after the type byte),
// returning the frame and the number of body bytes consumed (RFC 9000 §19.6).
fn parse_crypto_frame(body []u8) !(CryptoFrame, int) {
	offset, n := decode_varint(body)!
	length, n2 := decode_varint(body[n..])!
	off := n + n2
	if off + int(length) > body.len {
		return error('quic: CRYPTO frame length ${length} exceeds remaining ${body.len - off} bytes')
	}
	return CryptoFrame{
		offset: offset
		data:   body[off..off + int(length)].clone()
	}, off + int(length)
}

// encode_connection_close serializes a transport CONNECTION_CLOSE frame
// (RFC 9000 §19.19) carrying a QUIC transport error code (e.g. a CRYPTO_ERROR
// from AlertDescription.quic_connection_error()).
fn encode_connection_close(error_code u32, frame_type u64, reason []u8) ![]u8 {
	mut out := []u8{cap: reason.len + 16}
	out << frame_connection_close_transport
	mut code_bytes := []u8{len: 4}
	for i in 0 .. 4 {
		shift := (3 - i) * 8
		code_bytes[i] = u8((error_code >> shift) & 0xff)
	}
	out << code_bytes
	out << encode_varint(frame_type)!
	out << encode_varint(u64(reason.len))!
	out << reason
	return out
}

// ConnectionClose is a parsed transport CONNECTION_CLOSE frame
// (RFC 9000 §19.19).
struct ConnectionClose {
	error_code u32
	frame_type u64
	reason     []u8
}

// parse_connection_close parses a transport CONNECTION_CLOSE body (after the
// type byte) (RFC 9000 §19.19).
fn parse_connection_close(body []u8) !ConnectionClose {
	if body.len < 4 {
		return error('quic: CONNECTION_CLOSE truncated error code')
	}
	error_code := (u32(body[0]) << 24) | (u32(body[1]) << 16) | (u32(body[2]) << 8) | u32(body[3])
	frame_type, n := decode_varint(body[4..])!
	reason_len, n2 := decode_varint(body[4 + n..])!
	off := 4 + n + n2
	if off + int(reason_len) > body.len {
		return error('quic: CONNECTION_CLOSE reason length ${reason_len} exceeds body')
	}
	return ConnectionClose{
		error_code: error_code
		frame_type: frame_type
		reason:     body[off..off + int(reason_len)].clone()
	}
}

// pad_to returns `payload` followed by enough PADDING frames to make the whole
// QUIC packet at least 1200 bytes (RFC 9000 §14.1). QUIC requires every client
// Initial datagram carrying a ClientHello to be padded to this floor;
// `packet_overhead` is the cleartext-header-plus-AEAD-tag size the caller
// already commits to.
fn pad_datagram(payload []u8, packet_overhead int) []u8 {
	target := 1200
	mut out := payload.clone()
	for packet_overhead + out.len < target {
		out << frame_padding
	}
	return out
}
