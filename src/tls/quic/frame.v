// Copyright (c) 2026 blackshirt.
//
// frame.v implements the small set of QUIC frames (RFC 9000 §19) used during
// the handshake:
//
//   * CRYPTO (§19.6) — carries the handshake message stream, one frame per
//     encryption level, with an offset so a flight can span several packets.
//   * ACK (§19.3) — parsed so handshake packets containing acknowledgments can
//     be consumed; this engine does not track acknowledgments or emit ACKs.
//   * PADDING (§19.1) — inflates a ClientHello packet to the 1200-byte minimum.
//   * CONNECTION_CLOSE (§19.19) — carries a handshake failure's alert code.
//   * HANDSHAKE_DONE (§19.20) — the server's signal that the handshake is
//     confirmed, which is the engine's cue to zeroize handshake traffic secrets.
//
// Other frames (STREAM, flow control, Retry, NEW_TOKEN, etc.) are out of scope.
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

// parse_ack_frame parses an ACK or ACK_ECN body (after the type byte)
// (RFC 9000 §19.3, §19.4), returning the number of body bytes consumed.
fn parse_ack_frame(body []u8, with_ecn bool) !int {
	mut off := 0
	_, n := decode_varint(body[off..])!
	off += n
	_, n2 := decode_varint(body[off..])!
	off += n2
	count, n3 := decode_varint(body[off..])!
	off += n3
	_, n4 := decode_varint(body[off..])!
	off += n4
	mut o := off
	for _ in 0 .. int(count) {
		_, ng := decode_varint(body[o..])!
		o += ng
		_, nr := decode_varint(body[o..])!
		o += nr
	}
	if with_ecn {
		_, n_ect0 := decode_varint(body[o..])!
		o += n_ect0
		_, n_ect1 := decode_varint(body[o..])!
		o += n_ect1
		_, n_ce := decode_varint(body[o..])!
		o += n_ce
	}
	return o
}

// parse_crypto_frame parses a CRYPTO frame body (after the type byte),
// returning the frame and the number of body bytes consumed (RFC 9000 §19.6).
fn parse_crypto_frame(body []u8) !(CryptoFrame, int) {
	offset, n := decode_varint(body) or {
		return error('quic: invalid CRYPTO frame offset: ${err.msg()}')
	}
	length, n2 := decode_varint(body[n..]) or {
		return error('quic: invalid CRYPTO frame length: ${err.msg()}')
	}
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
// (RFC 9000 §19.19).
fn encode_connection_close(error_code u64, frame_type u64, reason []u8) ![]u8 {
	mut out := []u8{cap: reason.len + 16}
	out << frame_connection_close_transport
	out << encode_varint(error_code)!
	out << encode_varint(frame_type)!
	out << encode_varint(u64(reason.len))!
	out << reason
	return out
}

// ConnectionClose is a parsed transport or application CONNECTION_CLOSE frame.
struct ConnectionClose {
	error_code u64
	frame_type ?u64
	reason     []u8
}

// parse_connection_close parses a CONNECTION_CLOSE body after the type byte
// (RFC 9000 §19.19-20).
fn parse_connection_close(body []u8, application bool) !ConnectionClose {
	error_code, code_len := decode_varint(body) or {
		return error('quic: CONNECTION_CLOSE truncated error code: ${err.msg()}')
	}
	mut off := code_len
	mut frame_type := ?u64(none)
	if !application {
		parsed_frame_type, n := decode_varint(body[off..]) or {
			return error('quic: CONNECTION_CLOSE truncated triggering frame type: ${err.msg()}')
		}
		frame_type = parsed_frame_type
		off += n
	}
	reason_len, n2 := decode_varint(body[off..]) or {
		return error('quic: CONNECTION_CLOSE truncated reason length: ${err.msg()}')
	}
	off += n2
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
