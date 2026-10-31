// Copyright (c) 2026 blackshirt.
//
// frame.v implements the small set of QUIC frames the handshake uses (RFC 9000 §19):
// CRYPTO (§19.6) carries the handshake stream, offset across packets; ACK (§19.3) is
// both parsed and emitted (RFC 9000 §13.2 requires a receiver to acknowledge); PADDING
// (§19.1) inflates the Initial to the 1200-byte minimum; CONNECTION_CLOSE (§19.19)
// carries a failure's alert code; and HANDSHAKE_DONE (§19.20) is the engine's cue to
// release the handshake keys.
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

// RxRange is an inclusive [lo, hi] span of received packet numbers — the unit an ACK
// frame's range list encodes (RFC 9000 §19.3.1).
struct RxRange {
mut:
	lo u64
	hi u64
}

// max_ack_ranges bounds the received-range list so hostile reordering cannot grow it
// without bound; past the cap the oldest (lowest) spans are dropped.
const max_ack_ranges = 100

// add_rx_range records a received packet number into an ascending, coalesced range
// list and returns the new list. A number already covered leaves the list unchanged;
// otherwise pn is folded in by rebuilding: append it as a singleton, sort, then merge
// any adjacent/overlapping spans (RFC 9000 §19.3.1). Returning a fresh []RxRange (via
// the caller's field assignment) avoids mutating a `&[]RxRange` in place, which trips
// a V code-generation fault on `insert`/`delete` through the reference.
fn add_rx_range(ranges []RxRange, pn u64) []RxRange {
	for r in ranges {
		if pn >= r.lo && pn <= r.hi {
			return ranges.clone()
		}
	}
	mut items := ranges.clone()
	items << RxRange{
		lo: pn
		hi: pn
	}
	items.sort(a.lo < b.lo)
	mut merged := []RxRange{cap: items.len}
	for it in items {
		if merged.len > 0 && it.lo <= merged[merged.len - 1].hi + 1 {
			mut last := merged[merged.len - 1]
			if it.hi > last.hi {
				last.hi = it.hi
			}
			merged[merged.len - 1] = last
		} else {
			merged << it
		}
	}
	// Keep only the newest (highest) spans past the cap, so hostile reordering cannot
	// grow the list without bound; the low end is the least useful to acknowledge.
	if merged.len > max_ack_ranges {
		return merged[merged.len - max_ack_ranges..]
	}
	return merged
}

// encode_ack_frame serializes an ACK frame (§19.3) over an ascending, coalesced,
// non-empty range list. ack_delay is 0 here: the handshake client does not measure
// RTT. Largest Acknowledged and First ACK Range are derived from the top span.
fn encode_ack_frame(ranges []RxRange, ack_delay u64) ![]u8 {
	if ranges.len == 0 {
		return error('quic: cannot encode an ACK frame with no ranges')
	}
	mut out := []u8{cap: 1 + (ranges.len + 2) * 8}
	top := ranges.len - 1
	out << frame_ack
	out << encode_varint(ranges[top].hi)! // Largest Acknowledged
	out << encode_varint(ack_delay)! // ACK Delay
	out << encode_varint(u64(top))! // ACK Range Count (number of additional ranges)
	out << encode_varint(ranges[top].hi - ranges[top].lo)! // First ACK Range
	mut j := top
	for j > 0 {
		// Gap is the count of un-ACKed packets between the higher span's smallest
		// and this span's largest; spans are coalesced, so it is never negative.
		out << encode_varint(ranges[j].lo - ranges[j - 1].hi - 1)!
		out << encode_varint(ranges[j - 1].hi - ranges[j - 1].lo)!
		j--
	}
	return out
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

// min_client_initial_datagram_len is the RFC 9000 §14.1 floor: every client
// Initial datagram carrying a ClientHello must be padded to at least this many
// bytes so a server with no other state can confirm the attempt is genuine.
const min_client_initial_datagram_len = 1200

// pad_datagram returns `payload` followed by enough PADDING frames to make the
// whole QUIC packet at least `min_client_initial_datagram_len` bytes (RFC 9000
// §14.1). `packet_overhead` is the cleartext-header-plus-AEAD-tag size the caller
// already commits to.
fn pad_datagram(payload []u8, packet_overhead int) []u8 {
	mut out := payload.clone()
	for packet_overhead + out.len < min_client_initial_datagram_len {
		out << frame_padding
	}
	return out
}
