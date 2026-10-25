// Copyright (c) 2026 blackshirt.
//
// This seam owns the recordless handshake framing of RFC 9001 §4: over QUIC a
// handshake message rides the CRYPTO stream self-framed by its own 4-byte header
// (type || u24 length), so reassembly is the transport-neutral twin of the TLS
// layer's handshake parser.
module handshake

// max_handshake_message_len bounds one reassembled handshake message: the 24-bit
// length field permits ~16 MiB, so a cap keeps a hostile peer from forcing a huge buffer.
pub const max_handshake_message_len = 1 << 20

// handshake_header_len is the self-framing header of one recordless handshake
// message: HandshakeType (1 byte) || 24-bit body length (RFC 8446 §4 / RFC 9001 §4).
const handshake_header_len = 4

// next_recordless_message extracts one complete handshake message from the front of a
// CRYPTO byte stream, capped at max_handshake_message_len.
//
// "recordless" is the RFC 9001 §4 concept: the message bypasses the TLS record layer,
// self-framed by its own 4-byte header inside an opaque stream. The same framer therefore serves
// every recordless surface — the core's plaintext/handshake reassembly, the QUIC
// per-level CRYPTO streams, and the record adapter's post-handshake buffer — rather
// than being QUIC-specific.
//
// Contract: returns an empty slice — NOT an error — while the header or body is still
// incomplete, so callers loop until the result is empty; a non-empty result is consumed
// from buf in place (the caller's buffer keeps its identity). A declared length over
// max_handshake_message_len is the only error, rejected at the header before buffering.
@[direct_array_access]
pub fn next_recordless_message(mut buf []u8) ![]u8 {
	if buf.len < handshake_header_len {
		return []u8{} // even the handshake header has not fully arrived
	}
	msg_len := (int(buf[1]) << 16) | (int(buf[2]) << 8) | int(buf[3])
	if msg_len > max_handshake_message_len {
		return error('handshake: message length ${msg_len} exceeds maximum ${max_handshake_message_len}')
	}
	total := handshake_header_len + msg_len
	if buf.len < total {
		return []u8{} // body not fully received yet
	}
	msg := buf[..total].clone()
	buf.delete_many(0, total) // in-place consumption; the caller's buffer keeps its identity
	return msg
}
