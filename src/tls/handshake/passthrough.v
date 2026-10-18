// Copyright (c) 2026 blackshirt.
//
// passthrough.v owns the recordless handshake framing of RFC 9001 §4: over
// QUIC a handshake message rides the CRYPTO stream self-framed by its own
// 4-byte header (type || u24 length), so reassembly is the transport-neutral
// twin of the record layer's parse_record — which stays in tls, because
// content types and record headers are record-layer vocabulary the core must
// never see. The handshake core's feed() reassembly and a QUIC adapter share
// this plumbing.
module handshake

// max_handshake_message_len bounds one reassembled handshake message. The
// 24-bit length field on the wire permits ~16 MiB, and a server may fragment a
// message across arbitrarily many records (or, over QUIC, many CRYPTO frames),
// so without a cap a hostile peer could pin the client into buffering a
// gigantic "Certificate" piece by piece. Real chains are tens of KiB even at
// the 32-certificate chain bound the validator enforces, so 1 MiB leaves ample
// headroom while capping memory.
const max_handshake_message_len = 1 << 20

// next_passthrough_message extracts one complete handshake message from the
// front of a CRYPTO byte stream — the recordless analogue of the record
// layer's record parser. The declared length is capped at
// max_handshake_message_len from the header alone, before further fragments
// can be buffered toward it (the same DoS bound the record length check
// enforces for TCP records). Returns an empty slice when the buffer does not
// yet hold a full message — a complete handshake message is never empty
// (4-byte header minimum), so the caller can distinguish "await more bytes"
// from data. On success the message bytes (header included) are consumed from
// `buf`.
pub fn next_passthrough_message(mut buf []u8) ![]u8 {
	if buf.len < 4 {
		return []u8{} // even the handshake header has not fully arrived
	}
	msg_len := (int(buf[1]) << 16) | (int(buf[2]) << 8) | int(buf[3])
	if msg_len > max_handshake_message_len {
		return error('record: handshake message length ${msg_len} exceeds maximum ${max_handshake_message_len}')
	}
	total := 4 + msg_len
	if buf.len < total {
		return []u8{} // body not fully received yet
	}
	msg := buf[..total].clone()
	buf.delete_many(0, total) // in-place consumption; the caller's buffer keeps its identity
	return msg
}
