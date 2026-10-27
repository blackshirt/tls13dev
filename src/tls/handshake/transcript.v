// Copyright (c) 2026 blackshirt.
//
// transcript.v owns the running handshake transcript that the §7.1 key schedule and
// CertificateVerify hash over; it records raw messages so history can be rewritten at HRR.
module handshake

// max_transcript_len caps the total handshake transcript: every message is capped
// individually, so without a running bound a peer could keep sending legal-size
// handshake records and grow the buffer without ever completing the flight.
const max_transcript_len = 1 << 22

// transcript_buf_cap is the initial allocation for the accumulated transcript bytes.
const transcript_buf_cap = 4096

// hs_type_message_hash is the synthetic HandshakeType the HRR rewrite records under
// (RFC 8446 §4.4.1); it never appears on the wire.
const hs_type_message_hash = u8(0xfe)

// Transcript maintains the running handshake transcript and computes Transcript-Hash
// per RFC 8446 §4.4.1, storing raw messages so the HRR checkpoint can rewrite history.
struct Transcript {
mut:
	hash_algo HashAlgorithm // digest the transcript is hashed with; follows the negotiated suite
	messages  []u8          // concatenation of full handshake messages, transport framing excluded
}

// new_transcript initializes an empty handshake transcript.
fn new_transcript(hash_algo HashAlgorithm) Transcript {
	return Transcript{
		hash_algo: hash_algo
		messages:  []u8{cap: transcript_buf_cap}
	}
}

// update appends a raw handshake message (HandshakeType || 3-byte Length || Body)
// to the transcript, excluding the transport's framing (RFC 8446 §4.4.1), and
// enforces the running total bound so no caller can bypass it by appending directly.
fn (mut t Transcript) update(handshake_msg []u8) ! {
	if t.messages.len + handshake_msg.len > max_transcript_len {
		return error('handshake: transcript exceeds ${max_transcript_len} bytes')
	}
	t.messages << handshake_msg
}

// current_hash returns Hash(Handshake Context) over all messages accumulated so far.
fn (t &Transcript) current_hash() []u8 {
	return t.hash_algo.compute_hash(t.messages)
}

// apply_hello_retry_request replaces ClientHello1 with the synthetic message_hash
// (RFC 8446 §4.4.1), restarting the transcript from [message_hash, HRR]. The
// transcript holds only ClientHello1 at this point, so it supplies the hash input.
fn (mut t Transcript) apply_hello_retry_request(hello_retry_request []u8) {
	ch1_hash := t.hash_algo.compute_hash(t.messages)
	hash_len := t.hash_algo.hash_len()

	mut synthetic_msg := []u8{cap: 4 + hash_len}
	synthetic_msg << hs_type_message_hash // HandshakeType.message_hash
	synthetic_msg << 0x00
	synthetic_msg << 0x00
	synthetic_msg << u8(hash_len)
	synthetic_msg << ch1_hash

	t.messages = []u8{cap: transcript_buf_cap}
	t.messages << synthetic_msg
	t.messages << hello_retry_request
}
