// Copyright (c) 2026 blackshirt.
//
// transcript.v owns the running handshake transcript that the §7.1 key schedule and
// CertificateVerify both hash over; it records raw messages so history can be rewritten
// at the HelloRetryRequest checkpoint rather than maintained as a rolling digest.
module tls

// Transcript maintains the running handshake transcript and computes
// Transcript-Hash per RFC 8446 §4.4.1.
// It stores raw messages rather than a rolling digest because a
// HelloRetryRequest requires rewriting history (ClientHello1 is replaced by a
// synthetic message_hash, §4.4.1) and because the hash is needed at several
// checkpoints, each recomputed over the bytes accumulated so far.
struct Transcript {
mut:
	hash_algo HashAlgorithm // digest the transcript is hashed with; follows the negotiated suite
	messages  []u8          // concatenation of full handshake messages, record framing excluded
}

// new_transcript initializes an empty handshake transcript.
fn new_transcript(hash_algo HashAlgorithm) Transcript {
	return Transcript{
		hash_algo: hash_algo
		messages:  []u8{cap: 4096}
	}
}

// update appends a raw handshake message (HandshakeType || 3-byte Length || Body)
// to the transcript, excluding record-layer framing (RFC 8446 §4.4.1).
fn (mut t Transcript) update(handshake_msg []u8) {
	t.messages << handshake_msg
}

// current_hash returns Hash(Handshake Context) over all messages accumulated so far.
fn (t &Transcript) current_hash() []u8 {
	return t.hash_algo.compute_hash(t.messages)
}

// apply_hello_retry_request replaces ClientHello1 in the transcript with the
// synthetic message_hash per RFC 8446 §4.4.1:
//
//	message_hash = HandshakeType.message_hash (0xfe) || Length (3 bytes: 0x00, 0x00, hash_len) || Hash(ClientHello1)
//
// The transcript restarts from [message_hash, HRR] so both peers hash the same
// logical sequence without retaining the full first ClientHello.
fn (mut t Transcript) apply_hello_retry_request(client_hello1 []u8, hello_retry_request []u8) {
	ch1_hash := t.hash_algo.compute_hash(client_hello1)
	hash_len := t.hash_algo.hash_len()

	mut synthetic_msg := []u8{cap: 4 + hash_len}
	synthetic_msg << 0xfe // HandshakeType.message_hash
	synthetic_msg << 0x00
	synthetic_msg << 0x00
	synthetic_msg << u8(hash_len)
	synthetic_msg << ch1_hash

	t.messages = []u8{cap: 4096}
	t.messages << synthetic_msg
	t.messages << hello_retry_request
}
