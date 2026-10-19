// Copyright (c) 2026 blackshirt.
//
// CRYPTO-stream reassembly tests (RFC 9001 §4): next_passthrough_message
// extracts one complete 4-byte-headered handshake message at a time from a
// buffer that may hold fragments or coalesced messages, awaiting more bytes
// until a full frame is present and capping the declared length before it can
// drive a gigantic allocation. They live in the importable handshake core
// because a QUIC engine reuses exactly this plumbing.
module handshake

fn test_next_passthrough_message_reassembles_fragments() ! {
	mut buf := [u8(0x08), 0x00, 0x00] // EncryptedExtensions, declared len 5; header short
	assert next_passthrough_message(mut buf)!.len == 0
	assert buf.len == 3

	buf << u8(0x05) // header complete, body missing
	assert next_passthrough_message(mut buf)!.len == 0
	assert buf.len == 4

	buf << [u8(0x01), 0x02, 0x03, 0x04, 0x05]
	msg := next_passthrough_message(mut buf)!
	assert msg.len == 9
	assert msg[0] == u8(0x08)
	assert msg[8] == u8(0x05)
	assert buf.len == 0
}

fn test_next_passthrough_message_splits_coalesced() ! {
	// Two messages delivered in one run of CRYPTO bytes are extracted one at a
	// time, the remainder staying buffered — the recordless twin of records
	// coalesced into one TCP read.
	mut buf := [u8(0x08), 0x00, 0x00, 0x01, 0xaa, 0x14, 0x00, 0x00, 0x02, 0xbb, 0xcc]

	first := next_passthrough_message(mut buf)!
	assert first.len == 5
	assert first[0] == u8(0x08)
	assert buf.len == 6

	second := next_passthrough_message(mut buf)!
	assert second.len == 6
	assert second[0] == u8(0x14)
	assert buf.len == 0
}

fn test_next_passthrough_message_rejects_oversized_length() ! {
	// The declared length must fail at the header, before further fragments can
	// be buffered toward a gigantic message — the same DoS cap parse_record
	// enforces for TCP records.
	mut buf := [u8(0x08), 0xff, 0xff, 0xff, 0x00] // declares ~16 MiB
	next_passthrough_message(mut buf) or {
		assert err.msg().contains('exceeds maximum')
		return
	}
	assert false
}
