// Copyright (c) 2026 blackshirt.
//
// CRYPTO-stream reassembly tests (RFC 9001 §4): next_recordless_message
// extracts one complete 4-byte-headered message at a time from a buffer holding
// fragments or coalesced messages, and caps the declared length.
module handshake

// test_next_recordless_message_reassembles_fragments checks that a fragmented
// message is withheld until its header and body are complete.
fn test_next_recordless_message_reassembles_fragments() ! {
	mut buf := [u8(0x08), 0x00, 0x00] // EncryptedExtensions, declared len 5; header short
	assert next_recordless_message(mut buf)!.len == 0
	assert buf.len == 3

	buf << u8(0x05) // header complete, body missing
	assert next_recordless_message(mut buf)!.len == 0
	assert buf.len == 4

	buf << [u8(0x01), 0x02, 0x03, 0x04, 0x05]
	msg := next_recordless_message(mut buf)!
	assert msg.len == 9
	assert msg[0] == u8(0x08)
	assert msg[8] == u8(0x05)
	assert buf.len == 0
}

// test_next_recordless_message_splits_coalesced checks that coalesced
// messages are extracted one at a time, the remainder staying buffered.
fn test_next_recordless_message_splits_coalesced() ! {
	mut buf := [u8(0x08), 0x00, 0x00, 0x01, 0xaa, 0x14, 0x00, 0x00, 0x02, 0xbb, 0xcc]

	first := next_recordless_message(mut buf)!
	assert first.len == 5
	assert first[0] == u8(0x08)
	assert buf.len == 6

	second := next_recordless_message(mut buf)!
	assert second.len == 6
	assert second[0] == u8(0x14)
	assert buf.len == 0
}

// test_next_recordless_message_rejects_oversized_length checks that the
// declared length fails at the header, before a gigantic message is buffered.
fn test_next_recordless_message_rejects_oversized_length() ! {
	mut buf := [u8(0x08), 0xff, 0xff, 0xff, 0x00] // declares ~16 MiB
	next_recordless_message(mut buf) or {
		assert err.msg().contains('exceeds maximum')
		return
	}
	assert false
}
