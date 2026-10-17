// Copyright (c) 2026 blackshirt.
//
// Record layer tests: wire framing round-trips through serialize/parse, the
// AEAD cipher state encrypts and decrypts in sequence-number lockstep across
// records, and a single flipped ciphertext byte must fail the tag check.
module tls

import crypto.aes

fn test_record_serialization_roundtrip() ! {
	payload := [u8(1), 2, 3, 4, 5]
	rec := new_record(.handshake, payload)
	raw := rec.serialize()

	assert raw.len == record_header_len + payload.len
	assert raw[0] == u8(ContentType.handshake)
	assert raw[1] == 0x03
	assert raw[2] == 0x03
	assert raw[3] == 0x00
	assert raw[4] == 0x05

	mut r := new_reader(raw)
	parsed := parse_record(mut r)!
	assert parsed.content_type == .handshake
	assert parsed.legacy_version == legacy_record_version
	assert parsed.payload == payload
}

fn test_record_cipher_state_aes_gcm_roundtrip() ! {
	key := [u8(0x01), 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
		0x0f, 0x10]
	iv := [u8(0xa0), 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab]

	gcm_enc := aes.new_aes_gcm(key)!
	gcm_dec := aes.new_aes_gcm(key)!

	mut enc_state := new_record_cipher_state(gcm_enc, iv)!
	mut dec_state := new_record_cipher_state(gcm_dec, iv)!

	msg1 := 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'.bytes()
	encrypted_rec := enc_state.encrypt_record(.application_data, msg1)!
	assert encrypted_rec.content_type == .application_data

	decrypted_rec := dec_state.decrypt_record(encrypted_rec)!
	assert decrypted_rec.content_type == .application_data
	assert decrypted_rec.plaintext == msg1
	assert enc_state.seq_num == 1
	assert dec_state.seq_num == 1

	// Test second record (verifies sequence number increments and stays in sync)
	msg2 := 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK'.bytes()
	encrypted_rec2 := enc_state.encrypt_record(.application_data, msg2)!
	decrypted_rec2 := dec_state.decrypt_record(encrypted_rec2)!
	assert decrypted_rec2.content_type == .application_data
	assert decrypted_rec2.plaintext == msg2
	assert enc_state.seq_num == 2
	assert dec_state.seq_num == 2
}

fn test_record_cipher_state_tamper_detection() ! {
	key := [u8(0x11), 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
		0xff, 0x00]
	iv := [u8(0x01), 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]

	gcm_enc := aes.new_aes_gcm(key)!
	gcm_dec := aes.new_aes_gcm(key)!

	mut enc_state := new_record_cipher_state(gcm_enc, iv)!
	mut dec_state := new_record_cipher_state(gcm_dec, iv)!

	msg := 'Secret data'.bytes()
	mut encrypted_rec := enc_state.encrypt_record(.application_data, msg)!

	// Corrupt one byte of ciphertext
	encrypted_rec.payload[0] ^= 0x55

	dec_state.decrypt_record(encrypted_rec) or {
		assert err.msg().contains('AEAD decryption failed')
		return
	}
	assert false
}

// test_content_type_from_u8 pins the 1-byte record content-type decode: the five
// defined types map to their enum values and any other byte is a framing error.
fn test_content_type_from_u8() ! {
	assert content_type_from_u8(u8(0))! == .invalid
	assert content_type_from_u8(u8(20))! == .change_cipher_spec
	assert content_type_from_u8(u8(21))! == .alert
	assert content_type_from_u8(u8(22))! == .handshake
	assert content_type_from_u8(u8(23))! == .application_data
	content_type_from_u8(u8(99)) or {
		assert err.msg().contains('invalid content type')
		return
	}
	assert false
}

// test_change_cipher_spec_dummy_record verifies the middlebox-compat CCS record
// (RFC 8446 App. D.4): content type 20 carrying the single byte 0x01.
fn test_change_cipher_spec_dummy_record() ! {
	rec := change_cipher_spec()
	assert rec.content_type == .change_cipher_spec
	assert rec.legacy_version == legacy_record_version
	assert rec.payload == [u8(0x01)]
}

// test_parse_record_rejects_short_header: fewer than the 5-byte header is a
// framing error rather than an out-of-bounds read.
fn test_parse_record_rejects_short_header() ! {
	mut r := new_reader([u8(0x16), 0x03, 0x03, 0x00])
	parse_record(mut r) or {
		assert err.msg().contains('buffer too short')
		return
	}
	assert false
}

// test_parse_record_rejects_invalid_content_type: correct framing but an
// undefined content-type byte (0x99) must be rejected before payload handling.
fn test_parse_record_rejects_invalid_content_type() ! {
	mut r := new_reader([u8(0x99), 0x03, 0x03, 0x00, 0x01, 0xaa])
	parse_record(mut r) or {
		assert err.msg().contains('invalid content type')
		return
	}
	assert false
}

// test_parse_record_rejects_oversized_length: a declared length above
// max_ciphertext_record_len (RFC 8446 §5.2) is refused before any allocation.
fn test_parse_record_rejects_oversized_length() ! {
	// length field 0x5000 = 20480 > max_ciphertext_record_len 16640
	mut r := new_reader([u8(0x17), 0x03, 0x03, 0x50, 0x00])
	parse_record(mut r) or {
		assert err.msg().contains('exceeds maximum')
		return
	}
	assert false
}

// test_parse_record_rejects_incomplete_payload: the header declares 200 bytes
// but only 2 are present, so the record is truncated and must error.
fn test_parse_record_rejects_incomplete_payload() ! {
	mut r := new_reader([u8(0x16), 0x03, 0x03, 0x00, 0xc8, 0xaa, 0xbb])
	parse_record(mut r) or {
		assert err.msg().contains('incomplete record payload')
		return
	}
	assert false
}
