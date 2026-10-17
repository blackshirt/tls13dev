// Copyright (c) 2026 blackshirt.
// SPDX-License-Identifier: MIT
//
// Record layer tests: wire framing round-trips through serialize/parse, the
// AEAD cipher state encrypts and decrypts in sequence-number lockstep across
// records, and a single flipped ciphertext byte must fail the tag check.
module record

import crypto.aes
import wire

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

	mut r := wire.new_reader(raw)
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
