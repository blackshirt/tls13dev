// Copyright (c) 2026 blackshirt.
// SPDX-License-Identifier: MIT
//
// module record implements the TLS 1.3 record layer (RFC 8446 §5): record.v
// frames and (re)assembles plaintext and protected records, alert.v models the
// §6 alert protocol, and cipher_state.v carries per-direction AEAD sequence
// state across the handshake-to-application key transition.
module record

import wire

// ContentType identifies the type of message in a TLS record (RFC 8446 §5.1).
pub enum ContentType as u8 {
	invalid            = 0 // sentinel for an unset type; never valid on the wire
	change_cipher_spec = 20 // TLS 1.3 keeps this only as a middlebox-compat dummy
	alert              = 21
	handshake          = 22
	application_data   = 23 // also the outer type of every encrypted record
}

// content_type_from_u8 decodes a 1-byte record content type.
fn content_type_from_u8(b u8) !ContentType {
	return match b {
		0 { .invalid }
		20 { .change_cipher_spec }
		21 { .alert }
		22 { .handshake }
		23 { .application_data }
		else { error('record: invalid content type ${b}') }
	}
}

// Legacy record version mandated by RFC 8446 §5.1 for middlebox compatibility.
// TLS 1.3 always writes 0x0303 (TLS 1.2) in the record header; the real version
// lives inside the handshake.
const legacy_record_version = u16(0x0303) // TLS 1.2

// Wire-size limits for a single record (RFC 8446 §5.2). A plaintext record
// carries at most 2^14 bytes; a ciphertext record may be larger by the inner
// content type byte, the AEAD tag, and any padding.
pub const record_header_len = 5
pub const max_plaintext_record_len = 16384 // 2^14 bytes
const max_record_overhead = 256 // inner type byte + AEAD tag + padding (§5.2)
pub const max_ciphertext_record_len = max_plaintext_record_len + max_record_overhead

// Record is a raw TLS record frame: the 5-byte header plus its opaque payload.
pub struct Record {
pub:
	content_type   ContentType // kind of message carried in the payload
	legacy_version u16         // always legacy_record_version on the wire
pub mut:
	payload []u8 // record body: handshake bytes, alert bytes, or ciphertext
}

// new_record constructs a valid Record.
pub fn new_record(content_type ContentType, payload []u8) Record {
	return Record{
		content_type:   content_type
		legacy_version: legacy_record_version
		payload:        payload
	}
}

// change_cipher_spec builds the dummy single-byte ChangeCipherSpec record sent
// after ClientHello for middlebox compatibility (RFC 8446 App. D.4).
pub fn change_cipher_spec() Record {
	return new_record(.change_cipher_spec, [u8(0x01)])
}

// serialize encodes the record into wire format:
// [1 byte ContentType] [2 bytes Legacy Version] [2 bytes Length] [Payload].
// The payload length is cast to u16 without a re-check: every caller bounds it
// by construction, so an oversized payload would be a bug above, not input.
pub fn (r &Record) serialize() []u8 {
	mut w := wire.new_writer(record_header_len + r.payload.len)
	w.write_u8(u8(r.content_type))
	w.write_u16(r.legacy_version)
	w.write_u16(u16(r.payload.len))
	w.write_bytes(r.payload)
	return w.bytes()
}

// parse_record reads a single TLS record: a 5-byte header (content type, legacy
// version, payload length) followed by `length` payload bytes. It rejects
// undersized buffers and oversized length fields (RFC 8446 §5.2).
pub fn parse_record(mut r wire.Reader) !Record {
	if r.remaining() < record_header_len {
		return error('record: buffer too short for TLS record header (${r.remaining()} < ${record_header_len})')
	}
	raw_type := r.read_u8()!
	content_type := content_type_from_u8(raw_type)!
	// The version is stored but deliberately not validated: RFC 8446 §5.1 says
	// the record-layer version is meaningless (compatibility records may show
	// 0x0301). The real version gate is parse_server_hello requiring
	// supported_versions = 0x0304, which also catches 1.2 downgrade attempts.
	version := r.read_u16()!
	length := int(r.read_u16()!)

	if length > max_ciphertext_record_len {
		return error('record: record length ${length} exceeds maximum allowed ${max_ciphertext_record_len}')
	}

	if r.remaining() < length {
		return error('record: incomplete record payload: need ${length} bytes, have ${r.remaining()}')
	}

	payload := r.read_bytes(length)!
	return Record{
		content_type:   content_type
		legacy_version: version
		payload:        payload
	}
}
