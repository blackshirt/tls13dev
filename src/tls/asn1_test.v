// Copyright (c) 2026 blackshirt.
//
// ASN.1 DER reader tests: read_asn1_element must classify constructed vs
// primitive tags, decode short- and long-form lengths, and reject malformed
// framing (truncated header, DER-illegal indefinite length, a declared length
// beyond what is buffered) instead of over-reading; parse_sequence walks child
// TLVs in order and yields an empty list for empty input. Only parse_oid was
// covered previously (in pki_test.v); these fill the TLV/length paths.
module tls

fn test_asn1_read_element_short_form() ! {
	// SEQUENCE (0x30, constructed bit set) with a short-form 2-byte length.
	mut r := new_reader([u8(0x30), 0x02, 0xaa, 0xbb])
	el := read_asn1_element(mut r)!
	assert el.tag == 0x30
	assert el.is_construct
	assert el.data == [u8(0xaa), 0xbb]
}

fn test_asn1_read_element_primitive_flag() ! {
	// INTEGER (0x02) is primitive: the constructed bit (0x20) is clear.
	mut r := new_reader([u8(0x02), 0x01, 0x05])
	el := read_asn1_element(mut r)!
	assert !el.is_construct
	assert el.data == [u8(0x05)]
}

fn test_asn1_read_element_long_form() ! {
	// OCTET STRING (0x04) with a long-form length: 0x81 => one length octet
	// (0x03) follows, so exactly 3 value bytes are read.
	mut r := new_reader([u8(0x04), 0x81, 0x03, 0x01, 0x02, 0x03])
	el := read_asn1_element(mut r)!
	assert el.tag == 0x04
	assert !el.is_construct
	assert el.data == [u8(0x01), 0x02, 0x03]
}

fn test_asn1_read_element_truncated_header() ! {
	// Fewer than 2 bytes cannot form a tag+length header.
	mut r := new_reader([u8(0x30)])
	read_asn1_element(mut r) or {
		assert err.msg().contains('truncated element header')
		return
	}
	assert false
}

fn test_asn1_read_element_indefinite_length() ! {
	// 0x80 declares zero following length octets — the indefinite-length marker
	// that DER forbids — and must be rejected.
	mut r := new_reader([u8(0x30), 0x80, 0x01])
	read_asn1_element(mut r) or {
		assert err.msg().contains('invalid or unsupported length octets')
		return
	}
	assert false
}

fn test_asn1_read_element_length_exceeds_remaining() ! {
	// Short-form length 0x10 (16) but only 1 payload byte is buffered.
	mut r := new_reader([u8(0x02), 0x10, 0x01])
	read_asn1_element(mut r) or {
		assert err.msg().contains('exceeds remaining bytes')
		return
	}
	assert false
}

fn test_asn1_parse_sequence_children() ! {
	// Two concatenated INTEGER elements: both are returned, in order, with
	// their exact value bytes.
	data := [u8(0x02), 0x01, 0x0a, 0x02, 0x01, 0x14]
	els := parse_sequence(data)!
	assert els.len == 2
	assert els[0].data == [u8(0x0a)]
	assert els[1].data == [u8(0x14)]
	// An empty buffer yields an empty list, not an error.
	assert parse_sequence([]u8{})!.len == 0
}
