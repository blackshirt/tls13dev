module pki

import wire

// Asn1Element represents a parsed ASN.1 DER tag, length, and content bytes.
struct Asn1Element {
	tag          u8   // identifier octet, including class/constructed bits
	is_construct bool // bit 0x20 of the tag: data holds child TLVs rather than raw bytes
	data         []u8 // value octets; children for constructed, raw bytes for primitive
}

// read_asn1_element parses a single ASN.1 TLV (Tag-Length-Value) from the wire
// reader. Only definite-length encodings are supported, which DER mandates.
//   - bit 0x20 of the tag marks a constructed value (its data holds child TLVs)
//   - length short form: 1 byte, high bit clear
//   - length long form:  high bit set; low 7 bits give the number of length bytes
fn read_asn1_element(mut r wire.Reader) !Asn1Element {
	if r.remaining() < 2 {
		return error('asn1: truncated element header')
	}
	tag := r.read_u8()!
	is_construct := (tag & 0x20) != 0

	len_byte := r.read_u8()!
	mut length := u32(0)

	if (len_byte & 0x80) == 0 {
		// Short form: the byte is the length itself.
		length = u32(len_byte)
	} else {
		// Long form: low 7 bits count the big-endian length octets that follow.
		num_len_bytes := int(len_byte & 0x7f)
		if num_len_bytes == 0 || num_len_bytes > 4 {
			// 0 is reserved (indefinite length — not allowed in DER); >4 would
			// overflow the u32 accumulator, and no real certificate ever needs it:
			// an attacker-controlled huge length here must fail, not wrap.
			return error('asn1: invalid or unsupported length octets (${num_len_bytes})')
		}
		if r.remaining() < num_len_bytes {
			return error('asn1: truncated length octets')
		}
		for _ in 0 .. num_len_bytes {
			b := r.read_u8()!
			length = (length << 8) | u32(b)
		}
	}

	if r.remaining() < int(length) {
		return error('asn1: element length ${length} exceeds remaining bytes (${r.remaining()})')
	}

	data := r.read_bytes(int(length))!
	return Asn1Element{
		tag:          tag
		is_construct: is_construct
		data:         data
	}
}

// parse_sequence decodes an ASN.1 SEQUENCE into its child elements.
fn parse_sequence(data []u8) ![]Asn1Element {
	mut r := wire.new_reader(data)
	mut elements := []Asn1Element{}
	for r.remaining() > 0 {
		el := read_asn1_element(mut r)!
		elements << el
	}
	return elements
}

// parse_oid decodes an ASN.1 object identifier into dotted-decimal form.
// Certificates are identified entirely by OID strings (algorithms, extensions,
// attributes), so decoding to canonical dotted form gives a stable key for the
// string matches in x509/validator.
//
// The first subidentifier packs the first two arcs as (arc1 * 40 + arc2). Like
// every other subidentifier, it is a base-128 varint and may span several bytes
// (RFC 5280 §A.1).
fn parse_oid(data []u8) string {
	if data.len == 0 {
		return ''
	}
	// The final byte of an ASN.1 OID must have bit 7 clear (indicating termination)
	if (data[data.len - 1] & 0x80) != 0 {
		return ''
	}

	mut idx := 0
	mut first := u64(0)
	for {
		if idx >= data.len {
			return '' // truncated: subidentifier never terminated
		}
		b := data[idx]
		first = (first << 7) | u64(b & 0x7f)
		idx++
		if (b & 0x80) == 0 {
			break
		}
	}

	arc1 := if first < 40 {
		u64(0)
	} else if first < 80 {
		u64(1)
	} else {
		u64(2)
	}
	mut oid := '${arc1}.${first - arc1 * 40}'

	mut val := u64(0)
	for idx < data.len {
		b := data[idx]
		val = (val << 7) | u64(b & 0x7f)
		idx++
		if (b & 0x80) == 0 {
			oid += '.${val}'
			val = 0
		}
	}
	return oid
}
