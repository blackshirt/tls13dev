// Copyright (c) 2026 blackshirt.
//
// transport_params_test.v covers the framing the handshake deliberately refuses
// to do: reading and writing QUIC transport-parameter id/length/value triplets
// (RFC 9000 §7.3), including the duplicate-, size-, and presence-guards.
module quic

// A server declares both connection-ID parameters this stack checks, and parses
// them in the wire order this stack's fakeserver emits them: 0x00 then 0x0f.
fn test_server_wire_carries_both_connection_id_parameters() ! {
	original := [u8(0x83), 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]
	source := [u8(0x51), 0x54, 0x9c]
	mut server_bytes := [u8(0x00), u8(original.len)]
	server_bytes << original
	server_bytes << [u8(0x0f), u8(source.len)]
	server_bytes << source
	params := parse_transport_parameters(server_bytes)!
	assert params.original_dcid == original
	assert params.initial_scid == source
}

// test_encode_numeric_param_frames_a_varint_value pins one id/length/value triplet
// where the value is a multi-byte varint (RFC 9000 §7.3): id 0x01, a length equal to
// the value's byte count, then the value. 30000 (0x7530) exceeds 2^14, so it encodes
// as the 4-byte varint [0x80, 0x00, 0x75, 0x30].
fn test_encode_numeric_param_frames_a_varint_value() ! {
	one := encode_numeric_param(param_max_idle_timeout, 30000)!
	assert one == [u8(0x01), u8(0x04), u8(0x80), u8(0x00), u8(0x75), u8(0x30)]
}

// test_encode_transport_parameters_wire_format checks the full ascending client set:
// ten numeric triplets (all zero for a bare struct) then the initial_source_connection_id
// octets at the tail (0x0f, its length, then the bytes).
fn test_encode_transport_parameters_wire_format() ! {
	encoded := encode_transport_parameters(TransportParameters{
		initial_scid: [u8(0x12), u8(0x34)]
	})!
	// 10 numeric triplets x 3 bytes + a 4-byte initial_source_connection_id triplet.
	assert encoded.len == 34, 'client set length: ${encoded.len}'
	assert encoded[0..3] == [u8(0x01), u8(0x01), u8(0x00)]
	assert encoded[encoded.len - 4..] == [u8(0x0f), u8(0x02), u8(0x12), u8(0x34)]
}

// A client that sent original_destination_connection_id would be refused with
// TRANSPORT_PARAMETER_ERROR (RFC 9000 §7.3), so the encoder must not grow a way to
// emit it even when the field is populated by hand: with and without it are identical.
fn test_encode_transport_parameters_never_emits_server_only_parameter() ! {
	with_orig := encode_transport_parameters(TransportParameters{
		original_dcid: [u8(0xde), u8(0xad)]
		initial_scid:  [u8(0x12), u8(0x34)]
	})!
	without := encode_transport_parameters(TransportParameters{
		initial_scid: [u8(0x12), u8(0x34)]
	})!
	assert with_orig == without
}

// test_client_transport_parameters_round_trip decodes the full advertised set back
// into triplets and checks each numeric value, the source CID, ascending id order,
// and - the crux for the server's illegal_parameter - that no server-only id
// (0x00/0x02/0x10) is present.
fn test_client_transport_parameters_round_trip() ! {
	scid := [u8(0xaa), u8(0xbb), u8(0xcc)]
	encoded := encode_transport_parameters(client_transport_parameters(scid))!
	mut ids := []u64{}
	mut vals := map[u64]u64{}
	mut got_scid := []u8{}
	mut off := 0
	for off < encoded.len {
		id, n := decode_varint(encoded[off..])!
		off += n
		length, m := decode_varint(encoded[off..])!
		off += m
		value := encoded[off..off + int(length)]
		off += int(length)
		ids << id
		if id == param_initial_scid {
			got_scid = value.clone()
		} else {
			v, _ := decode_varint(value)!
			vals[id] = v
		}
	}
	assert got_scid == scid
	assert vals[param_max_idle_timeout] == 30000
	assert vals[param_max_udp_payload_size] == 1472
	assert vals[param_initial_max_data] == 1048576
	assert vals[param_initial_max_streams_bidi] == 128
	assert vals[param_initial_max_streams_uni] == 3
	assert vals[param_ack_delay_exponent] == 3
	assert vals[param_max_ack_delay] == 25
	for forbidden in [param_original_dcid, u64(0x02), u64(0x10)] {
		assert !(forbidden in ids), 'client must never emit server-only id 0x${forbidden:02x}'
	}
	mut prev := u64(0)
	for id in ids {
		assert id > prev, 'transport parameter ids must ascend'
		prev = id
	}
}

fn test_parse_transport_parameters_rejects_absent_initial_source_id() {
	// original_destination_connection_id alone is not enough.
	if _ := parse_transport_parameters([u8(0x00), 0x00]) {
		assert false
	}
}

fn test_parse_transport_parameters_rejects_absent_original_destination_id() {
	// initial_source_connection_id alone is not enough either: §7.3 makes the
	// absence of either one from a server a connection error.
	if _ := parse_transport_parameters([u8(0x0f), 0x00]) {
		assert false
	}
}

fn test_parse_transport_parameters_rejects_duplicate_ids() {
	// The duplicated id here is one the parser does not interpret, so this pins
	// that duplicate rejection runs over every parameter, not only known ones.
	if _ := parse_transport_parameters([u8(0x08), 0x00, 0x08, 0x00, 0x00, 0x00, 0x0f, 0x00]) {
		assert false
	}
}

// Duplicate detection runs on the decoded number, so re-encoding the second id in
// a wider, non-minimal form cannot smuggle a duplicate past the check.
fn test_parse_transport_parameters_rejects_duplicate_id_in_non_minimal_form() {
	if _ := parse_transport_parameters([u8(0x00), 0x00, 0x40, 0x00, 0x00, 0x0f, 0x00]) {
		assert false
	}
}

fn test_parse_transport_parameters_rejects_truncated_value() {
	// A complete original_destination_connection_id, then a length pointing past
	// the end of the extension.
	if _ := parse_transport_parameters([u8(0x00), 0x01, 0xaa, 0x0f, 0x05, 0x01, 0x02]) {
		assert false
	}
}

// RFC 9000 §7.3: an unknown parameter id is skipped, not a connection error -
// provided the parameters this stack depends on are still there.
fn test_parse_transport_parameters_skips_unknown_ids() ! {
	params := parse_transport_parameters([u8(0x08), 0x01, 0xaa, 0x00, 0x01, 0xbb, 0x0f, 0x01, 0xcc])!
	assert params.original_dcid == [u8(0xbb)]
	assert params.initial_scid == [u8(0xcc)]
}

fn test_encode_transport_parameters_rejects_overlong_connection_id() {
	scid := []u8{len: 21, init: u8(0x01)}
	if _ := encode_transport_parameters(TransportParameters{
		initial_scid: scid
	}) {
		assert false
	}
}

fn test_parse_transport_parameters_rejects_overlong_source_id() {
	mut data := [u8(0x00), 0x00]
	data << [u8(0x0f), 0x15]
	for _ in 0 .. 21 {
		data << u8(0x01)
	}
	if _ := parse_transport_parameters(data) {
		assert false
	}
}

fn test_parse_transport_parameters_rejects_overlong_original_destination_id() {
	mut data := [u8(0x00), 0x15]
	for _ in 0 .. 21 {
		data << u8(0x01)
	}
	data << [u8(0x0f), 0x00]
	if _ := parse_transport_parameters(data) {
		assert false
	}
}
