// Copyright (c) 2026 blackshirt.
//
// transport_params.v is the QUIC side of the TLS quic_transport_parameters
// extension (RFC 9001 §8.2). TLS treats that extension as opaque bytes and only
// rules on where they may appear; decoding the id/length/value triplets is a QUIC
// concern, so it lives here, in the adapter above the handshake, framed with this
// module's variable-length integer codec (RFC 9000 §16).
module quic

// param_initial_scid is the id of the initial_source_connection_id transport
// parameter (RFC 9000 §7.3, §18.2) - the source connection ID this endpoint put in
// the first Initial packet it sent.
const param_initial_scid = u64(0x0f)

// param_original_dcid is the id of the original_destination_connection_id
// transport parameter (RFC 9000 §7.3, §18.2): the destination connection ID the
// client used in its first Initial packet, echoed back by the server. It is a
// server-only parameter, so this stack reads it but never sends it.
const param_original_dcid = u64(0x00)

// TransportParameters is the subset of RFC 9000 §7.3 parameters this stack
// advertises and reads back from a peer. A client declares only
// initial_source_connection_id; original_dcid is filled in from a server's
// declaration, which §7.3 requires a server to make.
struct TransportParameters {
	original_dcid []u8
	initial_scid  []u8
}

// encode_transport_parameters serializes this endpoint's advertised parameters as
// a single id/length/value triplet: the initial_source_connection_id code, the
// length of the connection ID, then its raw bytes. RFC 9000 §5.1 caps a
// connection ID at max_cid_len bytes, enforced here.
//
// Only that one parameter is written. original_destination_connection_id,
// preferred_address, retry_source_connection_id and stateless_reset_token are
// server-only, and §7.3 makes sending any of them from a client a
// TRANSPORT_PARAMETER_ERROR the peer must refuse - so a client-shaped encoder must
// not grow those fields without also growing a server-shaped one.
fn encode_transport_parameters(params TransportParameters) ![]u8 {
	if params.initial_scid.len > max_cid_len {
		return error('quic: initial_source_connection_id exceeds ${max_cid_len} bytes')
	}
	mut out := encode_varint(param_initial_scid)!
	out << encode_varint(u64(params.initial_scid.len))!
	out << params.initial_scid
	return out
}

// parse_transport_parameters walks a peer's id/length/value triplets, rejecting a
// value that overruns the buffer and any repeated parameter id, and requiring both
// initial_source_connection_id and original_destination_connection_id. Those
// requirements are RFC 9000 §7.3 verbatim: an endpoint MUST treat the absence of
// either as a connection error, because receive() compares the two values against
// the connection IDs this endpoint actually saw on the wire - which is what stops
// an attacker from injecting packets that carry attacker-chosen connection IDs
// during the handshake. Unrecognized parameter ids are skipped, as §7.3 requires of
// parameters a peer does not understand. Duplicate ids are detected on the decoded
// number, so decode_varint tolerating a non-minimal encoding cannot smuggle a
// second copy of a parameter through.
@[direct_array_access]
fn parse_transport_parameters(data []u8) !TransportParameters {
	mut off := 0
	mut has_source_connection_id := false
	mut source_connection_id := []u8{}
	mut has_original_destination_id := false
	mut original_destination_id := []u8{}
	mut seen_ids := []u64{}
	for off < data.len {
		id, id_len := decode_varint(data[off..])!
		off += id_len
		length, length_len := decode_varint(data[off..])!
		off += length_len
		if length > u64(data.len - off) {
			return error('quic: truncated transport parameter value')
		}
		if id in seen_ids {
			return error('quic: duplicate transport parameter ${id}')
		}
		seen_ids << id
		value := data[off..off + int(length)]
		off += int(length)
		if id == param_initial_scid || id == param_original_dcid {
			// A zero-length connection ID is legal (§7.3), so only the 20-byte cap is
			// enforced here; emptiness of the *parameter list* is the handshake's call,
			// not this parser's.
			if value.len > max_cid_len {
				return error('quic: transport parameter connection ID exceeds ${max_cid_len} bytes')
			}
			if id == param_initial_scid {
				source_connection_id = value.clone()
				has_source_connection_id = true
			} else {
				original_destination_id = value.clone()
				has_original_destination_id = true
			}
		}
	}
	if !has_source_connection_id {
		return error('quic: transport parameters missing initial_source_connection_id')
	}
	if !has_original_destination_id {
		return error('quic: transport parameters missing original_destination_connection_id')
	}
	return TransportParameters{
		original_dcid: original_destination_id
		initial_scid:  source_connection_id
	}
}
