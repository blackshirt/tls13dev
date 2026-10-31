// Copyright (c) 2026 blackshirt.
//
// transport_params.v decodes the QUIC transport parameters carried in the TLS
// quic_transport_parameters extension (RFC 9001 §8.2). TLS passes those bytes through
// opaquely; interpreting the id/length/value triplets is a QUIC concern, framed with
// this module's varint codec (RFC 9000 §16).
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

// Numeric transport-parameter ids a client advertises (RFC 9000 §18.2 table).
const param_max_idle_timeout = u64(0x01)
const param_max_udp_payload_size = u64(0x03)
const param_initial_max_data = u64(0x04)
const param_initial_max_stream_data_bidi_local = u64(0x05)
const param_initial_max_stream_data_bidi_remote = u64(0x06)
const param_initial_max_stream_data_uni = u64(0x07)
const param_initial_max_streams_bidi = u64(0x08)
const param_initial_max_streams_uni = u64(0x09)
const param_ack_delay_exponent = u64(0x0a)
const param_max_ack_delay = u64(0x0b)

// TransportParameters is the subset of RFC 9000 §18.2 parameters this stack
// advertises and reads back from a peer. A client declares the numeric limits plus
// initial_source_connection_id; original_dcid is filled in only from a server's
// declaration, which §7.3 requires a server to make. The numeric fields carry the
// values the encoder emits and the decoder skips past (unrecognized ids are ignored
// per §7.3), so they round-trip without the adapter interpreting flow control.
struct TransportParameters {
	original_dcid                       []u8
	initial_scid                        []u8
	max_idle_timeout                    u64
	max_udp_payload_size                u64
	initial_max_data                    u64
	initial_max_stream_data_bidi_local  u64
	initial_max_stream_data_bidi_remote u64
	initial_max_stream_data_uni         u64
	initial_max_streams_bidi            u64
	initial_max_streams_uni             u64
	ack_delay_exponent                  u64
	max_ack_delay                       u64
}

// client_transport_parameters builds the handshake-only parameter set a client
// advertises. The flow-control numbers are placeholders for a stack that implements
// no stream data plane yet - they need only be legal, non-zero defaults (RFC 9000
// §18.2); a strict server treats an absent/undersized set as illegal_parameter, so
// a full set is sent even though these values are never acted on here.
fn client_transport_parameters(scid []u8) TransportParameters {
	return TransportParameters{
		max_idle_timeout:                    30000
		max_udp_payload_size:                1472
		initial_max_data:                    1048576
		initial_max_stream_data_bidi_local:  1048576
		initial_max_stream_data_bidi_remote: 1048576
		initial_max_stream_data_uni:         1048576
		initial_max_streams_bidi:            128
		initial_max_streams_uni:             3
		ack_delay_exponent:                  3
		max_ack_delay:                       25
		initial_scid:                        scid
	}
}

// encode_numeric_param frames one numeric transport parameter as its id/length/value
// triplet, the value itself a varint and the length that varint's byte count
// (RFC 9000 §7.3, §18).
fn encode_numeric_param(id u64, val u64) ![]u8 {
	value := encode_varint(val)!
	mut out := encode_varint(id)!
	out << encode_varint(u64(value.len))!
	out << value
	return out
}

// encode_transport_parameters serializes this endpoint's advertised parameters as
// ascending id/length/value triplets, the client's full §18.2 set. original_dcid,
// stateless_reset_token (0x02) and retry_source_connection_id (0x10) are server-only,
// and §7.3 makes a client sending any of them a TRANSPORT_PARAMETER_ERROR, so this
// encoder never emits them; the connection-ID-valued initial_source_connection_id is
// written as raw octets, not a varint (RFC 9000 §18.2).
fn encode_transport_parameters(params TransportParameters) ![]u8 {
	if params.initial_scid.len > max_cid_len {
		return error('quic: initial_source_connection_id exceeds ${max_cid_len} bytes')
	}
	mut out := []u8{cap: 96}
	out << encode_numeric_param(param_max_idle_timeout, params.max_idle_timeout)!
	out << encode_numeric_param(param_max_udp_payload_size, params.max_udp_payload_size)!
	out << encode_numeric_param(param_initial_max_data, params.initial_max_data)!
	out << encode_numeric_param(param_initial_max_stream_data_bidi_local, params.initial_max_stream_data_bidi_local)!
	out << encode_numeric_param(param_initial_max_stream_data_bidi_remote, params.initial_max_stream_data_bidi_remote)!
	out << encode_numeric_param(param_initial_max_stream_data_uni, params.initial_max_stream_data_uni)!
	out << encode_numeric_param(param_initial_max_streams_bidi, params.initial_max_streams_bidi)!
	out << encode_numeric_param(param_initial_max_streams_uni, params.initial_max_streams_uni)!
	out << encode_numeric_param(param_ack_delay_exponent, params.ack_delay_exponent)!
	out << encode_numeric_param(param_max_ack_delay, params.max_ack_delay)!
	out << encode_varint(param_initial_scid)!
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
