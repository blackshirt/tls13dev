// Copyright (c) 2026 blackshirt.
//
// quic_transport_parameters.v encodes and decodes the QUIC transport parameters
// extension (RFC 9001 §8.2) using QUIC's variable-length integers (RFC 9000 §16).
module handshake

const quic_param_initial_scid = u64(0x0f)

fn encode_quic_varint(value u64) ![]u8 {
	if value < (1 << 6) {
		return [u8(value)]
	}
	if value < (1 << 14) {
		return [u8(value >> 8) | 0x40, u8(value & 0xff)]
	}
	if value < (1 << 30) {
		return [
			u8(value >> 24) | 0x80,
			u8((value >> 16) & 0xff),
			u8((value >> 8) & 0xff),
			u8(value & 0xff),
		]
	}
	if value < (u64(1) << 62) {
		return [
			u8(value >> 56) | 0xc0,
			u8((value >> 48) & 0xff),
			u8((value >> 40) & 0xff),
			u8((value >> 32) & 0xff),
			u8((value >> 24) & 0xff),
			u8((value >> 16) & 0xff),
			u8((value >> 8) & 0xff),
			u8(value & 0xff),
		]
	}
	return error('handshake: QUIC transport parameter value exceeds 2^62-1')
}

fn decode_quic_varint(data []u8) !(u64, int) {
	if data.len == 0 {
		return error('handshake: truncated QUIC transport parameter')
	}
	n := 1 << (data[0] >> 6)
	if data.len < n {
		return error('handshake: truncated QUIC transport parameter varint')
	}
	mut value := u64(data[0] & 0x3f)
	for i in 1 .. n {
		value = (value << 8) | u64(data[i])
	}
	return value, n
}

fn encode_quic_transport_parameters(params QuicTransportParameters) ![]u8 {
	if params.initial_scid.len > 20 {
		return error('handshake: QUIC initial_source_connection_id exceeds 20 bytes')
	}
	mut out := encode_quic_varint(quic_param_initial_scid)!
	out << encode_quic_varint(u64(params.initial_scid.len))!
	out << params.initial_scid
	return out
}

fn parse_quic_transport_parameters(data []u8) !QuicTransportParameters {
	mut off := 0
	mut has_source_connection_id := false
	mut source_connection_id := []u8{}
	mut seen_ids := []u64{}
	for off < data.len {
		id, id_len := decode_quic_varint(data[off..])!
		off += id_len
		length, length_len := decode_quic_varint(data[off..])!
		off += length_len
		if length > u64(data.len - off) {
			return error('handshake: truncated QUIC transport parameter value')
		}
		for seen_id in seen_ids {
			if seen_id == id {
				return error('handshake: duplicate QUIC transport parameter ${id}')
			}
		}
		seen_ids << id
		value := data[off..off + int(length)]
		off += int(length)
		if id == quic_param_initial_scid {
			if value.len > 20 {
				return error('handshake: QUIC initial_source_connection_id exceeds 20 bytes')
			}
			source_connection_id = value.clone()
			has_source_connection_id = true
		}
	}
	if !has_source_connection_id {
		return error('handshake: QUIC transport parameters missing initial_source_connection_id')
	}
	return QuicTransportParameters{
		initial_scid: source_connection_id
	}
}
