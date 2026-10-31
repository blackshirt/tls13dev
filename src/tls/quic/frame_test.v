// Copyright (c) 2026 blackshirt.
//
// frame_test.v exercises the ACK frame encoder added for handshake acknowledgment
// (RFC 9000 §13.2, §19.3): the received-range tracker that coalesces packet numbers,
// and encode_ack_frame round-tripping against the existing parse_ack_frame across
// single spans, gaps, and the 1/2/4-byte varint boundaries.
module quic

// range_of builds an RxRange without the field-name boilerplate in every assertion.
fn range_of(lo u64, hi u64) RxRange {
	return RxRange{
		lo: lo
		hi: hi
	}
}

// test_add_rx_range_coalesces checks that contiguous and duplicate numbers fold into
// ascending, non-overlapping spans, while a gap opens a new one (RFC 9000 §19.3.1).
fn test_add_rx_range_coalesces() ! {
	mut ranges := []RxRange{}
	for pn in [u64(2), u64(0), u64(1), u64(5), u64(0), u64(3)] {
		ranges = add_rx_range(ranges, pn)
	}
	// 0..3 are contiguous (coalesced into one span); 5 stands alone past the gap at 4.
	assert ranges == [range_of(0, 3), range_of(5, 5)], 'unexpected ranges: ${ranges}'
}

// test_ack_frame_round_trips checks encode_ack_frame output parses back with every
// body byte consumed, over ranges that span 1-, 2-, and 4-byte varints.
fn test_ack_frame_round_trips() ! {
	mut cases := [][]RxRange{}
	cases << [range_of(0, 0)]
	cases << [range_of(0, 2), range_of(5, 5), range_of(9, 9)]
	cases << [range_of(63, 63)] // largest single-byte varint boundary
	cases << [range_of(16383, 16384)] // 16384 is the first 2-byte varint value
	cases << [range_of(0, 0), range_of(1073741824, 1073741830)] // 4-byte varint span
	for ranges in cases {
		encoded := encode_ack_frame(ranges, 0)!
		assert encoded[0] == frame_ack, 'ACK frame must carry the frame_ack type byte'
		// parse_ack_frame consumes the body after the type byte; a full consumption
		// proves the encoder's field count and varint widths are self-consistent.
		used := parse_ack_frame(encoded[1..], false)!
		assert used == encoded.len - 1, 'parse consumed ${used} of ${encoded.len - 1} ACK body bytes'
	}
}

// test_encode_ack_rejects_empty_ranges checks an ACK with no received packets is an
// error, not a malformed frame (there is no Largest Acknowledged to encode).
fn test_encode_ack_rejects_empty_ranges() ! {
	encode_ack_frame([]RxRange{}, 0) or {
		assert err.msg().contains('no ranges')
		return
	}
	assert false, 'encode_ack_frame should reject an empty range list'
}
