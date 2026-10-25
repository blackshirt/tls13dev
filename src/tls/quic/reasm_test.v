module quic

fn test_crypto_reasm_accepts_matching_overlaps_and_out_of_order_data() ! {
	mut reasm := CryptoReasm{}
	reasm.insert(4, 'ef'.bytes())!
	reasm.insert(0, 'abcd'.bytes())!
	reasm.insert(3, 'de'.bytes())!
	assert reasm.ready == 'abcdef'.bytes()
	assert reasm.pending.len == 0
	assert reasm.buffered_bytes == reasm.ready.len
}

fn test_crypto_reasm_rejects_out_of_bounds_stream_range() {
	mut reasm := CryptoReasm{}
	reasm.insert(u64(max_crypto_buffer), [u8(0x01)]) or {
		assert err.msg().contains('stream range exceeds')
		assert reasm.ready.len == 0
		assert reasm.pending.len == 0
		return
	}
	assert false
}

fn test_crypto_reasm_rejects_conflicting_ready_overlap() ! {
	mut reasm := CryptoReasm{}
	reasm.insert(0, 'abcd'.bytes())!
	reasm.insert(2, 'XX'.bytes()) or {
		assert err.msg().contains('conflicting overlapping')
		assert reasm.ready == 'abcd'.bytes()
		return
	}
	assert false
}

fn test_crypto_reasm_rejects_conflicting_pending_overlap() ! {
	mut reasm := CryptoReasm{}
	reasm.insert(4, 'ef'.bytes())!
	reasm.insert(5, 'X'.bytes()) or {
		assert err.msg().contains('conflicting overlapping')
		assert reasm.pending.len == 1
		reasm.insert(0, 'abcd'.bytes())!
		assert reasm.ready == 'abcdef'.bytes()
		return
	}
	assert false
}

fn test_crypto_reasm_preserves_pending_tail_on_short_retransmission() ! {
	mut reasm := CryptoReasm{}
	reasm.insert(4, 'efgh'.bytes())!
	reasm.insert(4, 'ef'.bytes())!
	assert reasm.pending.len == 1
	assert reasm.buffered_bytes == 4
	reasm.insert(0, 'abcd'.bytes())!
	assert reasm.ready == 'abcdefgh'.bytes()
	assert reasm.pending.len == 0
	assert reasm.buffered_bytes == reasm.ready.len
}

fn test_crypto_reasm_merges_partial_pending_overlap() ! {
	mut reasm := CryptoReasm{}
	reasm.insert(4, 'efgh'.bytes())!
	reasm.insert(6, 'ghij'.bytes())!
	assert reasm.pending.len == 1
	assert reasm.buffered_bytes == 6
	reasm.insert(0, 'abcd'.bytes())!
	assert reasm.ready == 'abcdefghij'.bytes()
	assert reasm.pending.len == 0
	assert reasm.buffered_bytes == reasm.ready.len
}

fn test_crypto_reasm_limits_pending_chunk_count() {
	mut reasm := CryptoReasm{}
	for i in 0 .. max_crypto_chunks {
		reasm.insert(u64(i * 2 + 1), [u8(0x00)]) or {
			assert false
			return
		}
	}
	reasm.insert(u64(max_crypto_chunks * 2 + 1), [u8(0x00)]) or {
		assert err.msg().contains('pending chunks')
		assert reasm.pending.len == max_crypto_chunks
		assert reasm.buffered_bytes == max_crypto_chunks
		return
	}
	assert false
}

// hello_msg is one complete recordless handshake message: type, 24-bit body
// length, then a 2-byte body (RFC 8446 §4).
fn hello_msg() []u8 {
	return [u8(0x01), 0x00, 0x00, 0x02, 0xaa, 0xbb]
}

fn test_crypto_reasm_accepts_chunks_continuing_past_delivered_bytes() ! {
	// A peer continues a level's CRYPTO stream after bytes we already handed to
	// the framer — the retry ClientHello after a HelloRetryRequest, or the tail of
	// a certificate split across packets. Measuring contiguity by ready.len alone
	// made `base` collapse to 0 once ready drained, so such a chunk was stranded in
	// pending forever and the handshake stalled (RFC 9000 §19.6).
	mut reasm := CryptoReasm{}
	first := hello_msg()
	reasm.insert(0, first)!
	msg := reasm.next_message()!
	assert msg == first
	assert reasm.base == 6, 'delivery must advance the absolute stream offset'
	assert reasm.ready.len == 0
	reasm.insert(6, 'xy'.bytes())!
	assert reasm.ready == 'xy'.bytes(), 'a chunk continuing the stream must fold into ready'
	assert reasm.pending.len == 0
}

fn test_crypto_reasm_rejects_conflicts_past_delivered_bytes() ! {
	// The same bookkeeping must stay strict about data still held: once the stream
	// base has advanced, rewriting a byte that is merely buffered, not delivered,
	// is a conflict exactly as it is at offset 0.
	mut reasm := CryptoReasm{}
	reasm.insert(0, hello_msg())!
	_ = reasm.next_message()!
	reasm.insert(6, 'abcd'.bytes())!
	reasm.insert(7, 'XX'.bytes()) or {
		assert err.msg().contains('conflicting overlapping')
		assert reasm.ready == 'abcd'.bytes()
		assert reasm.base == 6
		return
	}
	assert false, 'rewriting buffered stream bytes past the base must be rejected'
}
