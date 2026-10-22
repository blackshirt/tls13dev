// Copyright (c) 2026 blackshirt.
//
// reasm.v implements offset-ordered CRYPTO stream reassembly (RFC 9000 §19.6).
// Unlike a TLS record stream, QUIC CRYPTO bytes can arrive out of order (each
// packet carries a (offset, length) pair), so the engine buffers the contiguous
// prefix and stashes any higher-offset chunk until the gap fills.
module quic

// Bound both buffered bytes and per-chunk map overhead for out-of-order input.
const max_crypto_chunks = 256

// CryptoReasm reassembles one encryption level's CRYPTO stream. `ready` is the
// contiguous prefix from offset 0; `pending` holds out-of-order chunks keyed by
// their stream offset.
struct CryptoReasm {
mut:
	ready          []u8
	pending        map[u64][]u8
	buffered_bytes int
}

// insert adds a chunk at `offset`, then folds any pending chunks that have
// become contiguous into `ready`.
fn (mut r CryptoReasm) insert(offset u64, data []u8) ! {
	if data.len == 0 {
		return
	}
	data_len := u64(data.len)
	if offset > u64(max_crypto_buffer) || data_len > u64(max_crypto_buffer) - offset {
		return error('quic: CRYPTO stream range exceeds ${max_crypto_buffer} byte limit')
	}
	end := offset + data_len
	ready_end := u64(r.ready.len)
	if offset < ready_end {
		overlap_end := if end < ready_end { end } else { ready_end }
		for pos in offset .. overlap_end {
			if r.ready[int(pos)] != data[int(pos - offset)] {
				return error('quic: conflicting overlapping CRYPTO data')
			}
		}
	}
	for pending_offset, pending_data in r.pending {
		pending_end := pending_offset + u64(pending_data.len)
		overlap_start := if offset > pending_offset { offset } else { pending_offset }
		overlap_end := if end < pending_end { end } else { pending_end }
		if overlap_start < overlap_end {
			for pos in overlap_start .. overlap_end {
				if data[int(pos - offset)] != pending_data[int(pos - pending_offset)] {
					return error('quic: conflicting overlapping CRYPTO data')
				}
			}
		}
	}
	if offset <= ready_end {
		// Overlaps or abuts the ready prefix: append only the new tail.
		if end <= ready_end {
			return // wholly duplicate
		}
		start := int(offset)
		if start < r.ready.len {
			overlap := r.ready.len - start
			added := data.len - overlap
			if r.buffered_bytes + added > max_crypto_buffer {
				return error('quic: CRYPTO reassembly exceeds ${max_crypto_buffer} byte limit')
			}
			r.ready << data[overlap..]
			r.buffered_bytes += added
		} else {
			if r.buffered_bytes + data.len > max_crypto_buffer {
				return error('quic: CRYPTO reassembly exceeds ${max_crypto_buffer} byte limit')
			}
			r.ready << data
			r.buffered_bytes += data.len
		}
	} else {
		mut merged_start := offset
		mut merged_end := end
		mut merged_offsets := []u64{}
		mut old_bytes := 0
		mut changed := true
		for changed {
			changed = false
			for pending_offset, pending_data in r.pending {
				mut selected := false
				for selected_offset in merged_offsets {
					if pending_offset == selected_offset {
						selected = true
						break
					}
				}
				if selected {
					continue
				}
				pending_end := pending_offset + u64(pending_data.len)
				if pending_end < merged_start || pending_offset > merged_end {
					continue
				}
				merged_offsets << pending_offset
				old_bytes += pending_data.len
				if pending_offset < merged_start {
					merged_start = pending_offset
				}
				if pending_end > merged_end {
					merged_end = pending_end
				}
				changed = true
			}
		}
		merged_len := int(merged_end - merged_start)
		if r.buffered_bytes - old_bytes + merged_len > max_crypto_buffer {
			return error('quic: CRYPTO reassembly exceeds ${max_crypto_buffer} byte limit')
		}
		if r.pending.len - merged_offsets.len + 1 > max_crypto_chunks {
			return error('quic: CRYPTO reassembly exceeds ${max_crypto_chunks} pending chunks')
		}
		mut merged := []u8{len: merged_len}
		for i, b in data {
			merged[int(offset - merged_start) + i] = b
		}
		for pending_offset in merged_offsets {
			pending_data := r.pending[pending_offset] or {
				return error('quic: CRYPTO pending chunk disappeared during merge')
			}
			for i, b in pending_data {
				merged[int(pending_offset - merged_start) + i] = b
			}
		}
		// Merge overlapping or adjacent pending fragments so each stream byte
		// is buffered once and a later shorter retransmission cannot lose a tail.
		for pending_offset in merged_offsets {
			r.pending.delete(pending_offset)
		}
		r.pending[merged_start] = merged
		r.buffered_bytes = r.buffered_bytes - old_bytes + merged_len
	}
	r.drain_pending()
}

// drain_pending folds every pending chunk that now abuts the ready prefix.
fn (mut r CryptoReasm) drain_pending() {
	mut progressed := true
	for progressed {
		progressed = false
		for off, chunk in r.pending {
			if off <= u64(r.ready.len) {
				end := off + u64(chunk.len)
				mut appended := 0
				if end > u64(r.ready.len) {
					start := int(off)
					overlap := if start < r.ready.len { r.ready.len - start } else { 0 }
					r.ready << chunk[overlap..]
					appended = chunk.len - overlap
				}
				r.buffered_bytes += appended - chunk.len
				r.pending.delete(off)
				progressed = true
			}
		}
	}
}
