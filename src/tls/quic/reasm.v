// Copyright (c) 2026 blackshirt.
//
// reasm.v implements offset-ordered CRYPTO stream reassembly (RFC 9000 §19.6).
// Unlike a TLS record stream, QUIC CRYPTO bytes can arrive out of order (each
// packet carries a (offset, length) pair), so the engine buffers the contiguous
// prefix and stashes any higher-offset chunk until the gap fills.
module quic

// CryptoReasm reassembles one encryption level's CRYPTO stream. `ready` is the
// contiguous prefix from offset 0; `pending` holds out-of-order chunks keyed by
// their stream offset.
struct CryptoReasm {
mut:
	ready   []u8
	pending map[u64][]u8
}

// insert adds a chunk at `offset`, then folds any pending chunks that have
// become contiguous into `ready`.
fn (mut r CryptoReasm) insert(offset u64, data []u8) {
	if data.len == 0 {
		return
	}
	end := offset + u64(data.len)
	if offset <= u64(r.ready.len) {
		// Overlaps or abuts the ready prefix: append only the new tail.
		if end <= u64(r.ready.len) {
			return // wholly duplicate
		}
		start := int(offset)
		if start < r.ready.len {
			overlap := r.ready.len - start
			r.ready << data[overlap..]
		} else {
			r.ready << data
		}
	} else {
		// A gap: stash it (last-writer-wins on exact duplicates).
		r.pending[offset] = data.clone()
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
				if end > u64(r.ready.len) {
					start := int(off)
					overlap := if start < r.ready.len { r.ready.len - start } else { 0 }
					r.ready << chunk[overlap..]
				}
				r.pending.delete(off)
				progressed = true
			}
		}
	}
}
