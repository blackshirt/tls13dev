// Copyright (c) 2026 blackshirt.
//
// tcp_transport.v is the TLS record-layer transport for the TCP Conn: it frames
// handshake/application bytes into the length-prefixed records of RFC 8446 §5,
// batches a flight's records into a single socket push, and reassembles records
// from the TCP byte stream (which may split or coalesce them arbitrarily). The
// handshake core (tls.handshake's state_machine.v) speaks only raw messages;
// this file is the sole place those messages become wire records on the TCP
// path. The recordless QUIC framing (tls.handshake's passthrough.v, RFC 9001 §4)
// uses none of it — QUIC has no TLS record layer.
module tls

import tls.wire

// recv_buf_compact_threshold bounds the consumed prefix recv_buf may retain
// before its unconsumed tail is shifted to the front, making compaction
// amortized O(1) per byte while keeping memory bounded.
const recv_buf_compact_threshold = 16384

// recv_read_size is the number of bytes requested from the socket per read.
// Sized to the largest plaintext record so a full TLS record (plus header)
// typically arrives in one read(2) instead of four; the framing loop still
// copes with whatever fewer bytes the kernel actually returns.
const recv_read_size = max_plaintext_record_len

// write_batch_threshold caps how much ciphertext Conn.write() accumulates in
// memory before pushing it out, so a large write costs roughly one write(2)
// syscall per 128 KiB of records instead of one per 16 KiB record. The bound
// stays well below typical SO_SNDBUF, so a full batch almost always leaves in
// a single syscall; small writes flush on the last chunk and never wait.
const write_batch_threshold = 131072

// max_compat_ccs_records bounds how many middlebox-compatibility dummy
// ChangeCipherSpec records the client tolerates while awaiting its flight.
// RFC 8446 §5 / App. D.4 permit a peer at most one dummy CCS per ClientHello
// (two across a HelloRetryRequest round trip). Each CCS record otherwise hits a
// bare `continue` in do_handshake, so without a cap a malicious server could
// stream them forever and pin the handshake in an unbounded loop — the per-read
// socket timeout never fires because bytes keep arriving.
const max_compat_ccs_records = 2

// validate_compat_ccs checks one middlebox dummy ChangeCipherSpec record's
// framing and enforces the tolerance bound documented at
// max_compat_ccs_records. It takes the running count and returns the updated
// value, so do_handshake can abort as soon as the peer exceeds the bound.
fn validate_compat_ccs(payload []u8, seen int) !int {
	mut total := seen + 1
	if total > max_compat_ccs_records {
		return error('tls: too many change_cipher_spec records during handshake (unexpected_message)')
	}
	// Compliant peers send exactly the single byte 0x01 (App. D.4); anything else
	// is framing garbage, so refusing beats silently swallowing it.
	if payload.len != 1 || payload[0] != 0x01 {
		return error('tls: malformed change_cipher_spec during handshake (must be the single byte 0x01)')
	}
	return total
}

// write_records serializes the records into one buffer and pushes it to the
// peer, coalescing a multi-record flight into a single write(2) syscall: TLS
// rides the TCP byte stream, so the receiver's record framing cannot tell
// whether the bytes went out in one push or several (RFC 8446 §5). A short
// write resumes from the first unwritten byte instead of failing: a blocking
// socket may legitimately accept only part of a large buffer, and the old
// per-record form turned that ordinary kernel behavior into a fake error.
fn (mut c Conn) write_records(recs []Record) ! {
	if c.sock == unsafe { nil } {
		return error('tls: socket is nil')
	}
	if recs.len == 0 {
		return
	}
	mut total := 0
	for rec in recs {
		total += record_header_len + rec.payload.len
	}
	mut batched := []u8{cap: total}
	for rec in recs {
		rec.serialize_into(mut batched)
	}
	mut written := 0
	for written < batched.len {
		n := c.sock.write(batched[written..])!
		if n <= 0 {
			return error('tls: socket write made no progress (${written}/${batched.len} bytes)')
		}
		written += n
	}
}

// read_raw_record blocks until one complete TLS record (header + full payload)
// has been buffered, then parses it in place off recv_buf. TCP may deliver a
// record in pieces or several glued together, so the frame is only consumed
// once its declared length is actually available.
fn (mut c Conn) read_raw_record() !Record {
	// c.read_scratch is a connection-lifetime buffer (allocated once in dial()):
	// sock.read refills it in place, so a record arriving in TCP pieces costs
	// no allocation — every read just appends the received bytes onto recv_buf.
	for {
		avail := c.recv_buf.len - c.recv_pos
		if avail >= record_header_len {
			// Peek the length field (2 bytes at offset 3) without consuming it; do
			// not parse until a whole frame is buffered, since TCP can split records.
			payload_len := int(u16(c.recv_buf[c.recv_pos + 3]) << 8 | u16(c.recv_buf[c.recv_pos + 4]))
			if payload_len > max_ciphertext_record_len {
				return error('record: record length ${payload_len} exceeds maximum allowed ${max_ciphertext_record_len}')
			}
			total := record_header_len + payload_len
			if avail >= total {
				// Parse directly over the live recv_buf: the only bytes that must
				// outlive this call are the record payload, which read_bytes
				// already copies out, so no intermediate frame clone is needed.
				// The frame is consumed and compacted only after parsing, so the
				// aliased slice is never invalidated while the reader walks it.
				mut r := wire.new_reader(c.recv_buf[c.recv_pos..c.recv_pos + total])
				c.recv_pos += total
				rec := parse_record(mut r)!
				c.compact_recv_buf()
				return rec
			}
		}
		if c.sock == unsafe { nil } {
			return error('tls: connection closed (no socket available to read further records)')
		}
		n := c.sock.read(mut c.read_scratch) or {
			return error('tls: connection closed while reading record: ${err}')
		}
		if n == 0 {
			return error('tls: connection closed while reading record')
		}
		c.recv_buf << c.read_scratch[..n]
	}
	return error('tls: unreachable')
}

// compact_recv_buf reclaims the already-consumed prefix of recv_buf: a fully
// drained buffer keeps its capacity (clear retains cap), otherwise the tail is
// shifted to the front once the wasted prefix exceeds recv_buf_compact_threshold.
fn (mut c Conn) compact_recv_buf() {
	if c.recv_pos == c.recv_buf.len {
		// Fully drained: clear() drops the prefix but keeps capacity, so later reads
		// reuse the buffer and recv_pos resets to frame the next record at the front.
		c.recv_buf.clear()
		c.recv_pos = 0
	} else if c.recv_pos >= recv_buf_compact_threshold {
		// Consumed prefix exceeded the bound: shift the live tail down once,
		// amortizing reclaim to O(1) per byte while capping memory near the threshold.
		c.recv_buf = c.recv_buf[c.recv_pos..].clone()
		c.recv_pos = 0
	}
}
