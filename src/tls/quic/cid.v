// Copyright (c) 2026 blackshirt.
//
// Connection-ID helpers. Initial keys derive from the original DCID.
module quic

import crypto.rand

// max_cid_len is the longest connection ID a peer may carry (RFC 9000 §5.1).
const max_cid_len = 20

// random_cid returns n random connection-ID bytes (RFC 9000 §5.1).
fn random_cid(n int) ![]u8 {
	if n <= 0 || n > max_cid_len {
		return error('quic: connection ID length ${n} must be 1..${max_cid_len} (RFC 9000 §17.2)')
	}
	return rand.bytes(n)!
}
