// Copyright (c) 2026 blackshirt.
//
// Connection-ID helpers. Initial keys derive from the original DCID.
module quic

import crypto.rand

// random_cid returns n random connection-ID bytes (RFC 9000 §5.1).
fn random_cid(n int) ![]u8 {
	if n <= 0 || n > 20 {
		return error('quic: connection ID length ${n} must be 1..20 (RFC 9000 §17.2)')
	}
	return rand.bytes(n)!
}
