// Copyright (c) 2026 blackshirt.
//
// cid.v provides connection-ID helpers. A QUIC client picks its own Source
// Connection ID (the server echoes it) and a Destination Connection ID (the
// server may replace it). Initial keys are a fixed function of the *original*
// Destination Connection ID, so the engine keeps that first value separately.
module quic

import crypto.rand

// random_cid returns `n` cryptographically-random connection-ID bytes
// (RFC 9000 §5.1). Connection IDs should not be predictable, so the engine uses
// the platform CSPRNG.
fn random_cid(n int) ![]u8 {
	if n <= 0 || n > 20 {
		return error('quic: connection ID length ${n} must be 1..20 (RFC 9000 §17.2)')
	}
	return rand.bytes(n)!
}
