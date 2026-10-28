// Copyright (c) 2026 blackshirt.
//
// reassembly.v holds the core's per-level intake buffers: the initial- and
// handshake-level byte streams that have not yet framed into a complete message,
// with their append, drain and terminal-release operations. Framing legality is the
// receive loop's policy (flight.v), not these buffers'.
module handshake

// reassembly_buf_cap is the initial per-level reassembly allocation, not a limit: the
// hard bound a hostile peer must never exceed is enforced against
// max_handshake_message_len in append_and_drain_at and next_recordless_message.
const reassembly_buf_cap = 4096

// ReassemblyBuffers holds the initial- and handshake-level byte streams that do
// not yet form complete messages. Application-level bytes never reach the core.
struct ReassemblyBuffers {
mut:
	initial   []u8 // pre-ServerHello bytes, pending a complete message
	handshake []u8 // handshake-key-protected bytes, pending a complete message
}

// new_reassembly_buffers allocates both level buffers with the standard capacity.
fn new_reassembly_buffers() ReassemblyBuffers {
	return ReassemblyBuffers{
		initial:   []u8{cap: reassembly_buf_cap}
		handshake: []u8{cap: reassembly_buf_cap}
	}
}

// len reports the unconsumed byte count at one level.
fn (b &ReassemblyBuffers) len(level EncryptionLevel) int {
	return match level {
		.initial { b.initial.len }
		.handshake { b.handshake.len }
		.application { 0 }
	}
}

// append adds bytes to one level's reassembly buffer.
fn (mut b ReassemblyBuffers) append(level EncryptionLevel, bytes []u8) {
	match level {
		.initial { b.initial << bytes }
		.handshake { b.handshake << bytes }
		.application {}
	}
}

// handshake_leading_byte returns the first buffered handshake-level byte, if any.
fn (b &ReassemblyBuffers) handshake_leading_byte() ?u8 {
	if b.handshake.len == 0 {
		return none
	}
	return b.handshake[0]
}

// next_message extracts one complete framed message from one level's buffer.
fn (mut b ReassemblyBuffers) next_message(level EncryptionLevel) ![]u8 {
	match level {
		.initial { return next_recordless_message(mut b.initial) }
		.handshake { return next_recordless_message(mut b.handshake) }
		.application { return []u8{} }
	}
}

// take_handshake hands back a copy of the handshake-level buffer and scrubs the
// original, because those bytes were decrypted under handshake keys.
fn (mut b ReassemblyBuffers) take_handshake() []u8 {
	taken := b.handshake.clone()
	wipe_secret(mut b.handshake)
	return taken
}

// release_buffers drops both level buffers on terminal failure. Their contents are
// framing bytes, not key material, so no scrub is owed (§7.5 applies to secrets).
fn (mut b ReassemblyBuffers) release_buffers() {
	b.initial = []u8{}
	b.handshake = []u8{}
}
