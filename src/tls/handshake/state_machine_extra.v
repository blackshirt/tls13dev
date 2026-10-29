// Copyright (c) 2026 blackshirt.
//
// state_machine_extra.v holds the core's intake plumbing and terminal-failure
// primitives: the per-level reassembly buffers that hold inbound bytes until they frame
// into a complete message, the receive/dispatch routing that bounds, frames and gates
// those bytes against the state machine's ordering, and the failure-classification
// primitives every error path funnels through. The phase transitions themselves —
// ServerHello/HelloRetryRequest and the encrypted flight — are state_machine.v's.
module handshake

// failure_alert returns the alert description an adapter should surface when
// this handshake dies (RFC 8446 §6).
fn (h &HandshakeCore) failure_alert() AlertDescription {
	return h.fail_alert
}

// classify_failure is the single terminal-failure primitive for the core: it pins
// the alert the adapter must surface, zeroes every derived secret, parks the
// machine in .failed, and returns the IError to propagate (RFC 8446 §7.5), so a
// call site cannot record an alert and forget to zeroize. Idempotent, so outer
// teardown safety nets stay harmless.
fn (mut h HandshakeCore) classify_failure(alert AlertDescription, message string) IError {
	h.fail_alert = alert
	h.fail_and_zeroize_secrets()
	return error(message)
}

// fail_with classifies a propagated error without each call site repeating the
// err.msg() unwrap.
fn (mut h HandshakeCore) fail_with(alert AlertDescription, err IError) IError {
	return h.classify_failure(alert, err.msg())
}

// receive_msgs_at_level processes bytes using the encryption-level reassembly buffers
// owned by the selected transport facade, returning any outbound messages triggered.
// Module-private: adapters reach it through their phase-named receive_initial_bytes()
// and receive_handshake_bytes() entry points. Initial-level input is accepted only
// while awaiting ServerHello; handshake-level input is accepted only between
// ServerHello and Finished. Phase misuse is rejected without consuming bytes or
// changing state.
fn (mut h HandshakeCore) receive_msgs_at_level(level EncryptionLevel, bytes []u8) ![]HandshakeMessage {
	if h.state == .start {
		return error('handshake: handshake bytes fed before create_client_hello() — no ClientHello has been sent yet')
	}
	if h.state == .failed {
		return error('handshake: state machine has failed; further handshake bytes are refused')
	}
	if level == .application {
		return error('handshake: the handshake core does not accept application-level bytes')
	}
	if !h.level_is_open(level) {
		msg := if level == .handshake {
			'handshake: handshake-level bytes are only expected after ServerHello and before Finished (state: ${h.state()})'
		} else {
			'handshake: initial handshake bytes are only expected while awaiting ServerHello (state: ${h.state()})'
		}
		return error(msg)
	}
	return h.append_and_drain_at(level, bytes)
}

// append_and_drain_at bounds each append before allocating, while still allowing a
// transport to deliver multiple complete messages in one call. Inner failures
// already tear down via classify_failure; the fail_and_zeroize_secrets() safety
// nets below catch anything else — teardown is idempotent.
fn (mut h HandshakeCore) append_and_drain_at(level EncryptionLevel, bytes []u8) ![]HandshakeMessage {
	mut out := []HandshakeMessage{}
	mut offset := 0
	limit := handshake_header_len + max_handshake_message_len
	for {
		available := limit - h.buffers.len(level)
		if offset < bytes.len && available == 0 {
			alert := if level == .initial { 'initial-level' } else { 'handshake-level' }
			return h.classify_failure(.decode_error, 'handshake: ${alert} reassembly exceeds ${max_handshake_message_len} bytes without completing a message')
		}
		take := if bytes.len - offset > available { available } else { bytes.len - offset }
		if take > 0 {
			h.buffers.append(level, bytes[offset..offset + take])
			offset += take
		}
		messages := h.drain_at(level) or {
			h.fail_and_zeroize_secrets()
			return err
		}
		out << messages
		if offset == bytes.len {
			break
		}
	}
	return out
}

// level_is_open reports whether one level's buffer is legal for the current state;
// receive_msgs_at_level and drain_at() share it as the single phase-legality rule.
fn (h &HandshakeCore) level_is_open(level EncryptionLevel) bool {
	return match level {
		.initial { h.state == .wait_sh }
		.handshake { h.in_flight() }
		.application { false }
	}
}

// drain_at consumes every complete message one level's buffer currently holds.
// Framing-boundary checks remain adapter policy.
fn (mut h HandshakeCore) drain_at(level EncryptionLevel) ![]HandshakeMessage {
	mut out := []HandshakeMessage{}
	for h.level_is_open(level) {
		msg := h.buffers.next_message(level) or {
			return h.fail_with(.decode_error, err)
		}
		if msg.len == 0 {
			break // header or body still incomplete
		}
		out_msgs := if level == .initial {
			h.handle_server_hello_message(msg) or { return err }
		} else {
			h.handle_handshake_message(msg) or { return err }
		}
		out << out_msgs
	}
	return out
}

// accepts_handshake_message is the single ordering check for the encrypted
// flight: it names the message types legal in the current state, so each handler
// only parses and transitions.
fn (h &HandshakeCore) accepts_handshake_message(msg_type HandshakeType) bool {
	return match h.state {
		.wait_ee { msg_type == .encrypted_extensions }
		.wait_cert_cr {
			msg_type == .certificate_request || msg_type == .certificate
		}
		.wait_cert { msg_type == .certificate }
		.wait_cv { msg_type == .certificate_verify }
		.wait_finished { msg_type == .finished }
		else { false }
	}
}

// unexpected_handshake_message preserves the per-message wording adapters and
// tests rely on when ordering rejects a message.
fn unexpected_handshake_message(msg_type HandshakeType) string {
	return match msg_type {
		.encrypted_extensions { 'handshake: unexpected EncryptedExtensions' }
		.certificate_request { 'handshake: unexpected CertificateRequest' }
		.certificate { 'handshake: unexpected Certificate' }
		.certificate_verify { 'handshake: unexpected CertificateVerify' }
		.finished { 'handshake: unexpected Finished message' }
		else { 'handshake: unexpected handshake message ${msg_type}' }
	}
}

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
