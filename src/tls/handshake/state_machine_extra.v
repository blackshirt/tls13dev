// Copyright (c) 2026 blackshirt.
//
// state_machine_extra.v holds the core's intake plumbing and terminal-failure
// primitives: the per-phase reassembly buffers that hold inbound bytes until they frame
// into a complete message, the receive/dispatch routing that bounds, frames and gates
// those bytes against the state machine's ordering, and the failure-classification
// primitives every error path funnels through. The phase transitions themselves —
// ServerHello/HelloRetryRequest and the encrypted flight — are state_machine.v's.
module handshake

// failure_alert returns the alert description an adapter should surface when
// this handshake dies (RFC 8446 §6).
pub fn (h &HandshakeCore) failure_alert() AlertDescription {
	return h.fail_alert
}

// classify_failure is the core's single terminal-failure primitive: it pins the alert,
// zeroes every derived secret, parks .failed, and returns the IError (§7.5), so no site
// can record an alert and forget to zeroize. Idempotent, so safety nets stay harmless.
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

// core_receive_initial_bytes guards and dispatches inbound pre-ServerHello bytes:
// accepted only while awaiting ServerHello (state == .wait_sh). Misuse is rejected
// without consuming bytes or changing state; legal bytes append then consume.
fn (mut h HandshakeCore) core_receive_initial_bytes(bytes []u8) ![]HandshakeMessage {
	if h.state == .start {
		return error('handshake: handshake bytes fed before create_client_hello() — no ClientHello has been sent yet')
	}
	if h.state == .failed {
		return error('handshake: state machine has failed; further handshake bytes are refused')
	}
	if h.state != .wait_sh {
		return error('handshake: initial handshake bytes are only expected while awaiting ServerHello (state: ${h.state()})')
	}
	return h.append_and_consume(bytes, mut h.buffers.initial, 'initial-phase')
}

// core_receive_handshake_bytes guards and dispatches inbound handshake-key-protected
// bytes: accepted only while inside the encrypted server flight (is_in_flight()).
fn (mut h HandshakeCore) core_receive_handshake_bytes(bytes []u8) ![]HandshakeMessage {
	if h.state == .start {
		return error('handshake: handshake bytes fed before create_client_hello() — no ClientHello has been sent yet')
	}
	if h.state == .failed {
		return error('handshake: state machine has failed; further handshake bytes are refused')
	}
	if !h.is_in_flight() {
		return error('handshake: handshake-phase bytes are only expected after ServerHello and before Finished (state: ${h.state()})')
	}
	return h.append_and_consume(bytes, mut h.buffers.handshake, 'handshake-phase')
}

// append_and_consume bounds each append of `bytes` to the phase reassembly buffer
// before allocating, then drains complete phase messages. `phase` names the phase for
// the over-limit alert. The hard cap is max_handshake_message_len; exceeding it is a
// terminal decode_error. One reassembly loop serves both the initial (pre-ServerHello)
// and handshake (encrypted-flight) phases, keyed by the buffer passed in.
fn (mut h HandshakeCore) append_and_consume(bytes []u8, mut buf []u8, phase string) ![]HandshakeMessage {
	mut out := []HandshakeMessage{}
	mut offset := 0
	limit := handshake_header_len + max_handshake_message_len
	for {
		available := limit - buf.len
		if offset < bytes.len && available == 0 {
			return h.classify_failure(.decode_error, 'handshake: ${phase} reassembly exceeds ${max_handshake_message_len} bytes without completing a message')
		}
		take := if bytes.len - offset > available { available } else { bytes.len - offset }
		if take > 0 {
			buf << bytes[offset..offset + take]
			offset += take
		}
		messages := h.consume_msgs(mut buf) or {
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

// is_consuming_phase reports whether the core is in a phase that accepts inbound
// handshake bytes and can drain complete messages: awaiting ServerHello, or inside
// the encrypted server flight.
fn (h &HandshakeCore) is_consuming_phase() bool {
	return h.state == .wait_sh || h.is_in_flight()
}

// dispatch_handshake_message routes one complete framed message to the phase-correct
// handler: ServerHello/HelloRetryRequest while awaiting ServerHello, otherwise the
// encrypted-flight handler (EE, CertificateRequest, Certificate, CertificateVerify,
// Finished).
fn (mut h HandshakeCore) dispatch_handshake_message(full_msg []u8) ![]HandshakeMessage {
	if h.state == .wait_sh {
		return h.handle_server_hello_message(full_msg)
	}
	return h.handle_handshake_message(full_msg)
}

// consume_msgs drains complete framed messages from `buf`, dispatching each through
// dispatch_handshake_message. It stops when the buffer holds an incomplete header or
// body, or when the core leaves a consuming phase (ServerHello moves out of .wait_sh;
// Finished moves to .connected).
fn (mut h HandshakeCore) consume_msgs(mut buf []u8) ![]HandshakeMessage {
	mut out := []HandshakeMessage{}
	for h.is_consuming_phase() {
		msg := next_recordless_message(mut buf) or {
			return h.fail_with(.decode_error, err)
		}
		if msg.len == 0 {
			break // header or body still incomplete
		}
		out_msgs := h.dispatch_handshake_message(msg) or { return err }
		out << out_msgs
	}
	return out
}

// is_handshake_message_accepted is the single ordering check for the encrypted
// flight: it names the message types legal in the current state, so each handler
// only parses and transitions.
fn (h &HandshakeCore) is_handshake_message_accepted(msg_type HandshakeType) bool {
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

// reassembly_buf_cap is the initial per-phase reassembly allocation, not a limit: the
// hard bound a hostile peer must never exceed is enforced against
// max_handshake_message_len in the append-and-consume paths and
// next_recordless_message.
const reassembly_buf_cap = 4096

// ReassemblyBuffers holds the initial- and handshake-phase byte streams that do
// not yet form complete messages. Application-phase bytes never reach the core.
struct ReassemblyBuffers {
mut:
	initial   []u8 // pre-ServerHello bytes, pending a complete message
	handshake []u8 // handshake-key-protected bytes, pending a complete message
}

// new_reassembly_buffers allocates both phase buffers with the standard capacity.
fn new_reassembly_buffers() ReassemblyBuffers {
	return ReassemblyBuffers{
		initial:   []u8{cap: reassembly_buf_cap}
		handshake: []u8{cap: reassembly_buf_cap}
	}
}

// handshake_leading_byte returns the first buffered handshake-phase byte, if any.
fn (b &ReassemblyBuffers) handshake_leading_byte() ?u8 {
	if b.handshake.len == 0 {
		return none
	}
	return b.handshake[0]
}

// take_handshake hands back a copy of the handshake-phase buffer and scrubs the
// original, because those bytes were decrypted under handshake keys.
fn (mut b ReassemblyBuffers) take_handshake() []u8 {
	taken := b.handshake.clone()
	wipe_secret(mut b.handshake)
	return taken
}

// release_buffers drops both phase buffers on terminal failure. Their contents are
// framing bytes, not key material, so no scrub is owed (§7.5 applies to secrets).
fn (mut b ReassemblyBuffers) release_buffers() {
	b.initial = []u8{}
	b.handshake = []u8{}
}
