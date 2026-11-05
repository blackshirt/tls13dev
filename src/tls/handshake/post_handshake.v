// Copyright (c) 2026 blackshirt.
//
// post_handshake.v decodes NewSessionTicket and KeyUpdate messages (RFC 8446 §4.6).
module handshake

import tls.wire

// parse_key_update decodes a KeyUpdate body (RFC 8446 §4.6.3) and reports whether
// the sender requested that we also update our keys. Each failure tags the alert the
// record adapter must surface, so it can classify from the message alone.
@[direct_array_access]
pub fn parse_key_update(body []u8) !bool {
	if body.len != 1 {
		return error('handshake: KeyUpdate body must be 1 byte (decode_error)')
	}
	if body[0] > 1 {
		return error('handshake: invalid KeyUpdate request_update value ${body[0]} (illegal_parameter)')
	}
	return body[0] == 1
}

// build_key_update creates a KeyUpdate handshake message carrying the §4.6.3
// request_update byte (1 = update_requested, 0 = update_not_requested).
pub fn build_key_update(request_update bool) []u8 {
	val := if request_update { u8(1) } else { u8(0) }
	return wrap_handshake_message(.key_update, [val])
}

// NewSessionTicket holds a parsed NewSessionTicket (RFC 8446 §4.6.1); its fields are
// module-private. HandshakeCore.resumption_psk() consumes all of them when the
// caller asks for a §7.2 PSK, so no public accessor beyond lifetime() / bytes()
// is needed and age/nonce stay private to the module.
@[noinit]
pub struct NewSessionTicket {
mut:
	ticket_lifetime u32  // seconds the ticket may be used after issuance; 0 means no support
	ticket_age_add  u32  // random value for obfuscating ticket age in early_data (§4.6.1)
	ticket_nonce    []u8 // ties the ticket to this connection's resumption master secret
	ticket          []u8 // opaque resumption token to present in a future ClientHello
}

// lifetime returns the ticket_lifetime in seconds.
pub fn (t &NewSessionTicket) lifetime() u32 {
	return t.ticket_lifetime
}

// bytes returns the opaque ticket (the resumption token) to store for a future ClientHello.
pub fn (t &NewSessionTicket) bytes() []u8 {
	return t.ticket
}

// wipe clears the resumption token and nonce when their owning connection is
// torn down; it also releases all ticket metadata held in the parsed value.
pub fn (mut t NewSessionTicket) wipe() {
	for i in 0 .. t.ticket.len {
		t.ticket[i] = 0
	}
	for i in 0 .. t.ticket_nonce.len {
		t.ticket_nonce[i] = 0
	}
	t.ticket_lifetime = 0
	t.ticket_age_add = 0
	t.ticket = []u8{}
	t.ticket_nonce = []u8{}
}

// parse_new_session_ticket decodes NewSessionTicket (RFC 8446 §4.6.1); ticket
// storage belongs to the stack above this core (§4.6.1: the client keeps them
// for a future connection).
@[direct_array_access]
pub fn parse_new_session_ticket(body []u8) !NewSessionTicket {
	mut r := wire.new_reader(body)
	lifetime := r.read_u32()!
	// RFC 8446 §4.6.1: servers MUST NOT use a value greater than 604800 seconds.
	if lifetime > 604800 {
		return error('handshake: ticket_lifetime ${lifetime} exceeds maximum 604800 seconds (illegal_parameter)')
	}
	age_add := r.read_u32()!
	nonce := r.read_vector_u8()!
	ticket := r.read_vector_u16()!
	if ticket.len == 0 {
		return error('handshake: empty ticket in NewSessionTicket (decode_error)')
	}
	_ := r.read_vector_u16()! // extensions (max_early_data, …): skipped because
	// this stack does 1-RTT §7.2 resumption but never early data, so a
	// max_early_data value would be a hint with no code path to honour it.
	if r.remaining() != 0 {
		// Strict framing: leftover bytes mean the ticket was misframed.
		return error('handshake: trailing bytes in NewSessionTicket (decode_error)')
	}
	return NewSessionTicket{
		ticket_lifetime: lifetime
		ticket_age_add:  age_add
		ticket_nonce:    nonce
		ticket:          ticket
	}
}
