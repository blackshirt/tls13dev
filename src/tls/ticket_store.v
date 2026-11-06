// Copyright (c) 2026 blackshirt.
//
// ticket_store.v defines the SessionTicketStore abstraction: a read-only source
// of parsed NewSessionTicket values (RFC 8446 §4.6.1) that can be imported into
// a Conn at dial time and turned into resumption PSKs (§7.2) on a future
// connection.
//
// Conn owns its ticket backlog in memory. The store is consulted once at dial
// time to seed the backlog; tickets accepted during the connection are kept in
// Conn's own slice and wiped on teardown (§7.5).
module tls

import tls.handshake

// max_stored_session_tickets bounds how many tickets any store may hold.
// Servers may push many tickets; the client keeps at most this many.
const max_stored_session_tickets = 32

// SessionTicketStore is a read-only source of NewSessionTicket values.
//
// Implementations may keep tickets in memory, on disk, or anywhere else.
// tickets() returns stored tickets ready to be offered as resumption PSKs.
// Called once at dial time to seed Conn's ticket backlog.
pub interface SessionTicketStore {
	tickets() []handshake.NewSessionTicket
}

// InMemoryTicketStore keeps NewSessionTickets in a bounded slice.
// It is the default store used when Config.session_ticket_store is unset.
pub struct InMemoryTicketStore {
mut:
	tickets []handshake.NewSessionTicket
}

// new_in_memory_ticket_store creates a store bounded at max_stored_session_tickets.
pub fn new_in_memory_ticket_store() InMemoryTicketStore {
	return InMemoryTicketStore{
		tickets: []handshake.NewSessionTicket{cap: max_stored_session_tickets}
	}
}

// put stores a server-issued NewSessionTicket, dropping it if the store is full.
// Never fails: when full, the ticket is silently dropped.
fn (mut s InMemoryTicketStore) put(ticket handshake.NewSessionTicket) {
	if s.tickets.len >= max_stored_session_tickets {
		return
	}
	s.tickets << ticket
}

// tickets returns all stored tickets ready to be offered as resumption PSKs.
fn (s InMemoryTicketStore) tickets() []handshake.NewSessionTicket {
	return s.tickets.clone()
}

// wipe scrubs every stored ticket and clears the slice (§7.5).
fn (mut s InMemoryTicketStore) wipe() {
	for i in 0 .. s.tickets.len {
		s.tickets[i].wipe()
	}
	s.tickets.clear()
}
