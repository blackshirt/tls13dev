// Copyright (c) 2026 blackshirt.
//
// ticket_store_disk.v implements DiskTicketStore: a SessionTicketStore that
// persists parsed NewSessionTicket values to a single file in a directory
// (RFC 8446 §4.6.1). Tickets survive process restarts and can be reused as
// resumption PSKs (§7.2) on future connections.
//
// All tickets are stored concatenated in one file named tickets.bin, each
// encoded in its RFC 8446 wire format. Atomic writes (temp file + rename)
// prevent torn files on crash. wipe() truncates the file to zero bytes
// (§7.5).
//
// If the directory cannot be created or read, construction fails and the caller
// should fall back to an in-memory store.
module tls

import os
import tls.handshake

// ticket_store_filename is the filename for the persisted ticket store.
const ticket_store_filename = 'tickets.bin'

// temp_file_suffix is appended during atomic writes to prevent torn files.
const temp_file_suffix = '.tmp'

// DiskTicketStore persists NewSessionTicket values to a single file in a
// directory. It implements SessionTicketStore (read-only tickets() for seeding
// at dial time) and additionally provides put()/wipe() for connection-time
// persistence.
pub struct DiskTicketStore {
	dir  string
	path string
}

// new_disk_ticket_store creates a DiskTicketStore backed by `dir`. The
// directory is created if it does not exist. Existing tickets.bin is scanned
// on construction so tickets() reflects the persisted state.
// Returns an error if the directory cannot be created.
pub fn new_disk_ticket_store(dir string) !DiskTicketStore {
	os.mkdir(dir) or { return error('tls: cannot create ticket store directory ${dir}: ${err.msg()}') }
	return DiskTicketStore{
		dir:  dir
		path: '${dir}/${ticket_store_filename}'
	}
}

// tickets loads all persisted tickets from the store file and returns them as
// NewSessionTicket values. The file is parsed sequentially: each ticket's
// wire-encoded bytes are decoded in order. Corrupt trailing data is skipped.
fn (d DiskTicketStore) tickets() []handshake.NewSessionTicket {
	data := os.read_file(d.path) or { return []handshake.NewSessionTicket{} }
	db := data.bytes()
	mut out := []handshake.NewSessionTicket{}
	mut off := 0
	for off < db.len {
		// Each ticket is prefixed by its u16 length.
		if off + 2 > db.len {
			break
		}
		ticket_len := int(db[off]) << 8 | int(db[off + 1])
		off += 2
		if off + ticket_len > db.len {
			break
		}
		ticket_body := db[off..off + ticket_len]
		off += ticket_len
		ticket := handshake.parse_new_session_ticket(ticket_body) or { continue }
		out << ticket
	}
	return out
}

// put persists a server-issued NewSessionTicket by appending its encoded bytes
// to the store file atomically (temp file + rename).
// Never fails: write errors are silently ignored (the ticket remains in
// Conn's in-memory backlog even if it cannot be persisted).
fn (d DiskTicketStore) put(ticket handshake.NewSessionTicket) {
	// Read existing data, append new ticket, write atomically.
	mut existing := os.read_file(d.path) or { '' }
	mut w := existing.bytes()
	// Prefix with u16 length of the ticket body.
	body := ticket.encode()
	w << u8(body.len >> 8)
	w << u8(body.len & 0xff)
	w << body
	tmp_path := '${d.path}${temp_file_suffix}'
	os.write_file(tmp_path, w.bytestr()) or { return }
	os.rename(tmp_path, d.path) or { return }
}

// wipe truncates the store file to zero bytes (§7.5). Missing files are
// ignored; write errors are silently ignored.
fn (d DiskTicketStore) wipe() {
	os.write_file(d.path, '') or { return }
}
