// Copyright (c) 2026 blackshirt.
//
// Socket-free tests for the Conn read-side plumbing: read_raw_record exists to
// reassemble TLS records from a TCP byte stream (glued or split frames), and
// those paths are exercised here by pre-staging recv_buf — a populated buffer
// never reaches the nil sock. The write path and the real handshake loop need
// a live socket; dial_example.v is their end-to-end coverage.
module tls

import net
import sync
import tls.handshake
import tls.pki

// new_test_conn builds a fully-initialized Conn for the socket-free tests below.
// Conn is @[noinit], so a bare &Conn{} would leave every field as garbage; this
// helper supplies a real (but unused) handshake and zeroed buffers instead.
fn new_test_conn() !&Conn {
	mut hs := handshake.new_record_handshake('', []string{}, pki.new_validator(pki.new_trust_store(), false))!
	return &Conn{
		sock:              unsafe { nil }
		hs:                hs
		recv_buf:          []u8{}
		recv_pos:          0
		app_buf:           []u8{}
		app_pos:           0
		closed:            false
		close_notify_sent: false
		fatal_error:       ''
		rlock:             sync.new_mutex()
		wlock:             sync.new_mutex()
		negotiated_alpn:   ''
		server_name:       ''
	}
}

// test_read_raw_record_glued_frames stages two complete serialized records
// back-to-back (what TCP coalescing delivers) and verifies each read returns
// exactly one frame in order with intact payload.
fn test_read_raw_record_glued_frames() ! {
	mut c := new_test_conn()!
	c.recv_buf << new_record(.handshake, [u8(0xde), 0xad]).serialize()
	c.recv_buf << new_record(.handshake, [u8(0xbe), 0xef, 0x11]).serialize()

	rec1 := c.read_raw_record()!
	assert rec1.content_type == .handshake
	assert rec1.payload == [u8(0xde), 0xad]

	rec2 := c.read_raw_record()!
	assert rec2.payload == [u8(0xbe), 0xef, 0x11]
}

// test_read_raw_record_split_frame proves the framing state survives a partial
// trailing record: only the complete frame may be consumed, the leftover
// prefix stays buffered (across compaction) until its tail arrives — the exact
// mid-read disconnect pattern TCP produces.
fn test_read_raw_record_split_frame() ! {
	first := new_record(.handshake, [u8(1), 2, 3, 4]).serialize()
	second := new_record(.handshake, [u8(5), 6, 7]).serialize()

	mut c := new_test_conn()!
	c.recv_buf << first
	c.recv_buf << second[..4] // header plus one payload byte: not a full frame

	rec1 := c.read_raw_record()! // consumes only `first`
	assert rec1.payload == [u8(1), 0x02, 0x03, 0x04]

	c.recv_buf << second[4..] // complete the split frame
	rec2 := c.read_raw_record()!
	assert rec2.payload == [u8(5), 0x06, 0x07]
}

// test_host_from_address covers the dial-address forms that must still yield a
// usable SNI name when Config.server_name is unset.
fn test_host_from_address() ! {
	assert host_from_address('example.com:443') == 'example.com'
	assert host_from_address('[2001:db8::1]:443') == '2001:db8::1'
	assert host_from_address('localhost') == 'localhost'
}

// test_host_from_address_edge_cases pins the remaining dial-address forms that
// must still yield a usable SNI name when Config.server_name is unset.
fn test_host_from_address_edge_cases() ! {
	// Bracketed IPv6 with no trailing port: strip the brackets, keep the address.
	assert host_from_address('[2001:db8::1]') == '2001:db8::1'
	// Splits on the LAST colon, so an embedded colon stays part of the host.
	assert host_from_address('a:b:443') == 'a:b'
	// A bare, port-less host is returned unchanged.
	assert host_from_address('example.com') == 'example.com'
}

// test_read_raw_record_oversized_payload verifies immediate rejection of records
// with declared length > max_ciphertext_record_len before allocating/reading.
fn test_read_raw_record_oversized_payload() ! {
	mut c := new_test_conn()!
	// Header declaring 20000 bytes payload (> max_ciphertext_record_len 16640)
	c.recv_buf << [u8(0x17), 0x03, 0x03, 0x4e, 0x20]
	if _ := c.read_raw_record() {
		assert false
	}
}

// test_conn_nil_safety verifies that calling close() and read(empty) on a
// Conn with nil socket does not crash or panic.
fn test_conn_nil_safety() ! {
	mut c := new_test_conn()!
	c.close()!
	mut empty_buf := []u8{}
	assert c.read(mut empty_buf)! == 0
}

// test_validate_compat_ccs_framing: a CCS body that is not the single byte 0x01
// is framing garbage and must be refused, not silently dropped.
fn test_validate_compat_ccs_framing() ! {
	validate_compat_ccs([u8(0x02)], 0) or {
		assert err.msg().contains('malformed change_cipher_spec')
		return
	}
	assert false
}

// test_validate_compat_ccs_bounds_stream: exactly max_compat_ccs_records
// well-formed dummy CCS records pass (the count is returned and grows), and the
// next one aborts — the cap that stops do_handshake looping on a CCS flood.
fn test_validate_compat_ccs_bounds_stream() ! {
	mut seen := 0
	for i in 0 .. max_compat_ccs_records {
		seen = validate_compat_ccs([u8(0x01)], seen)!
		assert seen == i + 1
	}
	validate_compat_ccs([u8(0x01)], seen) or {
		assert err.msg().contains('too many change_cipher_spec')
		return
	}
	assert false
}

// test_close_notify_is_clean_eof: close_notify must surface as a clean EOF (0)
// with no sticky error, so a caller can distinguish orderly shutdown.
fn test_close_notify_is_clean_eof() ! {
	mut c := new_test_conn()!
	n := c.handle_alert([u8(1), 0])! // level warning, description close_notify
	assert n == 0
	assert c.closed
	assert c.fatal_error == ''
}

// test_fatal_alert_is_sticky_across_reads: a fatal alert must never be reduced
// to a clean EOF (0) on later reads. Previously c.closed was set for fatal
// alerts too, so a second read() returned 0 — recreating the truncation
// ambiguity close_notify exists to prevent. The sticky error is re-surfaced.
fn test_fatal_alert_is_sticky_across_reads() ! {
	mut c := new_test_conn()!
	c.handle_alert([u8(2), 80]) or { // level fatal, description internal_error
		assert err.msg().contains('received alert')
	}
	assert c.fatal_error != ''
	mut buf := []u8{len: 1}
	c.read(mut buf) or {
		assert err.msg().contains('received alert')
		return
	}
	assert false // read must not succeed nor report EOF after a fatal alert
}

// test_close_is_idempotent_with_live_socket exercises teardown over a real
// socket — the path new_test_conn's nil sock cannot reach. close() twice must
// release the fd exactly once: the second call previously re-closed an fd the
// kernel may have recycled for an unrelated connection, which would sever that
// connection instead of failing harmlessly. The handshake core stays fresh
// (never connected) here, so close() sends no alert record — only the fd
// ownership matters to this test.
fn test_close_is_idempotent_with_live_socket() ! {
	mut listener := net.listen_tcp(.ip, '127.0.0.1:0')!
	defer {
		listener.close() or {}
	}
	local := listener.addr()!
	mut sock := net.dial_tcp(local.str())!
	mut hs := handshake.new_record_handshake('', []string{}, pki.new_validator(pki.new_trust_store(), false))!
	mut c := &Conn{
		sock:              sock
		hs:                hs
		recv_buf:          []u8{}
		app_buf:           []u8{}
		closed:            false
		close_notify_sent: false
		sock_closed:       false
		fatal_error:       ''
		rlock:             sync.new_mutex()
		wlock:             sync.new_mutex()
		negotiated_alpn:   ''
		server_name:       ''
	}

	c.close()!
	assert c.closed
	assert c.close_notify_sent
	assert c.sock_closed

	// The second close must be a no-op for the fd: no panic, no re-close.
	c.close()!
	assert c.sock_closed
}
