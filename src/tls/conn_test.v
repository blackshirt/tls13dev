// Copyright (c) 2026 blackshirt.
//
// Socket-free tests for the Conn read-side plumbing: read_raw_record reassembles
// TLS records from a TCP byte stream, exercised here by pre-staging recv_buf —
// a populated buffer never reaches the nil sock. Also covers the caller-facing
// Config defaults and the connection close path.
module tls

import crypto.aes
import net
import sync
import time
import tls.handshake
import tls.pki

// new_test_conn builds a fully-initialized Conn for the socket-free tests below:
// Conn is @[noinit], so a bare &Conn{} would leave every field as garbage.
fn new_test_conn() !&Conn {
	mut hs := handshake.new_tls_handshake('', handshake.HandshakeOptions{ validator: pki.new_validator(pki.new_trust_store()) })!
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
		deadline_ms:       0 // socket-free fixture: post-handshake shape, no framing cap
		sock_timeout:      0 // unused without the do_handshake loop
		rlock:             sync.new_mutex()
		wlock:             sync.new_mutex()
		negotiated_alpn:   ''
		server_name:       ''
	}
}

// test_read_raw_record_glued_frames checks that two back-to-back serialized
// records are returned one frame at a time, in order, with intact payloads.
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

// test_read_raw_record_split_frame checks that a partial trailing record is not
// consumed until its tail arrives — the mid-read disconnect pattern TCP makes.
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

// test_host_from_address_edge_cases pins the remaining dial-address forms
// (bracketed IPv6, embedded colon, bare host) that must still yield an SNI name.
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

// test_validate_compat_ccs_framing checks that a CCS body other than the single
// byte 0x01 is framing garbage and must be refused, not silently dropped.
fn test_validate_compat_ccs_framing() ! {
	validate_compat_ccs([u8(0x02)], 0) or {
		assert err.msg().contains('malformed change_cipher_spec')
		return
	}
	assert false
}

// test_validate_compat_ccs_bounds_stream checks that exactly
// max_compat_ccs_records dummy CCS records pass and the next one aborts.
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

// test_read_bounds_empty_record_flood checks that Conn.read() gives up after
// max_tolerated_records_per_read consecutive zero-length padding records instead of
// spinning forever, and still delivers real data below the bound (§5.2).
fn test_read_bounds_empty_record_flood() ! {
	key := [u8(0x11), 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
		0xff, 0x00]
	iv := [u8(0xa0), 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab]

	mut c := new_test_conn()!
	mut writer := new_tls_protection(aes.new_aes_gcm(key)!, iv)!
	mut reader := new_tls_protection(aes.new_aes_gcm(key)!, iv)!
	c.s_app_protection = reader

	// Below the bound: a run of empty padding records followed by real data.
	for _ in 0 .. max_tolerated_records_per_read {
		c.recv_buf << writer.encrypt_record(.application_data, []u8{})!.serialize()
	}
	c.recv_buf << writer.encrypt_record(.application_data, [u8(42), 43, 44])!.serialize()
	mut buf := []u8{len: 1}
	assert c.read(mut buf)! == 1
	assert buf[0] == 42
	// The undelivered remainder keeps read() returning until it is drained, and
	// the final drain scrubs the staged plaintext instead of just shortening.
	assert c.read(mut buf)! == 1
	assert c.read(mut buf)! == 1
	assert c.app_buf.len == 0
	assert c.app_pos == 0

	// Past the bound: the very next run of empty records must abort the read.
	// Both sides restart their sequence numbers, as a fresh key generation would.
	writer.seq_num = 0
	c.s_app_protection.seq_num = 0
	for _ in 0 .. max_tolerated_records_per_read + 1 {
		c.recv_buf << writer.encrypt_record(.application_data, []u8{})!.serialize()
	}
	c.read(mut buf) or {
		assert err.msg().contains('too many skipped records')
		assert c.closed
		assert c.fatal_error == err.msg()
		assert c.hs.state() == .failed
		return
	}
	assert false, 'an empty-record flood must not spin read() forever'
}

// test_malformed_record_fails_closed checks that record-framing errors become
// sticky connection failures instead of leaving the read protection state usable.
fn test_malformed_record_fails_closed() ! {
	mut c := new_test_conn()!
	c.recv_buf << [u8(0x7f), 0x03, 0x03, 0x00, 0x00]
	mut buf := []u8{len: 1}
	c.read(mut buf) or {
		assert err.msg().contains('invalid content type')
		assert c.closed
		assert c.fatal_error == err.msg()
		pinned := c.fail_alert or { panic('malformed record must set a fatal alert') }
		assert pinned == handshake.AlertDescription.unexpected_message
		assert c.hs.state() == .failed
		return
	}
	assert false, 'an invalid record content type must fail closed'
}

// test_application_write_failure_fails_closed checks that a failed write
// cannot leave advanced record state available for accidental reuse.
fn test_application_write_failure_fails_closed() ! {
	key := [u8(0x11), 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
		0xff, 0x00]
	iv := [u8(0xa0), 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab]
	mut c := new_test_conn()!
	c.c_app_protection = new_tls_protection(aes.new_aes_gcm(key)!, iv)!
	// write() holds wlock across the encrypt/send and only reaches its phase-2 read-side
	// teardown after releasing it; reproduce that split against the nil test socket.
	c.wlock.lock()
	c.write_application_data([u8(42)]) or {
		c.wlock.unlock()
		assert err.msg().contains('application write failed')
		assert c.closed
		assert c.fatal_error == err.msg()
		// Phase 1 under wlock set the sticky flags; the protection-state wipe and the state
		// transition are write()'s phase 2. Run it here, then assert the terminal teardown.
		c.destroy_read_side()!
		assert c.hs.state() == .failed
		assert c.c_app_protection.iv.len == 0
		return
	}
	c.wlock.unlock()
	assert false, 'a failed socket write must make the connection terminal'
}

// test_post_handshake_reassembly_is_bounded checks that a peer streaming
// incomplete handshake fragments can never grow post_hsk_buf past one capped
// message plus header — the bound must fire as record_overflow before the
// buffer climbs without limit (§5.2; mirrors the core's max_handshake_message_len bound).
fn test_post_handshake_reassembly_is_bounded() ! {
	mut c := new_test_conn()!
	bound := record_header_len + handshake.max_handshake_message_len

	// Header declares a 1 MiB body that never completes: every chunk stays
	// reassembly-exempt from next_recordless_message's own oversized-declared
	// check, so only the running bound can stop it.
	mut chunk := [u8(0x0b), 0x0f, 0xff, 0xf8] // Certificate; declared len 1048568
	chunk << []u8{len: 512, init: 0xbb}
	for _ in 0 .. bound / chunk.len + 2 {
		c.handle_post_handshake(chunk) or {
			assert err.msg().contains('post-handshake reassembly exceeds')
			// Conn.fail_alert is an option (unlike the core's plain field), so unwrap it.
			pinned := c.fail_alert or { panic('the reassembly bound must pin a fail_alert') }
			assert pinned == handshake.AlertDescription.record_overflow
			assert c.closed
			assert c.fatal_error == err.msg()
			assert c.post_hsk_buf.len == 0
			assert c.hs.state() == .failed
			return
		}
		assert c.post_hsk_buf.len <= bound // below the bound the tail just buffers
	}
	assert false, 'unbounded post-handshake reassembly must fail closed'
}

// test_post_handshake_certificate_request_fails_closed checks that an
// unoffered post-handshake authentication request is terminal.
fn test_post_handshake_certificate_request_fails_closed() ! {
	mut c := new_test_conn()!
	c.handle_post_handshake([u8(13), 0, 0, 0]) or {
		assert err.msg().contains('unexpected post-handshake CertificateRequest')
		assert c.closed
		assert c.fatal_error == err.msg()
		assert c.hs.state() == .failed
		return
	}
	assert false
}

// test_read_bounds_handshake_record_flood checks that inner-type-handshake records
// share the skipped-record bound with empty padding: a verified NewSessionTicket
// or KeyUpdate flood must not spin read() without ever delivering data (§4.6).
fn test_read_bounds_handshake_record_flood() ! {
	key := [u8(0x11), 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
		0xff, 0x00]
	iv := [u8(0xa0), 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab]

	mut c := new_test_conn()!
	mut writer := new_tls_protection(aes.new_aes_gcm(key)!, iv)!
	c.s_app_protection = new_tls_protection(aes.new_aes_gcm(key)!, iv)!
	// An incomplete post-handshake fragment (declared body 1048568, never finished):
	// handle_post_handshake buffers and returns without processing, so no parse
	// error can preempt the bound — only the skipped-record cap may stop the flood.
	msg := [u8(4), 0x0f, 0xff, 0xf8] // NewSessionTicket header, declared len 1048568
	for _ in 0 .. max_tolerated_records_per_read + 1 {
		c.recv_buf << writer.encrypt_record(.handshake, msg)!.serialize()
	}
	mut buf := []u8{len: 1}
	c.read(mut buf) or {
		assert err.msg().contains('too many skipped records')
		assert c.closed
		assert c.fatal_error == err.msg()
		return
	}
	assert false, 'a handshake-record flood must not spin read() forever'
}

// test_post_handshake_bounds_messages_per_record checks that a record packing
// more complete messages than the cap is refused before the parse/rekey/response
// work climbs further — a maximal record can pack over 3000 eight-byte bodies.
// Valid NewSessionTickets are used: they are parsed and stored/dropped, whereas
// a KeyUpdate(update_requested) would fail on its response write at the nil
// test socket first.
fn test_post_handshake_bounds_messages_per_record() ! {
	mut c := new_test_conn()!
	nst_body := [u8(0), 0, 0, 1, 0, 0, 0, 0, 1, 0xab, 0, 2, 0xcd, 0xce, 0, 2, 0xef, 0xf0]
	mut payload := []u8{}
	for _ in 0 .. max_post_handshake_messages_per_record + 1 {
		payload << [u8(4), 0, 0, u8(nst_body.len)] // NewSessionTicket, complete
		payload << nst_body
	}
	c.handle_post_handshake(payload) or {
		assert err.msg().contains('too many post-handshake messages in one record')
		pinned := c.fail_alert or { panic('the message bound must pin a fail_alert') }
		assert pinned == handshake.AlertDescription.unexpected_message
		assert c.closed
		return
	}
	assert false, 'a per-record message flood must fail closed at the cap'
}

fn test_read_protocol_violation_fails_closed() ! {
	key := [u8(0x11), 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
		0xff, 0x00]
	iv := [u8(0xa0), 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab]
	mut c := new_test_conn()!
	mut writer := new_tls_protection(aes.new_aes_gcm(key)!, iv)!
	c.s_app_protection = new_tls_protection(aes.new_aes_gcm(key)!, iv)!
	c.recv_buf << writer.encrypt_record(.change_cipher_spec, [u8(1)])!.serialize()

	mut buf := []u8{len: 1}
	c.read(mut buf) or {
		assert err.msg().contains('unexpected inner content type')
		assert c.closed
		assert c.fatal_error == err.msg()
		assert c.hs.state() == .failed
		assert c.s_app_protection.iv.len == 0
		return
	}
	assert false
}

// test_close_notify_is_clean_eof checks that close_notify surfaces as a clean
// EOF (0) with no sticky error, so a caller can distinguish orderly shutdown.
fn test_close_notify_is_clean_eof() ! {
	mut c := new_test_conn()!
	n := c.handle_alert([u8(1), 0])! // level warning, description close_notify
	assert n == 0
	assert c.closed
	assert c.fatal_error == ''
}

// test_close_notify_fatal_level_clean_shutdown pins the §6 receive rule: the
// fatal-level close_notify (the TLS 1.3 conforming leveling, what a peer such
// as Go crypto/tls may send when it treats the shutdown as fatal-graded) must
// return 0 exactly like the warning-level form, so both levelings of the one
// clean-shutdown signal are accepted.
fn test_close_notify_fatal_level_clean_shutdown() ! {
	mut c := new_test_conn()!
	n := c.handle_alert([u8(2), 0])! // level fatal, description close_notify
	assert n == 0
	assert c.closed
	assert c.fatal_error == ''
}

// test_read_rejects_warning_alert pins the §6.2 gate: in TLS 1.3 a
// non-close_notify alert may never be warning level, so no_renegotiation
// dressed as a warning (01 64) is refused as a sticky unexpected_message — an
// error from read(), re-reported on every later read, never a clean 0.
fn test_read_rejects_warning_alert() ! {
	mut c := new_test_conn()!
	c.handle_alert([u8(1), 100]) or { // level warning, description no_renegotiation
		assert err.msg().contains('warning-level alert')
		assert err.msg().contains('unexpected_message')
		assert c.fatal_error == err.msg()
	}
	assert c.fatal_error != ''
	mut buf := []u8{len: 1}
	c.read(mut buf) or {
		assert err.msg().contains('warning-level alert')
		return
	}
	assert false, 'a warning alert must never surface as data or a clean EOF'
}

// test_fatal_alert_is_sticky_across_reads checks that a fatal alert is never
// reduced to a clean EOF (0) on later reads; the sticky error is re-surfaced.
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

// test_close_is_idempotent_with_live_socket checks that close() twice over a
// real socket releases the fd exactly once (no re-close of a recycled fd).
fn test_close_is_idempotent_with_live_socket() ! {
	mut listener := net.listen_tcp(.ip, '127.0.0.1:0')!
	defer {
		listener.close() or {}
	}
	local := listener.addr()!
	mut sock := net.dial_tcp(local.str())!
	mut hs := handshake.new_tls_handshake('', handshake.HandshakeOptions{ validator: pki.new_validator(pki.new_trust_store()) })!
	mut c := &Conn{
		sock:              sock
		hs:                hs
		recv_buf:          []u8{}
		app_buf:           []u8{}
		app_pos:           0
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
	// Two-phase teardown reached every reader-owned protection state (§7.5). The fixture
	// leaves the protection states unset, so this pins that close() never
	// rebound a nonempty IV.
	assert c.s_app_protection.iv.len == 0
	assert c.c_app_protection.iv.len == 0
	assert c.s_hsk_protection.iv.len == 0
	assert c.c_hsk_protection.iv.len == 0

	// The second close must be a no-op for the fd: no panic, no re-close.
	c.close()!
	assert c.sock_closed
}

// test_close_wipes_read_protection_states_and_buffers proves the Finding A two-phase
// teardown actually reaches the reader-owned state: close() must destroy all four
// protection states (including the server/read legs it no longer touches under wlock
// alone) and clear both read-side staging buffers, then surface a clean EOF on a later
// read().
fn test_close_wipes_read_protection_states_and_buffers() ! {
	key := [u8(0x11), 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
		0xff, 0x00]
	iv := [u8(0xa0), 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab]
	mut c := new_test_conn()!
	c.s_hsk_protection = new_tls_protection(aes.new_aes_gcm(key)!, iv)!
	c.c_hsk_protection = new_tls_protection(aes.new_aes_gcm(key)!, iv)!
	c.s_app_protection = new_tls_protection(aes.new_aes_gcm(key)!, iv)!
	c.c_app_protection = new_tls_protection(aes.new_aes_gcm(key)!, iv)!
	// Stage undelivered plaintext and a partial post-handshake message so teardown must
	// reach the reader-owned buffers, not just the protection states.
	c.app_buf << [u8(1), 2, 3]
	c.post_hsk_buf << [u8(4), 5, 6]

	c.close()!

	assert c.s_app_protection.iv.len == 0
	assert c.c_app_protection.iv.len == 0
	assert c.s_hsk_protection.iv.len == 0
	assert c.c_hsk_protection.iv.len == 0
	assert c.app_buf.len == 0
	assert c.app_pos == 0
	assert c.post_hsk_buf.len == 0
	assert c.closed
	assert c.close_notify_sent
	// A read after the two-phase teardown returns a clean 0, never a stale fatal error.
	mut buf := []u8{len: 4}
	assert c.read(mut buf)! == 0
}

// test_write_abort_terminates_read_side proves a write-origin abort destroys the
// reader-owned protection state and buffers only via the phase-2 destroy_read_side()
// (rlock -> wlock), never under wlock alone (Finding A). Forcing the nil-socket write
// failure and then running the same phase 2 write() does must wipe the read protection
// state and clear both buffers.
fn test_write_abort_terminates_read_side() ! {
	key := [u8(0x11), 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
		0xff, 0x00]
	iv := [u8(0xa0), 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab]
	mut c := new_test_conn()!
	c.c_app_protection = new_tls_protection(aes.new_aes_gcm(key)!, iv)!
	c.s_app_protection = new_tls_protection(aes.new_aes_gcm(key)!, iv)!
	c.app_buf << [u8(9), 8, 7]
	c.post_hsk_buf << [u8(6), 5]
	c.wlock.lock()
	c.write_application_data([u8(1)]) or {
		c.wlock.unlock()
		// Phase 1 pinned the sticky failure and left the reader-owned state intact.
		assert c.fatal_error != ''
		assert c.closed
		// Phase 2 (write() runs this after releasing wlock) reaches the read
		// protection state/buffers.
		c.destroy_read_side()!
		assert c.s_app_protection.iv.len == 0
		assert c.app_buf.len == 0
		assert c.post_hsk_buf.len == 0
		return
	}
	c.wlock.unlock()
	assert false, 'a write onto the nil socket must abort'
}

// test_read_surfaces_fatal_on_empty_buffer pins the Finding B reorder: a 0-length
// liveness probe must report a sticky fatal/truncation error rather than a clean EOF,
// so a failed connection can never masquerade as gracefully shut down (§6.1).
fn test_read_surfaces_fatal_on_empty_buffer() ! {
	mut c := new_test_conn()!
	c.fatal_error = 'tls: sticky fatal under test'
	mut empty := []u8{}
	c.read(mut empty) or {
		assert err.msg().contains('sticky fatal under test')
		return
	}
	assert false, 'a 0-length probe must not mask a sticky fatal error'
}

// test_decrypt_failure_alert_mapping pins the shared record-layer decrypt classifier:
// rekey exhaustion is record_overflow, a failed AEAD tag is bad_record_mac, and any
// other failure (e.g. an uninitialized protection state) defaults to unexpected_message.
fn test_decrypt_failure_alert_mapping() {
	assert decrypt_failure_alert('record: sequence limit reached; rekey required (§5.5)') == handshake.AlertDescription.record_overflow
	assert decrypt_failure_alert('record: AEAD decryption failed: bad tag') == handshake.AlertDescription.bad_record_mac
	assert decrypt_failure_alert('record: TLS 1.3 protection not initialized') == handshake.AlertDescription.unexpected_message
}

// test_default_config_applies_field_defaults checks a default Config still
// carries the conservative values (no ALPN offer, 30s timeout, verification on).
fn test_default_config_applies_field_defaults() {
	cfg := default_config('example.com')
	assert cfg.server_name == 'example.com'
	assert cfg.hsk_options.alpn.len == 0
	// The insecure escape hatch stays off.
	assert cfg.insecure_skip_verify == false
	// timeout inherits the declared 30s default rather than the 0 unset value.
	assert cfg.timeout == 30 * time.second
}
