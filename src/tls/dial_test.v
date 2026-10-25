// Copyright (c) 2026 blackshirt.
//
// dial_test.v runs the TLS client through dial() over real TCP sockets against
// scripted in-process peers: the full-handshake twin of the fakeserver (record
// layer and all), plus plaintext negatives that exercise the record-layer gates
// end to end.
module tls

import net
import time
import tls.fakeserver
import tls.handshake
import tls.wire

// scripted_read_full fills buf[start..] from the socket until full, so record
// headers and bodies split by TCP are reassembled like Conn.read_raw_record does.
fn scripted_read_full(mut c net.TcpConn, mut buf []u8, start int) ! {
	mut pos := start
	for pos < buf.len {
		n := c.read(mut buf[pos..]) or { return err }
		if n <= 0 {
			return error('tls test: unexpected EOF (read ${pos}/${buf.len} bytes)')
		}
		pos += n
	}
}

// scripted_read_record reads exactly one TLS record off the socket using the
// production parser, so scripts see the same Record the client would.
fn scripted_read_record(mut c net.TcpConn) !Record {
	mut hdr := []u8{len: record_header_len}
	scripted_read_full(mut c, mut hdr, 0)!
	plen := int(hdr[3]) << 8 | int(hdr[4])
	if plen > max_ciphertext_record_len {
		return error('tls test: record length ${plen} exceeds maximum')
	}
	mut full := []u8{len: record_header_len + plen}
	copy(mut full[..record_header_len], hdr)
	scripted_read_full(mut c, mut full, record_header_len)!
	mut r := wire.new_reader(full)
	return read_record(mut r)!
}

// start_scripted_server binds an ephemeral loopback listener, returns its
// address, and runs script against the first connection on a background thread.
fn start_scripted_server(script fn (mut c net.TcpConn) !) (string, chan string) {
	addr_ch := chan string{cap: 1}
	res_ch := chan string{cap: 1}
	spawn scripted_server_worker(script, addr_ch, res_ch)
	addr := <-addr_ch
	return addr, res_ch
}

// scripted_server_worker is the listener thread body: accept once, run the
// script, report the outcome on both channels so the test side never blocks.
fn scripted_server_worker(script fn (mut c net.TcpConn) !, addr_ch chan string, res_ch chan string) {
	mut l := net.listen_tcp(.ip, '127.0.0.1:0', net.ListenOptions{}) or {
		msg := 'ERR listen: ${err.msg()}'
		addr_ch <- msg
		res_ch <- msg
		return
	}
	a := l.addr() or {
		msg := 'ERR addr: ${err.msg()}'
		addr_ch <- msg
		res_ch <- msg
		return
	}
	port := a.port() or {
		msg := 'ERR port: ${err.msg()}'
		addr_ch <- msg
		res_ch <- msg
		return
	}
	addr_ch <- '127.0.0.1:${port}'
	mut c := l.accept() or {
		res_ch <- 'ERR accept: ${err.msg()}'
		l.close() or {}
		return
	}
	script(mut c) or {
		res_ch <- 'ERR script: ${err.msg()}'
		c.close() or {}
		l.close() or {}
		return
	}
	c.close() or {}
	l.close() or {}
	res_ch <- 'OK'
}

// expect_dial_failure dials addr expecting an error whose message contains
// want, waits for the scripted peer to finish, and reports a clean outcome.
fn expect_dial_failure(addr string, want string, res_ch chan string) ! {
	ts := fakeserver.test_trust_store() or { return error('fakeserver trust store: ${err.msg()}') }
	dial(addr, server_name: fakeserver.server_name, root_cas: ts, timeout: 5 * time.second) or {
		if !err.msg().contains(want) {
			return error('dial failed with "${err.msg()}", expected it to contain "${want}"')
		}
		res := <-res_ch
		if res != 'OK' {
			return error('scripted server did not finish cleanly: ${res}')
		}
		return
	}
	return error('dial unexpectedly succeeded; wanted a failure containing "${want}"')
}

// ---- Full handshake over TCP ----
// full_handshake_script is the record-layer twin of the fakeserver flight, with
// split_ticket spreading the NewSessionTicket over two application-key records.
fn full_handshake_script(mut c net.TcpConn) ! {
	run_full_handshake(mut c, false)!
}

// split_ticket_script is run_full_handshake with the NewSessionTicket fragmented.
fn split_ticket_script(mut c net.TcpConn) ! {
	run_full_handshake(mut c, true)!
}

// run_full_handshake drives the whole server flight; split_ticket fragments the ticket.
fn run_full_handshake(mut c net.TcpConn, split_ticket bool) ! {
	ch_rec := scripted_read_record(mut c)!
	if ch_rec.content_type != .handshake {
		return error('expected a handshake record first, got ${ch_rec.content_type}')
	}
	ccs_rec := scripted_read_record(mut c)!
	if ccs_rec.content_type != .change_cipher_spec {
		return error('expected the client dummy CCS second, got ${ccs_rec.content_type}')
	}

	mut srv := fakeserver.new_server(alpn: ['h2', 'http/1.1']) or {
		return error('fakeserver: ${err.msg()}')
	}
	fl := srv.handle_client_hello(ch_rec.payload) or {
		return error('fakeserver CH: ${err.msg()}')
	}
	if fl.is_hrr {
		return error('unexpected HelloRetryRequest in the default configuration')
	}

	// Plaintext ServerHello plus the server's dummy CCS (App. D.4).
	sh_rec := new_record(.handshake, fl.server_hello)
	c.write(sh_rec.serialize()) or { return err }
	c.write(change_cipher_spec().serialize()) or { return err }

	// The rest of the flight, one encrypted record per message, under the server handshake keys.
	skey, siv := srv.server_handshake_keys() or { return error('fakeserver keys: ${err.msg()}') }
	aead := handshake.new_aead_for_suite(.tls_aes_128_gcm_sha256, skey) or { return err }
	mut senc := new_tls_protection(aead, siv)!
	for m in fl.rest {
		enc := senc.encrypt_record(.handshake, m)!
		c.write(enc.serialize()) or { return err }
	}

	// The client's Finished arrives encrypted under the client handshake keys.
	cfin_rec := scripted_read_record(mut c)!
	ckey, civ := srv.client_handshake_keys() or { return error('fakeserver keys: ${err.msg()}') }
	caead := handshake.new_aead_for_suite(.tls_aes_128_gcm_sha256, ckey) or { return err }
	mut cdec := new_tls_protection(caead, civ)!
	dec := cdec.decrypt_record(cfin_rec)!
	if dec.content_type != .handshake {
		return error('client Finished has inner type ${dec.content_type}, expected handshake')
	}
	srv.handle_client_finished(dec.plaintext) or { return error('fakeserver Finished: ${err.msg()}') }

	// Post-handshake: a NewSessionTicket and one application record under the server application keys.
	akey, aiv := srv.server_app_keys() or { return error('fakeserver keys: ${err.msg()}') }
	aaead := handshake.new_aead_for_suite(.tls_aes_128_gcm_sha256, akey) or { return err }
	mut aenc := new_tls_protection(aaead, aiv)!
	nst := srv.new_session_ticket() or { return error('fakeserver NST: ${err.msg()}') }
	if split_ticket {
		// Split the ticket across two records: RFC 8446 §5.2 permits a message to span records.
		cut := 8
		c.write(aenc.encrypt_record(.handshake, nst[..cut])!.serialize()) or { return err }
		c.write(aenc.encrypt_record(.handshake, nst[cut..])!.serialize()) or { return err }
	} else {
		c.write(aenc.encrypt_record(.handshake, nst)!.serialize()) or { return err }
	}
	payload := 'hello from fakeserver'.bytes()
	c.write(aenc.encrypt_record(.application_data, payload)!.serialize()) or { return err }
}

// test_dial_completes_full_handshake_and_reads_app_data checks a full handshake
// negotiates ALPN, delivers app data, and surfaces the post-handshake ticket.
fn test_dial_completes_full_handshake_and_reads_app_data() ! {
	addr, res_ch := start_scripted_server(full_handshake_script)
	if addr.starts_with('ERR') {
		return error(addr)
	}
	ts := fakeserver.test_trust_store()!
	mut conn := dial(addr,
		server_name: fakeserver.server_name
		hsk_options: handshake.HandshakeOptions{
			alpn: ['h2']
		}
		root_cas:    ts
		timeout:     10 * time.second
	)!

	assert conn.negotiated_alpn() == 'h2'

	// read() consumes the NewSessionTicket as post-handshake traffic, then the app bytes.
	mut buf := []u8{len: 64}
	n := conn.read(mut buf)!
	assert buf[..n] == 'hello from fakeserver'.bytes()

	assert conn.session_tickets.len == 1
	assert conn.session_tickets[0].lifetime() == 3600
	assert conn.session_tickets[0].bytes() == [u8(0xaa), 0xbb, 0xcc, 0xdd]

	conn.close() or {}
	res := <-res_ch
	assert res == 'OK'
}

// test_dial_reassembles_post_handshake_message_across_records checks a
// NewSessionTicket fragmented over two records is reassembled (RFC 8446 §5.2).
fn test_dial_reassembles_post_handshake_message_across_records() ! {
	addr, res_ch := start_scripted_server(split_ticket_script)
	if addr.starts_with('ERR') {
		return error(addr)
	}
	ts := fakeserver.test_trust_store()!
	mut conn := dial(addr,
		server_name: fakeserver.server_name
		hsk_options: handshake.HandshakeOptions{
			alpn: ['h2']
		}
		root_cas:    ts
		timeout:     10 * time.second
	)!

	mut buf := []u8{len: 64}
	n := conn.read(mut buf)!
	assert buf[..n] == 'hello from fakeserver'.bytes()
	assert conn.session_tickets.len == 1
	assert conn.session_tickets[0].bytes() == [u8(0xaa), 0xbb, 0xcc, 0xdd]

	conn.close() or {}
	res := <-res_ch
	assert res == 'OK'
}

// ---- Plaintext / malformed-record negatives ----

// alert_before_sh_script rejects the ClientHello with a plaintext fatal alert,
// the only kind of alert legal before the ServerHello (RFC 8446 §6).
fn alert_before_sh_script(mut c net.TcpConn) ! {
	ch_rec := scripted_read_record(mut c)!
	if ch_rec.content_type != .handshake {
		return error('expected a handshake record first, got ${ch_rec.content_type}')
	}
	_ := scripted_read_record(mut c)! // client dummy CCS
	// fatal (2) handshake_failure (40).
	c.write(new_record(.alert, [u8(2), 40]).serialize()) or { return err }
}

// test_dial_rejects_plaintext_alert_before_server_hello checks that a
// plaintext alert before the ServerHello aborts the dial.
fn test_dial_rejects_plaintext_alert_before_server_hello() ! {
	addr, res_ch := start_scripted_server(alert_before_sh_script)
	if addr.starts_with('ERR') {
		return error(addr)
	}
	expect_dial_failure(addr, 'received alert', res_ch)!
}

// sh_trailing_junk_script answers the ClientHello with a ServerHello record
// carrying one extra trailing byte, violating the RFC 8446 §5.1 boundary rule.
fn sh_trailing_junk_script(mut c net.TcpConn) ! {
	ch_rec := scripted_read_record(mut c)!
	if ch_rec.content_type != .handshake {
		return error('expected a handshake record first, got ${ch_rec.content_type}')
	}
	_ := scripted_read_record(mut c)!
	mut srv := fakeserver.new_server() or { return error('fakeserver: ${err.msg()}') }
	fl := srv.handle_client_hello(ch_rec.payload) or { return error('fakeserver CH: ${err.msg()}') }
	mut payload := fl.server_hello.clone()
	payload << 0x00 // the forbidden trailing byte
	c.write(new_record(.handshake, payload).serialize()) or { return err }
}

// test_dial_rejects_trailing_bytes_after_server_hello checks that bytes past
// the ServerHello abort the dial.
fn test_dial_rejects_trailing_bytes_after_server_hello() ! {
	addr, res_ch := start_scripted_server(sh_trailing_junk_script)
	if addr.starts_with('ERR') {
		return error(addr)
	}
	expect_dial_failure(addr, 'misframed ServerHello', res_ch)!
}

// excess_ccs_script floods the client with three dummy CCS records; RFC 8446
// App. D.4 allows one per ClientHello, so the third must abort the handshake.
fn excess_ccs_script(mut c net.TcpConn) ! {
	ch_rec := scripted_read_record(mut c)!
	if ch_rec.content_type != .handshake {
		return error('expected a handshake record first, got ${ch_rec.content_type}')
	}
	_ := scripted_read_record(mut c)! // client dummy CCS
	for _ in 0 .. 3 {
		c.write(change_cipher_spec().serialize()) or { return err }
	}
}

// test_dial_rejects_third_ccs_record checks that a third dummy CCS record
// aborts the handshake.
fn test_dial_rejects_third_ccs_record() ! {
	addr, res_ch := start_scripted_server(excess_ccs_script)
	if addr.starts_with('ERR') {
		return error(addr)
	}
	expect_dial_failure(addr, 'too many change_cipher_spec', res_ch)!
}

// garbage_type_script writes a well-framed record whose content type is not a
// TLS content type at all.
fn garbage_type_script(mut c net.TcpConn) ! {
	ch_rec := scripted_read_record(mut c)!
	if ch_rec.content_type != .handshake {
		return error('expected a handshake record first, got ${ch_rec.content_type}')
	}
	// [type=99] [version 0x0303] [length 0]
	c.write([u8(99), 0x03, 0x03, 0x00, 0x00]) or { return err }
}

// test_dial_rejects_invalid_record_content_type checks that a record with an
// undefined content type is refused.
fn test_dial_rejects_invalid_record_content_type() ! {
	addr, res_ch := start_scripted_server(garbage_type_script)
	if addr.starts_with('ERR') {
		return error(addr)
	}
	expect_dial_failure(addr, 'invalid content type', res_ch)!
}

// ---- HelloRetryRequest over TCP ----

// hrr_script performs the change_group HelloRetryRequest round trip at the
// record layer: HRR+CCS, retry ClientHello+CCS, then the normal flight.
fn hrr_script(mut c net.TcpConn) ! {
	ch_rec := scripted_read_record(mut c)!
	if ch_rec.content_type != .handshake {
		return error('expected a handshake record first, got ${ch_rec.content_type}')
	}
	_ := scripted_read_record(mut c)!

	mut srv := fakeserver.new_server(hrr: .change_group) or { return error('fakeserver: ${err.msg()}') }
	fl1 := srv.handle_client_hello(ch_rec.payload) or { return error('fakeserver CH1: ${err.msg()}') }
	if !fl1.is_hrr {
		return error('expected a HelloRetryRequest')
	}
	c.write(new_record(.handshake, fl1.server_hello).serialize()) or { return err }
	c.write(change_cipher_spec().serialize()) or { return err }

	// The client's retry ClientHello + a fresh dummy CCS (App. D.4).
	ch2_rec := scripted_read_record(mut c)!
	if ch2_rec.content_type != .handshake {
		return error('expected the retry ClientHello as a handshake record')
	}
	_ := scripted_read_record(mut c)!

	fl2 := srv.handle_client_hello(ch2_rec.payload) or { return error('fakeserver CH2: ${err.msg()}') }
	if fl2.is_hrr {
		return error('unexpected second HelloRetryRequest')
	}
	c.write(new_record(.handshake, fl2.server_hello).serialize()) or { return err }
	c.write(change_cipher_spec().serialize()) or { return err }

	skey, siv := srv.server_handshake_keys() or { return error('fakeserver keys: ${err.msg()}') }
	aead := handshake.new_aead_for_suite(.tls_aes_128_gcm_sha256, skey) or { return err }
	mut senc := new_tls_protection(aead, siv)!
	for m in fl2.rest {
		enc := senc.encrypt_record(.handshake, m)!
		c.write(enc.serialize()) or { return err }
	}

	cfin_rec := scripted_read_record(mut c)!
	ckey, civ := srv.client_handshake_keys() or { return error('fakeserver keys: ${err.msg()}') }
	caead := handshake.new_aead_for_suite(.tls_aes_128_gcm_sha256, ckey) or { return err }
	mut cdec := new_tls_protection(caead, civ)!
	dec := cdec.decrypt_record(cfin_rec)!
	srv.handle_client_finished(dec.plaintext) or { return error('fakeserver Finished: ${err.msg()}') }
}

// test_dial_completes_hello_retry_request_round_trip checks that an HRR round
// trip completes and an empty ALPN offer yields an empty pick.
fn test_dial_completes_hello_retry_request_round_trip() ! {
	addr, res_ch := start_scripted_server(hrr_script)
	if addr.starts_with('ERR') {
		return error(addr)
	}
	ts := fakeserver.test_trust_store()!
	mut conn := dial(addr,
		server_name: fakeserver.server_name
		root_cas:    ts
		timeout:     10 * time.second
	)!
	assert conn.negotiated_alpn() == ''
	conn.close() or {}
	res := <-res_ch
	assert res == 'OK'
}

// ---- Failure alerts over TCP ----
// alert_back_script drives the client to fail on a bad CertificateVerify and
// checks its own fatal alert: encrypted, and carrying the expected code.
fn alert_back_script(mut c net.TcpConn) ! {
	ch_rec := scripted_read_record(mut c)!
	if ch_rec.content_type != .handshake {
		return error('expected a handshake record first, got ${ch_rec.content_type}')
	}
	_ := scripted_read_record(mut c)!

	mut srv := fakeserver.new_server(bad_certificate_verify: true) or {
		return error('fakeserver: ${err.msg()}')
	}
	fl := srv.handle_client_hello(ch_rec.payload) or { return error('fakeserver CH: ${err.msg()}') }
	c.write(new_record(.handshake, fl.server_hello).serialize()) or { return err }
	c.write(change_cipher_spec().serialize()) or { return err }

	skey, siv := srv.server_handshake_keys() or { return error('fakeserver keys: ${err.msg()}') }
	aead := handshake.new_aead_for_suite(.tls_aes_128_gcm_sha256, skey) or { return err }
	mut senc := new_tls_protection(aead, siv)!
	for m in fl.rest {
		c.write(senc.encrypt_record(.handshake, m)!.serialize()) or { return err }
	}

	// The client answers with a fatal alert encrypted under its client handshake keys.
	alert_rec := scripted_read_record(mut c)!
	if alert_rec.content_type != .application_data {
		return error('client alert has outer type ${alert_rec.content_type}, expected application_data (encrypted)')
	}
	ckey, civ := srv.client_handshake_keys() or { return error('fakeserver keys: ${err.msg()}') }
	caead := handshake.new_aead_for_suite(.tls_aes_128_gcm_sha256, ckey) or { return err }
	mut cdec := new_tls_protection(caead, civ)!
	dec := cdec.decrypt_record(alert_rec)!
	if dec.content_type != .alert {
		return error('client sent inner type ${dec.content_type}, expected alert')
	}
	peer_alert := handshake.parse_alert(dec.plaintext)!
	if peer_alert.level != .fatal {
		return error('client alert level is ${peer_alert.level}, expected fatal')
	}
	if peer_alert.description != .decrypt_error {
		return error('client alert is ${peer_alert.description}, expected decrypt_error')
	}
}

// test_dial_sends_fatal_alert_on_certificate_verify_failure checks that the
// client answers a bad CertificateVerify with a fatal alert.
fn test_dial_sends_fatal_alert_on_certificate_verify_failure() ! {
	addr, res_ch := start_scripted_server(alert_back_script)
	if addr.starts_with('ERR') {
		return error(addr)
	}
	expect_dial_failure(addr, 'CertificateVerify failed', res_ch)!
}

// bad_record_mac_script drives the client to fail AEAD decryption of a bogus record
// sent under the handshake keys, and checks it answers with a fatal bad_record_mac
// alert — the handshake phase must classify a non-opening record exactly like the
// read() path does, not fall back to the stale .internal_error default.
fn bad_record_mac_script(mut c net.TcpConn) ! {
	ch_rec := scripted_read_record(mut c)!
	if ch_rec.content_type != .handshake {
		return error('expected a handshake record first, got ${ch_rec.content_type}')
	}
	_ := scripted_read_record(mut c)!

	mut srv := fakeserver.new_server() or {
		return error('fakeserver: ${err.msg()}')
	}
	fl := srv.handle_client_hello(ch_rec.payload) or { return error('fakeserver CH: ${err.msg()}') }
	// A valid ServerHello so the client derives and installs its handshake keys.
	c.write(new_record(.handshake, fl.server_hello).serialize()) or { return err }
	c.write(change_cipher_spec().serialize()) or { return err }
	// Then an outer application_data record that cannot AEAD-open under those keys.
	c.write(new_record(.application_data, []u8{len: 28, init: 0xa5}).serialize()) or { return err }

	// The client answers with a fatal alert encrypted under its client handshake keys.
	alert_rec := scripted_read_record(mut c)!
	if alert_rec.content_type != .application_data {
		return error('client alert has outer type ${alert_rec.content_type}, expected application_data (encrypted)')
	}
	ckey, civ := srv.client_handshake_keys() or { return error('fakeserver keys: ${err.msg()}') }
	caead := handshake.new_aead_for_suite(.tls_aes_128_gcm_sha256, ckey) or { return err }
	mut cdec := new_tls_protection(caead, civ)!
	dec := cdec.decrypt_record(alert_rec)!
	if dec.content_type != .alert {
		return error('client sent inner type ${dec.content_type}, expected alert')
	}
	peer_alert := handshake.parse_alert(dec.plaintext)!
	if peer_alert.level != .fatal {
		return error('client alert level is ${peer_alert.level}, expected fatal')
	}
	if peer_alert.description != .bad_record_mac {
		return error('client alert is ${peer_alert.description}, expected bad_record_mac')
	}
}

// test_dial_sends_bad_record_mac_on_undecryptable_flight checks that a record that
// will not open under the handshake keys yields a fatal bad_record_mac alert.
fn test_dial_sends_bad_record_mac_on_undecryptable_flight() ! {
	addr, res_ch := start_scripted_server(bad_record_mac_script)
	if addr.starts_with('ERR') {
		return error(addr)
	}
	expect_dial_failure(addr, 'AEAD decryption failed', res_ch)!
}

// alert_back_pre_sh_script answers the ClientHello with a malformed ServerHello
// body that fails before any keys are derived, then reads the plaintext alert.
fn alert_back_pre_sh_script(mut c net.TcpConn) ! {
	ch_rec := scripted_read_record(mut c)!
	if ch_rec.content_type != .handshake {
		return error('expected a handshake record first, got ${ch_rec.content_type}')
	}
	_ := scripted_read_record(mut c)!
	// A complete ServerHello header with an empty body: the client fails in parse, before installing keys.
	c.write(new_record(.handshake, [u8(0x02), 0x00, 0x00, 0x00]).serialize()) or { return err }

	alert_rec := scripted_read_record(mut c)!
	if alert_rec.content_type != .alert {
		return error('client pre-SH alert has type ${alert_rec.content_type}, expected plaintext alert')
	}
	peer_alert := handshake.parse_alert(alert_rec.payload)!
	if peer_alert.level != .fatal {
		return error('client alert level is ${peer_alert.level}, expected fatal')
	}
}

// test_dial_sends_plaintext_fatal_alert_before_server_hello checks that a
// malformed ServerHello yields a plaintext fatal alert.
fn test_dial_sends_plaintext_fatal_alert_before_server_hello() ! {
	addr, res_ch := start_scripted_server(alert_back_pre_sh_script)
	if addr.starts_with('ERR') {
		return error(addr)
	}
	// A malformed ServerHello fails before classification: the surfaced message is the parse error.
	expect_dial_failure(addr, 'unexpected EOF', res_ch)!
}

// ---- Client authentication (CertificateRequest) over TCP ----

// client_auth_script sends a CertificateRequest, reads the client's encrypted
// empty Certificate, then streams the deferred Cert/CV/Fin tail.
fn client_auth_script(mut c net.TcpConn) ! {
	ch_rec := scripted_read_record(mut c)!
	if ch_rec.content_type != .handshake {
		return error('expected a handshake record first, got ${ch_rec.content_type}')
	}
	_ := scripted_read_record(mut c)!

	mut srv := fakeserver.new_server(client_auth: true) or {
		return error('fakeserver: ${err.msg()}')
	}
	fl := srv.handle_client_hello(ch_rec.payload) or { return error('fakeserver CH: ${err.msg()}') }
	c.write(new_record(.handshake, fl.server_hello).serialize()) or { return err }
	c.write(change_cipher_spec().serialize()) or { return err }

	skey, siv := srv.server_handshake_keys() or { return error('fakeserver keys: ${err.msg()}') }
	aead := handshake.new_aead_for_suite(.tls_aes_128_gcm_sha256, skey) or { return err }
	mut senc := new_tls_protection(aead, siv)!
	// fl.rest is [EncryptedExtensions, CertificateRequest].
	for m in fl.rest {
		c.write(senc.encrypt_record(.handshake, m)!.serialize()) or { return err }
	}

	// The client answers with its empty Certificate under the client handshake keys.
	ckey, civ := srv.client_handshake_keys() or { return error('fakeserver keys: ${err.msg()}') }
	caead := handshake.new_aead_for_suite(.tls_aes_128_gcm_sha256, ckey) or { return err }
	mut cdec := new_tls_protection(caead, civ)!
	ccert_rec := scripted_read_record(mut c)!
	ccert := cdec.decrypt_record(ccert_rec)!
	if ccert.content_type != .handshake {
		return error('client Certificate inner type ${ccert.content_type}, expected handshake')
	}
	tail := srv.handle_client_certificate(ccert.plaintext) or {
		return error('fakeserver client Certificate: ${err.msg()}')
	}

	// The deferred tail continues under the same server handshake key generation.
	for m in tail {
		c.write(senc.encrypt_record(.handshake, m)!.serialize()) or { return err }
	}

	cfin_rec := scripted_read_record(mut c)!
	cfin := cdec.decrypt_record(cfin_rec)!
	if cfin.content_type != .handshake {
		return error('client Finished inner type ${cfin.content_type}, expected handshake')
	}
	srv.handle_client_finished(cfin.plaintext) or { return error('fakeserver Finished: ${err.msg()}') }
}

// test_dial_answers_certificate_request_with_empty_certificate checks that a
// CertificateRequest is answered with an empty Certificate.
fn test_dial_answers_certificate_request_with_empty_certificate() ! {
	addr, res_ch := start_scripted_server(client_auth_script)
	if addr.starts_with('ERR') {
		return error(addr)
	}
	ts := fakeserver.test_trust_store()!
	mut conn := dial(addr,
		server_name: fakeserver.server_name
		root_cas:    ts
		timeout:     10 * time.second
	)!
	assert conn.negotiated_alpn() == ''
	conn.close() or {}
	res := <-res_ch
	assert res == 'OK'
}
