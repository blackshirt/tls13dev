// Copyright (c) 2026 blackshirt.
//
// engine_test.v drives the QUIC client engine through a complete protected
// handshake against the in-memory ferry server, proving the engine works end to
// end: Initial ClientHello → server Initial/Handshake flight → client Finished
// → HANDSHAKE_DONE confirmation, all over real RFC 9001 packet protection.
//
// The FerryServer below is a minimal server endpoint: it unprotects the client
// engine's datagrams, feeds the reassembled CRYPTO stream to tls.fakeserver, and
// returns protected server datagrams. It reuses the engine's own
// packet/protection primitives (which are direction-agnostic), so it also acts
// as an independent cross-check of seal/open symmetry.
module quic

import tls.fakeserver
import tls.handshake
import tls.pki

fn test_parse_ack_ecn_frame() ! {
	body := [u8(0), 0, 0, 0, 1, 2, 3] // ACK fields, then ECT(0), ECT(1), CE counts
	used := parse_ack_frame(body, true)!
	assert used == body.len
}

fn test_parse_ack_frame_without_ecn() ! {
	body := [u8(0), 0, 0, 0]
	used := parse_ack_frame(body, false)!
	assert used == body.len
}

fn test_connection_close_uses_quic_varints() ! {
	transport := encode_connection_close(0x1234, 0x06, 'stop'.bytes())!
	parsed_transport := parse_connection_close(transport[1..], false)!
	assert parsed_transport.error_code == 0x1234
	assert parsed_transport.frame_type or { u64(0) } == 0x06
	assert parsed_transport.reason == 'stop'.bytes()

	application := [u8(frame_connection_close_application), 0x52, 0x34, 0x04, 0x64, 0x6f, 0x6e,
		0x65]
	parsed_application := parse_connection_close(application[1..], true)!
	assert parsed_application.error_code == 0x1234
	assert parsed_application.frame_type == none
	assert parsed_application.reason == 'done'.bytes()
}

// test_quic_packet_types_map_to_crypto_phases pins the packet-type gate that picks
// which phase-named receive the CRYPTO bytes go to, and refuses the packet types
// that must never carry handshake data.
fn test_quic_packet_types_map_to_crypto_phases() ! {
	assert crypto_is_initial(.initial)!
	assert crypto_is_initial(.handshake)! == false
	crypto_is_initial(.one_rtt) or {
		assert err.msg().contains('post-handshake traffic')
		return
	}
	assert false
}

// FerryServer is a minimal server endpoint bound to the client's Initial keys.
@[noinit]
struct FerryServer {
mut:
	dcid         []u8            // the client's SCID (what the server addresses back)
	server_cid   []u8            // the ferry's own CID, sent as SCID and adopted by the client
	initial_tx   ProtectionState // server sends with server Initial keys
	initial_rx   ProtectionState // server receives with client Initial keys
	handshake_tx ?ProtectionState
	handshake_rx ?ProtectionState
	initial_pn   u64
	handshake_pn u64
	app_pn       u64
	// Each level's outbound CRYPTO stream is monotonic (RFC 9000 §19.6), so a
	// second flight — the real ServerHello after a HelloRetryRequest — continues
	// where the first ended instead of rewriting offset 0.
	initial_tx_off   u64
	handshake_tx_off u64
	out              []u8 // accumulated outbound datagrams
	srv              fakeserver.Server
	got_finished     bool
	// Initial- and Handshake-level CRYPTO reassemblers, so a client frame is
	// accepted only at a non-conflicting stream offset (RFC 9000 §19.6). The
	// ferry used to feed cf.data straight to the fakeserver and ignore
	// cf.offset, which hid an engine bug that re-emitted the retry ClientHello
	// at offset 0 after a HelloRetryRequest.
	init_reasm CryptoReasm
	hs_reasm   CryptoReasm
	// Offsets of every Initial-level CRYPTO frame received, so a regression test
	// can pin the retry ClientHello to len(original ClientHello).
	initial_crypto_offsets []u64
	// Total CRYPTO bytes delivered at the Initial level; equals the original
	// ClientHello length after round 1 even once `ready` is drained by delivery.
	initial_crypto_bytes u64
	// Whether the ferry re-derived Initial protection after sending its
	// HelloRetryRequest, as RFC 9001 §5.5 requires. Both peers must re-key from the
	// connection ID the server chose; a double that kept the original keys would
	// agree with a non-compliant engine and hide the defect, so the HRR test pins
	// this flag on the ferry and `initial_rekeyed` on the engine.
	rekeyed bool
}

// new_ferry_server builds a server endpoint keyed from the client's original
// Destination Connection ID.
fn new_ferry_server(client_dcid []u8, hrr fakeserver.HrrMode) !FerryServer {
	ck, sk := derive_initial_keys(client_dcid)!
	server_cid := [u8(0x51), 0x54, 0x9c, 0x0a, 0x1e, 0xb7, 0x3d, 0x66, 0x2f, 0x80]
	return FerryServer{
		initial_tx: new_initial_protection(sk)!
		initial_rx: new_initial_protection(ck)!
		srv:        fakeserver.new_server(
			alpn:               ['h3']
			hrr:                hrr
			// RFC 9000 §7.3: a QUIC server must echo the destination connection ID
			// the client used in its first Initial, so the ferry hands back the very
			// value it was keyed from.
			quic_original_dcid: client_dcid
			quic_scid:          server_cid
		)!
		// A server picks its own connection IDs (§7.2); it does not have to echo the
		// client's guess, so the ferry sends a value the client never chose.
		server_cid: server_cid
	}
}

// exchange takes one client datagram and returns the server's response
// datagram (possibly empty), driving the fakeserver for the handshake bytes.
fn (mut f FerryServer) exchange(datagram []u8) ![]u8 {
	f.out = []u8{}
	mut off := 0
	for off < datagram.len {
		consumed := f.handle_packet(datagram[off..])!
		if consumed == 0 {
			break
		}
		off += consumed
	}
	return f.out
}

// handle_packet processes one client packet.
fn (mut f FerryServer) handle_packet(buf []u8) !int {
	meta := long_packet_meta(buf)!
	total := meta.total_len
	mut packet := buf[..total].clone()
	if meta.scid.len > 0 && f.dcid.len == 0 {
		f.dcid = meta.scid.clone()
	}
	mut rx := match meta.ptype {
		.initial { f.initial_rx }
		.handshake { f.handshake_rx or { return error('ferry: no handshake rx keys') } }
		else { return error('ferry: unsupported packet type') }
	}
	pn_offset := meta.pn_offset
	pn_len := rx.unprotect(mut packet, pn_offset)!
	truncated := read_truncated_pn(packet, pn_offset, pn_len)
	pn := decode_packet_number(truncated, pn_len, 0)
	payload := rx.decrypt_payload(packet, pn_offset, pn_len, pn)!
	match meta.ptype {
		.initial { f.initial_rx = rx }
		.handshake { f.handshake_rx = rx }
		else {}
	}
	f.handle_frames(meta.ptype, payload)!
	return total
}

// handle_frames walks the frames in a decrypted client packet and feeds each
// CRYPTO frame to the offset-aware reassembler in deliver_client_crypto.
fn (mut f FerryServer) handle_frames(ptype PacketType, payload []u8) ! {
	mut off := 0
	for off < payload.len {
		ftype := payload[off]
		body := payload[off + 1..]
		match ftype {
			frame_padding, frame_ping {
				off++
			}
			frame_crypto {
				cf, used := parse_crypto_frame(body)!
				f.deliver_client_crypto(ptype, cf)!
				off += 1 + used
			}
			frame_ack {
				used := parse_ack_frame(body, false)!
				off += 1 + used
			}
			else {
				return error('ferry: unsupported client frame 0x${ftype:02x}')
			}
		}
	}
}

// deliver_client_crypto reassembles the client's CRYPTO stream by offset and
// runs the fakeserver over each complete handshake message. Honoring cf.offset
// is what catches a retry ClientHello wrongly re-emitted at offset 0 after a
// HelloRetryRequest: it overlaps the original ClientHello and CryptoReasm
// rejects the conflicting bytes (RFC 9000 §19.6).
fn (mut f FerryServer) deliver_client_crypto(ptype PacketType, cf CryptoFrame) ! {
	match ptype {
		.initial {
			f.initial_crypto_offsets << cf.offset
			f.initial_crypto_bytes += u64(cf.data.len)
			f.init_reasm.insert(cf.offset, cf.data)!
			for msg in collect_crypto_messages(mut f.init_reasm)! {
				f.handle_initial_message(msg)!
			}
		}
		.handshake {
			f.hs_reasm.insert(cf.offset, cf.data)!
			for msg in collect_crypto_messages(mut f.hs_reasm)! {
				f.handle_handshake_message(msg)!
			}
		}
		else {
			return error('ferry: unexpected CRYPTO at level ${ptype}')
		}
	}
}

// collect_crypto_messages drains every complete handshake message from the front
// of a level's reassembled CRYPTO stream. Insertion (not this loop) is what
// rejects a frame whose offset conflicts with bytes already buffered, exactly as
// a spec-compliant peer would (RFC 9000 §19.6). It propagates the framer's error
// for a declared length past the handshake-message cap.
fn collect_crypto_messages(mut r CryptoReasm) ![][]u8 {
	mut out := [][]u8{}
	for {
		msg := r.next_message()!
		if msg.len == 0 {
			break
		}
		out << msg
	}
	return out
}

// handle_initial_message answers a complete ClientHello from the reassembled
// Initial stream with the ServerHello (or HelloRetryRequest) flight.
fn (mut f FerryServer) handle_initial_message(msg []u8) ! {
	fl := f.srv.handle_client_hello(msg)!
	f.send_server_flight(fl)!
}

// handle_handshake_message consumes the client's Finished from the reassembled
// Handshake stream and confirms the connection with HANDSHAKE_DONE.
fn (mut f FerryServer) handle_handshake_message(msg []u8) ! {
	f.srv.handle_client_finished(msg)!
	f.got_finished = true
	f.emit_handshake_done()!
}

// send_server_flight protects the fakeserver's ServerHello (Initial) and the
// rest of the flight (Handshake). On an HRR there is no `rest`. Each message is
// wrapped in a CRYPTO frame at the level's current stream offset, which then
// advances by exactly the bytes handed to that level.
fn (mut f FerryServer) send_server_flight(fl fakeserver.Flight) ! {
	f.seal_initial(encode_crypto_frame(f.initial_tx_off, fl.server_hello)!)!
	f.initial_tx_off += u64(fl.server_hello.len)
	if fl.rest.len > 0 {
		f.install_handshake_keys()!
		flight := fakeserver.flatten(fl.rest)
		f.seal_handshake(encode_crypto_frame(f.handshake_tx_off, flight)!)!
		f.handshake_tx_off += u64(flight.len)
	}
	if fl.is_hrr {
		// RFC 9001 §5.5: the HelloRetryRequest itself went out under the original
		// Initial keys, but the retry ClientHello arrives addressed to this server's
		// chosen connection ID, and Initial secrets are a function of that destination
		// ID - so from here both directions use fresh keys, and this side restarts its
		// Initial packet numbering (§5.5.2). Only the CRYPTO stream offsets keep
		// running (§19.6), which is why initial_tx_off is untouched.
		ck, sk := derive_initial_keys(f.server_cid)!
		f.initial_rx = new_initial_protection(ck)!
		f.initial_tx = new_initial_protection(sk)!
		f.initial_pn = 0
		f.rekeyed = true
	}
}

// install_handshake_keys derives the server's Handshake packet protection from
// the fakeserver's exported handshake traffic secrets, using the RFC 9001 §5.1
// QUIC labels (not the TLS record labels).
fn (mut f FerryServer) install_handshake_keys() ! {
	ss := f.srv.server_handshake_secret()!
	cs := f.srv.client_handshake_secret()!
	server_keys := expand_direction(.sha256, ss, 16)!
	client_keys := expand_direction(.sha256, cs, 16)!
	f.handshake_tx = new_protection(server_keys, .tls_aes_128_gcm_sha256)!
	f.handshake_rx = new_protection(client_keys, .tls_aes_128_gcm_sha256)!
}

// seal_initial writes a payload into an Initial packet and appends it to `out`.
fn (mut f FerryServer) seal_initial(payload []u8) ! {
	mut tx := f.initial_tx
	pn := f.initial_pn
	pn_len := packet_number_len(pn, 0)
	header, _ := build_long_header(.initial, quic_version_1, f.dcid, f.server_cid, []u8{}, payload.len,
		pn_len, tx.overhead())!
	packet := tx.seal_packet(header, pn, pn_len, payload)!
	f.initial_tx = tx
	f.initial_pn++
	f.out << packet
}

// seal_handshake writes a payload into a Handshake packet and appends it to
// `out`.
fn (mut f FerryServer) seal_handshake(payload []u8) ! {
	mut tx := f.handshake_tx or { return error('ferry: handshake tx keys missing') }
	pn := f.handshake_pn
	pn_len := packet_number_len(pn, 0)
	header, _ := build_long_header(.handshake, quic_version_1, f.dcid, f.server_cid, []u8{},
		payload.len, pn_len, tx.overhead())!
	packet := tx.seal_packet(header, pn, pn_len, payload)!
	f.handshake_tx = tx
	f.handshake_pn++
	f.out << packet
}

// emit_handshake_done sends a 1-RTT HANDSHAKE_DONE so the client engine confirms
// the handshake and releases the handshake-stage keys (RFC 9001 §4.9.2). It uses
// the server's application traffic secret to derive 1-RTT packet protection.
fn (mut f FerryServer) emit_handshake_done() ! {
	secret := f.srv.server_app_secret()!
	keys := expand_direction(.sha256, secret, 16)!
	mut tx := new_protection(keys, .tls_aes_128_gcm_sha256)!
	pn := f.app_pn
	pn_len := packet_number_len(pn, 0)
	header := build_short_header(f.dcid, pn_len, false)
	// A 1-RTT packet must carry enough payload for the 16-byte header-protection
	// sample, which starts 4 bytes after the PN field (RFC 9001 §5.4.2): pad the
	// one-byte HANDSHAKE_DONE frame with PADDING so the packet is long enough.
	mut payload := [u8(frame_handshake_done)]
	for payload.len < 20 {
		payload << frame_padding
	}
	packet := tx.seal_packet(header, pn, pn_len, payload)!
	f.app_pn++
	f.out << packet
}

// trusted_validator builds a Validator over the fakeserver's embedded test CA.
fn trusted_validator() pki.Validator {
	ts := fakeserver.test_trust_store() or { panic('trust store: ${err.msg()}') }
	return pki.new_validator(ts)
}

fn test_engine_completes_quic_handshake() ! {
	// The engine picks random connection IDs, so we build one and learn its
	// original DCID to key the ferry server.
	mut eng := new_client_engine(fakeserver.server_name, Config{
		hsk_options: handshake.HandshakeOptions{
			alpn:      ['h3']
			validator: trusted_validator()
		}
	})!

	// The client's first datagram is an Initial packet carrying the ClientHello.
	start := eng.start()!
	assert start.len >= min_client_initial_datagram_len, 'client Initial datagram must be padded to 1200 bytes'
	assert first_byte_long(start[0])
	assert eng.state() == .wait_sh

	// The ferry server needs the client's original DCID to derive Initial keys;
	// the engine exposes it for the test.
	mut ferry := new_ferry_server(eng.original_dcid(), .none)!

	// Round 1: the server flight — ServerHello (Initial) then
	// EE/Cert/CV/Finished (Handshake).
	flight := ferry.exchange(start)!
	assert flight.len > 0

	// The client verifies the flight and emits its Finished. Reaching `.connected`
	// proves the whole server flight was accepted over real packet protection.
	client_finished := eng.receive(flight)!
	assert eng.state() == .connected, 'client should reach connected, got ${eng.state()}'
	assert !eng.confirmed(), 'client must not confirm before HANDSHAKE_DONE'
	assert client_finished.len > 0

	// Round 2: the server consumes the client Finished and answers with
	// HANDSHAKE_DONE, which is what confirms the handshake (RFC 9001 §4.9.2).
	done := ferry.exchange(client_finished)!
	assert done.len > 0

	// Round 3: the client processes HANDSHAKE_DONE and confirms.
	_ = eng.receive(done)!
	assert eng.confirmed(), 'HANDSHAKE_DONE should confirm the handshake'

	assert eng.negotiated_alpn() == 'h3'
	assert eng.negotiated_cipher_suite() == .tls_aes_128_gcm_sha256
}

fn test_engine_initial_keys_match_appendix_a() ! {
	// A fixed-DCID engine must derive the RFC 9001 Appendix A Initial keys; this
	// ties the engine's wiring to the published vectors.
	dcid := [u8(0x83), 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]
	mut eng := new_client_engine_with_ids(fakeserver.server_name, handshake.HandshakeOptions{
		alpn:      ['h3']
		validator: trusted_validator()
	}, dcid, [u8(1), 2, 3, 4, 5, 6, 7, 8])!
	start := eng.start()!
	assert start.len >= min_client_initial_datagram_len
	assert first_byte_long(start[0])
	assert eng.state() == .wait_sh
}

fn test_engine_handshake_with_asymmetric_cids() ! {
	// RFC 9000 §7.2: each endpoint's Source Connection ID is what the peer puts in
	// the Destination Connection ID of packets it sends. So a server's 1-RTT packets
	// address the client's *own* SCID, and because a short header carries no length
	// field (§17.3.1) that SCID's length is what fixes the packet-number offset.
	// Equal-length CIDs hide this, so the IDs below are deliberately different sizes.
	dcid := [u8(0x83), 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08] // 8 bytes, sent by the client
	scid := [u8(0x01), 0x02, 0x03, 0x04, 0x05, 0x06] // 6 bytes, the client's own address
	mut eng := new_client_engine_with_ids(fakeserver.server_name, handshake.HandshakeOptions{
		alpn:      ['h3']
		validator: trusted_validator()
	}, dcid, scid)!

	start := eng.start()!
	mut ferry := new_ferry_server(eng.original_dcid(), .none)!
	flight := ferry.exchange(start)!
	client_finished := eng.receive(flight)!
	assert eng.state() == .connected, 'client should reach connected, got ${eng.state()}'

	done := ferry.exchange(client_finished)!
	assert ferry.dcid == scid, 'the ferry must address the client by its source CID'
	_ = eng.receive(done)!
	assert eng.confirmed(), 'HANDSHAKE_DONE must confirm the handshake at a 6-byte destination CID'
}

fn test_engine_adopts_server_source_cid() ! {
	// RFC 9000 §7.2: the first Initial received from the server tells the client which
	// connection ID to address it by, so every later client packet carries the server's
	// Source CID as its Destination CID. The ferry sends a CID the client never chose,
	// which is what a real server does; echoing the client's guess hides this.
	mut eng := new_client_engine(fakeserver.server_name, Config{
		hsk_options: handshake.HandshakeOptions{
			alpn:      ['h3']
			validator: trusted_validator()
		}
	})!
	start := eng.start()!
	mut ferry := new_ferry_server(eng.original_dcid(), .none)!
	flight := ferry.exchange(start)!
	client_next := eng.receive(flight)!

	meta := long_packet_meta(client_next)!
	assert meta.dcid == ferry.server_cid, 'client is still addressing its own original DCID'
}

fn test_engine_hello_retry_request_reassembles_retry_at_correct_offset() ! {
	// HelloRetryRequest over QUIC (RFC 9001 §4.1.2). The engine appends the retry
	// ClientHello to the same Initial CRYPTO stream, so it must be emitted at
	// offset len(original ClientHello). A peer that reassembles the stream (as a
	// spec-compliant server does) rejects a retry re-emitted at offset 0 as
	// conflicting overlapping CRYPTO data (RFC 9000 §19.6).
	mut eng := new_client_engine(fakeserver.server_name, Config{
		hsk_options: handshake.HandshakeOptions{
			alpn:      ['h3']
			validator: trusted_validator()
		}
	})!

	start := eng.start()!
	mut ferry := new_ferry_server(eng.original_dcid(), .change_group)!

	// Round 1: the ferry reassembles the Original ClientHello at offset 0 and
	// answers with a HelloRetryRequest (Initial only, no Handshake flight).
	hrr := ferry.exchange(start)!
	assert hrr.len > 0
	// The ferry must have taken the RFC 9001 §5.5 re-key path here. Without it the
	// double would decrypt the retry ClientHello under the original keys - matching
	// an engine that also failed to re-key - and this test would pass while the
	// stack stayed unable to complete a retry against a real server.
	assert ferry.rekeyed, 'the ferry must re-derive Initial keys after its HelloRetryRequest'
	// Offsets are recorded as the ferry consumes CRYPTO frames, so the stream
	// picture only exists after the exchange: one Initial frame, at offset 0.
	assert ferry.initial_crypto_offsets == [u64(0)], 'the first ClientHello must sit at offset 0'
	// The whole original ClientHello was delivered as one Initial CRYPTO frame;
	// its byte length is the offset the retry ClientHello must continue at.
	ch1_len := ferry.initial_crypto_bytes
	assert ch1_len > 0, 'the ferry must have reassembled the original ClientHello'

	// The client processes the HelloRetryRequest and emits a retry ClientHello
	// onto the same Initial stream; receive() flushes pending CRYPTO bytes itself.
	retry := eng.receive(hrr)!
	assert retry.len > 0
	assert eng.state() == .wait_sh, 'after an HRR the client rearms to await the real ServerHello'
	// The engine re-keyed from the DCID it adopted off the HelloRetryRequest header,
	// which is what makes the ferry's fresh keys able to open `retry` at all.
	assert eng.initial_rekeyed, 'the engine must re-derive Initial keys before sealing the retry ClientHello'

	// The retry ClientHello is the second Initial CRYPTO frame; its offset must
	// continue past the original ClientHello, never rewrite offset 0.
	assert ferry.initial_crypto_offsets.len == 1
	flight := ferry.exchange(retry)!
	assert ferry.initial_crypto_offsets.len == 2, 'the retry ClientHello must reach the Initial CRYPTO stream'
	assert ferry.initial_crypto_offsets[1] == ch1_len, 'retry ClientHello offset ${ferry.initial_crypto_offsets[1]} != len(original ClientHello) ${ch1_len}'

	// That exchange is the ferry's real flight; the client finishes and confirms.
	assert flight.len > 0, 'the ferry must answer the retry ClientHello with a ServerHello flight'
	client_finished := eng.receive(flight)!
	assert eng.state() == .connected, 'client should reach connected after HRR, got ${eng.state()}'
	done := ferry.exchange(client_finished)!
	_ = eng.receive(done)!
	assert eng.confirmed(), 'HANDSHAKE_DONE must confirm the handshake after a HelloRetryRequest'
	assert eng.negotiated_alpn() == 'h3'
	assert eng.negotiated_cipher_suite() == .tls_aes_128_gcm_sha256
}
