// Copyright (c) 2026 blackshirt.
//
// engine.v is the QUIC client engine: it drives the transport-neutral
// tls.handshake state machine over protected QUIC packets, so a caller can run a
// full RFC 9001 handshake in memory or over any datagram transport without
// touching the TLS record layer.
//
// The engine owns everything the handshake core deliberately does not:
//
//   * per-level packet-number spaces (Initial, Handshake, 1-RTT),
//   * per-level packet protection, keyed from Initial secrets (§5.2, derived
//     here) and from the core's exported Handshake/Application secrets (§5.1),
//   * CRYPTO frame packing and stream reassembly (its own offset-ordered
//     buffer, separate from the core's message reassembler, because a QUIC
//     CRYPTO stream may arrive out of order and re-encrypted per packet),
//   * the packet loop that turns handshake output into packets to send and
//     turns received CRYPTO bytes into handshake input.
//
// What it does NOT do (see QUIC.md §7): ACK-based loss recovery, congestion
// control, streams, flow control, connection migration, Retry/0-RTT, or the
// 1-RTT Key Phase update. It is a handshake engine, not a full QUIC stack.
module quic

import tls.handshake

// quic_version_1 is the RFC 9000 version number this engine speaks.
pub const quic_version_1 = u32(0x00000001)

// max_datagram_size bounds reassembly buffers defensively.
const max_crypto_buffer = 1 << 20

// LevelKeys holds one level's packet-number-space state and its inbound CRYPTO
// reassembly. Protection state lives in the per-direction option fields on
// Conn.
struct LevelKeys {
mut:
	next_pn    u64         // Next packet number to send in this space.
	largest_rx u64         // Largest received packet number, used for reconstruction.
	any_rx     bool        // Whether any packet has been received in this space.
	reasm      CryptoReasm // Contiguous inbound CRYPTO stream and pending fragments.
}

// Conn is a QUIC client handshake. It wraps a `handshake.QuicHandshake`
// and the packet layer around it. Construct it with new_client_engine, feed it
// datagrams, and take the datagrams it returns to send.
@[noinit]
pub struct Conn {
mut:
	// TLS handshake state and negotiated parameters.
	hs handshake.QuicHandshake // Shared TLS handshake and traffic-secret state.

	// Connection IDs used for packet routing and Initial key derivation.
	dcid      []u8 // Current destination CID used in outbound packets.
	scid      []u8 // This endpoint's source CID, advertised to the peer.
	orig_dcid []u8 // Original destination CID; Initial keys remain based on it.
	adopted   bool // Whether a successfully decrypted server Initial set dcid.

	// Per-level packet protection, with independent send and receive state.
	initial_tx   ?ProtectionState // Initial keys for outbound packets.
	initial_rx   ?ProtectionState // Initial keys for inbound packets.
	handshake_tx ?ProtectionState // Handshake keys for outbound packets.
	handshake_rx ?ProtectionState // Handshake keys for inbound packets.
	app_tx       ?ProtectionState // 1-RTT keys for outbound packets.
	app_rx       ?ProtectionState // 1-RTT keys for inbound packets.

	// Packet-number spaces and inbound CRYPTO reassembly, one per level.
	initial_ns   LevelKeys
	handshake_ns LevelKeys
	app_ns       LevelKeys

	// Outbound TLS handshake bytes awaiting CRYPTO packetization.
	tx_crypto_initial []u8
	tx_crypto_hands   []u8

	// Connection and handshake lifecycle.
	confirmed   bool // Whether HANDSHAKE_DONE was received.
	closed      bool // Whether the engine has entered its terminal closed state.
	close_error u64  // Last QUIC error code set when closing, if any.

	// Current 1-RTT Key Phase bit; key updates are not implemented yet.
	key_phase bool
}

// new_client_engine constructs a QUIC client connection for server_name.
// Configure TLS behavior through Config; connection IDs are generated
// automatically, and Initial keys are derived from the original DCID (§5.2).
pub fn new_client_engine(server_name string, config Config) !Conn {
	return new_client_engine_with_ids(server_name, config.handshake_options,
		random_cid(8)!, random_cid(8)!)!
}

// new_client_engine_with_ids constructs an engine with caller-chosen connection
// IDs. It is private because fixed IDs are only needed by package tests.
fn new_client_engine_with_ids(server_name string, options handshake.HandshakeOptions, dcid []u8, scid []u8) !Conn {
	mut hs_options := options
	hs_options.quic_transport_params = handshake.QuicTransportParameters{
		initial_scid: scid.clone()
	}
	hs := handshake.new_quic_handshake(server_name, hs_options)!
	mut eng := Conn{
		hs:        hs
		dcid:      dcid.clone()
		scid:      scid.clone()
		orig_dcid: dcid.clone()
	}
	eng.install_initial_keys()!
	return eng
}

// install_initial_keys derives and stores the Initial protection in both
// directions (RFC 9001 §5.2).
fn (mut e Conn) install_initial_keys() ! {
	ck, sk := derive_initial_keys(e.orig_dcid)!
	e.initial_tx = new_initial_protection(ck)!
	e.initial_rx = new_initial_protection(sk)!
}

// state exposes the handshake state (handshake.HandshakeState) for polling.
pub fn (e &Conn) state() handshake.HandshakeState {
	return e.hs.state()
}

// negotiated_alpn returns the server's ALPN pick ('' if none).
pub fn (e &Conn) negotiated_alpn() string {
	return e.hs.negotiated_alpn()
}

// negotiated_cipher_suite returns the negotiated suite.
pub fn (e &Conn) negotiated_cipher_suite() handshake.CipherSuite {
	return e.hs.negotiated_cipher_suite()
}

// confirmed reports whether the engine has processed HANDSHAKE_DONE and released
// the handshake-stage material.
pub fn (e &Conn) confirmed() bool {
	return e.confirmed
}

// original_dcid returns the Destination Connection ID the engine used in its
// first Initial packet. Initial keys are a fixed function of it (RFC 9001 §5.2),
// so a peer needs it to derive matching Initial protection.
pub fn (e &Conn) original_dcid() []u8 {
	return e.orig_dcid
}

// source_cid returns the engine's Source Connection ID (the server echoes it).
pub fn (e &Conn) source_cid() []u8 {
	return e.scid
}

// failure_alert returns the alert the handshake core classified on failure.
pub fn (e &Conn) failure_alert() handshake.AlertDescription {
	return e.hs.failure_alert()
}

// close_error_code returns the QUIC transport error code the engine last closed
// with (a CRYPTO_ERROR, 0x100 + alert, on a handshake failure).
pub fn (e &Conn) close_error_code() u64 {
	return e.close_error
}

// start returns the initial outbound datagram carrying the first ClientHello in
// an Initial packet. It must be called once after construction, before any input
// is fed (RFC 9000 §7).
pub fn (mut e Conn) start() ![]u8 {
	ch := e.hs.create_client_hello()!
	e.tx_crypto_initial << ch
	return e.flush()!
}

// receive processes one received datagram and returns the datagrams to send in
// response. It decrypts each coalesced packet, appends CRYPTO bytes to the
// matching level's stream, drives the handshake core with newly-completed
// messages, installs handshake/application keys as the core exports them, and
// flushes any outbound handshake bytes into fresh packets.
pub fn (mut e Conn) receive(datagram []u8) ![]u8 {
	if e.closed {
		return error('quic: engine is closed')
	}
	mut off := 0
	for off < datagram.len {
		consumed := e.receive_packet(datagram[off..])!
		if consumed == 0 {
			break
		}
		off += consumed
	}
	out := e.flush()!
	if params := e.hs.peer_transport_parameters() {
		if params.initial_scid != e.dcid {
			return error('quic: server initial_source_connection_id does not match its source connection ID')
		}
	}
	return out
}

// receive_packet handles one coalesced packet at the front of `buf`, returning
// how many bytes it consumed (RFC 9000 §12.2).
fn (mut e Conn) receive_packet(buf []u8) !int {
	if buf.len == 0 {
		return 0
	}
	if first_byte_long(buf[0]) {
		return e.receive_long_packet(buf)
	}
	return e.receive_short_packet(buf)
}

// receive_long_packet parses, deprotects and handles a long-header packet.
fn (mut e Conn) receive_long_packet(buf []u8) !int {
	// Parse the protection-independent framing: the connection IDs, token and
	// length field are all readable before header protection is removed.
	meta := long_packet_meta(buf)!
	total := meta.total_len
	if total > buf.len {
		return error('quic: long packet claims ${total} bytes, only ${buf.len} available')
	}
	mut packet := buf[..total].clone()
	pn_offset := meta.pn_offset
	mut state := e.rx_state_for(meta.ptype)!
	pn_len := state.unprotect(mut packet, pn_offset)!
	truncated := read_truncated_pn(packet, pn_offset, pn_len)
	pn := decode_packet_number(truncated, pn_len, e.largest_rx(meta.ptype))
	payload := state.decrypt_payload(packet, pn_offset, pn_len, pn)!
	e.store_rx(meta.ptype, state)
	e.note_rx(meta.ptype, pn)
	// RFC 9000 §7.2: the first Initial received from the server fixes the connection ID
	// the client addresses it by; only NEW_CONNECTION_ID may change it afterwards.
	// Adopted only after a successful decrypt, so junk cannot redirect the flight.
	if meta.ptype == .initial && !e.adopted {
		e.dcid = meta.scid.clone()
		e.adopted = true
	}
	e.handle_frames(meta.ptype, payload)!
	return total
}

// receive_short_packet parses, deprotects and handles a 1-RTT packet.
fn (mut e Conn) receive_short_packet(buf []u8) !int {
	if e.app_rx == none {
		return error('quic: received a 1-RTT packet before application keys exist')
	}
	// Short headers have no length field: the packet runs to the end of the
	// datagram. A client's 1-RTT packets are not coalesced here.
	mut packet := buf.clone()
	// RFC 9000 §7.2: a peer addresses us by the Source Connection ID we sent, so a
	// server's DCID here is the client's own scid; a short header has no length field
	// (§17.3.1), so that length — not the DCID the client sends — locates the PN.
	pn_offset := 1 + e.scid.len
	mut state := e.app_rx or { return error('quic: application receive keys missing') }
	pn_len := state.unprotect(mut packet, pn_offset)!
	truncated := read_truncated_pn(packet, pn_offset, pn_len)
	pn := decode_packet_number(truncated, pn_len, e.app_ns.largest_rx)
	payload := state.decrypt_payload(packet, pn_offset, pn_len, pn)!
	e.app_rx = state
	e.note_rx(.one_rtt, pn)
	e.handle_frames(.one_rtt, payload)!
	return buf.len
}

// read_truncated_pn reads the truncated packet-number bytes as a big-endian
// integer (RFC 9000 §17.1).
fn read_truncated_pn(packet []u8, pn_offset int, pn_len int) u64 {
	mut v := u64(0)
	for i in 0 .. pn_len {
		v = (v << 8) | u64(packet[pn_offset + i])
	}
	return v
}

// store_rx writes a possibly-advanced receive protection state back.
fn (mut e Conn) store_rx(ptype PacketType, state ProtectionState) {
	match ptype {
		.initial { e.initial_rx = state }
		.handshake { e.handshake_rx = state }
		.one_rtt { e.app_rx = state }
		.retry, .zero_rtt {}
	}
}

// rx_state_for returns the receive ProtectionState for a parsed packet type.
fn (e &Conn) rx_state_for(ptype PacketType) !ProtectionState {
	return match ptype {
		.initial { e.initial_rx or { return error('quic: no Initial receive keys') } }
		.handshake { e.handshake_rx or { return error('quic: no Handshake receive keys') } }
		.one_rtt { e.app_rx or { return error('quic: no application receive keys') } }
		.retry, .zero_rtt { return error('quic: unsupported packet type ${ptype}') }
	}
}

// handle_frames walks the frame list in a decrypted packet payload and applies
// each frame that matters to the handshake (RFC 9000 §12.4).
fn (mut e Conn) handle_frames(ptype PacketType, payload []u8) ! {
	mut off := 0
	for off < payload.len {
		frame_type := payload[off]
		body := payload[off + 1..]
		match frame_type {
			frame_padding, frame_ping {
				// A run of PADDING (0x00) or a single PING consumes one byte.
				if frame_type == frame_padding && body.len > 0 && body[0] == frame_padding {
					// Consume the whole padding run efficiently.
					mut k := 0
					for k < body.len && body[k] == frame_padding {
						k++
					}
					off += 1 + k
					continue
				}
				off++
			}
			frame_ack, frame_ack_ecn {
				used := parse_ack_frame(body, frame_type == frame_ack_ecn) or {
					return error('quic: invalid ${if frame_type == frame_ack_ecn {
						'ACK_ECN'
					} else {
						'ACK'
					}} frame: ${err.msg()}')
				}
				off += 1 + used
			}
			frame_crypto {
				cf, used := parse_crypto_frame(body) or {
					return error('quic: invalid CRYPTO frame: ${err.msg()}')
				}
				e.deliver_crypto(ptype, cf)!
				off += 1 + used
			}
			frame_handshake_done {
				e.confirmed = true
				e.hs.zeroize_handshake_traffic_secrets()!
				e.drop_handshake_keys()
				off++
			}
			frame_connection_close_transport, frame_connection_close_application {
				is_application := frame_type == frame_connection_close_application
				if is_application && ptype != .one_rtt {
					return error('quic: application CONNECTION_CLOSE is only valid in 1-RTT packets')
				}
				cc := parse_connection_close(body, is_application) or {
					return error('quic: invalid CONNECTION_CLOSE frame: ${err.msg()}')
				}
				e.closed = true
				e.close_error = cc.error_code
				return error('quic: peer closed the connection (${describe_connection_error(cc.error_code)}) during ${e.hs.state()}: ${cc.reason.bytestr()}')
			}
			else {
				return error('quic: unsupported frame type 0x${frame_type:02x} during handshake')
			}
		}
	}
}

fn describe_connection_error(code u64) string {
	if code >= 0x100 && code <= 0x1ff {
		return 'CRYPTO_ERROR (TLS alert ${code - 0x100})'
	}
	return 'QUIC error ${code}'
}

// deliver_crypto inserts a CRYPTO frame's bytes into the level's reassembler
// and drives the handshake core with any newly-complete messages.
fn (mut e Conn) deliver_crypto(ptype PacketType, cf CryptoFrame) ! {
	mut ns := e.ns_mut(ptype)
	ns.reasm.insert(cf.offset, cf.data)!
	e.drain_contiguous(ptype)!
}

// drain_contiguous feeds every complete handshake message at the front of the
// level's CRYPTO stream to the core, then installs any new keys the core exposes.
fn (mut e Conn) drain_contiguous(ptype PacketType) ! {
	level := level_of(ptype)!
	mut produced := []handshake.HandshakeMessage{}
	for {
		mut ns := e.ns_mut(ptype)
		if ns.reasm.ready.len < 4 {
			break
		}
		msg_len := (int(ns.reasm.ready[1]) << 16) | (int(ns.reasm.ready[2]) << 8) | int(ns.reasm.ready[3])
		if ns.reasm.ready.len < 4 + msg_len {
			break
		}
		msg := ns.reasm.ready[..4 + msg_len].clone()
		ns.reasm.ready = ns.reasm.ready[4 + msg_len..].clone()
		out := e.hs.receive(level, msg) or {
			// A core failure must become a QUIC connection error: classify the
			// alert, record the CRYPTO_ERROR code, and stop.
			e.fail_close()!
			return error('quic: handshake failed: ${err.msg()}')
		}
		produced << out
	}
	for m in produced {
		e.queue_outbound(m)!
	}
	e.install_exported_keys()!
}

// queue_outbound places an outbound handshake message into the right level's
// outbound CRYPTO buffer.
fn (mut e Conn) queue_outbound(m handshake.HandshakeMessage) ! {
	match m.level() {
		.initial { e.tx_crypto_initial << m.msg() }
		.handshake { e.tx_crypto_hands << m.msg() }
	}
}

// install_exported_keys derives packet protection from the handshake core's
// exported traffic secrets as soon as each level becomes available
// (RFC 9001 §5.1). It is idempotent: keys are only installed once.
fn (mut e Conn) install_exported_keys() ! {
	state := e.hs.state()
	if !e.confirmed && e.handshake_tx == none && e.handshake_rx == none
		&& state != .start && state != .wait_server_hello {
		ck, sk := e.hs.quic_traffic_secrets(.handshake)!
		suite := e.hs.negotiated_cipher_suite()
		chash := handshake.suite_hash_algo(suite)
		klen := handshake.suite_key_len(suite)
		client_keys := expand_direction(chash, ck, klen)!
		server_keys := expand_direction(chash, sk, klen)!
		e.handshake_tx = new_protection(client_keys, suite)!
		e.handshake_rx = new_protection(server_keys, suite)!
	}
	if e.hs.state() == .connected && e.app_tx == none && e.app_rx == none {
		ck, sk := e.hs.quic_traffic_secrets(.application)!
		suite := e.hs.negotiated_cipher_suite()
		chash := handshake.suite_hash_algo(suite)
		klen := handshake.suite_key_len(suite)
		client_keys := expand_direction(chash, ck, klen)!
		server_keys := expand_direction(chash, sk, klen)!
		e.app_tx = new_protection(client_keys, suite)!
		e.app_rx = new_protection(server_keys, suite)!
	}
}

// expand_direction runs the RFC 9001 §5.1 per-direction expansions over one
// traffic secret.
fn expand_direction(hash handshake.HashAlgorithm, secret []u8, key_len int) !ProtectionKeys {
	key := handshake.hkdf_expand_label(hash, secret, 'quic key', []u8{}, key_len)!
	iv := handshake.hkdf_expand_label(hash, secret, 'quic iv', []u8{}, handshake.aead_nonce_len)!
	hp := handshake.hkdf_expand_label(hash, secret, 'quic hp', []u8{}, key_len)!
	return ProtectionKeys{
		key: key
		iv:  iv
		hp:  hp
	}
}

// flush turns all pending outbound CRYPTO bytes into protected packets. Each
// level's bytes are sent in as many packets as needed; the datagrams are
// concatenated in level order (Initial, Handshake, 1-RTT), as the coalescing
// rules require (RFC 9000 §12.2).
pub fn (mut e Conn) flush() ![]u8 {
	mut out := []u8{}
	initial := e.flush_level(.initial)!
	out << initial
	hands := e.flush_level(.handshake)!
	out << hands
	app := e.flush_level(.one_rtt)!
	out << app
	return out
}

// flush_level emits the pending CRYPTO bytes for one level as one or more
// protected packets.
fn (mut e Conn) flush_level(ptype PacketType) ![]u8 {
	// If the key isn't installed, this level has nothing to send.
	mut tx := match ptype {
		.initial { e.initial_tx or { return []u8{} } }
		.handshake { e.handshake_tx or { return []u8{} } }
		.one_rtt { e.app_tx or { return []u8{} } }
		.retry, .zero_rtt { return []u8{} }
	}
	pending := e.take_pending(ptype)
	if pending.len == 0 {
		return []u8{}
	}
	// One CRYPTO frame per level for the handshake (flights are small); a real
	// stack fragments against the datagram MTU.
	frame := encode_crypto_frame(0, pending)!
	pn := e.next_pn(ptype)
	pn_len := packet_number_len(pn, 0)
	mut payload := frame.clone()
	// Every client Initial datagram must reach 1200 bytes (RFC 9000 §14.1).
	if ptype == .initial {
		payload = pad_datagram(payload, 30)
	}
	packet := e.seal(ptype, mut tx, pn, pn_len, payload)!
	e.store_tx(ptype, tx)
	e.bump_pn(ptype)
	return packet
}

// seal builds and protects one packet at a level with the (possibly updated)
// protection state.
fn (mut e Conn) seal(ptype PacketType, mut tx ProtectionState, pn u64, pn_len int, payload []u8) ![]u8 {
	tag := tx.overhead()
	match ptype {
		.initial {
			header, _ := build_long_header(.initial, quic_version_1, e.dcid, e.scid, []u8{}, payload.len,
				pn_len, tag)!
			return tx.seal_packet(header, pn, pn_len, payload)!
		}
		.handshake {
			header, _ := build_long_header(.handshake, quic_version_1, e.dcid, e.scid, []u8{},
				payload.len, pn_len, tag)!
			return tx.seal_packet(header, pn, pn_len, payload)!
		}
		.one_rtt {
			header := build_short_header(e.dcid, pn_len, e.key_phase)
			return tx.seal_packet(header, pn, pn_len, payload)!
		}
		.retry, .zero_rtt { return error('quic: cannot seal ${ptype}') }
	}
}

// fail_close classifies the handshake failure's alert as a QUIC CRYPTO_ERROR and
// records it (RFC 9001 §4.8). The caller emits a CONNECTION_CLOSE with this code.
fn (mut e Conn) fail_close() ! {
	e.close_error = u64(e.hs.failure_alert().quic_connection_error())
	e.closed = true
}

// close builds a CONNECTION_CLOSE datagram carrying a transport error code and
// reason, for the caller to send (RFC 9000 §19.19). It uses 1-RTT protection if
// the handshake got far enough to install application keys, otherwise Initial
// protection.
pub fn (mut e Conn) close(error_code u32, reason string) ![]u8 {
	e.closed = true
	e.close_error = error_code
	frame := encode_connection_close(u64(error_code), 0, reason.bytes())!
	if e.app_tx != none {
		return e.seal_raw(.one_rtt, frame)!
	}
	if e.handshake_tx != none {
		return e.seal_raw(.handshake, frame)!
	}
	return e.seal_raw(.initial, frame)!
}

// seal_raw seals an arbitrary frame payload (not CRYPTO) into one packet at the
// chosen level. It is used for CONNECTION_CLOSE, which no CRYPTO buffer holds.
fn (mut e Conn) seal_raw(ptype PacketType, payload []u8) ![]u8 {
	mut tx := match ptype {
		.initial { e.initial_tx or { return error('quic: no Initial send keys') } }
		.handshake { e.handshake_tx or { return error('quic: no Handshake send keys') } }
		.one_rtt { e.app_tx or { return error('quic: no application send keys') } }
		.retry, .zero_rtt { return error('quic: cannot seal ${ptype}') }
	}
	pn := e.next_pn(ptype)
	pn_len := packet_number_len(pn, 0)
	packet := e.seal(ptype, mut tx, pn, pn_len, payload)!
	e.store_tx(ptype, tx)
	e.bump_pn(ptype)
	return packet
}

// drop_handshake_keys discards the Handshake-level protection after
// HANDSHAKE_DONE (RFC 9001 §4.9.2).
fn (mut e Conn) drop_handshake_keys() {
	e.handshake_tx = none
	e.handshake_rx = none
}

// --- small helpers -----------------------------------------------------------

// ns_mut returns the LevelKeys for a parsed packet type.
fn (mut e Conn) ns_mut(ptype PacketType) &LevelKeys {
	return match ptype {
		.initial { &e.initial_ns }
		.handshake { &e.handshake_ns }
		.one_rtt { &e.app_ns }
		.retry, .zero_rtt { &e.app_ns }
	}
}

// largest_rx returns the largest received packet number at a level.
fn (e &Conn) largest_rx(ptype PacketType) u64 {
	return match ptype {
		.initial { e.initial_ns.largest_rx }
		.handshake { e.handshake_ns.largest_rx }
		.one_rtt { e.app_ns.largest_rx }
		.retry, .zero_rtt { u64(0) }
	}
}

// note_rx records a received packet number for PN reconstruction.
fn (mut e Conn) note_rx(ptype PacketType, pn u64) {
	mut ns := e.ns_mut(ptype)
	if !ns.any_rx || pn > ns.largest_rx {
		ns.largest_rx = pn
	}
	ns.any_rx = true
}

// level_of maps QUIC packet protection levels to shared TLS handshake phases.
fn level_of(ptype PacketType) !handshake.EncryptionLevel {
	return match ptype {
		.initial { .initial }
		.handshake { .handshake }
		.one_rtt {
			return error('quic: 1-RTT CRYPTO data is post-handshake traffic and is unsupported')
		}
		.retry, .zero_rtt { return error('quic: CRYPTO data is not accepted at ${ptype}') }
	}
}

// take_pending returns and clears the outbound CRYPTO bytes for a level.
fn (mut e Conn) take_pending(ptype PacketType) []u8 {
	mut buf := match ptype {
		.initial { e.tx_crypto_initial }
		.handshake { e.tx_crypto_hands }
		else { []u8{} }
	}
	if buf.len == 0 {
		return []u8{}
	}
	match ptype {
		.initial { e.tx_crypto_initial = []u8{} }
		.handshake { e.tx_crypto_hands = []u8{} }
		else {}
	}
	return buf
}

// next_pn returns the next packet number to send at a level.
fn (e &Conn) next_pn(ptype PacketType) u64 {
	return match ptype {
		.initial { e.initial_ns.next_pn }
		.handshake { e.handshake_ns.next_pn }
		.one_rtt { e.app_ns.next_pn }
		.retry, .zero_rtt { u64(0) }
	}
}

// bump_pn advances a level's send packet number.
fn (mut e Conn) bump_pn(ptype PacketType) {
	mut ns := e.ns_mut(ptype)
	ns.next_pn++
}

// store_tx writes a possibly-updated protection state back to the engine.
fn (mut e Conn) store_tx(ptype PacketType, tx ProtectionState) {
	match ptype {
		.initial { e.initial_tx = tx }
		.handshake { e.handshake_tx = tx }
		.one_rtt { e.app_tx = tx }
		.retry, .zero_rtt {}
	}
}
