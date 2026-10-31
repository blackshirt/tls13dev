// Copyright (c) 2026 blackshirt.
//
// engine.v is the QUIC client engine: it drives the transport-neutral
// tls.handshake state machine over protected QUIC packets, so a caller can run a
// full RFC 9001 handshake in memory or over any datagram transport without
// touching the TLS record layer.
//
// It owns what the core does not: per-level packet-number spaces and packet
// protection, CRYPTO frame packing and offset-ordered reassembly, and the packet loop
// shuttling bytes between transport and core. It is a handshake engine, not a full
// QUIC stack — no loss recovery, congestion control, streams, migration, Retry/0-RTT,
// or Key Phase (see QUIC.md §7).
module quic

import crypto.rand
import time
import tls.handshake

// quic_version_1 is the RFC 9000 version number this engine speaks.
pub const quic_version_1 = u32(0x00000001)

// max_datagram_size bounds reassembly buffers defensively.
const max_crypto_buffer = 1 << 20

// default_max_packet_size is the RFC 9000 §14.1 Internet datagram floor; outbound
// CRYPTO is fragmented so no single sealed packet exceeds it.
const default_max_packet_size = 1200

// initial_pto_ms and max_pto_ms bound the handshake probe-timeout backoff: the
// first retransmit fires after 300ms and doubles up to the 4s cap (RFC 9000 §6.2.1).
const initial_pto_ms = i64(300)
const max_pto_ms = i64(4000)

// LevelKeys holds one level's packet-number-space state and its inbound CRYPTO
// reassembly. Protection state lives in the per-direction option fields on
// Engine.
struct LevelKeys {
mut:
	next_pn     u64         // Next packet number to send in this space.
	tx_offset   u64         // Next outbound CRYPTO stream offset for this level.
	largest_rx  u64         // Largest received packet number, used for reconstruction.
	any_rx      bool        // Whether any packet has been received in this space.
	reasm       CryptoReasm // Contiguous inbound CRYPTO stream and pending fragments.
	rx_ranges   []RxRange   // Ascending, coalesced spans of received packet numbers to acknowledge (RFC 9000 §19.3.1).
	ack_pending bool        // Whether rx_ranges holds numbers not yet carried in an ACK.
}

// UnackedFrame is a sent-but-unacknowledged handshake CRYPTO frame, held so a
// probe-timeout firing can re-seal the identical bytes under a fresh packet number
// (RFC 9000 §6.2.1). A byte-identical resend is safe: the receiver dedups the
// overlapping offset instead of rejecting it as a conflict (§19.6).
struct UnackedFrame {
mut:
	ptype PacketType
	frame []u8
}

// Engine is the transport-agnostic QUIC client handshake. It wraps a `handshake.HandshakeCore`
// in QUIC mode and the packet layer around it. Construct it with new_client_engine,
// feed it datagrams, and take the datagrams it returns to send.
@[noinit]
struct Engine {
mut:
	// TLS handshake state and negotiated parameters.
	hs handshake.HandshakeCore // Unified handshake core in QUIC mode (is_quic true).

	// Connection IDs used for packet routing and Initial key derivation.
	dcid            []u8 // Current destination CID used in outbound packets.
	scid            []u8 // This endpoint's source CID, advertised to the peer.
	orig_dcid       []u8 // Destination CID of the first Initial; those keys derive from it.
	adopted         bool // Whether a successfully decrypted server Initial set dcid.
	initial_rekeyed bool // Whether Initial keys were re-derived after a HelloRetryRequest.

	// Per-level packet protection, with independent send and receive state.
	initial_tx   ?ProtectionState // Initial keys for outbound packets.
	initial_rx   ?ProtectionState // Initial keys for inbound packets.
	handshake_tx ?ProtectionState // Handshake keys for outbound packets.
	handshake_rx ?ProtectionState // Handshake keys for inbound packets.
	app_tx       ?ProtectionState // 1-RTT keys for outbound packets.
	app_rx       ?ProtectionState // 1-RTT keys for inbound packets.

	// Packet-number spaces and inbound CRYPTO reassembly, one per level.
	initial_ns   LevelKeys // Initial-space send state and inbound CRYPTO stream.
	handshake_ns LevelKeys // Handshake-space equivalents.
	app_ns       LevelKeys // Application-space equivalents; Retry and 0-RTT routing also resolve here.

	// Outbound TLS handshake bytes awaiting CRYPTO packetization.
	tx_crypto_initial []u8 // queued bytes for the Initial-level CRYPTO stream.
	tx_crypto_hands   []u8 // queued bytes for the Handshake-level CRYPTO stream.

	// Connection and handshake lifecycle.
	confirmed   bool // Whether HANDSHAKE_DONE was received.
	closed      bool // Whether the engine has entered its terminal closed state.
	close_error u64  // Last QUIC error code set when closing, if any.

	// Current 1-RTT Key Phase bit; key updates are not implemented yet.
	key_phase bool

	// Handshake retransmission state: frames awaiting acknowledgment and the probe-
	// timeout clock the caller drives with a monotonic millisecond value (§6.2.1).
	unacked     []UnackedFrame // Sent handshake CRYPTO frames not yet acknowledged.
	pto_ms      i64            // Current probe timeout, doubling on each firing.
	next_pto_ms i64            // Absolute millisecond mark at which the flight is retransmitted (0 = unarmed).

	// Packetization limit; no sealed outbound packet exceeds this many bytes (§14.1).
	max_packet_size int
}

// Config holds options consumed when creating a QUIC client connection.
@[params]
pub struct Config {
pub:
	// hsk_options configures certificate validation, ALPN, and ClientHello preferences.
	hsk_options handshake.HandshakeOptions = handshake.HandshakeOptions{}
	// server_name is the TLS SNI value; dial() derives it from the address host when empty.
	server_name string
	// timeout bounds the whole handshake when dialed through the socket-owning facade.
	timeout time.Duration = 30 * time.second
	// max_packet_size caps each sealed outbound packet; 0 selects the RFC 9000 §14.1 default.
	max_packet_size int = default_max_packet_size
}

// max_cid_len is the longest connection ID a peer may carry (RFC 9000 §5.1).
const max_cid_len = 20

// random_cid returns n random connection-ID bytes (RFC 9000 §5.1).
fn random_cid(n int) ![]u8 {
	if n <= 0 || n > max_cid_len {
		return error('quic: connection ID length ${n} must be 1..${max_cid_len} (RFC 9000 §17.2)')
	}
	return rand.bytes(n)!
}

// new_client_engine constructs a QUIC client connection for server_name.
// Configure TLS behavior through Config; connection IDs are generated
// automatically, and Initial keys are derived from the original DCID (§5.2).
pub fn new_client_engine(server_name string, config Config) !Engine {
	mut eng := new_client_engine_with_ids(server_name, config.hsk_options,
		random_cid(8)!, random_cid(8)!)!
	if config.max_packet_size > 0 {
		eng.max_packet_size = config.max_packet_size
	}
	return eng
}

// state exposes the handshake state (handshake.HandshakeState) for polling.
pub fn (e &Engine) state() handshake.HandshakeState {
	return e.hs.state()
}

// negotiated_alpn returns the server's ALPN pick ('' if none).
pub fn (e &Engine) negotiated_alpn() string {
	return e.hs.negotiated_alpn()
}

// negotiated_cipher_suite returns the negotiated suite.
pub fn (e &Engine) negotiated_cipher_suite() handshake.CipherSuite {
	return e.hs.negotiated_cipher_suite()
}

// is_confirmed reports whether the engine has processed HANDSHAKE_DONE and released
// the handshake-stage material.
pub fn (e &Engine) is_confirmed() bool {
	return e.confirmed
}

// original_dcid returns the Destination Connection ID the engine used in its
// first Initial packet. Initial keys are a function of it (RFC 9001 §5.2) only
// until a HelloRetryRequest changes the destination ID, after which both peers
// re-derive from the server-chosen ID (§5.5); a peer still keyed on this value
// cannot open the retry flight.
pub fn (e &Engine) original_dcid() []u8 {
	return e.orig_dcid
}

// source_cid returns the engine's Source Connection ID (the server echoes it).
pub fn (e &Engine) source_cid() []u8 {
	return e.scid
}

// failure_alert returns the alert the handshake core classified on failure.
pub fn (e &Engine) failure_alert() handshake.AlertDescription {
	return e.hs.failure_alert()
}

// close_error_code returns the QUIC transport error code the engine last closed
// with (a CRYPTO_ERROR, 0x100 + alert, on a handshake failure).
pub fn (e &Engine) close_error_code() u64 {
	return e.close_error
}

// start returns the initial outbound datagram carrying the first ClientHello in
// an Initial packet. It must be called once after construction, before any input
// is fed (RFC 9000 §7).
pub fn (mut e Engine) start() ![]u8 {
	ch := e.hs.create_client_hello()!
	e.tx_crypto_initial << ch
	return e.flush()!
}

// receive processes one received datagram and returns the datagrams to send in
// response. It decrypts each coalesced packet, appends CRYPTO bytes to the
// matching level's stream, drives the handshake core with newly-completed
// messages, installs handshake/application keys as the core exports them, and
// flushes any outbound handshake bytes into fresh packets.
pub fn (mut e Engine) receive(datagram []u8) ![]u8 {
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
	// RFC 9001 §5.5: an accepted HelloRetryRequest stales the Initial keys this
	// engine holds, because the retry ClientHello is addressed to the connection ID
	// the server chose. Re-key before anything is sealed.
	e.rederive_initial_keys_after_retry()!
	// The transport-parameter binding check runs before the flush, not after: RFC
	// 9000 §7.3 requires the client to discard the server's keys when the connection
	// IDs the server declares do not match the connection IDs this endpoint actually
	// saw on the wire, so a mismatch must emit nothing rather than a Finished sealed
	// under keys already known to be unbound. The handshake guarantees a QUIC server
	// sent *something* here and hands it over undecoded; interpreting it is this
	// adapter's responsibility.
	raw := e.hs.peer_transport_parameters()!
	if raw.len > 0 {
		params := parse_transport_parameters(raw)!
		// initial_source_connection_id binds the server's declaration to the source
		// ID it really sent; original_destination_connection_id echoes the client's own
		// first Destination ID, so checking it proves the flight belongs to this
		// connection rather than one an attacker is trying to splice in.
		if params.initial_scid != e.dcid {
			return error('quic: server initial_source_connection_id does not match its source connection ID')
		}
		if params.original_dcid != e.orig_dcid {
			return error('quic: server original_destination_connection_id does not match the original Destination Connection ID')
		}
	}
	mut out := e.flush()!
	// flush_level already carries an ACK in any packet it sends; when there was no
	// CRYPTO to send, emit the still-owed acknowledgments as bare ACK packets so the
	// server stops retransmitting its flight (RFC 9000 §13.2).
	if out.len == 0 {
		for pt in [PacketType.initial, .handshake, .one_rtt] {
			out << e.ack_only(pt)!
		}
	}
	return out
}

// flush turns all pending outbound CRYPTO bytes into protected packets. Each
// level's bytes are sent in as many packets as needed; the datagrams are
// concatenated in level order (Initial, Handshake, 1-RTT), as the coalescing
// rules require (RFC 9000 §12.2).
pub fn (mut e Engine) flush() ![]u8 {
	mut out := []u8{}
	initial := e.flush_level(.initial)!
	out << initial
	hands := e.flush_level(.handshake)!
	out << hands
	app := e.flush_level(.one_rtt)!
	out << app
	return out
}

// close builds a CONNECTION_CLOSE datagram carrying a transport error code and
// reason, for the caller to send (RFC 9000 §19.19). It uses 1-RTT protection if
// the handshake got far enough to install application keys, otherwise Initial
// protection.
pub fn (mut e Engine) close(error_code u32, reason string) ![]u8 {
	e.closed = true
	e.close_error = error_code
	frame := encode_connection_close(u64(error_code), 0, reason.bytes())!
	// Seal the CONNECTION_CLOSE while the packet keys are still present, then destroy.
	mut packet := []u8{}
	if e.app_tx != none {
		packet = e.seal_raw(.one_rtt, frame)!
	} else if e.handshake_tx != none {
		packet = e.seal_raw(.handshake, frame)!
	} else {
		packet = e.seal_raw(.initial, frame)!
	}
	e.destroy_on_close()!
	return packet
}

// new_client_engine_with_ids constructs an engine with caller-chosen connection
// IDs. It is private because fixed IDs are only needed by package tests.
fn new_client_engine_with_ids(server_name string, options handshake.HandshakeOptions, dcid []u8, scid []u8) !Engine {
	mut hs_options := options
	// TLS carries these bytes verbatim into the quic_transport_parameters
	// extension (RFC 9001 §8.2) and never reads them, so encoding them is the
	// adapter's job. This assignment overrides any caller-supplied value: the
	// advertised parameters are this engine's own limits, keyed to its source CID.
	hs_options.quic_transport_params = encode_transport_parameters(client_transport_parameters(scid.clone()))!
	hs := handshake.new_quic_handshake(server_name, hs_options)!
	mut eng := Engine{
		hs:              hs
		dcid:            dcid.clone()
		scid:            scid.clone()
		orig_dcid:       dcid.clone()
		max_packet_size: default_max_packet_size
		pto_ms:          initial_pto_ms
	}
	eng.install_initial_keys(dcid)!
	return eng
}

// install_initial_keys derives and stores the Initial protection in both
// directions from the destination connection ID the client's Current Initial
// packet carries: the original DCID for the first ClientHello (RFC 9001 §5.2), or
// the server-chosen one for the retry after a HelloRetryRequest (§5.5).
fn (mut e Engine) install_initial_keys(client_dcid []u8) ! {
	ck, sk := derive_initial_keys(client_dcid)!
	e.initial_tx = new_initial_protection(ck)!
	e.initial_rx = new_initial_protection(sk)!
}

// rederive_initial_keys_after_retry applies RFC 9001 §5.5 once, when the core has
// accepted a HelloRetryRequest: the retry ClientHello is addressed to the
// connection ID the server chose in its HRR packet, and Initial secrets are a
// function of that destination ID, so both directions change (§5.5). The Initial
// packet-number space resets with them (§5.5.2) - the peer starts numbering its
// second Initial from 0 again, and reconstructing that number against a
// high-water mark left over from the old keys would place it past the window.
//
// What does NOT reset is the CRYPTO stream at this level: offsets within a level
// are absolute and monotonic (§19.6), which is what lets the retry ClientHello
// continue past the original instead of rewriting offset 0.
fn (mut e Engine) rederive_initial_keys_after_retry() ! {
	if e.initial_rekeyed || !e.hs.is_hello_retry_request_received()! {
		return
	}
	e.install_initial_keys(e.dcid)!
	e.initial_ns.next_pn = 0
	e.initial_ns.largest_rx = 0
	e.initial_ns.any_rx = false
	e.initial_ns.rx_ranges = []RxRange{}
	e.initial_ns.ack_pending = false
	e.initial_rekeyed = true
}

// receive_packet handles one coalesced packet at the front of `buf`, returning
// how many bytes it consumed (RFC 9000 §12.2).
fn (mut e Engine) receive_packet(buf []u8) !int {
	if buf.len == 0 {
		return 0
	}
	if first_byte_long(buf[0]) {
		return e.receive_long_packet(buf)
	}
	return e.receive_short_packet(buf)
}

// receive_long_packet parses, deprotects and handles a long-header packet.
fn (mut e Engine) receive_long_packet(buf []u8) !int {
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
fn (mut e Engine) receive_short_packet(buf []u8) !int {
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
fn (mut e Engine) store_rx(ptype PacketType, state ProtectionState) {
	match ptype {
		.initial { e.initial_rx = state }
		.handshake { e.handshake_rx = state }
		.one_rtt { e.app_rx = state }
		.retry, .zero_rtt {}
	}
}

// rx_state_for returns the receive ProtectionState for a parsed packet type.
fn (e &Engine) rx_state_for(ptype PacketType) !ProtectionState {
	return match ptype {
		.initial { e.initial_rx or { return error('quic: no Initial receive keys') } }
		.handshake { e.handshake_rx or { return error('quic: no Handshake receive keys') } }
		.one_rtt { e.app_rx or { return error('quic: no application receive keys') } }
		.retry, .zero_rtt { return error('quic: unsupported packet type ${ptype}') }
	}
}

// handle_frames walks the frame list in a decrypted packet payload and applies
// each frame that matters to the handshake (RFC 9000 §12.4).
fn (mut e Engine) handle_frames(ptype PacketType, payload []u8) ! {
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
				e.clear_unacked()
				e.release_handshake_keys()!
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
fn (mut e Engine) deliver_crypto(ptype PacketType, cf CryptoFrame) ! {
	mut ns := e.ns_mut(ptype)
	ns.reasm.insert(cf.offset, cf.data)!
	// Inbound CRYPTO means the peer is making progress and has taken our outstanding
	// flight, so stop holding it for retransmission (RFC 9000 §6.2.1).
	e.clear_unacked()
	e.drain_contiguous(ptype)!
}

// drain_contiguous feeds every complete handshake message at the front of the
// level's CRYPTO stream to the core, then installs any new keys the core exposes.
// Delivery goes through reasm.next_message(), which advances the reassembler's
// absolute offset so a peer may keep appending to the stream past what we took.
fn (mut e Engine) drain_contiguous(ptype PacketType) ! {
	// The packet type settles which core phase to feed, and is rejected outright
	// before anything is consumed from the reassembler.
	is_initial := crypto_is_initial(ptype)!
	mut produced := []handshake.HandshakeMessage{}
	for {
		mut ns := e.ns_mut(ptype)
		msg := ns.reasm.next_message()!
		if msg.len == 0 {
			break
		}
		out := e.feed_crypto(is_initial, msg) or {
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
	e.install_packet_keys()!
}

// feed_crypto routes one complete CRYPTO message to the core phase selected by
// is_initial and returns the outbound messages it triggers.
fn (mut e Engine) feed_crypto(is_initial bool, msg []u8) ![]handshake.HandshakeMessage {
	if is_initial {
		return e.hs.receive_initial_bytes(msg)!
	}
	return e.hs.receive_handshake_bytes(msg)!
}

// queue_outbound places an outbound handshake message into the right level's
// outbound CRYPTO buffer.
fn (mut e Engine) queue_outbound(m handshake.HandshakeMessage) ! {
	if m.is_initial() {
		e.tx_crypto_initial << m.msg()
	} else {
		e.tx_crypto_hands << m.msg()
	}
}

// install_packet_keys derives packet protection from the core's shared traffic-keys
// accessors as soon as each level becomes available (RFC 9001 §5.1; the core's QUIC
// mode answers these calls with filled key+iv+hp legs). It is
// idempotent: keys are only installed once.
fn (mut e Engine) install_packet_keys() ! {
	// Readiness comes from the core's secret-phase query, not from decoding
	// HandshakeState: a phase is true exactly while both directions' traffic secrets
	// exist, so a .failed handshake (schedule wiped) never reaches these expands with
	// live secrets. The adapter keeps its own install-once flags.
	phases := e.hs.available_secret_phases()
	if !e.confirmed && e.handshake_tx == none && e.handshake_rx == none && phases.handshake {
		e.install_handshake_protection()!
	}
	if phases.application && e.app_tx == none && e.app_rx == none {
		e.install_application_protection()!
	}
}

// install_protection derives one phase's packet protection from the core's shared
// traffic-keys accessor (RFC 9001 §5.1); is_application selects 1-RTT over Handshake. The core
// returns an opaque caller-owned generation: draining each leg moves key, iv and hp
// whole into new_protection(), whose backend copies what it keeps, so the deferred
// handle wipes and field wipes scrub every local copy on all exit paths (§7.5) —
// raw traffic secrets never cross into tls.quic at all.
fn (mut e Engine) install_protection(is_application bool) ! {
	mut gen := if is_application {
		e.hs.application_traffic_keys()!
	} else {
		e.hs.handshake_traffic_keys()!
	}
	suite := e.hs.negotiated_cipher_suite()
	mut client_leg := gen.take_client_material()
	mut server_leg := gen.take_server_material()
	mut client_keys := drain_packet_keys(mut client_leg)
	mut server_keys := drain_packet_keys(mut server_leg)
	defer {
		gen.wipe()
		client_leg.wipe()
		server_leg.wipe()
		zero_bytes(mut client_keys.key)
		zero_bytes(mut client_keys.iv)
		zero_bytes(mut client_keys.hp)
		zero_bytes(mut server_keys.key)
		zero_bytes(mut server_keys.iv)
		zero_bytes(mut server_keys.hp)
	}
	if !is_application {
		e.handshake_tx = new_protection(client_keys, suite)!
		e.handshake_rx = new_protection(server_keys, suite)!
	} else {
		e.app_tx = new_protection(client_keys, suite)!
		e.app_rx = new_protection(server_keys, suite)!
	}
}

// drain_packet_keys moves one leg's three material slots out of the core's opaque
// handle into this module's ProtectionKeys; the handle is left emptied for its wipe().
fn drain_packet_keys(mut k handshake.KeyMaterial) ProtectionKeys {
	return ProtectionKeys{
		key: k.take_key()
		iv:  k.take_iv()
		hp:  k.take_hp()
	}
}

// install_handshake_protection derives the Handshake-level packet protection from
// the core's handshake packet keys.
fn (mut e Engine) install_handshake_protection() ! {
	e.install_protection(false)!
}

// install_application_protection derives the 1-RTT packet protection from the
// core's application packet keys.
fn (mut e Engine) install_application_protection() ! {
	e.install_protection(true)!
}

// zero_bytes overwrites a buffer in place, the §7.5 scrub for dead QUIC key material
// that never reaches a tracked protection state. tls.quic's copy of the per-module
// zero-fill described in tls.handshake's wipe_secret comment.
@[direct_array_access]
fn zero_bytes(mut buf []u8) {
	for i in 0 .. buf.len {
		buf[i] = 0
	}
}

// flush_level emits the pending CRYPTO bytes for one level as one or more
// protected packets, fragmenting so no sealed packet exceeds max_packet_size
// (RFC 9000 §14, §18.2) and retaining each CRYPTO frame for handshake retransmit.
fn (mut e Engine) flush_level(ptype PacketType) ![]u8 {
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
	// An ACK for this level's newly received packets rides at the front of the first
	// packet, so the peer can stop retransmitting while the datagram count stays low
	// (RFC 9000 §13.2).
	mut ack := []u8{}
	mut ns := e.ns_mut(ptype)
	if ns.ack_pending && ns.rx_ranges.len > 0 {
		ack = encode_ack_frame(ns.rx_ranges, 0)!
		ns.ack_pending = false
	}
	tag := tx.overhead()
	mut out := []u8{cap: pending.len + 64}
	mut idx := 0
	mut first := true
	for idx < pending.len {
		pn := e.next_pn(ptype)
		pn_len := packet_number_len(pn, 0)
		overhead := e.packet_overhead(ptype, pn_len, tag)
		// The offset advances by the bytes already emitted on this level's CRYPTO
		// stream, so a retry ClientHello after a HelloRetryRequest continues past the
		// original instead of rewriting offset 0 (RFC 9000 §7.5, §19.6).
		crypto_offset := e.ns_mut(ptype).tx_offset
		// CRYPTO frame cost: type byte, offset varint, and a length varint (2 bytes
		// for any fragment under 2^14, which the MTU guarantees).
		frame_hdr := 1 + encode_varint(crypto_offset)!.len + 2
		mut budget := e.max_packet_size - overhead - frame_hdr - ack.len
		if budget < 1 {
			budget = 1 // never emit an empty CRYPTO fragment, even over the MTU
		}
		mut take := pending.len - idx
		if take > budget {
			take = budget
		}
		frame := encode_crypto_frame(crypto_offset, pending[idx..idx + take])!
		mut payload := ack.clone()
		payload << frame
		// Every client Initial datagram must reach 1200 bytes (RFC 9000 §14.1).
		if ptype == .initial && first {
			payload = pad_datagram(payload, overhead)
		}
		packet := e.seal(ptype, mut tx, pn, pn_len, payload)!
		e.store_tx(ptype, tx)
		e.bump_pn(ptype)
		e.ns_mut(ptype).tx_offset += u64(take)
		idx += take
		out << packet
		// Retain the CRYPTO frame so a lost packet is re-sealed under a fresh number;
		// 1-RTT handshake traffic is not retransmitted here.
		if ptype == .initial || ptype == .handshake {
			e.unacked << UnackedFrame{
				ptype: ptype
				frame: frame
			}
		}
		ack = []u8{}
		first = false
	}
	return out
}

// packet_overhead returns the bytes a sealed packet costs beyond its plaintext
// payload: the cleartext header through the length field, the packet number, and
// the AEAD tag. The length field is assumed to encode in two varint bytes, which
// holds for every packet under the MTU this engine targets.
fn (e &Engine) packet_overhead(ptype PacketType, pn_len int, tag int) int {
	if ptype == .one_rtt {
		return 1 + e.dcid.len + pn_len + tag // short header: first byte + DCID
	}
	mut n := 1 + 4 + 1 + e.dcid.len + 1 + e.scid.len // first, version, DCID, SCID
	if ptype == .initial {
		n += 1 // zero-length token varint
	}
	return n + 2 + pn_len + tag // length varint + packet number + tag
}

// seal builds and protects one packet at a level with the (possibly updated)
// protection state.
fn (mut e Engine) seal(ptype PacketType, mut tx ProtectionState, pn u64, pn_len int, payload []u8) ![]u8 {
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

// seal_raw seals an arbitrary frame payload (not CRYPTO) into one packet at the
// chosen level. It is used for CONNECTION_CLOSE, which no CRYPTO buffer holds.
fn (mut e Engine) seal_raw(ptype PacketType, payload []u8) ![]u8 {
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

// ack_only seals a bare ACK packet for a level that has newly received packets
// but no CRYPTO to send, so the peer's flight is acknowledged even when this engine
// has nothing new to emit (RFC 9000 §13.2). Returns no bytes when there is nothing
// owed or the level has no send keys yet.
fn (mut e Engine) ack_only(ptype PacketType) ![]u8 {
	mut ns := e.ns_mut(ptype)
	if !ns.ack_pending || ns.rx_ranges.len == 0 {
		return []u8{}
	}
	if !e.tx_keys_present(ptype) {
		return []u8{}
	}
	payload := encode_ack_frame(ns.rx_ranges, 0)!
	ns.ack_pending = false
	return e.seal_raw(ptype, payload)!
}

// tx_keys_present reports whether a level's send protection has been installed.
fn (e &Engine) tx_keys_present(ptype PacketType) bool {
	return match ptype {
		.initial { e.initial_tx != none }
		.handshake { e.handshake_tx != none }
		.one_rtt { e.app_tx != none }
		.retry, .zero_rtt { false }
	}
}

// tx_state_for returns a level's send ProtectionState, erroring if it is not yet
// installed. It mirrors seal_raw's key lookup for the retransmit path.
fn (e &Engine) tx_state_for(ptype PacketType) !ProtectionState {
	return match ptype {
		.initial { e.initial_tx or { return error('quic: no Initial send keys') } }
		.handshake { e.handshake_tx or { return error('quic: no Handshake send keys') } }
		.one_rtt { e.app_tx or { return error('quic: no application send keys') } }
		.retry, .zero_rtt { return error('quic: cannot seal ${ptype}') }
	}
}

// retransmit_expired re-emits the outstanding handshake flight once the probe
// timeout elapses, doubling the timeout on each firing (RFC 9000 §6.2.1, §A.4). The
// engine keeps no clock of its own: the caller passes a monotonic `now_ms` on every
// timer tick, and the first call after a send arms the initial timeout. Retransmits
// reuse the stored CRYPTO bytes under fresh packet numbers, so a peer that already
// has them simply dedups the offset.
pub fn (mut e Engine) retransmit_expired(now_ms i64) ![]u8 {
	if e.closed || e.unacked.len == 0 {
		return []u8{}
	}
	if e.next_pto_ms == 0 {
		e.next_pto_ms = now_ms + e.pto_ms
		return []u8{}
	}
	if now_ms < e.next_pto_ms {
		return []u8{}
	}
	mut out := []u8{}
	unacked := e.unacked.clone()
	for rec in unacked {
		if !e.tx_keys_present(rec.ptype) {
			continue
		}
		mut tx := e.tx_state_for(rec.ptype)!
		pn := e.next_pn(rec.ptype)
		pn_len := packet_number_len(pn, 0)
		packet := e.seal(rec.ptype, mut tx, pn, pn_len, rec.frame)!
		e.store_tx(rec.ptype, tx)
		e.bump_pn(rec.ptype)
		out << packet
	}
	if e.pto_ms < max_pto_ms {
		e.pto_ms *= 2
		if e.pto_ms > max_pto_ms {
			e.pto_ms = max_pto_ms
		}
	}
	e.next_pto_ms = now_ms + e.pto_ms
	return out
}

// probe_wait_ms tells the socket-owning facade how long to block on a read before
// consulting retransmit_expired: a full PTO while the clock is not yet armed, else the
// time remaining until it fires. It returns -1 when no handshake flight is outstanding
// (or the engine is closed), so the caller falls back to its own socket timeout
// (RFC 9000 §6.2.1, §A.4).
pub fn (e &Engine) probe_wait_ms(now_ms i64) i64 {
	if e.closed || e.unacked.len == 0 {
		return -1
	}
	if e.next_pto_ms == 0 {
		return e.pto_ms
	}
	mut d := e.next_pto_ms - now_ms
	if d < 0 {
		d = 0
	}
	return d
}

// clear_unacked drops the retransmit queue and resets the probe-timeout backoff.
// It runs whenever the peer delivers new handshake bytes or confirms, since that
// progress proves it received the flight we were holding (§6.2.1).
fn (mut e Engine) clear_unacked() {
	if e.unacked.len == 0 {
		return
	}
	e.unacked = []UnackedFrame{}
	e.pto_ms = initial_pto_ms
	e.next_pto_ms = 0
}

// fail_close classifies the handshake failure's alert as a QUIC CRYPTO_ERROR,
// records it, and destroys the handshake key material (RFC 9001 §4.8, RFC 8446
// §7.5). The record adapter wipes its core secrets on failure (its dial-time
// destroy_on_close); the QUIC adapter must do the same, or a dead handshake
// leaves the ephemeral ECDHE private key and derived traffic secrets in memory.
// The caller emits a CONNECTION_CLOSE with the recorded code.
fn (mut e Engine) fail_close() ! {
	e.close_error = u64(e.hs.failure_alert().quic_connection_error())
	e.hs.fail_and_zeroize_secrets()
	e.closed = true
}

// wipe_protection_state zeroes one protection slot's key material, then releases the
// holder. The slot may already be none, which is the idempotent no-op; this is the
// engine's only wipe-then-release sequence, so release_handshake_keys() and
// wipe_packet_keys() cannot drift apart (RFC 8446 §7.5, RFC 9001 §4.9.2).
fn wipe_protection_state(mut slot ?ProtectionState) {
	mut ps := slot or { ProtectionState{ aead: unsafe { nil } } }
	ps.wipe()
	slot = none
}

// release_handshake_keys releases the Handshake-level packet keys AND the core's
// handshake traffic secrets together after HANDSHAKE_DONE, so an adapter cannot wipe
// one half and forget the other (RFC 9001 §4.9.2, RFC 8446 §7.5). It zeroes the
// handshake protection states before releasing them, and is idempotent.
fn (mut e Engine) release_handshake_keys() ! {
	e.hs.zeroize_handshake_secrets()!
	wipe_protection_state(mut e.handshake_tx)
	wipe_protection_state(mut e.handshake_rx)
}

// wipe_packet_keys zeroes and releases every packet-protection state this engine
// owns, so a dead or closed connection leaves no AEAD key, IV, or header-protection
// key behind (RFC 8446 §7.5, RFC 9001 §4.9.2). Idempotent.
fn (mut e Engine) wipe_packet_keys() {
	wipe_protection_state(mut e.initial_tx)
	wipe_protection_state(mut e.initial_rx)
	wipe_protection_state(mut e.handshake_tx)
	wipe_protection_state(mut e.handshake_rx)
	wipe_protection_state(mut e.app_tx)
	wipe_protection_state(mut e.app_rx)
}

// destroy_on_close is the QUIC adapter's single terminal teardown: it drops the
// application traffic secrets once the handshake reached .connected (or the whole
// key schedule otherwise) and zeroes every packet-protection state, so no close path
// can wipe one layer and forget the other (RFC 8446 §1.3.1/§7.5, RFC 9001 §4.9.2).
// It runs only after the final CONNECTION_CLOSE has been sealed, since sealing still
// needs the packet keys; that is why the failure path (fail_close) does not call it.
fn (mut e Engine) destroy_on_close() ! {
	if e.hs.state() == .connected {
		e.hs.zeroize_application_secrets()!
	} else {
		e.hs.fail_and_zeroize_secrets()
	}
	e.wipe_packet_keys()
	e.tx_crypto_initial = []u8{}
	e.tx_crypto_hands = []u8{}
}

// ns_mut returns the LevelKeys for a parsed packet type.
fn (mut e Engine) ns_mut(ptype PacketType) &LevelKeys {
	return match ptype {
		.initial { &e.initial_ns }
		.handshake { &e.handshake_ns }
		.one_rtt { &e.app_ns }
		.retry, .zero_rtt { &e.app_ns }
	}
}

// largest_rx returns the largest received packet number at a level.
fn (e &Engine) largest_rx(ptype PacketType) u64 {
	return match ptype {
		.initial { e.initial_ns.largest_rx }
		.handshake { e.handshake_ns.largest_rx }
		.one_rtt { e.app_ns.largest_rx }
		.retry, .zero_rtt { u64(0) }
	}
}

// note_rx records a received packet number for PN reconstruction and for the
// level's ACK range list, marking that a fresh acknowledgment is owed to the peer.
fn (mut e Engine) note_rx(ptype PacketType, pn u64) {
	mut ns := e.ns_mut(ptype)
	if !ns.any_rx || pn > ns.largest_rx {
		ns.largest_rx = pn
	}
	ns.any_rx = true
	ns.rx_ranges = add_rx_range(ns.rx_ranges, pn)
	ns.ack_pending = true
}

// crypto_is_initial validates that a packet type may carry handshake CRYPTO and
// reports the core phase to feed: Initial packets carry the pre-ServerHello phase,
// Handshake packets the handshake-key phase. 1-RTT CRYPTO is post-handshake traffic
// this engine does not accept; Retry and 0-RTT packets carry none (RFC 9001 §4.1.4).
fn crypto_is_initial(ptype PacketType) !bool {
	return match ptype {
		.initial { true }
		.handshake { false }
		.one_rtt {
			return error('quic: 1-RTT CRYPTO data is post-handshake traffic and is unsupported')
		}
		.retry, .zero_rtt { return error('quic: CRYPTO data is not accepted at ${ptype}') }
	}
}

// take_pending returns and clears the outbound CRYPTO bytes for a level.
fn (mut e Engine) take_pending(ptype PacketType) []u8 {
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
fn (e &Engine) next_pn(ptype PacketType) u64 {
	return match ptype {
		.initial { e.initial_ns.next_pn }
		.handshake { e.handshake_ns.next_pn }
		.one_rtt { e.app_ns.next_pn }
		.retry, .zero_rtt { u64(0) }
	}
}

// bump_pn advances a level's send packet number.
fn (mut e Engine) bump_pn(ptype PacketType) {
	mut ns := e.ns_mut(ptype)
	ns.next_pn++
}

// store_tx writes a possibly-updated protection state back to the engine.
fn (mut e Engine) store_tx(ptype PacketType, tx ProtectionState) {
	match ptype {
		.initial { e.initial_tx = tx }
		.handshake { e.handshake_tx = tx }
		.one_rtt { e.app_tx = tx }
		.retry, .zero_rtt {}
	}
}
