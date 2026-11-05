// Copyright (c) 2026 blackshirt.
//
// psk.v owns the RFC 8446 §4.2.11/§4.2.9 pre-shared key surface: the Psk handle
// and wire types, the §7.1 binder key/computation, the pre_shared_key and
// psk_key_exchange_modes builders, and the ServerHello selected-identity decode.
// HKDF primitives live in key_schedule.v; transcript truncation in client_hello.v.
module handshake

import tls.wire

// supported_psk_key_exchange_modes is the mode list this client offers:
// psk_dhe_ke only, so every PSK handshake keeps forward secrecy.
const supported_psk_key_exchange_modes = [PskKeyExchangeMode.psk_dhe_ke]

// psk_identity_max_len is the RFC 8446 §4.2.11 opaque<0..2^16-1> wire limit;
// a longer identity could never be framed, so new_psk rejects it outright.
const psk_identity_max_len = 65535

// psk_key_min_len is the RFC 8446 §7.1 Hash.length floor for SHA-256, the
// default hash. Below it the PSK also falls under §2.2's psk_dhe_ke entropy
// minimum, so new_psk rejects rather than silently weakening the Early Secret.
const psk_key_min_len = 32

// psk_key_max_len is a policy ceiling. RFC 8446 sets no upper bound (the PSK
// is not sent on the wire), but HMAC pre-hashes past the block size anyway
// and the key lives on the heap for the connection's lifetime.
const psk_key_max_len = 1024

// PskKeyExchangeMode names the PSK key-exchange modes (RFC 8446 §4.2.9).
enum PskKeyExchangeMode as u8 {
	psk_ke     = 0 // PSK only, no (EC)DHE (no forward secrecy)
	psk_dhe_ke = 1 // PSK with (EC)DHE (forward secrecy)
}

// PskIdentity is one offered PSK: an opaque ticket (the identity) and its
// obfuscated ticket age (ticket_age_add + age mod 2^32) (RFC 8446 §4.2.11).
@[noinit]
struct PskIdentity {
mut:
	identity              []u8 // opaque PSK identity (a NewSessionTicket's ticket bytes)
	obfuscated_ticket_age u32  // ticket_age_add + age (mod 2^32), obfuscating real age
}

// Psk is a usable pre-shared key: the wire identity plus the key material
// both sides feed to binders and the Early Secret (RFC 8446 §4.2.11/§7.1).
// identity and key are required; obfuscated_ticket_age, external, and
// hash_algo default to zero (fresh ticket, "res binder", SHA-256).
@[noinit]
pub struct Psk {
mut:
	identity []u8 // opaque PSK identity (ticket bytes, sent in the ClientHello)
	key      []u8 // PSK key material (known to both client and server)
	// obfuscated_ticket_age is the ticket_age_add-obfuscated age sent for a
	// resumption PSK (RFC 8446 §4.2.11); zero is valid for a freshly issued ticket.
	obfuscated_ticket_age u32
	// external selects the "ext binder" label over the resumption default
	// "res binder" (RFC 8446 §7.1); importers of externally provisioned PSKs set it.
	external bool
	// hash_algo is the single Hash associated with this PSK (RFC 8446 §4.2.11) —
	// the ticket connection's KDF hash, or SHA-256 (the enum zero) for external PSKs.
	hash_algo HashAlgorithm
}

// new_psk constructs a Psk, screening inputs against the wire limits and
// entropy floors documented on the psk_* consts above, and cloning both so
// caller-side mutation cannot reach the bytes the handshake binds over.
// obfuscated_ticket_age, external, and hash_algo default to zero values.
@[direct_array_access]
pub fn new_psk(identity []u8, key []u8) !Psk {
	if identity.len == 0 {
		return error('handshake: PSK identity must not be empty')
	}
	if identity.len > psk_identity_max_len {
		return error('handshake: PSK identity of ${identity.len} bytes exceeds the ${psk_identity_max_len}-byte wire limit')
	}
	if key.len == 0 {
		return error('handshake: PSK key must not be empty')
	}
	if key.len < psk_key_min_len {
		return error('handshake: PSK key of ${key.len} bytes is below the ${psk_key_min_len}-byte §7.1 minimum')
	}
	if key.len > psk_key_max_len {
		return error('handshake: PSK key of ${key.len} bytes exceeds the ${psk_key_max_len}-byte policy ceiling')
	}
	return Psk{
		identity: identity.clone()
		key:      key.clone()
	}
}

// identity returns the opaque PSK identity (ticket bytes, sent in the ClientHello).
pub fn (p &Psk) identity() []u8 {
	return p.identity
}

// key returns the PSK key material (known to both client and server).
pub fn (p &Psk) key() []u8 {
	return p.key
}

// PskBinderEntry is one PSK binder: an HMAC over the finished binder key and
// the truncated ClientHello transcript hash (RFC 8446 §4.2.11).
@[noinit]
struct PskBinderEntry {
mut:
	binder []u8
}

// psk_binder_label returns the binder key label for a PSK: external PSKs use
// "ext binder", resumption PSKs the default "res binder" (RFC 8446 §7.1).
fn psk_binder_label(psk Psk) string {
	return if psk.external { 'ext binder' } else { 'res binder' }
}

// derive_binder_key expands a resumption PSK binder key from the Early Secret
// (RFC 8446 §7.1, "res binder" label); the caller wipes the returned key.
fn derive_binder_key(hash_algo HashAlgorithm, early_secret []u8) ![]u8 {
	return derive_binder_key_labeled(hash_algo, early_secret, 'res binder')
}

// derive_binder_key_labeled expands a binder key under either the resumption
// or external PSK label (RFC 8446 §7.1). Derive-Secret context is Hash("") —
// the digest of the empty message, not an empty byte string.
fn derive_binder_key_labeled(hash_algo HashAlgorithm, early_secret []u8, label string) ![]u8 {
	return derive_secret(hash_algo, early_secret, label, empty_transcript_hash(hash_algo))!
}

// compute_psk_binder derives one §4.2.11 binder: bind the PSK into the Early
// Secret, expand the labeled binder key and finished key, then HMAC the
// transcript hash. Every intermediate is wiped before returning.
fn compute_psk_binder(hash_algo HashAlgorithm, psk_key []u8, label string, transcript_hash []u8) ![]u8 {
	mut early_secret := hkdf_extract(hash_algo, []u8{}, psk_key)
	defer { wipe_secret(mut early_secret) }
	mut binder_key := derive_binder_key_labeled(hash_algo, early_secret, label)!
	defer { wipe_secret(mut binder_key) }
	mut finished_key := derive_finished_key(hash_algo, binder_key)!
	defer { wipe_secret(mut finished_key) }
	return hash_algo.compute_hmac(finished_key, transcript_hash)
}

// build_psk_key_exchange_modes_extension encodes the psk_key_exchange_modes
// extension (RFC 8446 §4.2.9): a u8-length vector of modes.
fn build_psk_key_exchange_modes_extension() ![]u8 {
	mut body := wire.new_writer(1 + 3)
	mut modes := wire.new_writer(2)
	for m in supported_psk_key_exchange_modes {
		modes.write_u8(u8(m))
	}
	body.write_vector_u8(modes.bytes())!
	return body.bytes()
}

// build_pre_shared_key_identities encodes the identities vector of the
// pre_shared_key extension (RFC 8446 §4.2.11), including its u16 length prefix.
fn build_pre_shared_key_identities(identities []PskIdentity) ![]u8 {
	mut entries := wire.new_writer(64)
	for id in identities {
		entries.write_vector_u16(id.identity)!
		entries.write_u32(id.obfuscated_ticket_age)
	}
	mut out := wire.new_writer(entries.len() + 2)
	out.write_vector_u16(entries.bytes())!
	return out.bytes()
}

// build_pre_shared_key_binders encodes the binders vector of the
// pre_shared_key extension (RFC 8446 §4.2.11), including its u16 length prefix.
// Each PskBinderEntry is an opaque<32..255>, so its own length is one byte.
fn build_pre_shared_key_binders(binders []PskBinderEntry) ![]u8 {
	mut entries := wire.new_writer(64)
	for b in binders {
		entries.write_vector_u8(b.binder)!
	}
	mut out := wire.new_writer(entries.len() + 2)
	out.write_vector_u16(entries.bytes())!
	return out.bytes()
}

// build_pre_shared_key_extension encodes the pre_shared_key extension body
// (RFC 8446 §4.2.11): a u16-length vector of identities followed by a u16-length
// vector of binders. Binders may be empty placeholders to be filled later.
fn build_pre_shared_key_extension(identities []PskIdentity, binders []PskBinderEntry) ![]u8 {
	if identities.len != binders.len {
		return error('handshake: pre_shared_key has ${identities.len} identities but ${binders.len} binders')
	}
	ids := build_pre_shared_key_identities(identities)!
	binds := build_pre_shared_key_binders(binders)!
	mut body := wire.new_writer(ids.len + binds.len)
	body.write_bytes(ids)
	body.write_bytes(binds)
	return body.bytes()
}

// parse_server_selected_psk decodes the pre_shared_key extension body from a
// ServerHello: exactly one u16 selected identity index (RFC 8446 §4.2.11).
fn parse_server_selected_psk(ext_data []u8) !u16 {
	mut r := wire.new_reader(ext_data)
	selected := r.read_u16()!
	if r.remaining() != 0 {
		return error('handshake: trailing bytes in ServerHello pre_shared_key extension')
	}
	return selected
}

// resumption_psk turns one NewSessionTicket the server issued on this
// connection into a Psk the caller can offer on the next one (RFC 8446 §7.2):
// identity = the opaque ticket bytes, key = HKDF-Expand-Label(RMS, "resumption",
// ticket_nonce), hash_algo = this session's negotiated hash so the next
// ClientHello's binder is derived on the same early-secret chain. Requires
// HandshakeCore to still hold the Resumption Master Secret, i.e. the caller
// must ask before zeroize_traffic_secrets() runs at close.
//
// obfuscated_ticket_age is set to the ticket's age_add alone (§4.6.1: age +
// age_add mod 2^32); the stack does not track wall-clock since issuance, so
// every PSK presents as freshly minted. Servers treat a stale age as a signal
// to fall back to the full handshake, never as an error.
pub fn (h &HandshakeCore) resumption_psk(ticket &NewSessionTicket) !Psk {
	if h.resumption_master_secret.len == 0 {
		return error('handshake: no resumption master secret (call before zeroize_traffic_secrets(), or the connection never reached .connected)')
	}
	if ticket.ticket.len == 0 {
		return error('handshake: NewSessionTicket has empty identity bytes')
	}
	if ticket.ticket.len > psk_identity_max_len {
		return error('handshake: NewSessionTicket identity of ${ticket.ticket.len} bytes exceeds the ${psk_identity_max_len}-byte wire limit')
	}
	derived := derive_resumption_psk(h.hash_algo, h.resumption_master_secret, ticket.ticket_nonce)!
	return Psk{
		identity:              ticket.ticket.clone()
		key:                   derived
		obfuscated_ticket_age: ticket.ticket_age_add
		external:              false
		hash_algo:             h.hash_algo
	}
}
