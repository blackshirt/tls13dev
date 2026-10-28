// Copyright (c) 2026 blackshirt.
//
// key_schedule.v runs the RFC 8446 §7.1 HKDF key-derivation ladder that turns the
// (EC)DHE secret into every handshake and application key, and owns the §7.5
// zeroization lifecycle declared on HandshakeCore. The SecretPhases readiness type
// and the opaque RecordKeys / TrafficRecordKeys handles the record facade caches are
// declared here, beside the derivations that fill them.
module handshake

import crypto.hmac
import crypto.sha256
import crypto.sha512

// HashAlgorithm specifies the hash function used by the negotiated cipher suite.
// Pub because hkdf_expand_label needs it, and a QUIC engine names the suite's
// hash to expand the RFC 9001 §5.1 labels.
pub enum HashAlgorithm {
	sha256
	sha384
}

// hash_len returns the digest length in bytes.
fn (h HashAlgorithm) hash_len() int {
	return match h {
		.sha256 { 32 }
		.sha384 { 48 }
	}
}

// compute_hash calculates the hash of data.
fn (h HashAlgorithm) compute_hash(data []u8) []u8 {
	return match h {
		.sha256 { sha256.sum256(data) }
		.sha384 { sha512.sum384(data) }
	}
}

// HMAC block sizes in bytes (RFC 2104), which must match the underlying hash.
const sha256_block_size = 64
const sha384_block_size = 128

// compute_hmac calculates the HMAC of data using key.
fn (h HashAlgorithm) compute_hmac(key []u8, data []u8) []u8 {
	return match h {
		.sha256 { hmac.new(key, data, sha256.sum256, sha256_block_size) }
		.sha384 { hmac.new(key, data, sha512.sum384, sha384_block_size) }
	}
}

// hkdf_extract implements HKDF-Extract(salt, ikm) (RFC 5869 §2.2).
// An empty salt means a string of Hash.length zeros, the RFC 5869 default.
fn hkdf_extract(hash HashAlgorithm, salt []u8, ikm []u8) []u8 {
	effective_salt := if salt.len == 0 { []u8{len: hash.hash_len()} } else { salt }
	return hash.compute_hmac(effective_salt, ikm)
}

// hkdf_expand implements HKDF-Expand(prk, info, length) (RFC 5869 §2.3), producing
// T(1) || T(2) || … where T(i) = HMAC(PRK, T(i-1) || info || i).
@[direct_array_access]
fn hkdf_expand(hash HashAlgorithm, prk []u8, info []u8, length int) ![]u8 {
	hash_len := hash.hash_len()
	// A zero or negative expansion is meaningless; fail closed instead of returning
	// an empty slice that would silently shorten every derived key.
	if length <= 0 {
		return error('handshake: HKDF-Expand requested length ${length} is not positive')
	}
	// At most 255 blocks are reachable (one byte of counter); more would repeat a block (RFC 5869 §2.3).
	if length > 255 * hash_len {
		return error('handshake: HKDF-Expand requested length ${length} exceeds maximum (${255 * hash_len})')
	}
	mut out := []u8{cap: length}
	mut prev := []u8{} // T(0) is the empty string, so the first round has no prior block
	mut counter := u8(1) // blocks are indexed from 1; appended to every HMAC input

	for out.len < length {
		// T(i) = HMAC(PRK, T(i-1) || info || i): each round is unique to its index.
		mut step_input := []u8{cap: prev.len + info.len + 1}
		step_input << prev
		step_input << info
		step_input << counter
		// prev is now copied into step_input, so wipe the previous block before the
		// handle is rebound — orphaned HMAC outputs are key material (§7.5).
		wipe_secret(mut prev)

		prev = hash.compute_hmac(prk, step_input)
		// Append only the bytes still required, landing `out` on exactly `length`.
		needed := length - out.len
		to_copy := if needed < prev.len { needed } else { prev.len }
		out << prev[..to_copy]
		counter++
		// The round input embeds the prk-derived chain; zero it as the handle dies.
		wipe_secret(mut step_input)
	}
	// The final T(i) was copied into out; wipe the live handle too.
	wipe_secret(mut prev)
	return out
}

// hkdf_expand_label implements HKDF-Expand-Label (RFC 8446 §7.1), prefixing the
// label with "tls13 "; pub for the RFC 9001 §5.1 quic key/iv/hp derivations.
pub fn hkdf_expand_label(hash HashAlgorithm, secret []u8, label string, context []u8, length int) ![]u8 {
	full_label := 'tls13 ' + label
	if full_label.len > 255 {
		return error('handshake: HKDF-Expand-Label label too long')
	}
	if context.len > 255 {
		return error('handshake: HKDF-Expand-Label context too long')
	}

	mut hkdf_label := []u8{cap: 2 + 1 + full_label.len + 1 + context.len}
	hkdf_label << u8((length >> 8) & 0xff)
	hkdf_label << u8(length & 0xff)
	hkdf_label << u8(full_label.len)
	hkdf_label << full_label.bytes()
	hkdf_label << u8(context.len)
	hkdf_label << context

	return hkdf_expand(hash, secret, hkdf_label, length)!
}

// derive_secret implements Derive-Secret (RFC 8446 §7.1):
// HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length).
fn derive_secret(hash HashAlgorithm, secret []u8, label string, transcript_hash []u8) ![]u8 {
	return hkdf_expand_label(hash, secret, label, transcript_hash, hash.hash_len())!
}

// empty_transcript_hash returns the hash of an empty input (RFC 8446 §7.1 "derived" steps).
fn empty_transcript_hash(hash HashAlgorithm) []u8 {
	return hash.compute_hash([]u8{})
}

// derive_handshake_secret runs the §7.1 Early->Handshake ladder: the zero-PSK Early
// Secret, then the Handshake Secret mixing in the ECDHE shared secret. The early chain
// is dead once the Handshake extract consumed it (§7.5), so its locals zeroize here.
fn derive_handshake_secret(hash_algo HashAlgorithm, shared_secret []u8) ![]u8 {
	// Early Secret = HKDF-Extract(0, 0); without a PSK the IKM is empty but is still mixed in.
	mut early_secret := hkdf_extract(hash_algo, []u8{}, []u8{len: hash_algo.hash_len()})
	mut derived_early := derive_secret(hash_algo, early_secret, 'derived', empty_transcript_hash(hash_algo))!
	wipe_secret(mut early_secret)
	// Handshake Secret = HKDF-Extract(Derive-Secret(Early, "derived"), ECDHE)
	handshake_secret := hkdf_extract(hash_algo, derived_early, shared_secret)
	wipe_secret(mut derived_early)
	return handshake_secret
}

// derive_client_hs_secret expands the client handshake traffic secret (RFC 8446
// §7.1, "c hs traffic" label) from the Handshake Secret over the ClientHello..ServerHello transcript.
fn derive_client_hs_secret(hash_algo HashAlgorithm, handshake_secret []u8, th_ch_sh []u8) ![]u8 {
	return derive_secret(hash_algo, handshake_secret, 'c hs traffic', th_ch_sh)!
}

// derive_server_hs_secret expands the server handshake traffic secret (RFC 8446
// §7.1, "s hs traffic" label) from the Handshake Secret over the same transcript.
fn derive_server_hs_secret(hash_algo HashAlgorithm, handshake_secret []u8, th_ch_sh []u8) ![]u8 {
	return derive_secret(hash_algo, handshake_secret, 's hs traffic', th_ch_sh)!
}

// derive_master_secret advances the §7.1 Handshake->Master ladder from the Handshake
// Secret: the "derived" salt then a zero-PSK extract. The derived_hs intermediate is
// wiped here (§7.5); the returned Master Secret is zeroized by the caller after both
// application traffic secrets are expanded, since it is never stored.
fn derive_master_secret(hash_algo HashAlgorithm, handshake_secret []u8) ![]u8 {
	mut derived_hs := derive_secret(hash_algo, handshake_secret, 'derived', empty_transcript_hash(hash_algo))!
	master_secret := hkdf_extract(hash_algo, derived_hs, []u8{len: hash_algo.hash_len()})
	wipe_secret(mut derived_hs)
	return master_secret
}

// derive_client_app_secret expands the client application traffic secret (RFC 8446
// §7.1, "c ap traffic" label) from the Master Secret; KeyUpdate chains from it (§7.2).
fn derive_client_app_secret(hash_algo HashAlgorithm, master_secret []u8, th_sfin []u8) ![]u8 {
	return derive_secret(hash_algo, master_secret, 'c ap traffic', th_sfin)!
}

// derive_server_app_secret expands the server application traffic secret (RFC 8446
// §7.1, "s ap traffic" label) from the Master Secret; KeyUpdate chains from it (§7.2).
fn derive_server_app_secret(hash_algo HashAlgorithm, master_secret []u8, th_sfin []u8) ![]u8 {
	return derive_secret(hash_algo, master_secret, 's ap traffic', th_sfin)!
}

// wipe_secret overwrites a secret buffer before releasing it. The zeroing loop is
// the security-relevant step; the rebinding merely clears the local handle. This is
// tls.handshake's one zero-fill — tls and tls.quic each keep a private zero_bytes
// (V cannot share a private fn across a module boundary), so the three loops stay
// byte-identical by convention and every scrub in a module routes through its own.
fn wipe_secret(mut secret []u8) {
	for i in 0 .. secret.len {
		secret[i] = 0
	}
	secret = []u8{}
}

// derive_traffic_key expands a traffic secret into the AEAD key
// (RFC 8446 §7.1, "key" label).
@[direct_array_access]
fn derive_traffic_key(hash HashAlgorithm, secret []u8, key_len int) ![]u8 {
	return hkdf_expand_label(hash, secret, 'key', []u8{}, key_len)!
}

// derive_traffic_iv expands a traffic secret into the static nonce base the
// adapter consumes (RFC 8446 §7.1, "iv" label).
@[direct_array_access]
fn derive_traffic_iv(hash HashAlgorithm, secret []u8, iv_len int) ![]u8 {
	return hkdf_expand_label(hash, secret, 'iv', []u8{}, iv_len)!
}

// derive_finished_key computes the finished_key = HKDF-Expand-Label(BaseKey, "finished",
// "", Hash.length) MAC key RFC 8446 §4.4.4 binds to a Finished message.
@[direct_array_access]
fn derive_finished_key(hash HashAlgorithm, base_key []u8) ![]u8 {
	return hkdf_expand_label(hash, base_key, 'finished', []u8{}, hash.hash_len())!
}

// compute_finished_verify_data derives finished_key and computes HMAC over
// transcript_hash (RFC 8446 §4.4.4).
@[direct_array_access]
fn compute_finished_verify_data(hash HashAlgorithm, base_key []u8, transcript_hash []u8) ![]u8 {
	mut finished_key := derive_finished_key(hash, base_key)!
	// The finished MAC key is single-use: wipe it the moment the HMAC consumed it.
	defer {
		wipe_secret(mut finished_key)
	}
	return hash.compute_hmac(finished_key, transcript_hash)
}

// RecordKeys is one direction's record material: the AEAD key and the nonce base it must
// always travel with. The fields are private, which makes the handle opaque:
// tls.handshake constructs it, and a caller outside the module can only take values out
// of it or wipe it, so a key can never be installed without its IV. The direction is
// carried by the field name it is stored under (`client` / `server`), not by the type.
@[noinit]
pub struct RecordKeys {
mut:
	key []u8 // AEAD key
	iv  []u8 // nonce base
}

// take_key moves the AEAD key out and leaves the field empty, so the bytes have exactly
// one owner and that owner can prove it scrubbed them (§7.5). Moving instead of cloning
// keeps the key copy count across the module boundary at one per generation.
pub fn (mut k RecordKeys) take_key() []u8 {
	bytes := k.key
	k.key = []u8{}
	return bytes
}

// take_iv moves the nonce base out on the same terms as take_key: a leg is drained a pair
// at a time, never a half of it, so no key can reach the record layer without its IV.
pub fn (mut k RecordKeys) take_iv() []u8 {
	bytes := k.iv
	k.iv = []u8{}
	return bytes
}

// wipe zeroes every value the handle still owns and drops them; idempotent, so it is
// safe as a deferred safety net after a partial drain.
pub fn (mut k RecordKeys) wipe() {
	wipe_secret(mut k.key)
	wipe_secret(mut k.iv)
}

// ready reports whether this handle holds a key. Module-private: presence is an internal
// precondition of the phase accessor, whose error says more than a bool.
fn (k &RecordKeys) ready() bool {
	return k.key.len > 0
}

// copies is the one non-moving read: it clones, because a V struct copy would share the
// cache's array data and leave the record layer unable to scrub its own generation.
fn (k &RecordKeys) copies() RecordKeys {
	return RecordKeys{
		key: k.key.clone()
		iv:  k.iv.clone()
	}
}

// TrafficRecordKeys is an opaque handle to one generation of cached TLS record keys,
// holding one RecordKeys handle per direction (client and server).
@[noinit]
pub struct TrafficRecordKeys {
mut:
	client RecordKeys // client-direction key and nonce base
	server RecordKeys // server-direction key and nonce base
}

// HandshakeRecordKeys and ApplicationRecordKeys are phase-typed aliases of TrafficRecordKeys.
pub type HandshakeRecordKeys = TrafficRecordKeys
pub type ApplicationRecordKeys = TrafficRecordKeys

// take_client moves the client-direction pair out of the generation, leaving an empty
// handle behind; take_server does the same for the server direction. The pair travels
// whole, which is the reason a leg has no separate take method of its own.
pub fn (mut k TrafficRecordKeys) take_client() RecordKeys {
	leg := k.client
	k.client = RecordKeys{}
	return leg
}

// take_server moves the server-direction pair out of the generation; take_client is
// its client-side mirror.
pub fn (mut k TrafficRecordKeys) take_server() RecordKeys {
	leg := k.server
	k.server = RecordKeys{}
	return leg
}

// wipe zeroes both directions of this generation (§7.5).
pub fn (mut k TrafficRecordKeys) wipe() {
	k.client.wipe()
	k.server.wipe()
}

// ready reports whether both directions hold a key: an install or a wipe always takes
// a whole generation, never one leg of it. Module-private, as on the direction handles.
fn (k &TrafficRecordKeys) ready() bool {
	return k.client.ready() && k.server.ready()
}

// copies returns an independent deep copy of the generation; see the direction handles.
fn (k &TrafficRecordKeys) copies() TrafficRecordKeys {
	return TrafficRecordKeys{
		client: k.client.copies()
		server: k.server.copies()
	}
}

// SecretPhases reports which traffic-secret phases the core currently holds
// (derived, not yet zeroized, both directions present). Transport-neutral: it lets
// adapters install record or packet keys when the material actually exists instead
// of re-deriving readiness from HandshakeState.
pub struct SecretPhases {
pub:
	handshake   bool // client+server handshake traffic secrets available
	application bool // client+server application traffic secrets available
}

// available_secret_phases reports the current key-material readiness.
fn (h &HandshakeCore) available_secret_phases() SecretPhases {
	return SecretPhases{
		handshake:   h.c_hsk_tsec.len > 0 && h.s_hsk_tsec.len > 0
		application: h.c_app_tsec.len > 0 && h.s_app_tsec.len > 0
	}
}

// release_ephemeral_keys drops both ephemeral ECDHE private halves: the vlib key
// types expose no in-place wipe, so releasing the handles is the available
// destruction (§7.5). Sole caller is wipe_key_schedule_secrets(), reached from both
// the .connected lifecycle and the failure path.
fn (mut h HandshakeCore) release_ephemeral_keys() {
	h.priv_x25519 = unsafe { nil }
	h.priv_p256 = none
}

// wipe_traffic_secrets_at is the unguarded per-level wipe: it zeroes the client and
// server traffic secrets for one encryption level; the initial level has no TLS
// traffic secrets. It mirrors the QUIC-side peer_traffic_secrets_at() accessor
// (quic_handshake.v) so reads and wipes share the same phase vocabulary.
fn (mut h HandshakeCore) wipe_traffic_secrets_at(level EncryptionLevel) {
	match level {
		.initial {}
		.handshake {
			wipe_secret(mut h.c_hsk_tsec)
			wipe_secret(mut h.s_hsk_tsec)
		}
		.application {
			wipe_secret(mut h.c_app_tsec)
			wipe_secret(mut h.s_app_tsec)
		}
	}
}

// wipe_key_schedule_secrets destroys the key-schedule intermediate and the dead
// ephemeral ECDHE halves at .connected (RFC 8446 §1.3.1/§7.5); it spares the
// handshake traffic secrets.
fn (mut h HandshakeCore) wipe_key_schedule_secrets() {
	wipe_secret(mut h.handshake_secret)
	h.release_ephemeral_keys()
}

// zeroize_traffic_secrets_at is the guarded lifecycle entry, normal teardown's only
// route to the per-level wipe: it destroys one level's client and server traffic
// secrets (and, on the record facade, that level's cached record keys) once the
// adapter no longer needs them. Valid only after .connected; the initial level is
// refused (RFC 8446 §7.5). Module-private: adapters call their phase-named
// zeroize_handshake_secrets() / zeroize_application_secrets() entry points.
fn (mut h HandshakeCore) zeroize_traffic_secrets_at(level EncryptionLevel) ! {
	match level {
		.initial {
			return error('handshake: initial level has no traffic secrets to zeroize')
		}
		.handshake, .application {
			if h.state != .connected {
				return error('handshake: zeroizing ${level} traffic secrets is only valid once the handshake reaches .connected (state: ${h.state()})')
			}
			h.wipe_traffic_secrets_at(level)
		}
	}
}

// fail_and_zeroize_secrets is the unguarded terminal entry: it composes every wipe
// above — key-schedule intermediate, ephemeral halves, both traffic-secret levels —
// releases the reassembly buffers, and parks the machine in .failed (RFC 8446
// §1.3.1/§7.5). It bypasses the zeroize_* lifecycle guard: a failure can land before
// .connected ever held.
fn (mut h HandshakeCore) fail_and_zeroize_secrets() {
	h.wipe_key_schedule_secrets()
	h.wipe_traffic_secrets_at(.handshake)
	h.wipe_traffic_secrets_at(.application)
	h.buffers.release_buffers()
	h.state = .failed
}
