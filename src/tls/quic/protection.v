// Copyright (c) 2026 blackshirt.
//
// protection.v implements QUIC packet protection (RFC 9001 §5): the AEAD
// sealing/opening of the packet payload (§5.3) and header protection (§5.4),
// which masks the first byte's low bits and the packet number so an observer
// cannot read them or associate packets by number until they have the key.
//
// The keying material is one direction's (key, iv, hp): `key` drives AES-128-GCM
// (or a negotiated suite), `iv` is the packet-number nonce base, and `hp` drives
// the header-protection mask. Only Initial and Handshake packets are AES-128-GCM
// in this engine; 1-RTT uses whatever the handshake negotiated.
module quic

import crypto.aes
import crypto.cipher
import tls.handshake
import x.crypto.chacha20

// hp_sample_len is the number of ciphertext bytes sampled to derive the header
// protection mask (RFC 9001 §5.4.2). It is one AES block.
const hp_sample_len = 16

// ProtectionKeys is one direction's packet-protection material at one
// encryption level (RFC 9001 §5.1): the AEAD packet key, the 12-byte
// packet-number nonce base, and the header-protection key.
struct ProtectionKeys {
	key []u8
	iv  []u8
	hp  []u8
}

// ProtectionState is a live, stateful packet protector for one direction at one
// level: a cipher built from `key`, the nonce base `iv`, the header-protection
// key `hp`, and the suite (which selects the AEAD and the mask algorithm).
@[noinit]
struct ProtectionState {
mut:
	suite handshake.CipherSuite
	aead  cipher.AEAD
	iv    []u8
	hp    []u8
}

// new_initial_protection builds a ProtectionState for the Initial level, which
// is always AES-128-GCM (RFC 9001 §5.2).
fn new_initial_protection(k InitialKeys) !ProtectionState {
	return new_protection(ProtectionKeys{
		key: k.key
		iv:  k.iv
		hp:  k.hp
	}, .tls_aes_128_gcm_sha256)
}

// new_protection builds a ProtectionState for one direction at one level from
// its ProtectionKeys and the negotiated suite.
fn new_protection(k ProtectionKeys, suite handshake.CipherSuite) !ProtectionState {
	if k.iv.len != handshake.aead_nonce_len {
		return error('quic: nonce base must be ${handshake.aead_nonce_len} bytes, got ${k.iv.len}')
	}
	if k.key.len != handshake.suite_key_len(suite) {
		return error('quic: key length ${k.key.len} does not match suite ${suite}')
	}
	if k.hp.len != handshake.suite_key_len(suite) {
		return error('quic: header-protection key length ${k.hp.len} does not match suite ${suite}')
	}
	aead := handshake.new_aead_for_suite(suite, k.key)!
	return ProtectionState{
		suite: suite
		aead:  aead
		iv:    k.iv.clone()
		hp:    k.hp.clone()
	}
}

// overhead returns the AEAD tag length in bytes (16 for both AES-GCM and
// ChaCha20-Poly1305), which the QUIC Length field must include.
fn (s &ProtectionState) overhead() int {
	return s.aead.overhead()
}

// compute_nonce builds the per-packet AEAD nonce by XORing the packet number
// into the trailing 8 bytes of the nonce base (RFC 9001 §5.3). Identical in
// shape to the TLS record nonce (RFC 8446 §5.3).
fn (s &ProtectionState) compute_nonce(pn u64) []u8 {
	mut nonce := s.iv.clone()
	for i in 0 .. 8 {
		shift := (7 - i) * 8
		nonce[handshake.aead_nonce_len - 8 + i] ^= u8((pn >> shift) & 0xff)
	}
	return nonce
}

// compute_mask derives the 5-byte header-protection mask from the sampled
// ciphertext (RFC 9001 §5.4.1/§5.4.2): AES-ECB encrypts the 16-byte sample with
// the hp key (AES suites) or ChaCha20 runs with the sample as nonce and the
// first 4 bytes of hp as counter (ChaCha20 suite).
fn (s &ProtectionState) compute_mask(sample []u8) ![]u8 {
	if sample.len < hp_sample_len {
		return error('quic: header-protection sample needs ${hp_sample_len} bytes, got ${sample.len}')
	}
	match s.suite {
		.tls_aes_128_gcm_sha256, .tls_aes_256_gcm_sha384 {
			block := aes.new_cipher(s.hp)!
			mut out := []u8{len: hp_sample_len}
			block.encrypt(mut out, sample[..hp_sample_len])
			return out[..5]
		}
		.tls_chacha20_poly1305_sha256 {
			// The ChaCha20 suite derives the mask with the *first 4 bytes* of hp
			// as the little-endian block counter and the 16-byte sample's first 12
			// bytes as the nonce (RFC 9001 §5.4.4), then encrypts five zero bytes.
			counter := u32(s.hp[0]) | (u32(s.hp[1]) << 8) | (u32(s.hp[2]) << 16) | (u32(s.hp[3]) << 24)
			mut c := chacha20.new_cipher(s.hp[4..], sample[..12], chacha20.Options{})!
			c.set_counter(u64(counter))
			mut zeros := []u8{len: 5}
			mut out := []u8{len: 5}
			c.xor_key_stream(mut out, zeros)
			return out
		}
	}
}

// apply_header_protection masks the first byte's low bits and the packet number
// in place (RFC 9001 §5.4.1). `pn_offset` is where the unprotected packet number
// begins; `sample_off` is where the 16-byte ciphertext sample begins.
fn (s &ProtectionState) apply_header_protection(mut packet []u8, pn_offset int, sample_off int, pn_len int) ! {
	mask := s.compute_mask(packet[sample_off..])!
	// Long headers mask the low nibble (0x0f); short headers mask the low five
	// bits (0x1f) so the Key Phase bit stays visible to a key-updating peer.
	if first_byte_long(packet[0]) {
		packet[0] ^= mask[0] & 0x0f
	} else {
		packet[0] ^= mask[0] & 0x1f
	}
	for i in 0 .. pn_len {
		packet[pn_offset + i] ^= mask[1 + i]
	}
}

// remove_header_protection reverses apply_header_protection given a packet whose
// first byte and packet number are still masked (RFC 9001 §5.4.1). It returns
// the unmasked packet number length.
fn (s &ProtectionState) remove_header_protection(mut packet []u8, pn_offset int, sample_off int) !int {
	mask := s.compute_mask(packet[sample_off..])!
	if first_byte_long(packet[0]) {
		packet[0] ^= mask[0] & 0x0f
	} else {
		packet[0] ^= mask[0] & 0x1f
	}
	pn_len := int(packet[0] & 0x03) + 1
	for i in 0 .. pn_len {
		packet[pn_offset + i] ^= mask[1 + i]
	}
	return pn_len
}

// seal_packet encrypts `payload` and applies header protection, returning the
// full protected packet: cleartext header prefix ∥ masked PN ∥ AEAD payload
// (RFC 9001 §5.3/§5.4). `header` is the already-serialized header prefix through
// the length field (from build_long_header / build_short_header); `pn` is the
// packet number.
fn (mut s ProtectionState) seal_packet(header []u8, pn u64, pn_len int, payload []u8) ![]u8 {
	pn_bytes := encode_packet_number(pn, pn_len)!
	mut packet := []u8{cap: header.len + pn_len + payload.len + 16}
	packet << header
	packet << pn_bytes
	// The AEAD AAD is the entire cleartext header including the packet number
	// (RFC 9001 §5.3), with the packet number in its truncated form.
	aad := packet.clone()
	nonce := s.compute_nonce(pn)
	ciphertext := s.aead.encrypt(payload, nonce, aad)!
	packet << ciphertext
	// Header protection samples the payload 4 bytes after the start of the
	// packet-number field, which is *assumed to be 4 bytes* regardless of the
	// actual pn_len (RFC 9001 §5.4.2).
	sample_off := header.len + 4
	if sample_off + hp_sample_len > packet.len {
		return error('quic: packet too short to sample for header protection')
	}
	s.apply_header_protection(mut packet, header.len, sample_off, pn_len)!
	return packet
}

// unprotect removes header protection from a received packet in place and
// returns the packet-number length (RFC 9001 §5.4.1). After this call the first
// byte and packet number are in the clear, so the caller can read the truncated
// packet number, reconstruct the full value, and call decrypt_payload.
fn (mut s ProtectionState) unprotect(mut packet []u8, pn_offset int) !int {
	sample_off := pn_offset + 4
	if sample_off + hp_sample_len > packet.len {
		return error('quic: packet too short to remove header protection')
	}
	return s.remove_header_protection(mut packet, pn_offset, sample_off)!
}

// decrypt_payload decrypts a packet already stripped of header protection
// (RFC 9001 §5.3). `pn_offset` is the start of the (now clear) packet number,
// `pn_len` its length, and `full_pn` the reconstructed packet number that keys
// the nonce.
fn (mut s ProtectionState) decrypt_payload(packet []u8, pn_offset int, pn_len int, full_pn u64) ![]u8 {
	header_total := pn_offset + pn_len
	if header_total > packet.len {
		return error('quic: packet number runs past packet end')
	}
	aad := packet[..header_total]
	ciphertext := packet[header_total..]
	if ciphertext.len < s.aead.overhead() {
		return error('quic: protected payload shorter than AEAD tag')
	}
	nonce := s.compute_nonce(full_pn)
	return s.aead.decrypt(ciphertext, nonce, aad)!
}
