// Copyright (c) 2026 blackshirt.
//
// QUIC packet protection: AEAD sealing/opening (§5.3) and header protection (§5.4) (RFC 9001 §5).
module quic

import crypto.aes
import crypto.cipher
import tls.handshake
import x.crypto.chacha20

// hp_sample_len is the header-protection sample length (RFC 9001 §5.4.2).
const hp_sample_len = 16

// ProtectionKeys holds one direction's packet-protection material (RFC 9001 §5.1).
struct ProtectionKeys {
	key []u8
	iv  []u8
	hp  []u8
}

// ProtectionState protects packets at one level (RFC 9001 §5).
@[noinit]
struct ProtectionState {
mut:
	suite handshake.CipherSuite
	aead  cipher.AEAD
	iv    []u8
	hp    []u8
}

// new_initial_protection builds Initial-level protection (AES-128-GCM, RFC 9001 §5.2).
fn new_initial_protection(k InitialKeys) !ProtectionState {
	return new_protection(ProtectionKeys{
		key: k.key
		iv:  k.iv
		hp:  k.hp
	}, .tls_aes_128_gcm_sha256)
}

// new_protection builds protection state for a suite (RFC 9001 §5).
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

// overhead returns AEAD tag length (RFC 9001 §5.3).
fn (s &ProtectionState) overhead() int {
	return s.aead.overhead()
}

// compute_nonce builds per-packet AEAD nonce (RFC 9001 §5.3).
fn (s &ProtectionState) compute_nonce(pn u64) []u8 {
	mut nonce := s.iv.clone()
	for i in 0 .. 8 {
		shift := (7 - i) * 8
		nonce[handshake.aead_nonce_len - 8 + i] ^= u8((pn >> shift) & 0xff)
	}
	return nonce
}

// compute_mask derives header-protection mask (RFC 9001 §5.4.3/§5.4.4).
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
			// ChaCha20 mask (§5.4.4): the full hp key is the key, the first 4 bytes of
			// the *sample* are the little-endian counter, the last 12 are the nonce.
			samp := sample[..hp_sample_len]
			counter := u32(samp[0]) | (u32(samp[1]) << 8) | (u32(samp[2]) << 16) | (u32(samp[3]) << 24)
			mut c := chacha20.new_cipher(s.hp, samp[4..], chacha20.Options{})!
			c.set_counter(u64(counter))
			mut zeros := []u8{len: 5}
			mut out := []u8{len: 5}
			c.xor_key_stream(mut out, zeros)
			return out
		}
	}
}

// apply_header_protection masks first byte and packet number (RFC 9001 §5.4.1).
fn (s &ProtectionState) apply_header_protection(mut packet []u8, pn_offset int, sample_off int, pn_len int) ! {
	mask := s.compute_mask(packet[sample_off..])!
	// Long headers mask 0x0f; short headers mask 0x1f to keep Key Phase visible.
	if first_byte_long(packet[0]) {
		packet[0] ^= mask[0] & 0x0f
	} else {
		packet[0] ^= mask[0] & 0x1f
	}
	for i in 0 .. pn_len {
		packet[pn_offset + i] ^= mask[1 + i]
	}
}

// remove_header_protection unmasks header and PN; returns PN length (RFC 9001 §5.4.1).
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

// seal_packet encrypts payload and applies header protection (RFC 9001 §5.3/§5.4).
fn (mut s ProtectionState) seal_packet(header []u8, pn u64, pn_len int, payload []u8) ![]u8 {
	pn_bytes := encode_packet_number(pn, pn_len)!
	mut packet := []u8{cap: header.len + pn_len + payload.len + 16}
	packet << header
	packet << pn_bytes
	// AAD includes cleartext header + truncated PN (RFC 9001 §5.3).
	aad := packet.clone()
	nonce := s.compute_nonce(pn)
	ciphertext := s.aead.encrypt(payload, nonce, aad)!
	packet << ciphertext
	// Sample starts 4 bytes after PN field regardless of pn_len (RFC 9001 §5.4.2).
	sample_off := header.len + 4
	if sample_off + hp_sample_len > packet.len {
		return error('quic: packet too short to sample for header protection')
	}
	s.apply_header_protection(mut packet, header.len, sample_off, pn_len)!
	return packet
}

// unprotect removes header protection; returns PN length (RFC 9001 §5.4.1).
fn (mut s ProtectionState) unprotect(mut packet []u8, pn_offset int) !int {
	sample_off := pn_offset + 4
	if sample_off + hp_sample_len > packet.len {
		return error('quic: packet too short to remove header protection')
	}
	return s.remove_header_protection(mut packet, pn_offset, sample_off)!
}

// decrypt_payload decrypts after header protection removal (RFC 9001 §5.3).
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
