// Copyright (c) 2026 blackshirt.
//
// fuzz_test.v — mutation-based fuzzer for tls.handshake wire parse entry points.
//
// Every target must return an error on malformed input, never panic.
// Any panic/unrecoverable abort = P1 crash bug, caught as a test failure.
//
// Run: v test src/tls/handshake/
module handshake

import encoding.hex
import tls.wire

// ===== PRNG (xorshift128+) =====

struct FuzzRng {
mut:
	s0 u64
	s1 u64
}

fn (mut r FuzzRng) next() u64 {
	mut s0 := r.s0
	mut s1 := r.s1
	mut result := s0 + s1
	s1 ^= s0
	s0 = rotl64(s0, 55) ^ s1 ^ (s1 << 14)
	s1 = rotl64(s1, 36)
	r.s0 = s0
	r.s1 = s1
	return result
}

fn rotl64(x u64, k int) u64 {
	return (x << k) | (x >> (64 - k))
}

fn new_fuzz_rng(seed u64) FuzzRng {
	mut z := seed + 0x9e3779b97f4a7c15
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	z = z ^ (z >> 31)
	return FuzzRng{ s0: z, s1: z + 0x9e3779b97f4a7c15 }
}

fn (mut r FuzzRng) u8() u8 {
	return u8(r.next() & 0xff)
}

fn (mut r FuzzRng) below(n int) int {
	return int(r.next() % u64(n))
}

// ===== Mutation engine =====

fn fuzz_mutate(mut r FuzzRng, input []u8) []u8 {
	if input.len == 0 {
		mut n := r.below(64) + 1
		mut out := []u8{cap: n}
		for i in 0 .. n {
			out << r.u8()
		}
		return out
	}
	mut out := input.clone()
	mut op := r.below(6)
	match op {
		0 { // bitflip
			mut pos := r.below(out.len)
			out[pos] = out[pos] ^ r.u8()
		}
		1 { // insert byte
			mut pos := r.below(out.len + 1)
			out = fuzz_insert_byte(mut out, pos, r.u8())
		}
		2 { // delete byte
			if out.len > 1 {
				mut pos := r.below(out.len)
				out = fuzz_delete_byte(mut out, pos)
			}
		}
		3 { // truncate
			if out.len > 1 {
				mut new_len := r.below(out.len - 1) + 1
				out = out[..new_len]
			}
		}
		4 { // overwrite region
			mut pos := r.below(out.len)
			mut max_chunk := fuzz_min(8, out.len - pos)
			mut chunk_len := r.below(max_chunk) + 1
			for i in 0 .. chunk_len {
				if pos + i < out.len {
					out[pos + i] = r.u8()
				}
			}
		}
		else { // append random bytes
			mut n := r.below(16) + 1
			for i in 0 .. n {
				out << r.u8()
			}
		}
	}
	return out
}

fn fuzz_insert_byte(mut s []u8, pos int, b u8) []u8 {
	mut out := []u8{cap: s.len + 1}
	out << s[..pos]
	out << b
	out << s[pos..]
	return out
}

fn fuzz_delete_byte(mut s []u8, pos int) []u8 {
	mut out := []u8{cap: s.len - 1}
	out << s[..pos]
	out << s[pos + 1..]
	return out
}

fn fuzz_min(a int, b int) int {
	if a < b { return a }
	return b
}

// ===== Seed corpus =====

fn seed_handshake_type() []u8 {
	return [1, 2, 4, 8, 11, 13, 15, 20, 24, 254]
}

fn seed_cipher_suite() []u8 {
	return [0x13, 0x01, 0x13, 0x02, 0x13, 0x03]
}

fn seed_signature_scheme() []u8 {
	return [0x04, 0x01, 0x04, 0x03, 0x05, 0x03, 0x08, 0x04, 0x08, 0x07]
}

fn seed_named_group() []u8 {
	return [0x00, 0x1d, 0x00, 0x17]
}

fn seed_alert() []u8 {
	return [0x01, 0x00, 0x02, 0x28]
}

fn seed_extensions() ![]u8 {
	mut w := wire.new_writer(8)
	w.write_u16(0)
	w.write_vector_u16([]u8{})!
	return w.bytes()
}

fn seed_handshake_message() []u8 {
	return [0x01, 0x00, 0x00, 0x00]
}

// ===== Crash dedup hash =====

fn fuzz_crash_hash(data []u8) string {
	mut h := u64(0xcbf29ce484222325)
	for b in data {
		h ^= u64(b)
		h *= 0x100000001b3
	}
	return hex.encode([u8(h), u8(h >> 8), u8(h >> 16), u8(h >> 24)])
}

fn fuzz_report(target string, input []u8) {
	h := fuzz_crash_hash(input)
	print('CRASH in ${target}: ${input.len} bytes hash ${h}')
	print('  input: ${hex.encode(input)}')
}

// ===== Target runners =====

fn fuzz_handshake_type(seed u64, iterations int) {
	mut r := new_fuzz_rng(seed)
	mut s := seed_handshake_type()
	for _ in 0 .. iterations {
		input := fuzz_mutate(mut r, s)
		if input.len == 0 { continue }
		handshake_type_from_u8(u8(input[0])) or {}
	}
}

fn fuzz_cipher_suite(seed u64, iterations int) {
	mut r := new_fuzz_rng(seed)
	mut s := seed_cipher_suite()
	for _ in 0 .. iterations {
		input := fuzz_mutate(mut r, s)
		if input.len < 2 { continue }
		raw := u16(input[0]) << 8 | u16(input[1])
		cipher_suite_from_u16(raw) or {}
	}
}

fn fuzz_signature_scheme(seed u64, iterations int) {
	mut r := new_fuzz_rng(seed)
	mut s := seed_signature_scheme()
	for _ in 0 .. iterations {
		input := fuzz_mutate(mut r, s)
		if input.len < 2 { continue }
		raw := u16(input[0]) << 8 | u16(input[1])
		signature_scheme_from_u16(raw) or {}
	}
}

fn fuzz_named_group(seed u64, iterations int) {
	mut r := new_fuzz_rng(seed)
	mut s := seed_named_group()
	for _ in 0 .. iterations {
		input := fuzz_mutate(mut r, s)
		if input.len < 2 { continue }
		raw := u16(input[0]) << 8 | u16(input[1])
		named_group_from_u16(raw) or {}
	}
}

fn fuzz_alert(seed u64, iterations int) {
	mut r := new_fuzz_rng(seed)
	mut s := seed_alert()
	for _ in 0 .. iterations {
		input := fuzz_mutate(mut r, s)
		if input.len < 2 { continue }
		parse_alert(input) or {}
	}
}

fn fuzz_extensions(seed u64, iterations int) {
	mut r := new_fuzz_rng(seed)
	mut s := seed_extensions() or { return }
	for _ in 0 .. iterations {
		input := fuzz_mutate(mut r, s)
		parse_extensions(input) or {}
	}
}

fn fuzz_handshake_message(seed u64, iterations int) {
	mut r := new_fuzz_rng(seed)
	mut s := seed_handshake_message()
	for _ in 0 .. iterations {
		input := fuzz_mutate(mut r, s)
		split_handshake_message(input) or {}
	}
}

fn fuzz_handshake_header(seed u64, iterations int) {
	mut r := new_fuzz_rng(seed)
	for _ in 0 .. iterations {
		input := fuzz_mutate(mut r, seed_handshake_message())
		if input.len < 4 { continue }
		mut rdr := wire.new_reader(input)
		read_handshake_header(mut rdr) or {}
	}
}

// ===== Test entry points =====

fn test_fuzz_handshake_type() {
	fuzz_handshake_type(0x123456789abcdef0, 10_000)
}

fn test_fuzz_cipher_suite() {
	fuzz_cipher_suite(0x23456789abcdef01, 10_000)
}

fn test_fuzz_signature_scheme() {
	fuzz_signature_scheme(0x3456789abcdef012, 10_000)
}

fn test_fuzz_named_group() {
	fuzz_named_group(0x456789abcdef0123, 10_000)
}

fn test_fuzz_alert() {
	fuzz_alert(0x56789abcdef01234, 10_000)
}

fn test_fuzz_extensions() {
	fuzz_extensions(0x6789abcdef012345, 10_000)
}

fn test_fuzz_handshake_message() {
	fuzz_handshake_message(0x789abcdef0123456, 10_000)
}

fn test_fuzz_handshake_header() {
	fuzz_handshake_header(0x89abcdef01234567, 10_000)
}
