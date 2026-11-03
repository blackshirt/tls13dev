// Copyright (c) 2026 blackshirt.
//
// hkdf_audit_test.v verifies RFC 5869 HKDF-Extract and HKDF-Expand structural
// properties: deterministic output, correct output length, input validation.
// Exact RFC 5869 byte vectors require the official test values; here we verify
// that the implementation is internally consistent and produces correct-length output.
module handshake

fn test_hkdf_extract_deterministic() ! {
	salt := []u8{len: 13, init: 0x00}
	ikm := []u8{len: 22, init: 0x00}
	prk1 := hkdf_extract(.sha256, salt, ikm)
	prk2 := hkdf_extract(.sha256, salt, ikm)
	assert prk1 == prk2 // same inputs => same output
	assert prk1.len == 32 // SHA-256 output is 32 bytes
}

fn test_hkdf_extract_sha384_uses_48_bytes() ! {
	salt := []u8{len: 13, init: 0x00}
	ikm := []u8{len: 22, init: 0x00}
	prk := hkdf_extract(.sha384, salt, ikm)
	assert prk.len == 48 // SHA-384 output is 48 bytes
}

fn test_hkdf_expand_produces_requested_length() ! {
	prk := []u8{len: 32, init: 0xAA}
	for length in [1, 16, 32, 48, 64, 100] {
		okm := hkdf_expand(.sha256, prk, []u8{}, length)!
		assert okm.len == length
	}
}

fn test_hkdf_expand_deterministic() ! {
	prk := []u8{len: 32, init: 0xAA}
	mut info := []u8{len: 3, init: 0}
	info[0] = 1
	info[1] = 2
	info[2] = 3
	okm1 := hkdf_expand(.sha256, prk, info, 32)!
	okm2 := hkdf_expand(.sha256, prk, info, 32)!
	assert okm1 == okm2
}

fn test_hkdf_expand_rejects_zero_length() ! {
	prk := []u8{len: 32, init: 0xAA}
	hkdf_expand(.sha256, prk, []u8{}, 0) or {
		assert err.msg().contains('not positive')
		return
	}
	assert false
}

fn test_hkdf_expand_rejects_over_max() ! {
	prk := []u8{len: 32, init: 0xAA}
	hkdf_expand(.sha256, prk, []u8{}, 255 * 32 + 1) or {
		assert err.msg().contains('exceeds maximum')
		return
	}
	assert false
}

fn test_derive_secret_uses_full_hash_len_sha256() ! {
	secret := []u8{len: 32, init: 0xAB}
	th := []u8{len: 32, init: 0xCD}
	out := derive_secret(.sha256, secret, 'c hs traffic', th)!
	assert out.len == 32
}

fn test_derive_secret_uses_full_hash_len_sha384() ! {
	secret := []u8{len: 48, init: 0xAB}
	th := []u8{len: 48, init: 0xCD}
	out := derive_secret(.sha384, secret, 'c hs traffic', th)!
	assert out.len == 48
}
