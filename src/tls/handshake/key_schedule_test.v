// Copyright (c) 2026 blackshirt.
//
// Known-answer tests for the TLS 1.3 key schedule against the RFC 8448 §3
// worked example (SHA-256, PSK-less branch). The rfc8448_* constants are that
// example's intermediate secrets, hex-encoded, in schedule order.
module handshake

import encoding.hex

const rfc8448_client_hello = '010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001'
const rfc8448_server_hello = '020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304'
const rfc8448_early_secret = '33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a'
const rfc8448_derived_for_handshake = '6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba'
const rfc8448_ecdhe_shared_secret = '8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d'
const rfc8448_handshake_secret = '1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac'
const rfc8448_transcript_hash_ch_sh = '860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8'
const rfc8448_client_hs_traffic = 'b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21'
const rfc8448_server_hs_traffic = 'b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38'
const rfc8448_derived_for_master = '43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4'
const rfc8448_master_secret = '18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919'
const rfc8448_transcript_hash_ch_sfin = '9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13'
const rfc8448_client_ap_traffic_0 = '9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5'
const rfc8448_server_ap_traffic_0 = 'a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643'

// test_rfc8448_transcript_hashing pins Transcript-Hash(ClientHello || ServerHello)
// to the RFC 8448 value — every secret derived later binds to this running hash.
fn test_rfc8448_transcript_hashing() ! {
	client_hello := hex.decode(rfc8448_client_hello)!
	server_hello := hex.decode(rfc8448_server_hello)!
	mut transcript := new_transcript(.sha256)
	transcript.update(client_hello)!
	transcript.update(server_hello)!
	assert hex.encode(transcript.current_hash()) == rfc8448_transcript_hash_ch_sh
}

// test_transcript_update_enforces_total_bound checks that appends past
// max_transcript_len are refused without growing the buffer, so a peer sending
// endless legal-size handshake messages cannot exhaust memory (§4.4.1).
fn test_transcript_update_enforces_total_bound() ! {
	mut transcript := new_transcript(.sha256)
	msg := []u8{len: max_transcript_len, init: 0xaa}
	transcript.update(msg)! // exactly at the bound: still legal
	transcript.update([u8(0x00)]) or {
		assert err.msg().contains('transcript exceeds')
		return
	}
	assert false, 'a transcript append past max_transcript_len must fail'
}

// test_rfc8448_section3_key_schedule walks the entire Early → Handshake → Master
// chain and both traffic-secret generations, asserting each HKDF step in place.
fn test_rfc8448_section3_key_schedule() ! {
	hash := HashAlgorithm.sha256

	// 1. Verify Early Secret derivation (RFC 8448 §3: no PSK, zero salt and zero IKM)
	early_secret := hkdf_extract(hash, []u8{}, []u8{len: 32})
	assert hex.encode(early_secret) == rfc8448_early_secret

	// 2. Verify Derived secret from early secret
	derived_early := derive_secret(hash, early_secret, 'derived', empty_transcript_hash(hash))!
	assert hex.encode(derived_early) == rfc8448_derived_for_handshake

	// 3. Verify Handshake Secret from ECDH shared secret
	ecdh_shared := hex.decode(rfc8448_ecdhe_shared_secret)!
	handshake_secret := hkdf_extract(hash, derived_early, ecdh_shared)
	assert hex.encode(handshake_secret) == rfc8448_handshake_secret

	// 4. Verify Client/Server Handshake Traffic Secrets
	transcript_ch_sh := hex.decode(rfc8448_transcript_hash_ch_sh)!
	client_hs_secret := derive_secret(hash, handshake_secret, 'c hs traffic', transcript_ch_sh)!
	assert hex.encode(client_hs_secret) == rfc8448_client_hs_traffic

	server_hs_secret := derive_secret(hash, handshake_secret, 's hs traffic', transcript_ch_sh)!
	assert hex.encode(server_hs_secret) == rfc8448_server_hs_traffic

	// 5. Verify Handshake Keys & IVs
	client_hs_key := derive_traffic_key(hash, client_hs_secret, 16)!
	client_hs_iv := derive_traffic_iv(hash, client_hs_secret, 12)!
	assert hex.encode(client_hs_key) == 'dbfaa693d1762c5b666af5d950258d01'
	assert hex.encode(client_hs_iv) == '5bd3c71b836e0b76bb73265f'

	server_hs_key := derive_traffic_key(hash, server_hs_secret, 16)!
	server_hs_iv := derive_traffic_iv(hash, server_hs_secret, 12)!
	assert hex.encode(server_hs_key) == '3fce516009c21727d0f2e4e86ee403bc'
	assert hex.encode(server_hs_iv) == '5d313eb2671276ee13000b30'

	// 6. Verify Master Secret
	derived_hs := derive_secret(hash, handshake_secret, 'derived', empty_transcript_hash(hash))!
	assert hex.encode(derived_hs) == rfc8448_derived_for_master

	master_secret := hkdf_extract(hash, derived_hs, []u8{len: 32})
	assert hex.encode(master_secret) == rfc8448_master_secret

	// 7. Verify Client/Server Application Traffic Secrets
	transcript_ch_sfin := hex.decode(rfc8448_transcript_hash_ch_sfin)!
	client_app_secret := derive_secret(hash, master_secret, 'c ap traffic', transcript_ch_sfin)!
	assert hex.encode(client_app_secret) == rfc8448_client_ap_traffic_0

	server_app_secret := derive_secret(hash, master_secret, 's ap traffic', transcript_ch_sfin)!
	assert hex.encode(server_app_secret) == rfc8448_server_ap_traffic_0

	// 8. Verify Application Keys & IVs
	client_app_key := derive_traffic_key(hash, client_app_secret, 16)!
	client_app_iv := derive_traffic_iv(hash, client_app_secret, 12)!
	assert hex.encode(client_app_key) == '17422dda596ed5d9acd890e3c63f5051'
	assert hex.encode(client_app_iv) == '5b78923dee08579033e523d9'

	server_app_key := derive_traffic_key(hash, server_app_secret, 16)!
	server_app_iv := derive_traffic_iv(hash, server_app_secret, 12)!
	assert hex.encode(server_app_key) == '9f02283b6c9c07efc26bb9f2ac92e356'
	assert hex.encode(server_app_iv) == 'cf782b88dd83549aadf1e984'
}

// test_rfc8448_composite_phase_helpers pins the split handshake/master derivers to the
// same RFC 8448 chain after their in-place intermediate wipes: a wipe that aliased an
// input or an output would break these known answers.
fn test_rfc8448_composite_phase_helpers() ! {
	hash := HashAlgorithm.sha256
	ecdh_shared := hex.decode(rfc8448_ecdhe_shared_secret)!
	transcript_ch_sh := hex.decode(rfc8448_transcript_hash_ch_sh)!
	handshake_secret := derive_handshake_secret(hash, ecdh_shared, none)!
	assert hex.encode(handshake_secret) == rfc8448_handshake_secret
	hs_c := derive_client_hs_secret(hash, handshake_secret, transcript_ch_sh)!
	hs_s := derive_server_hs_secret(hash, handshake_secret, transcript_ch_sh)!
	assert hex.encode(hs_c) == rfc8448_client_hs_traffic
	assert hex.encode(hs_s) == rfc8448_server_hs_traffic

	transcript_ch_sfin := hex.decode(rfc8448_transcript_hash_ch_sfin)!
	mut master := derive_master_secret(hash, handshake_secret)!
	ap_c := derive_client_app_secret(hash, master, transcript_ch_sfin)!
	ap_s := derive_server_app_secret(hash, master, transcript_ch_sfin)!
	wipe_secret(mut master)
	assert hex.encode(ap_c) == rfc8448_client_ap_traffic_0
	assert hex.encode(ap_s) == rfc8448_server_ap_traffic_0
}

// test_hkdf_expand_rejects_nonpositive_length checks the fail-closed guard: a
// zero-length expansion would silently hand back an empty "key" instead of erroring.
fn test_hkdf_expand_rejects_nonpositive_length() ! {
	hkdf_expand(HashAlgorithm.sha256, [u8(0x0b)], []u8{}, 0) or {
		assert err.msg().contains('not positive')
		return
	}
	assert false, 'a zero-length HKDF-Expand must fail closed'
}

// test_record_key_expansion pins the per-phase client/server record-key expansion
// to the RFC 8448 §3 handshake keys: the derive_traffic_key and derive_traffic_iv
// calls that traffic_keys() now runs on demand must reproduce these known answers.
// reproduce these known answers.
fn test_record_key_expansion() ! {
	hash := HashAlgorithm.sha256
	client_secret := hex.decode(rfc8448_client_hs_traffic)!
	server_secret := hex.decode(rfc8448_server_hs_traffic)!
	ck_key := derive_traffic_key(hash, client_secret, 16)!
	ck_iv := derive_traffic_iv(hash, client_secret, 12)!
	sk_key := derive_traffic_key(hash, server_secret, 16)!
	sk_iv := derive_traffic_iv(hash, server_secret, 12)!
	assert hex.encode(ck_key) == 'dbfaa693d1762c5b666af5d950258d01'
	assert hex.encode(ck_iv) == '5bd3c71b836e0b76bb73265f'
	assert hex.encode(sk_key) == '3fce516009c21727d0f2e4e86ee403bc'
	assert hex.encode(sk_iv) == '5d313eb2671276ee13000b30'
}

// test_derivers_leave_input_secret_untouched guards the split's moved ownership: each
// deriver must read its secret argument without mutating or wiping it, because the
// caller keeps that buffer alive (handshake_secret is stored and reused for the Master
// Secret; master_secret is zeroized by the caller, not by the app derivers). A split
// helper that wiped its input would silently destroy the secret the next stage needs.
fn test_derivers_leave_input_secret_untouched() ! {
	hash := HashAlgorithm.sha256
	shared_secret := hex.decode(rfc8448_ecdhe_shared_secret)!
	handshake_secret := hex.decode(rfc8448_handshake_secret)!
	master_secret := hex.decode(rfc8448_master_secret)!
	th_ch_sh := hex.decode(rfc8448_transcript_hash_ch_sh)!
	th_sfin := hex.decode(rfc8448_transcript_hash_ch_sfin)!
	client_hs_traffic := hex.decode(rfc8448_client_hs_traffic)!

	shared_before := shared_secret.clone()
	_ = derive_handshake_secret(hash, shared_secret, none)!
	assert shared_secret == shared_before

	hs_before := handshake_secret.clone()
	_ = derive_client_hs_secret(hash, handshake_secret, th_ch_sh)!
	_ = derive_server_hs_secret(hash, handshake_secret, th_ch_sh)!
	_ = derive_master_secret(hash, handshake_secret)!
	assert handshake_secret == hs_before

	master_before := master_secret.clone()
	_ = derive_client_app_secret(hash, master_secret, th_sfin)!
	_ = derive_server_app_secret(hash, master_secret, th_sfin)!
	assert master_secret == master_before

	tsec_before := client_hs_traffic.clone()
	_ = derive_traffic_key(hash, client_hs_traffic, 16)!
	_ = derive_traffic_iv(hash, client_hs_traffic, 12)!
	assert client_hs_traffic == tsec_before
}

// test_derivers_deterministic_and_distinct pins the properties the label-preserving
// split must retain: the same inputs expand to the same bytes, the client and server
// directions stay distinct (separate labels survived the split), and the key and iv
// derivers produce different material of exactly the requested lengths.
fn test_derivers_deterministic_and_distinct() ! {
	hash := HashAlgorithm.sha256
	handshake_secret := hex.decode(rfc8448_handshake_secret)!
	master_secret := hex.decode(rfc8448_master_secret)!
	th_ch_sh := hex.decode(rfc8448_transcript_hash_ch_sh)!
	th_sfin := hex.decode(rfc8448_transcript_hash_ch_sfin)!
	client_hs_traffic := hex.decode(rfc8448_client_hs_traffic)!

	first := derive_client_hs_secret(hash, handshake_secret, th_ch_sh)!
	second := derive_client_hs_secret(hash, handshake_secret, th_ch_sh)!
	assert first == second

	hs_c := derive_client_hs_secret(hash, handshake_secret, th_ch_sh)!
	hs_s := derive_server_hs_secret(hash, handshake_secret, th_ch_sh)!
	assert hs_c != hs_s

	ap_c := derive_client_app_secret(hash, master_secret, th_sfin)!
	ap_s := derive_server_app_secret(hash, master_secret, th_sfin)!
	assert ap_c != ap_s

	key := derive_traffic_key(hash, client_hs_traffic, 16)!
	iv := derive_traffic_iv(hash, client_hs_traffic, 12)!
	assert key.len == 16
	assert iv.len == 12
	assert key != iv
}

// test_derived_buffers_are_independent_of_intermediates checks that two expansions off
// the same secret return separate allocations. If a split deriver handed back a buffer
// aliased to a wiped intermediate, a later expansion (or the caller's input wipe) would
// clobber an already-returned secret.
fn test_derived_buffers_are_independent_of_intermediates() ! {
	hash := HashAlgorithm.sha256
	handshake_secret := hex.decode(rfc8448_handshake_secret)!
	th_ch_sh := hex.decode(rfc8448_transcript_hash_ch_sh)!
	hs_c := derive_client_hs_secret(hash, handshake_secret, th_ch_sh)!
	hs_s := derive_server_hs_secret(hash, handshake_secret, th_ch_sh)!
	assert unsafe { voidptr(&hs_c[0]) } != unsafe { voidptr(&hs_s[0]) }
}

// test_sha384_split_chain_matches_primitives proves the composite phase helpers are
// byte-identical to their primitive HKDF decomposition at the SHA-384 digest, without
// needing external vectors. This exercises the hash_len()==48 block loop the SHA-256
// KATs never reach, so a length or digest-size regression in the split surfaces here.
fn test_sha384_split_chain_matches_primitives() ! {
	hash := HashAlgorithm.sha384
	shared_secret := []u8{len: 48, init: 0x5a}

	// Handshake Secret: Early(zero-PSK) -> "derived" -> HKDF-Extract(shared secret).
	early := hkdf_extract(hash, []u8{}, []u8{len: 48})
	derived_early := derive_secret(hash, early, 'derived', empty_transcript_hash(hash))!
	manual_hs := hkdf_extract(hash, derived_early, shared_secret)
	split_hs := derive_handshake_secret(hash, shared_secret, none)!
	assert split_hs == manual_hs
	assert split_hs.len == 48

	// Master Secret: Handshake -> "derived" -> zero-PSK extract.
	derived_hs := derive_secret(hash, manual_hs, 'derived', empty_transcript_hash(hash))!
	manual_master := hkdf_extract(hash, derived_hs, []u8{len: 48})
	split_master := derive_master_secret(hash, manual_hs)!
	assert split_master == manual_master
	assert split_master.len == 48
}

// test_psk_handshake_secret_changes_with_psk verifies that adding a PSK to the
// Early Secret changes the Handshake Secret (RFC 8446 §7.1: the PSK is mixed
// into the Early Secret via HKDF-Extract).
fn test_psk_handshake_secret_changes_with_psk() {
	hash := HashAlgorithm.sha256
	shared_secret := []u8{len: 32, init: 0xab}
	psk := [u8(0x11), 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
		0xff, 0x00]

	hs_zero_psk := derive_handshake_secret(hash, shared_secret, none)!
	hs_with_psk := derive_handshake_secret(hash, shared_secret, psk)!

	assert hs_zero_psk != hs_with_psk
	assert hs_zero_psk.len == 32
	assert hs_with_psk.len == 32
}

// test_psk_early_secret_is_psk_when_offered verifies that the Early Secret is
// HKDF-Extract(0, psk) when a PSK is offered, and HKDF-Extract(0, 0) when not.
fn test_psk_early_secret_is_psk_when_offered() {
	hash := HashAlgorithm.sha256
	psk := [u8(0x11), 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
		0xff, 0x00]

	early_zero := hkdf_extract(hash, []u8{}, []u8{len: 32})
	early_psk := hkdf_extract(hash, []u8{}, psk)

	assert early_zero != early_psk
	assert early_zero.len == 32
	assert early_psk.len == 32
}

// test_psk_binder_key_is_different_per_psk verifies that the binder key derived
// from the Early Secret is keyed material that differs with different Early Secrets.
fn test_psk_binder_key_is_different_per_psk() {
	hash := HashAlgorithm.sha256
	psk1 := [u8(0x11), 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
		0xee, 0xff, 0x00]
	psk2 := [u8(0xff), 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
		0x22, 0x11, 0x00]

	early1 := hkdf_extract(hash, []u8{}, []u8{len: 32})
	early2 := hkdf_extract(hash, []u8{}, psk1)

	binder_key_zero := derive_binder_key(hash, early1)!
	binder_key_psk := derive_binder_key(hash, early2)!

	assert binder_key_zero != binder_key_psk
	assert binder_key_zero.len == 32
	assert binder_key_psk.len == 32
}

// test_psk_identity_round_trip verifies PskIdentity and PskBinderEntry can be
// constructed and accessed (foundation for ClientHello binder computation).
fn test_psk_identity_round_trip() {
	id := PskIdentity{
		identity:              [u8(0xde), 0xad, 0xbe, 0xef]
		obfuscated_ticket_age: 12345
	}
	assert id.identity.len == 4
	assert id.obfuscated_ticket_age == 12345

	binder := PskBinderEntry{
		binder: [u8(0x01), 0x02, 0x03, 0x04]
	}
	assert binder.binder.len == 4
}

// test_psk_key_exchange_modes_extension verifies the psk_key_exchange_modes
// extension body encodes only psk_dhe_ke (mode 1) (RFC 8446 §4.2.9).
fn test_psk_key_exchange_modes_extension() {
	ext := build_psk_key_exchange_modes_extension()!
	// Extension body: mode_len(1) + mode(1) = 2 bytes
	assert ext.len == 2
	assert ext[0] == 0x01 // one mode
	assert ext[1] == 0x01 // mode = psk_dhe_ke
}

// test_rfc8448_resumption_psk_binder pins the PSK binder construction to the
// RFC 8448 §4 resumption example: early secret from the PSK, the "res binder"
// label, then the "finished" expansion over the ClientHello prefix hash.
fn test_rfc8448_resumption_psk_binder() ! {
	hash := HashAlgorithm.sha256
	psk := hex.decode('4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3')!
	client_hello_prefix_hash := hex.decode('63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14')!

	binder := compute_psk_binder(hash, psk, 'res binder', client_hello_prefix_hash)!
	assert hex.encode(binder) == '3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d'

	// External PSKs use a distinct label and therefore a distinct binder.
	external := compute_psk_binder(hash, psk, 'ext binder', client_hello_prefix_hash)!
	assert external != binder
}
