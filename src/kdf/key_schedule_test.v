// Copyright (c) 2026 blackshirt.
// SPDX-License-Identifier: MIT
//
// Known-answer tests for the TLS 1.3 key schedule against the RFC 8448 §3
// worked example (SHA-256/PSK-less branch). The rfc8448_* constants are that
// example's intermediate secrets, hex-encoded, in schedule order; inline hex
// literals cover the derived key/IV pairs the constants list omits.
module kdf

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
	transcript.update(client_hello)
	transcript.update(server_hello)
	assert hex.encode(transcript.current_hash()) == rfc8448_transcript_hash_ch_sh
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
	client_hs_keys := derive_traffic_keys(hash, client_hs_secret, 16, 12)!
	assert hex.encode(client_hs_keys.key) == 'dbfaa693d1762c5b666af5d950258d01'
	assert hex.encode(client_hs_keys.iv) == '5bd3c71b836e0b76bb73265f'

	server_hs_keys := derive_traffic_keys(hash, server_hs_secret, 16, 12)!
	assert hex.encode(server_hs_keys.key) == '3fce516009c21727d0f2e4e86ee403bc'
	assert hex.encode(server_hs_keys.iv) == '5d313eb2671276ee13000b30'

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
	client_app_keys := derive_traffic_keys(hash, client_app_secret, 16, 12)!
	assert hex.encode(client_app_keys.key) == '17422dda596ed5d9acd890e3c63f5051'
	assert hex.encode(client_app_keys.iv) == '5b78923dee08579033e523d9'

	server_app_keys := derive_traffic_keys(hash, server_app_secret, 16, 12)!
	assert hex.encode(server_app_keys.key) == '9f02283b6c9c07efc26bb9f2ac92e356'
	assert hex.encode(server_app_keys.iv) == 'cf782b88dd83549aadf1e984'
}
