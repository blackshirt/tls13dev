// Copyright (c) 2026 blackshirt.
//
// Tests for psk.v: PskIdentity/PskBinderEntry wire types, the psk_key_exchange_modes
// and pre_shared_key framing (including the ClientHello binder layout), the
// binder computation pinned to the RFC 8448 §4 resumption vector, the identity/
// binder count guard, and the new_psk input screening.
module handshake

import encoding.hex
import tls.wire

// new_psk_error calls the public constructor and returns its rejection
// message, or '' when the construction succeeds.
fn new_psk_error(identity []u8, key []u8) string {
	_ = new_psk(identity, key) or {
		return err.msg()
	}
	return ''
}

// test_new_psk_rejects_empty_identity pins the constructor guard against a
// zero-length identity, which could never be framed as an offered PSK.
fn test_new_psk_rejects_empty_identity() {
	msg := new_psk_error([]u8{}, []u8{len: 32, init: 0x11})
	assert msg.contains('PSK identity must not be empty'), msg
}

// test_new_psk_rejects_empty_key rejects a zero-length key at construction.
fn test_new_psk_rejects_empty_key() {
	msg := new_psk_error('ticket'.bytes(), []u8{})
	assert msg.contains('PSK key must not be empty'), msg
}

// test_new_psk_rejects_overlong_identity rejects an identity past the
// §4.2.11 wire limit before it reaches the extension codec.
fn test_new_psk_rejects_overlong_identity() {
	msg := new_psk_error([]u8{len: 65536, init: 0x61}, []u8{len: 32, init: 0x11})
	assert msg.contains('exceeds the 65535-byte wire limit'), msg
}

// test_new_psk_copies_caller_bytes proves the handle owns its inputs: mutating
// the caller's slices after construction cannot change psk.identity()/psk.key().
fn test_new_psk_copies_caller_bytes() ! {
	mut identity := 'ticket'.bytes()
	mut key := [u8(0x11)].repeat(32)
	psk := new_psk(identity, key)!
	for i in 0 .. identity.len {
		identity[i] = u8(0xff)
	}
	for i in 0 .. key.len {
		key[i] = u8(0xff)
	}
	assert psk.identity() == 'ticket'.bytes()
	assert psk.key() == [u8(0x11)].repeat(32)
}

// test_new_psk_rejects_short_key rejects a key below the §7.1 Hash.length floor
// documented on psk_key_min_len.
fn test_new_psk_rejects_short_key() {
	msg := new_psk_error('ticket'.bytes(), [u8(0xab)].repeat(16))
	assert msg.contains('below the 32-byte §7.1 minimum'), msg
}

// test_new_psk_rejects_overlong_key rejects a key past the psk_key_max_len
// policy ceiling.
fn test_new_psk_rejects_overlong_key() {
	msg := new_psk_error('ticket'.bytes(), [u8(0xab)].repeat(1025))
	assert msg.contains('exceeds the 1024-byte policy ceiling'), msg
}

// test_new_psk_accepts_key_at_boundaries proves both key-length bounds are
// inclusive: 32 (min) and 1024 (max) construct cleanly.
fn test_new_psk_accepts_key_at_boundaries() ! {
	min_psk := new_psk('ticket'.bytes(), [u8(0x11)].repeat(32))!
	assert min_psk.key().len == 32
	max_psk := new_psk('ticket'.bytes(), [u8(0x22)].repeat(1024))!
	assert max_psk.key().len == 1024
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

// test_psk_binder_key_is_different_per_psk verifies that the binder key derived
// from the Early Secret is keyed material that differs with different Early Secrets.
fn test_psk_binder_key_is_different_per_psk() {
	hash := HashAlgorithm.sha256
	psk1 := [u8(0x11), 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
		0xee, 0xff, 0x00]

	early1 := hkdf_extract(hash, []u8{}, []u8{len: 32})
	early2 := hkdf_extract(hash, []u8{}, psk1)

	binder_key_zero := derive_binder_key(hash, early1)!
	binder_key_psk := derive_binder_key(hash, early2)!

	assert binder_key_zero != binder_key_psk
	assert binder_key_zero.len == 32
	assert binder_key_psk.len == 32
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

// test_build_client_hello_pre_shared_key_encoding checks the §4.2.11 wire shape:
// pre_shared_key is the final extension, identities carry u16 lengths plus the
// obfuscated age, binders use a u8 entry length inside a u16 vector, and each
// binder covers the ClientHello truncated before the binders vector.
fn test_build_client_hello_pre_shared_key_encoding() ! {
	psk_a := Psk{
		identity:              [u8(0xaa), 0xbb, 0xcc]
		key:                   []u8{len: 32, init: 0x11}
		obfuscated_ticket_age: 0x11223344
	}
	psk_b := Psk{
		identity:              [u8(0xdd), 0xee]
		key:                   []u8{len: 32, init: 0x22}
		external:              true
		obfuscated_ticket_age: 0x55667788
	}
	psk_c := Psk{
		identity:              [u8(0xff)]
		key:                   []u8{len: 32, init: 0x33}
		obfuscated_ticket_age: 0x99aabbcc
		hash_algo:             .sha384
	}
	cfg := ClientHelloConfig{
		client_share: KeyShareEntry{
			group:        .x25519
			key_exchange: []u8{len: 32, init: 0xaa}
		}
		session_id:   []u8{len: 32, init: 0x33}
		random:       []u8{len: client_hello_random_len, init: 0x44}
		psks:         [psk_a, psk_b, psk_c]
	}
	_, full := build_client_hello(cfg)!

	mut r := wire.new_reader(full[4..])
	_ = r.read_u16()!
	_ = r.read_bytes(client_hello_random_len)!
	_ = r.read_vector_u8()!
	_ = r.read_vector_u16()!
	_ = r.read_vector_u8()!
	ext_bytes := r.read_vector_u16()!

	mut ext_reader := wire.new_reader(ext_bytes)
	mut last_type := u16(0)
	mut saw_modes := false
	mut psk_data := []u8{}
	for ext_reader.remaining() > 0 {
		typ := ext_reader.read_u16()!
		data := ext_reader.read_vector_u16()!
		last_type = typ
		if typ == u16(ExtensionType.psk_key_exchange_modes) {
			saw_modes = true
		}
		if typ == u16(ExtensionType.pre_shared_key) {
			psk_data = data.clone()
		}
	}
	assert saw_modes
	assert last_type == u16(ExtensionType.pre_shared_key), 'pre_shared_key must be last'

	mut psk_reader := wire.new_reader(psk_data)
	ids_bytes := psk_reader.read_vector_u16()!
	mut ids_reader := wire.new_reader(ids_bytes)
	for expected in [psk_a, psk_b, psk_c] {
		assert ids_reader.read_vector_u16()! == expected.identity
		assert ids_reader.read_u32()! == expected.obfuscated_ticket_age
	}
	assert ids_reader.remaining() == 0

	binder_bytes := psk_reader.read_vector_u16()!
	mut binder_reader := wire.new_reader(binder_bytes)
	mut binders := [][]u8{}
	for binder_reader.remaining() > 0 {
		binders << binder_reader.read_vector_u8()!
	}
	assert binders.len == 3
	assert binders[0].len == 32
	assert binders[1].len == 32
	assert binders[2].len == 48, 'a SHA-384 PSK binder must be Hash.length bytes'
	assert psk_reader.remaining() == 0

	// Recompute each binder over the message bytes that precede the binders
	// vector; the builder must have used the same truncated transcript, with
	// full-message length fields already in place.
	binder_tail_len := 2 + (1 + 32) + (1 + 32) + (1 + 48)
	prefix := full[..full.len - binder_tail_len]
	for i, psk in [psk_a, psk_b, psk_c] {
		prefix_hash := psk.hash_algo.compute_hash(prefix)
		expected := compute_psk_binder(psk.hash_algo, psk.key, psk_binder_label(psk),
			prefix_hash)!
		assert binders[i] == expected, 'binder ${i} does not use its PSK hash'
	}
}

// test_build_pre_shared_key_rejects_identity_binder_mismatch guards the codec
// from producing an OfferedPsks with unequal identity and binder counts.
fn test_build_pre_shared_key_rejects_identity_binder_mismatch() {
	build_pre_shared_key_extension([
		PskIdentity{
			identity:              [u8(0x01)]
			obfuscated_ticket_age: 0
		},
	], []) or {
		assert err.msg().contains('1 identities but 0 binders')
		return
	}
	assert false, 'mismatched identities/binders must be rejected'
}
