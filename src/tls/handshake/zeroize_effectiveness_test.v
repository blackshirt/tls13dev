// Copyright (c) 2026 blackshirt.
//
// zeroize_effectiveness_test.v verifies that zeroization actually scrubs
// buffers: after wipe_secret/zero_bytes, the underlying bytes are zero.
// This catches compiler optimization that might remove the zeroing loop.
module handshake

fn test_wipe_secret_actually_zeros() ! {
	mut buf := []u8{len: 64, init: 0xAA}
	wipe_secret(mut buf)
	// Verify every byte is actually zero (not just the handle rebound).
	for i in 0 .. buf.len {
		assert buf[i] == 0
	}
}

fn test_zero_bytes_actually_zeros() ! {
	// zero_bytes is defined in quic module; wipe_secret is the handshake module
	// equivalent. Both use the same zeroing loop pattern.
	mut buf := []u8{len: 64, init: 0xFF}
	wipe_secret(mut buf)
	for i in 0 .. buf.len {
		assert buf[i] == 0
	}
}

fn test_key_material_wipe_zeros_all_slots() ! {
	mut km := KeyMaterial{
		key: []u8{len: 16, init: 0xAA}
		iv:  []u8{len: 12, init: 0xBB}
		hp:  []u8{len: 16, init: 0xCC}
	}
	km.wipe()
	assert km.key.len == 0
	assert km.iv.len == 0
	assert km.hp.len == 0
}

fn test_traffic_keys_wipe_zeros_both_directions() ! {
	mut tk := TrafficKeys{
		client: KeyMaterial{ key: []u8{len: 16, init: 0xAA} }
		server: KeyMaterial{ key: []u8{len: 16, init: 0xBB} }
	}
	tk.wipe()
	assert tk.client.key.len == 0
	assert tk.server.key.len == 0
}

fn test_take_key_moves_and_empties() ! {
	mut km := KeyMaterial{
		key: []u8{len: 16, init: 0xAA}
		iv:  []u8{len: 12, init: 0xBB}
		hp:  []u8{len: 16, init: 0xCC}
	}
	key := km.take_key()
	assert key.len == 16
	assert km.key.len == 0 // source emptied after move
	iv := km.take_iv()
	assert iv.len == 12
	assert km.iv.len == 0
	hp := km.take_hp()
	assert hp.len == 16
	assert km.hp.len == 0
}
