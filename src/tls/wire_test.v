// Copyright (c) 2026 blackshirt.
//
// Wire codec tests: big-endian primitives and length-prefixed vectors must read
// back exactly what was written, and truncated reads must fail with the bounds
// error instead of indexing past the buffer.
module tls

fn test_wire_roundtrip_primitives() ! {
	mut w := new_writer(64)
	w.write_u8(0x42)
	w.write_u16(0x1234)
	w.write_u24(0x010203)
	w.write_u32(0xaabbccdd)
	w.write_u64(0x0102030405060708)

	bytes := w.bytes()
	assert bytes.len == 1 + 2 + 3 + 4 + 8

	mut r := new_reader(bytes)
	assert r.read_u8()! == 0x42
	assert r.read_u16()! == 0x1234
	assert r.read_u24()! == 0x010203
	assert r.read_u32()! == 0xaabbccdd
	assert r.read_u64()! == 0x0102030405060708
	assert r.remaining() == 0
}

fn test_wire_vectors() ! {
	mut w := new_writer(64)
	payload := [u8(10), 20, 30, 40]
	w.write_vector_u8(payload)!
	w.write_vector_u16(payload)!
	w.write_vector_u24(payload)!

	mut r := new_reader(w.bytes())
	assert r.read_vector_u8()! == payload
	assert r.read_vector_u16()! == payload
	assert r.read_vector_u24()! == payload
	assert r.remaining() == 0
}

fn test_wire_reader_bounds_check() {
	mut r := new_reader([u8(1), 2])
	assert r.read_u8() or { 0 } == 1
	assert r.read_u8() or { 0 } == 2
	r.read_u8() or {
		assert err.msg().contains('unexpected EOF')
		return
	}
	assert false
}
