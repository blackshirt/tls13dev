module client

// Socket-free tests for the Conn read-side plumbing: read_raw_record exists to
// reassemble TLS records from a TCP byte stream (glued or split frames), and
// those paths are exercised here by pre-staging recv_buf — a populated buffer
// never reaches the nil sock. The write path and the real handshake loop need
// a live socket; dial_example.v is their end-to-end coverage.

import record

// test_read_raw_record_glued_frames stages two complete serialized records
// back-to-back (what TCP coalescing delivers) and verifies each read returns
// exactly one frame in order with intact payload.
fn test_read_raw_record_glued_frames() ! {
	mut c := &Conn{}
	c.recv_buf << record.new_record(.handshake, [u8(0xde), 0xad]).serialize()
	c.recv_buf << record.new_record(.handshake, [u8(0xbe), 0xef, 0x11]).serialize()

	rec1 := c.read_raw_record()!
	assert rec1.content_type == .handshake
	assert rec1.payload == [u8(0xde), 0xad]

	rec2 := c.read_raw_record()!
	assert rec2.payload == [u8(0xbe), 0xef, 0x11]
}

// test_read_raw_record_split_frame proves the framing state survives a partial
// trailing record: only the complete frame may be consumed, the leftover
// prefix stays buffered (across compaction) until its tail arrives — the exact
// mid-read disconnect pattern TCP produces.
fn test_read_raw_record_split_frame() ! {
	first := record.new_record(.handshake, [u8(1), 2, 3, 4]).serialize()
	second := record.new_record(.handshake, [u8(5), 6, 7]).serialize()

	mut c := &Conn{}
	c.recv_buf << first
	c.recv_buf << second[..4] // header plus one payload byte: not a full frame

	rec1 := c.read_raw_record()! // consumes only `first`
	assert rec1.payload == [u8(1), 0x02, 0x03, 0x04]

	c.recv_buf << second[4..] // complete the split frame
	rec2 := c.read_raw_record()!
	assert rec2.payload == [u8(5), 0x06, 0x07]
}

// test_host_from_address covers the dial-address forms that must still yield a
// usable SNI name when Config.server_name is unset.
fn test_host_from_address() ! {
	assert host_from_address('example.com:443') == 'example.com'
	assert host_from_address('[2001:db8::1]:443') == '2001:db8::1'
	assert host_from_address('localhost') == 'localhost'
}
