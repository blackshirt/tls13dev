// Copyright (c) 2026 blackshirt.
//
// client_test.v covers the socket-owning facade's network-free surface: the address
// host derivation that supplies SNI, and the argument validation dial() runs before it
// opens a socket. The end-to-end handshake itself is proven over the in-memory ferry
// in engine_test.v; a live UDP loopback dial would depend on socket timing, so it is
// deliberately not tested here.
module quic

import time

fn test_host_from_address() ! {
	assert host_from_address('example.com:443') == 'example.com'
	assert host_from_address('127.0.0.1:9000') == '127.0.0.1'
	// A bracketed IPv6 literal yields the inner address, not the port separator.
	assert host_from_address('[::1]:8443') == '::1'
	// No port: the whole string is already the host.
	assert host_from_address('localhost') == 'localhost'
}

// test_dial_rejects_empty_name checks dial fails on an empty SNI name before it opens
// any socket: the address's host part is empty and no server_name was supplied.
fn test_dial_rejects_empty_name() ! {
	dial(':4433', Config{}) or {
		assert err.msg().contains('empty server name')
		return
	}
	assert false, 'dial with an empty server name must fail'
}

// test_dial_rejects_whitespace_name checks stray surrounding whitespace is refused
// rather than carried verbatim into SNI and hostname verification.
fn test_dial_rejects_whitespace_name() ! {
	dial('example.com:443', Config{ server_name: ' example.com' }) or {
		assert err.msg().contains('stray whitespace')
		return
	}
	assert false, 'dial with a whitespace-padded server name must fail'
}

// test_dial_rejects_overlong_name checks a name past the DNS ceiling (RFC 1035 §2.3.4)
// cannot be dialed, since it would not fit the u16 SNI length field.
fn test_dial_rejects_overlong_name() ! {
	mut overlong := ''
	for _ in 0 .. max_server_name_len + 1 {
		overlong += 'a'
	}
	dial('example.com:443', Config{ server_name: overlong }) or {
		assert err.msg().contains('exceeds')
		return
	}
	assert false, 'dial with an overlong server name must fail'
}

// test_config_defaults_documents_the_bound guards the Config defaults the facade's
// deadline and packetization math relies on.
fn test_config_defaults_documents_the_bound() ! {
	cfg := Config{}
	assert cfg.timeout == 30 * time.second
	assert cfg.max_packet_size == default_max_packet_size
}
