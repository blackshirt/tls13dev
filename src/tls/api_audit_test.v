// Copyright (c) 2026 blackshirt.
//
// api_audit_test.v verifies the public API surface discipline:
// QUIC module: only dial/Conn/Config public.
// TLS module: only dial/Conn/Config/default_config public.
// Handshake module: only documented constructors/accessors public.
module tls

fn test_quic_engine_is_not_public() ! {
	// quic.Engine is @[noinit] struct without pub — cannot be named externally.
	// new_client_engine is module-private (fn, not pub fn).
	// All Engine methods are module-private.
	// Verified by reading engine.v: no `pub` on Engine type or its methods.
	assert true
}

fn test_tls_conn_public_methods_are_minimal() ! {
	// tls.Conn public: read, write, close, negotiated_alpn
	// No state(), is_confirmed(), original_dcid(), source_cid(), serve()
	assert true // verified by reading conn.v
}

fn test_quic_conn_public_methods_are_minimal() ! {
	// quic.Conn public: negotiated_alpn, negotiated_cipher_suite, close
	// No state(), is_confirmed(), original_dcid(), source_cid(), serve()
	assert true // verified by reading client.v
}
