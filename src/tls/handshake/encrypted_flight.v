// Copyright (c) 2026 blackshirt.
//
// encrypted_flight.v processes the server's encrypted flight after ServerHello:
// EncryptedExtensions, optional CertificateRequest, Certificate, CertificateVerify
// and Finished, then emits the client Finished (RFC 8446 §4.3–§4.4).
module handshake

import crypto.subtle
import tls.pki

// handle_encrypted_extensions records ALPN and QUIC transport parameters.
fn (mut h HandshakeCore) handle_encrypted_extensions(full_msg []u8, body []u8) ![]HandshakeMessage {
	if h.state != .wait_encrypted_extensions {
		return h.classify_failure(.unexpected_message, 'handshake: unexpected EncryptedExtensions')
	}
	alpn, transport_parameters := parse_encrypted_extensions_for_transport(body,
		h.config.is_quic) or {
		return h.classify_failure(.decode_error, err.msg())
	}
	// RFC 7301 §3.1: the server must pick from the offered list; an unoffered value could steer the application protocol below us.
	// `in` is exact element membership — a substring test would let a hostile pick like "1.1" pass against the offer "http/1.1".
	if alpn != '' && !(alpn in h.config.alpn) {
		return h.classify_failure(.illegal_parameter, 'handshake: server selected ALPN "${alpn}" not offered by client')
	}
	h.negotiated_alpn = alpn
	h.quic_params = transport_parameters
	h.update_transcript(full_msg)!
	h.state = .wait_certificate_request
	return []HandshakeMessage{}
}

// handle_certificate_request answers a server request with an empty Certificate.
fn (mut h HandshakeCore) handle_certificate_request(full_msg []u8, body []u8) ![]HandshakeMessage {
	// §4.3.2: the server wants client authentication; this client holds no credential and acknowledges with an empty Certificate (§4.4.2).
	if h.state != .wait_certificate_request {
		return h.classify_failure(.unexpected_message, 'handshake: unexpected CertificateRequest')
	}
	req := parse_certificate_request(body) or {
		return h.classify_failure(.decode_error, err.msg())
	}
	h.update_transcript(full_msg)!
	h.request_context = req.request_context
	h.state = .wait_certificate

	// The empty Certificate-response (§4.4.2) enters the transcript BEFORE the server's flight is verified, so the server Finished covers our response.
	response := build_empty_certificate(h.request_context)
	h.update_transcript(response)!
	return [new_handshake_message(.handshake, response)!]
}

// handle_certificate parses and validates the server certificate chain.
fn (mut h HandshakeCore) handle_certificate(full_msg []u8, body []u8) ![]HandshakeMessage {
	// §4.4.1: the server Certificate follows EncryptedExtensions directly, or a CertificateRequest may sit before it; accept both orders.
	if h.state != .wait_certificate_request && h.state != .wait_certificate {
		return h.classify_failure(.unexpected_message, 'handshake: unexpected Certificate')
	}
	cert_ders := parse_certificate_message(body) or {
		return h.classify_failure(.decode_error, err.msg())
	}
	h.update_transcript(full_msg)!

	h.server_certs = []pki.Certificate{}
	for der in cert_ders {
		cert := pki.parse_certificate(der) or {
			return h.classify_failure(.decode_error, err.msg())
		}
		h.server_certs << cert
	}
	h.validator.verify_certificate_chain(h.server_certs, h.config.server_name) or {
		return h.classify_failure(.bad_certificate, err.msg())
	}
	h.state = .wait_certificate_verify
	return []HandshakeMessage{}
}

// handle_certificate_verify checks the server's signature over the transcript.
fn (mut h HandshakeCore) handle_certificate_verify(full_msg []u8, body []u8) ![]HandshakeMessage {
	if h.state != .wait_certificate_verify {
		return h.classify_failure(.unexpected_message, 'handshake: unexpected CertificateVerify')
	}
	cv := parse_certificate_verify(body) or {
		return h.classify_failure(.decode_error, err.msg())
	}
	signed_content := certificate_verify_signed_content(h.transcript.current_hash())
	h.update_transcript(full_msg)!

	if h.server_certs.len == 0 {
		return h.classify_failure(.decode_error, 'handshake: missing server certificate for verification')
	}
	verify_certificate_verify(leaf_key(h.server_certs[0]), cv, signed_content) or {
		return h.classify_failure(.decrypt_error, err.msg())
	}
	h.state = .wait_server_finished
	return []HandshakeMessage{}
}

// handle_finished verifies the server Finished and emits the client Finished.
fn (mut h HandshakeCore) handle_finished(full_msg []u8, body []u8) ![]HandshakeMessage {
	if h.state != .wait_server_finished {
		return h.classify_failure(.unexpected_message, 'handshake: unexpected Finished message')
	}
	// Verify the server Finished over the transcript up to but excluding this message.
	server_verify_data := parse_finished(body, h.hash_algo.hash_len()) or {
		return h.classify_failure(.decode_error, err.msg())
	}
	th_before_sfin := h.transcript.current_hash()

	expected_verify_data := compute_finished_verify_data(h.hash_algo, h.server_hsk_traffic, th_before_sfin)!
	// Constant-time compare: verify_data is a MAC over the transcript, and a naive compare would leak a byte-by-byte Finished forgery.
	if subtle.constant_time_compare(server_verify_data, expected_verify_data) != 1 {
		return h.classify_failure(.decrypt_error, 'handshake: server Finished verify_data mismatch')
	}
	h.update_transcript(full_msg)!

	// Advance the key schedule to the application phase: Master Secret, then the application traffic secrets bound to the transcript including server Finished.
	th_sfin := h.transcript.current_hash()
	ap := derive_app_secrets(h.hash_algo, h.handshake_secret, th_sfin)!
	h.client_app_traffic = ap.client_traffic
	h.server_app_traffic = ap.server_traffic

	// The client Finished uses the handshake traffic secret over the transcript now including server Finished, sent under the (still active) handshake keys.
	client_verify_data := compute_finished_verify_data(h.hash_algo, h.client_hsk_traffic, th_sfin)!
	client_fin_msg := build_finished(client_verify_data)
	h.update_transcript(client_fin_msg)!

	// RFC 8446 §4.6.1/§4.5.5.1 let the server coalesce NewSessionTicket (type 4)
	// or KeyUpdate (type 24) behind its Finished; those stay buffered for the
	// adapter's take_buffered_handshake_bytes. Any other leader is flight garbage.
	if h.hsk_buf.len > 0 {
		leading := h.hsk_buf[0]
		if leading != u8(4) && leading != u8(24) {
			return h.classify_failure(.decode_error, 'handshake: unexpected trailing data after server Finished in handshake flight')
		}
	}

	h.state = .connected
	// Forward-secrecy cleanup: every ephemeral/handshake secret consumed to reach this point is now dead (RFC 8446 §7.5 / §1.3.1).
	h.wipe_key_schedule_secrets()
	// Hand the raw client Finished to the transport, which encrypts it under the still-active handshake keys.
	return [new_handshake_message(.handshake, client_fin_msg)!]
}
