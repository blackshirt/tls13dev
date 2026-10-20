// Copyright (c) 2026 blackshirt.
//
// End-to-end demo of the tls API: TLS 1.3 handshake → HTTP/1.1 request →
// status line, headers, and de-chunked body printed in labeled sections →
// orderly close_notify.
//
// Usage:
//
//	v run src/example/dial_example.v [host[:port]] [path] [flags]
//
// Flags:
//
//	--insecure        skip certificate verification (never ship this enabled)
//	--timeout <secs>  socket timeout in seconds (default 30)
//	--alpn <proto>    offer a single ALPN protocol (default http/1.1)
//
// With no arguments it targets tls-v1-3.testserver.host (path
// /tls/client-hello), an endpoint that echoes the ClientHello back as JSON.
module main

import os
import time
import tls

const default_host = 'tls-v1-3.testserver.host'
const default_path = '/tls/client-hello'

struct Options {
mut:
	address  string
	path     string
	alpn     string
	timeout  int
	insecure bool
}

fn main() {
	opts := parse_args(os.args[1..]) or {
		eprintln('argument error: ${err}')
		eprintln('usage: dial_example.v [host[:port]] [path] [--insecure] [--timeout <secs>] [--alpn <proto>]')
		exit(2)
	}

	mut conn := tls.dial(opts.address,
		server_name:          host_without_port(opts.address)
		alpn:                 [opts.alpn]
		insecure_skip_verify: opts.insecure
		timeout:              opts.timeout * time.second
	) or {
		eprintln('dial failed: ${err}')
		exit(1)
	}

	// Explicit, orderly shutdown: send our close_notify, wipe the application
	// traffic secrets, and close the socket. close() is idempotent, so this
	// defer is a safety net for the error paths below — the success path calls
	// it explicitly first and the defer then becomes a no-op.
	mut explicit_close := true
	defer {
		if explicit_close {
			conn.close() or { eprintln('close failed: ${err}') }
		}
	}
	if opts.insecure {
		eprintln('WARNING: certificate verification disabled (--insecure)')
	}

	// Plain HTTP/1.1 request over the established TLS tunnel. The library moves
	// bytes, not HTTP, so we frame the request ourselves; `Connection: close`
	// tells the server to end the body and shut down, which is what lets the
	// read loop below finish on the peer's close_notify.
	host := host_without_port(opts.address)
	req := 'GET ${opts.path} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n'.bytes()
	conn.write(req) or {
		eprintln('write failed: ${err}')
		exit(1)
	}

	// Read until the peer's close_notify. A single read() returns at most one
	// record's worth, so loop: a clean close_notify surfaces as read() == 0
	// (RFC 8446 §6.1), which ends the HTTP/1.1 "Connection: close" body.
	mut raw := []u8{}
	mut buf := []u8{len: 8192}
	for {
		n := conn.read(mut buf) or {
			eprintln('read failed: ${err}')
			exit(1)
		}
		if n == 0 {
			break
		}
		raw << buf[..n]
	}

	resp := parse_http_response(raw) or {
		// Not parseable as HTTP (or a non-2xx status): print it raw so the demo
		// still shows whatever the server actually returned.
		eprintln('response parse failed: ${err}')
		print(raw.bytestr())
		conn.close() or { eprintln('close failed: ${err}') }
		explicit_close = false
		return
	}

	eprintln('HTTP status: ${resp.status}')
	alpn := conn.negotiated_alpn()
	eprintln('ALPN: ${if alpn != '' { alpn } else { '(none negotiated)' }}')
	eprintln('Content-Type: ${resp.content_type}')
	eprintln('--- body (${resp.body.len} bytes) ---')
	print(resp.body.bytestr())

	// Explicit cleanup, then disarm the defer so close() runs exactly once.
	conn.close() or {
		eprintln('close failed: ${err}')
		exit(1)
	}
	explicit_close = false
}

struct HttpResponse {
	status       string
	content_type string
	body         []u8
}

// parse_http_response splits an HTTP/1.1 response into its status line, a
// handful of interesting headers, and a body de-framed per Content-Length or
// Transfer-Encoding: chunked. It is deliberately small — enough for a demo,
// not a general HTTP parser.
fn parse_http_response(raw []u8) !HttpResponse {
	sep := find_header_end(raw) or { return error('no header terminator in response') }
	head := raw[..sep].bytestr()
	mut rest := raw[sep + 4..].clone()
	lines := head.split('\r\n')
	if lines.len == 0 {
		return error('empty response head')
	}
	mut status := lines[0]
	mut content_type := ''
	mut chunked := false
	mut content_length := -1
	for line in lines[1..] {
		lower := line.to_lower()
		if lower.starts_with('content-type:') {
			content_type = line.all_after(':').trim_space()
		} else if lower.starts_with('content-length:') {
			content_length = line.all_after(':').trim_space().int()
		} else if lower.starts_with('transfer-encoding:') && lower.contains('chunked') {
			chunked = true
		}
	}
	if chunked {
		rest = dechunk(rest)!
	} else if content_length >= 0 && content_length < rest.len {
		rest = rest[..content_length]
	}
	return HttpResponse{
		status:       status
		content_type: content_type
		body:         rest
	}
}

// find_header_end returns the index of the CRLFCRLF that ends the header block.
fn find_header_end(raw []u8) ?int {
	for i := 0; i + 4 <= raw.len; i++ {
		if raw[i] == `\r` && raw[i + 1] == `\n` && raw[i + 2] == `\r` && raw[i + 3] == `\n` {
			return i
		}
	}
	return none
}

// dechunk decodes HTTP/1.1 chunked transfer coding (RFC 7230 §4.1): each chunk
// is a hex length line, CRLF, that many bytes, CRLF, until a zero-length chunk.
fn dechunk(data []u8) ![]u8 {
	mut out := []u8{}
	mut i := 0
	for {
		line_end := find_crlf(data, i) or { return error('truncated chunk size line') }
		size_str := data[i..line_end].bytestr().trim_space()
		size := size_str.all_before(';').trim_space().parse_int(16, 64) or {
			return error('bad chunk size: ${size_str}')
		}
		i = line_end + 2
		if size == 0 {
			break
		}
		if i + size > data.len {
			return error('chunk overruns body')
		}
		out << data[i..i + size]
		i += size
		// Consume the CRLF that follows the chunk data.
		if i + 2 > data.len {
			return error('missing chunk terminator')
		}
		i += 2
	}
	return out
}

// find_crlf returns the index of the next CRLF at or after `from`.
fn find_crlf(data []u8, from int) ?int {
	for i := from; i + 1 < data.len; i++ {
		if data[i] == `\r` && data[i + 1] == `\n` {
			return i
		}
	}
	return none
}

// parse_args applies positional [host[:port]] [path] plus the demo's flags.
fn parse_args(args []string) !Options {
	mut opts := Options{
		address: default_host
		path:    default_path
		alpn:    'http/1.1'
		timeout: 30
	}
	mut positional := []string{}
	mut i := 0
	for i < args.len {
		a := args[i]
		match a {
			'--insecure' {
				opts.insecure = true
			}
			'--timeout' {
				i++
				if i >= args.len {
					return error('--timeout needs a value')
				}
				opts.timeout = args[i].int()
				if opts.timeout <= 0 {
					return error('--timeout must be a positive integer')
				}
			}
			'--alpn' {
				i++
				if i >= args.len {
					return error('--alpn needs a value')
				}
				opts.alpn = args[i]
			}
			else {
				if a.starts_with('-') {
					return error('unknown flag ${a}')
				}
				positional << a
			}
		}
		i++
	}
	if positional.len > 0 {
		opts.address = positional[0]
	}
	if positional.len > 1 {
		opts.path = positional[1]
	}
	// Append the default port when the caller gave only a host, leaving an
	// explicit port (or a bracketed IPv6 literal's own port) untouched.
	if !opts.address.ends_with(']') && !has_port(opts.address) {
		opts.address = '${opts.address}:443'
	}
	return opts
}

// has_port reports whether an authority carries an explicit port, ignoring the
// colons inside a bracketed IPv6 literal.
fn has_port(address string) bool {
	if address.starts_with('[') {
		end := address.index(']') or { return false }
		return address[end..].contains(':')
	}
	return address.contains(':')
}

// host_without_port strips a trailing :port from an authority, handling the
// bracketed IPv6 form ([::1]:443 → ::1). It is only used for the Host header
// and SNI name; the dial address keeps the port.
fn host_without_port(address string) string {
	if address.starts_with('[') {
		if end := address.index(']') {
			return address[1..end]
		}
	}
	if i := address.last_index(':') {
		return address[..i]
	}
	return address
}
