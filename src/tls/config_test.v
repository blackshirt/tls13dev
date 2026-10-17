// Copyright (c) 2026 blackshirt.
//
// default_config regression test: after Config moved to @[params], `alpn` and
// `timeout` are no longer assigned inside default_config — they must inherit the
// field-level defaults declared on the struct. This pins that a default Config
// still carries the intended conservative values (empty ALPN offer, 30s timeout,
// verification strictly on), so a future edit to the field defaults that breaks
// the constructor's contract surfaces here.
module tls

import time

fn test_default_config_applies_field_defaults() {
	cfg := default_config('example.com')
	assert cfg.server_name == 'example.com'
	// alpn inherits the declared `[]string{}` default → empty offer.
	assert cfg.alpn.len == 0
	// The insecure escape hatch stays off.
	assert cfg.insecure_skip_verify == false
	// timeout inherits the declared 30s default rather than the 0 unset value.
	assert cfg.timeout == 30 * time.second
}
