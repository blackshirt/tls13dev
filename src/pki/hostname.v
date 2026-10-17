module pki

import net

// match_hostname reports whether `hostname` matches a single certificate name
// `pattern` (one dNSName SAN entry or a legacy CN), per RFC 6125.
// It compares one pattern against one name — the caller iterates the SAN list
// (see verify_hostnames). Names are lowercased first: DNS names are
// case-insensitive (RFC 4343) while certificate contents are frequently
// mixed-case, so comparison must be on case-folded forms.
// is_ip_literal reports whether host is an IPv4 or IPv6 address.
fn is_ip_literal(host string) bool {
	// Trim surrounding whitespace so a padded host string is still recognized;
	// an empty result is trivially not an address.
	h := host.trim_space()
	if h.len == 0 {
		return false
	}
	// Any ':' means IPv6 — it is the only hostname syntax that uses colons — so
	// classify it as an address without fully parsing the (possibly bracketed) form.
	if h.contains(':') {
		return true
	}
	// IPv4 candidate: exactly four dot-separated labels, each 1–3 decimal digits
	// within 0..255. Anything else (hex, letters, a wrong label count) is a name.
	parts := h.split('.')
	if parts.len == 4 {
		for p in parts {
			// Reject empty or over-long octets before converting, so '300' or '0x10'
			// cannot be mistaken for a valid single-byte value.
			if p.len == 0 || p.len > 3 {
				return false
			}
			for c in p {
				// Digits only: one non-numeric character disqualifies the dotted quad.
				if c < `0` || c > `9` {
					return false
				}
			}
			val := p.int()
			// Each octet must fit a single byte; 256+ is not a real IPv4 address.
			if val < 0 || val > 255 {
				return false
			}
		}
		return true
	}
	// Not four dot-separated numeric labels, so this is an ordinary DNS name.
	return false
}

// match_hostname reports whether `hostname` matches a single certificate name
// `pattern` (one dNSName SAN entry or a legacy CN), per RFC 6125.
// It compares one pattern against one name — the caller iterates the SAN list
// (see verify_hostnames). Names are lowercased first: DNS names are
// case-insensitive (RFC 4343) while certificate contents are frequently
// mixed-case, so comparison must be on case-folded forms.
fn match_hostname(pattern string, hostname string) bool {
	p := pattern.to_lower().trim_space()
	h := hostname.to_lower().trim_space()

	if p == h {
		return true
	}

	// Wildcard matching: e.g. *.example.com matches foo.example.com
	if p.starts_with('*.') {
		// RFC 6125 §6.4.3: Wildcards must not match IP addresses.
		if is_ip_literal(h) {
			return false
		}
		wildcard_suffix := p[1..] // '.example.com'
		// RFC 6125 §6.4.3: Wildcards must not match top-level domains (e.g. *.com).
		// The suffix without the leading dot must contain at least one dot (domain + TLD).
		if !wildcard_suffix[1..].contains('.') {
			return false
		}
		if !h.ends_with(wildcard_suffix) {
			return false
		}
		prefix := h[..h.len - wildcard_suffix.len]
		// Wildcard can only match a single label (cannot contain dot) and cannot be empty.
		// RFC 6125 §6.4.3 / CA-Browser-Forum baseline: a '*' stands for exactly one
		// label, so '*.example.com' must NOT match 'a.b.example.com' — otherwise one
		// mis-issued wildcard cert would silently authorize every depth of the domain.
		if prefix.len > 0 && !prefix.contains('.') {
			return true
		}
	}

	return false
}

// ip_san_matches reports whether `host` is an IP literal matching any of the raw
// iPAddress SANs. IPv4 SANs are compared in dotted-decimal form and IPv6 SANs in
// canonical RFC 5952 form.
// Both sides are canonicalized before comparison because one IPv6 address has
// many equivalent textual spellings (::1, 0:0:0:0:0:0:0:1, leading zeros,
// mixed-case); raw string equality would wrongly reject valid certificates.
fn ip_san_matches(ip_sans [][]u8, host string) bool {
	h := host.trim_space()
	// Canonicalize the host once as an IPv6 string ('' when it is not an IPv6
	// literal) so every 16-byte SAN can be compared against the same form.
	target_v6 := net.canonical_ipv6(h) or { '' }
	for ip in ip_sans {
		// The SAN's byte length selects the family: 4 = IPv4, 16 = IPv6; any other
		// length is not a valid address encoding and is skipped outright.
		match ip.len {
			4 {
				// Rebuild dotted-decimal text from the raw octets and compare directly —
				// IPv4 has a single canonical spelling, so no folding is needed.
				if h == '${ip[0]}.${ip[1]}.${ip[2]}.${ip[3]}' {
					return true
				}
			}
			16 {
				// Put the SAN through the same RFC 5952 canonicalization as the host so
				// equivalent textual forms compare equal; skip when the host is not
				// itself an IPv6 literal (target_v6 == '').
				san_v6 := net.canonical_ipv6_from_bytes(ip) or { '' }
				if target_v6 != '' && san_v6 == target_v6 {
					return true
				}
			}
			else {}
		}
	}
	return false
}

// verify_hostnames checks if `hostname` matches at least one of `sans` or fallback `cn`.
fn verify_hostnames(sans []string, cn string, hostname string) bool {
	if sans.len > 0 {
		// SAN present ⇒ CN is ignored entirely, even on mismatch (RFC 6125 §6.4.4):
		// letting a cert with dNSName SANs also vouch via CN would re-open the
		// confused-deputy attacks that made CN checking deprecated (RFC 2818).
		for san in sans {
			if match_hostname(san, hostname) {
				return true
			}
		}
		return false
	}
	// Fallback to Common Name (legacy) if SAN is absent
	if cn != '' {
		return match_hostname(cn, hostname)
	}
	return false
}
