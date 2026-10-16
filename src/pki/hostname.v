module pki

import net

// match_hostname reports whether `hostname` matches a single certificate name
// `pattern` (one dNSName SAN entry or a legacy CN), per RFC 6125.
// It compares one pattern against one name — the caller iterates the SAN list
// (see verify_hostnames). Names are lowercased first: DNS names are
// case-insensitive (RFC 4343) while certificate contents are frequently
// mixed-case, so comparison must be on case-folded forms.
pub fn match_hostname(pattern string, hostname string) bool {
	p := pattern.to_lower().trim_space()
	h := hostname.to_lower().trim_space()

	if p == h {
		return true
	}

	// Wildcard matching: e.g. *.example.com matches foo.example.com
	if p.starts_with('*.') {
		wildcard_suffix := p[1..] // '.example.com'
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
pub fn ip_san_matches(ip_sans [][]u8, host string) bool {
	h := host.trim_space()
	target_v6 := net.canonical_ipv6(h) or { '' }
	for ip in ip_sans {
		match ip.len {
			4 {
				if h == '${ip[0]}.${ip[1]}.${ip[2]}.${ip[3]}' {
					return true
				}
			}
			16 {
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
pub fn verify_hostnames(sans []string, cn string, hostname string) bool {
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
