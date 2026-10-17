# tls

A **TLS 1.3 client library written in [V](https://vlang.io)**, implementing
[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) from the wire format up:
no bindings to OpenSSL — handshake messaging, record protection, key
schedule, and X.509 path validation are built from V standard/crypto modules.

> **Status: experimental.** The handshake, record layer, and certificate
> validation are complete and covered by unit tests (handshake vectors from
> RFC 8448, protocol-state and PKI rules from hand-built fixtures), but
> this library has had limited exposure to real-world servers and is **not
> audited**. Don't ship it in production yet.

## Requirements

A current V toolchain — the library uses standard-library crypto only
(`crypto.aes`, `x.crypto.chacha20poly1305`, `x.crypto.curve25519`, ECDSA /
Ed25519 from `crypto.*`), so no external dependencies, but also no stable-release
backward compatibility promise while V itself is pre-1.0.

## Quick start

```bash
v test all                 # unit tests for the tls module
v run src/example/dial_example.v       # live demo: handshake + HTTP GET over TLS
v run src/example/dial_hrr_example.v   # live demo: a HelloRetryRequest group-retry round trip
```

```v
import tls

mut conn := tls.dial('example.com:443', tls.default_config('example.com'))!
conn.write('GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n'.bytes())!
// conn.read(mut buf), conn.negotiated_alpn, conn.close() ...
```

`Config` exposes the caller-facing knobs: `server_name` (SNI + the name the
certificate is checked against), `alpn` (offered protocols — the server's pick
is verified against this list), `root_cas` (override the system trust store),
and `insecure_skip_verify` (test/lab only; it removes all authentication). Those
fields are read-only; because `Config` is a `@[params]` struct you customise it by
passing named arguments straight to `dial()` — e.g.
`tls.dial('example.com:443', server_name: 'example.com', alpn: ['h2'])!` — and any
field you omit keeps the default declared on it (`default_config()` remains an
explicit way to build the same value).

The module deliberately exports only this surface: `Conn`, `dial()`, `Config`
(plus the `default_config()` helper) and the `TrustStore` used to populate
`Config.root_cas`. Everything else — the record layer, wire codec, key schedule,
handshake state machine, and X.509/ASN.1 parsing — is module-private
implementation detail, not part of the API contract.

## Architecture

Everything lives in a single `tls` module (`src/tls/`); the source files are
grouped by concern, each still owning one layer of the stack:

| Source area      | Responsibility                                                               |
|------------------|-----------------------------------------------------------------------------|
| `conn`, `config` | The **entire public API**: `dial()`, `Conn` (read/write/close, `server_name`/`negotiated_alpn`), `Config` + `default_config()`, `TrustStore` — all else is module-private |
| `messages`, `state_machine`, `handshake_keys`, `aead`, `certificate_verify` | Message codecs, the handshake state machine, §7.1 adapter, AEAD primitives |
| `record`, `alert`, `cipher_state` | Record layer (RFC 8446 §5), alerts (§6), per-direction cipher state |
| `key_schedule`, `transcript` | HKDF key schedule (§7.1) and the running transcript hash                     |
| `x509`, `asn1`, `validator`, `hostname`, `trust_store`, `rsa` | X.509/ASN.1 parsing, chain validation, hostname matching, trust store |
| `reader`, `writer` | Bounds-checked byte reader / length-prefixed writer (no TLS semantics)       |

Layering is still strict by convention: the wire codec knows nothing of TLS, the
record layer knows nothing of handshake messages, and the handshake owns no
socket — `conn.v` drives it all.

## Repository layout

```
src/
  example/
    dial_example.v     runnable end-to-end demo (handshake + HTTP GET over TLS)
    dial_hrr_example.v same flow, against a server that forces a HelloRetryRequest
  tls/              the whole library as one module: wire codec, record layer,
                    handshake state machine, key schedule, PKI validation, and
                    the public client API (with its *_test.v files alongside)
```

The demo lives under `src/` (not a top-level `example/`) because V resolves the
library's bare sibling import (`tls`) relative to the executable's own directory
— a runnable that imports it must sit beside it.

## What is implemented

- **Cipher suites**: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
  `TLS_CHACHA20_POLY1305_SHA256`
- **Key exchange**: X25519 and P-256 (`secp256r1`) key share negotiation,
  including full **HelloRetryRequest** handling with cookie support
- **Certificate verification**: chain to a trusted root (system bundle or
  caller-provided), validity windows, basic constraints, EKU `serverAuth`,
  RFC 6125 hostname matching (dNSName SANs with CN fallback only when no SAN
  list exists, single-label wildcards, IP SANs)
- **Signature schemes**: RSA-PSS (SHA-256/384/512), RSA-PKCS1-v1_5 SHA-256,
  ECDSA P-256/P-384, Ed25519 — for CertificateVerify and chain signatures
- **Server auth completeness**: `Finished` verify_data, `CertificateVerify`
  over the §4.4.3 signed content, transcript-hash binding throughout
- **ALPN** negotiation with RFC 7301 §3.1 selection checks
- **Post-handshake**: `NewSessionTicket` collection, `KeyUpdate` handling
  (read keys ratchet on receipt; a response is sent with correct §4.6.3
  old-key-before-new ordering when the server requests it), `close_notify`

### Hardened parsing

Message decoding is deliberately strict — extensions must appear at most once
(RFC 8446 §4.2), must belong in the message they appear in (ServerHello /
EncryptedExtensions allowlists), fixed-format extension data must be exactly
its defined length, and ECDHE shares are size- and encoding-gated (§4.2.8.2)
before any crypto backend sees them. Malformed input is a handshake error,
never a panic.

## Not (yet) implemented

- Session resumption / PSK / 0-RTT (tickets are received but not usable;
  the key schedule always runs the no-PSK "early secret" path)
- Client authentication (`CertificateRequest` is recognized, not answered)
- Post-handshake record reassembly across fragmented records (fine for
  NewSessionTicket/KeyUpdate, which servers send one-per-record)
- TLS 1.2 and below (legacy fields are wired for compatibility only)
- A server mode — this crate is client-only

## Testing

```
v test all
```

covers: wire framing and bounds, record round trips and AEAD tamper
detection, the RFC 8448 §3 key-schedule and transcript vectors, handshake
message codecs against RFC 8448's ServerHello plus hand-built malformed
fixtures (duplicate/unpermitted/trailing-byte extensions, bad share sizes),
the full HRR state-machine path (group change, cookie echo, cipher-suite
binding, replay rejection), X.509 name matching including the SAN-vs-CN
precedence rule, and TCP record (re)framing in the connection layer.

Coverage honesty: the RFC 8448 worked vectors exercise the AES-128-GCM /
SHA-256 key-schedule and transcript path from the fixed shared secret
outward (the ECDHE computation itself is not vector-pinned); AES-256-GCM,
SHA-384, and ChaCha20-Poly1305 are verified by round trips and
suite-parameter consistency rather than external vectors, and real-server
behavior (all suites, HRR retries, interop quirks) is what the runnable demos
(`v run src/example/dial_example.v`, and `.../dial_hrr_example.v` which exercises
the HelloRetryRequest retry path) are for.

## References

- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) — TLS 1.3
- [RFC 8448](https://www.rfc-editor.org/rfc/rfc8448) — test vectors
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) — X.509 profiles
- [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125) — hostname validation
- [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017) — RSA (PKCS#1 v1.5 / PSS)
- [RFC 7301](https://www.rfc-editor.org/rfc/rfc7301) — ALPN
- [RFC 5746](https://www.rfc-editor.org/rfc/rfc5746) — renegotiation_info

## Notes for contributors

The codebase has a documentation convention worth keeping: comments explain
*why*, cite the governing RFC section inline (e.g. `§4.2.8.2`), and call out
deliberate trade-offs rather than hiding them. Each source file carries a doc
preamble describing its layer's role in the stack.

MIT licensed — see `v.mod`.
