# tls

A **TLS 1.3 client library written in [V](https://vlang.io)**, implementing
[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) from the wire format up:
no bindings to OpenSSL — handshake messaging, record protection, key
schedule, and X.509 path validation are built from V standard/crypto modules.

Full module and API reference documentation lives in [`docs.md`](docs.md).

> **Status: experimental.** The handshake, record layer, and certificate
> validation are complete and covered by unit tests (handshake vectors from
> RFC 8448, protocol-state and PKI rules from hand-built fixtures), but
> this library has had limited exposure to real-world servers and is **not
> audited**. Don't ship it in production yet.

## Requirements

A current V toolchain — the library uses standard-library crypto only
(`crypto.aes`, `x.crypto.chacha20poly1305`, `x.crypto.curve25519`, ECDSA /
Ed25519 from `crypto.*`), so no external dependencies, but also no stable-release
backward compatibility promise while V itself is pre-1.0. Compile anything
performance-sensitive with `v -prod`: V's default `tcc` backend is 20–50×
slower on this library's crypto hot paths (a chacha20-poly1305 bulk transfer
measures ~4 MB/s by default versus ~100 MB/s under `-prod`).

## Quick start

```bash
v test .                                # unit tests across all four modules
v run src/example/simple_example.v      # minimal client: HTTPS GET
v run src/example/dial_example.v        # live demo: handshake + HTTP GET over TLS
v run src/example/trust_store_example.v # client supplying its own root_cas
```

```v
import tls

mut conn := tls.dial('example.com:443', tls.default_config('example.com'))!
conn.write('GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n'.bytes())!
// conn.read(mut buf), conn.negotiated_alpn(), conn.close() ...
```

`Config` exposes the caller-facing knobs: `server_name` (SNI + the name the
certificate is checked against), `alpn` (offered protocols — the server's pick
is verified against this list), `root_cas` (override the system trust store),
and `insecure_skip_verify` (test/lab only; it removes all authentication). See
[`docs.md`](docs.md) for the complete API reference — signatures, defaults,
behavioral guarantees, and usage recipes. Those fields are read-only; because
`Config` is a `@[params]` struct you customise it by
passing named arguments straight to `dial()` — e.g.
`tls.dial('example.com:443', server_name: 'example.com', alpn: ['h2'])!` — and any
field you omit keeps the default declared on it (`default_config()` remains an
explicit way to build the same value).

For a TLS-over-TCP client the entry point is the `tls` module, which
deliberately exports only `Conn`, `dial()`, `Config` (plus the
`default_config()` helper) and the `pki.TrustStore` (from `tls.pki`) used to
populate `Config.root_cas`. The record layer, cipher state, and TCP transport
stay `tls`-private. The handshake core itself is not hidden: it is a separate,
deliberately importable module (`tls.handshake`) whose `pub` surface is the
adapter contract below, so a non-TCP transport (QUIC) can drive it directly
without ever importing `tls`.

## Architecture

The library is split into four V modules under `src/tls/`, each owning one
layer of the stack, with a strictly downward dependency graph (no cycles — a
child never imports its parent):

```
tls  ──▶  tls.handshake  ──▶  tls.pki  ──▶  tls.wire
  └───────────────────────────────────────────┘
```

| Module          | Responsibility                                                                              |
|-----------------|---------------------------------------------------------------------------------------------|
| `tls`           | TLS 1.3 **record layer** (RFC 8446 §5) + the public TCP client API: `conn`, `config`, `record`, `cipher_state` |
| `tls.handshake` | **Transport-neutral handshake core**: message codecs, the state machine, §7.1 key schedule, transcript, AEAD constructors, alerts vocabulary, QUIC passthrough framing (`messages`, `state_machine`, `key_schedule`, `transcript`, `handshake_keys`, `aead`, `alert`, `certificate_verify`, `passthrough`) |
| `tls.pki`       | Trust & parsing: `asn1`, `x509`, `validator`, `hostname`, `trust_store`, `rsa`              |
| `tls.wire`      | Bounds-checked byte reader / length-prefixed writer (no TLS semantics)                       |

Layering is enforced by construction: `tls.wire` knows nothing of TLS, `tls.pki`
only of certificates, and `tls.handshake` owns **no record, cipher, or socket
concept** — a grep gate over `src/tls/handshake/` (`Record`, `RecordProtector`,
`ContentType`, `change_cipher_spec`, `record_header_len`) keeps it that way.
`conn.v` in the `tls` module is the reference adapter that
drives the core.

### Adapter contract

The TCP record layer and QUIC engine use separate `tls.handshake` facades over
the same private core. Transport-specific operations are only present on the
matching facade; framing and encryption decisions stay adapter-side:

```v
// shared (both facades)
new_record_handshake(server_name, alpn, pki.Validator) !RecordHandshaker
new_quic_handshake(server_name, alpn, pki.Validator) !QuicHandshaker
create_client_hello() ![]u8
receive(level SecretLevel, bytes []u8) ![]HandshakeMessage   // single inbound entry
state() HandshakeState  /  negotiated_alpn() string  /  negotiated_cipher_suite() CipherSuite
failure_alert() AlertDescription  /  fail_and_destroy_secrets()  /  zeroize_app_secrets()

// RecordHandshaker only
record_unconsumed_bytes(level SecretLevel) int                     // §5.1 boundary hook
record_traffic_keys(level SecretLevel) !(TrafficKeys, TrafficKeys)  // client, server
record_update_read_traffic_keys() !  /  record_update_write_traffic_keys() !  // §7.2 ratchet
on_handshake_confirmed() !                                           // record confirmation

// QuicHandshaker only
quic_traffic_secrets(level SecretLevel) !([]u8, []u8)     // RFC 9001 §5.1 expansions
on_handshake_confirmed() !                                 // QUIC confirmation
```

The shared implementation, including per-level receive buffers for each
handshake instance, is in `state_machine.v`; the record and QUIC APIs are
defined in `record_handshaker.v` and `quic_handshaker.v`, respectively.
Both facades share `hkdf_expand_label`, `suite_hash_algo`, `suite_key_len`, and
`new_aead_for_suite`.

`SecretLevel` (`initial`/`handshake`/`application`, RFC 9001 §4.1) tags both
`receive()` and the returned `HandshakeMessage`s. `receive()` appends level-tagged bytes to the core's per-level reassembly
buffer and consumes as many complete messages as are available, returning
outbound messages ready to send. The TCP `Conn`
encrypts each returned message under the cipher matching its level; a QUIC
adapter maps the same levels onto Initial/Handshake/Application packet-number
spaces. All security checks (size caps, HRR rules, transcript binding) live in
the core, so both transports inherit them.

## Repository layout

```
src/
  example/
    simple_example.v      minimal client (handshake + HTTPS GET, no flags)
    trust_store_example.v minimal client with its own Config.root_cas
    dial_example.v        fuller demo (CLI args/flags, HTTP parsing, chunked bodies)
  tls/              module `tls`: record layer + public TCP client API
    handshake/      module `tls.handshake`: transport-neutral handshake core
    pki/            module `tls.pki`: X.509/ASN.1 parsing + chain validation
    wire/           module `tls.wire`: bounds-checked byte reader/writer
```

Each module keeps its `*_test.v` files alongside its sources. V resolves
submodules by directory path, so `v.mod` stays rooted at `tls` and the child
directories become `tls.handshake`, `tls.pki`, and `tls.wire`. The demo lives
under `src/` (not a top-level `example/`) because V resolves the library's bare
sibling import (`tls`) relative to the executable's own directory — a runnable
that imports it must sit beside it.

## What is implemented

- **Cipher suites**: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
  `TLS_CHACHA20_POLY1305_SHA256`
- **Key exchange**: X25519 and P-256 (`secp256r1`) key share negotiation,
  including full **HelloRetryRequest** handling with cookie support
- **Certificate verification**: chain to a trusted root (system bundle or
  caller-provided), validity windows, basic constraints, EKU `serverAuth`,
  RFC 6125 hostname matching (dNSName SANs with CN fallback only when no SAN
  list exists, single-label wildcards, IP SANs), Name Constraints
  (permitted/excluded dNSName and iPAddress subtrees, RFC 5280 §4.2.1.10), and
  a default-on RSA leaf-key strength floor (≥2048 bits, adjustable or disabled
  via `Validator.set_min_rsa_bits`)
- **Signature schemes**: RSA-PSS (SHA-256/384/512), ECDSA P-256/P-384, and
  Ed25519 for CertificateVerify and chain signatures; RSA-PKCS1-v1_5 SHA-256
  is accepted for chain signatures only — RFC 8446 §4.4.3 restricts
  CertificateVerify's RSA instances to RSASSA-PSS
- **Server auth completeness**: `Finished` verify_data, `CertificateVerify`
  over the §4.4.3 signed content, transcript-hash binding throughout
- **ALPN** negotiation with RFC 7301 §3.1 selection checks
- **Post-handshake**: `NewSessionTicket` collection, `KeyUpdate` handling
  (read keys ratchet on receipt; a response is sent with correct §4.6.3
  old-key-before-new ordering when the server requests it), sender-side
  automatic rekey at the §5.5 per-key record limit, `close_notify`
- **Client authentication**: a server `CertificateRequest` is answered with the
  empty `Certificate` a credential-less client must send (RFC 8446 §4.4.2),
  bound into the transcript before the server flight is verified
- **Failure handling**: a failed handshake classifies its alert (`internal_error`
  as the §6 catch-all, with `unexpected_message`/`illegal_parameter`/
  `decrypt_error`/`bad_certificate` set where the cause is known) and sends it —
  plaintext before the ServerHello, under the handshake keys after — before
  destroying every derived secret (§7.5) and closing the socket

### Hardened parsing

Message decoding is deliberately strict — extensions must appear at most once
(RFC 8446 §4.2), must belong in the message they appear in (ServerHello /
EncryptedExtensions allowlists), fixed-format extension data must be exactly
its defined length, and ECDHE shares are size- and encoding-gated (§4.2.8.2)
before any crypto backend sees them. Resource use is equally bounded: a single
reassembled handshake message is capped at 1 MiB, a `Certificate` list longer
than 32 entries is refused at parse time (before each entry is decoded), at
most two middlebox dummy ChangeCipherSpec records are tolerated before the
handshake aborts, per-key record counts enforce the §5.5 rekeying obligation in
both directions, and RSA keys below 2048 bits are refused — CAs always, and the
leaf under the default `min_rsa_bits` floor (see `Validator` in `docs.md`).
Malformed input is a handshake error, never a panic.

Certificate validation is strict X.509 too: DER must use minimal length
encodings (X.690 §10.1), each certificate extension OID appears at most once
(RFC 5280 §4.2), and a `keyUsage`/`basicConstraints` extension is honored when
present — a leaf must assert `digitalSignature`, a signing CA `keyCertSign`,
and `pathLenConstraint` caps how many intermediates may sit below a CA (a
malformed constraint collapses to the most restrictive 0, never the unlimited
default). TBSCertificate fields are element-counted after the optional `version
[0]` is consumed, so a truncated v3 certificate fails the decode instead of
indexing past the array, and RSA public keys must carry a non-zero, odd
exponent (e=1 and even e are refused). The CertificateVerify scheme must match
the leaf key type — and ECDSA schemes their exact curve (RFC 8446 §4.2.3) —
before any key material is read. An unparseable validity date fails the whole
decode rather than silently disabling expiry enforcement — UTCTime and
GeneralizedTime must be exact-width all-digit strings ending in `Z` — and the
X25519 exchange rejects every small-order shared secret (0, 1, p−1) not just
the all-zero one.

## Not (yet) implemented

- Session resumption / PSK / 0-RTT (tickets are received but not usable;
  the key schedule always runs the no-PSK "early secret" path)
- Certificate **revocation** — CRL and OCSP are not implemented, so a
  revoked-but-unexpired certificate is accepted. There is no callback hook
  either; a caller needing revocation must validate out of band before
  trusting the connection. See [`docs.md`](docs.md) for the rationale and the
  recommended pattern.
- TLS 1.2 and below (legacy fields are wired for compatibility only)
- A QUIC transport stack (RFC 9001) — packet building, header protection,
  packet-number spaces, and `CONNECTION_CLOSE` signaling are out of scope. The
  handshake core is nonetheless built to be driven over QUIC: it lives in the
  importable `tls.handshake` module (with the passthrough framing helpers, the
  level-tagged `receive`/`record_traffic_keys`/`quic_traffic_secrets` seam, and the
  `AlertDescription → quic_connection_error()` mapping), so a QUIC engine needs
  only `tls.handshake` + `tls.pki` and never imports `tls`; the full
  eight-step engine loop over that seam is walked through in
  [`src/tls/handshake/QUIC.md`](src/tls/handshake/QUIC.md). The API contract and
  the separate shared-core, record-facade, and QUIC-facade source files are
  documented in
  [`src/tls/handshake/CONTRACT.md`](src/tls/handshake/CONTRACT.md),
  [`state_machine.v`](src/tls/handshake/state_machine.v),
  [`record_handshaker.v`](src/tls/handshake/record_handshaker.v), and
  [`quic_handshaker.v`](src/tls/handshake/quic_handshaker.v).
- A server mode — this library is client-only

## Testing

```
v test .
```

covers: wire framing and bounds, record round trips and AEAD tamper
detection, the RFC 8448 §3 key-schedule and transcript vectors, handshake
message codecs against RFC 8448's ServerHello plus hand-built malformed
fixtures (duplicate/unpermitted/trailing-byte extensions, bad share sizes,
bad CertificateVerify framing, strict validity-time and pathLenConstraint
encodings, non-context-tag GeneralNames, duplicate certificate extensions,
and the dummy-CCS flood bound), the full HRR state-machine path (group
change, cookie echo, cipher-suite binding, replay rejection), X.509 decoding
end to end — a full hand-built v3 certificate with extensions, truncation
regressions for the element-count guards, and OID edge inputs — plus name
matching including the SAN-vs-CN precedence rule, Name Constraints subtree
enforcement (permitted/excluded dNSName and iPAddress), the RSA exponent
policy and leaf strength floor, CertificateVerify scheme-vs-key-type and
curve binding, forward-secrecy zeroization of handshake and application
secrets, and TCP record (re)framing in the connection layer.

The core flight is additionally exercised end to end against an in-repo fake
TLS 1.3 server (`src/tls/fakeserver/`, a test-only module): tests drive the
real `RecordHandshaker` through a complete X25519 handshake byte by byte,
asserting the client's ServerHello/Finished/alert bytes and the derived
traffic keys, then the same handshake over a live loopback TCP socket through
`tls.dial()` — including HelloRetryRequest, a CertificateRequest answered
with an empty `Certificate`, post-handshake messages split across records, and
the negative paths (bad Finished, bad CertificateVerify, unoffered ALPN,
out-of-order certificate, plaintext alert, trailing ServerHello junk, excess
ChangeCipherSpec, illegal content type). The fake server reimplements the key
schedule locally and imports only `tls.wire`/`tls.pki`, so it never shares code
with the implementation under test.

Coverage honesty: the RFC 8448 worked vectors exercise the AES-128-GCM /
SHA-256 key-schedule and transcript path from the fixed shared secret
outward (the ECDHE computation itself is not vector-pinned); AES-256-GCM,
SHA-384, and ChaCha20-Poly1305 are verified by round trips and
suite-parameter consistency rather than external vectors, and real-server
behavior (all suites, HRR retries, interop quirks) is what the runnable demo
(`v run src/example/dial_example.v`) is for — the HRR retry path itself is
proven by both the state-machine tests and the fake-server flight.

## References

- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) — TLS 1.3
- [RFC 8448](https://www.rfc-editor.org/rfc/rfc8448) — test vectors
- [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) — TLS 1.3 over QUIC (the `tls.handshake` core is importable by a QUIC adapter; §4 CRYPTO framing, §4.1 secret levels, §4.8 alert→error mapping, §6 Key Phase)
- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) — QUIC transport (CONNECTION_CLOSE frame types and packet-number spaces referenced by the QUIC walkthrough in `tls.handshake`)
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
