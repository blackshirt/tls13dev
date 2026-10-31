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

## Quick start

```bash
v test .                                # unit tests across all modules
v run src/example/simple_example.v      # minimal client: HTTPS GET
v run src/example/dial_example.v        # live demo: handshake + HTTP GET over TLS
v run src/example/trust_store_example.v # client supplying its own root_cas
v run src/example/quic_dial_example.v   # QUIC handshake attempt with test.privateoctopus.com:4433
```

```v
import tls

mut conn := tls.dial('example.com:443', tls.default_config('example.com'))!
conn.write('GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n'.bytes())!
// conn.read(mut buf), conn.negotiated_alpn(), conn.close() ...
```

`Conn.close()` sends `close_notify` when possible, then releases the TCP
socket; after a peer `close_notify`, `read()` returns clean EOF but `close()`
is still needed to release the socket.

`Config` is a `@[params]` struct: pass named arguments straight to `dial()`,
and any field you omit keeps its declared default (`default_config()` is an
explicit way to build the same value). The caller-facing knobs are
`server_name` (SNI + the name the certificate is checked against),
`hsk_options` (offered ALPN protocols and handshake preferences), `root_cas`
(override the system trust store), and `insecure_skip_verify` (test/lab only;
it removes all authentication). The complete field table, defaults, and
behavioral guarantees live in [`docs.md`](docs.md).

The `tls` module deliberately exports only `dial()`, `Conn`, `Config`,
`default_config()`, and the `pki.TrustStore` behind `Config.root_cas`; the
record layer and TCP transport stay module-private. The handshake core is
separately importable (`tls.handshake`) — its `pub` seam is the adapter
contract in [CONTRACT.md](src/tls/handshake/CONTRACT.md) — so a non-TCP
transport like QUIC can drive it without ever importing `tls`.

## Repository layout

```
src/
  example/
    simple_example.v      minimal client (handshake + HTTPS GET, no flags)
    trust_store_example.v minimal client with its own Config.root_cas
    dial_example.v        fuller demo (CLI args/flags, HTTP parsing, chunked bodies)
    quic_dial_example.v   QUIC handshake attempt with test.privateoctopus.com:4433
  tls/              module `tls`: record layer + public TCP client API
    handshake/      module `tls.handshake`: transport-neutral handshake core
    pki/            module `tls.pki`: X.509/ASN.1 parsing + chain validation
    wire/           module `tls.wire`: bounds-checked byte reader/writer
    quic/           module `tls.quic`: QUIC engine + socket-owning dial() facade
    fakeserver/     module `tls.fakeserver`: test-only fake TLS 1.3 server
```

Each module keeps its `*_test.v` files alongside its sources. V resolves
submodules by directory path, so `v.mod` stays rooted at `tls` and the child
directories become `tls.handshake`, `tls.pki`, `tls.quic`, `tls.wire`, and the
test-only `tls.fakeserver`. The demo lives under `src/` (not a top-level
`example/`) because V resolves the library's bare sibling import (`tls`)
relative to the executable's own directory.

## What is implemented

- **Cipher suites**: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
  `TLS_CHACHA20_POLY1305_SHA256`
- **Key exchange**: X25519 and P-256 (`secp256r1`) key share negotiation,
  including full **HelloRetryRequest** handling with cookie support
- **Certificate verification**: chain to a trusted root (system bundle or
  caller-provided), validity windows, basic constraints, EKU `serverAuth`,
  RFC 6125 hostname matching (SANs with CN fallback only when no SAN list
  exists, single-label wildcards, IP SANs), Name Constraints
  (RFC 5280 §4.2.1.10), and a default-on RSA key-strength floor (≥2048 bits,
  adjustable)
- **Signature schemes**: RSA-PSS (SHA-256/384/512), ECDSA P-256/P-384, and
  Ed25519 for CertificateVerify and chain signatures; RSA-PKCS1-v1_5 SHA-256
  is accepted for chain signatures only — RFC 8446 §4.4.3 restricts
  CertificateVerify's RSA instances to RSASSA-PSS
- **Server auth completeness**: `Finished` verify_data, `CertificateVerify`
  over the §4.4.3 signed content, transcript-hash binding throughout
- **ALPN** negotiation with RFC 7301 §3.1 selection checks
- **Post-handshake**: `NewSessionTicket` collection, `KeyUpdate` handling
  (read keys update on receipt; a response is sent with correct §4.6.3
  old-key-before-new ordering when the server requests it), sender-side
  automatic rekey at the §5.5 per-key record limit, `close_notify`
- **Client authentication**: a server `CertificateRequest` is answered with the
  empty `Certificate` a credential-less client must send (RFC 8446 §4.4.2),
  bound into the transcript before the server flight is verified
- **Failure handling**: a failed handshake classifies its fatal alert (with
  the §6 `internal_error` catch-all where the cause is unknown) and sends it —
  plaintext before the ServerHello, under the handshake keys after — before
  destroying every derived secret (§7.5) and closing the socket

## Not (yet) implemented

- Session resumption / PSK / 0-RTT (tickets are received but not usable;
  the key schedule always runs the no-PSK "early secret" path)
- Certificate **revocation** — CRL and OCSP are not implemented, so a
  revoked-but-unexpired certificate is accepted; there is no callback hook
  either. See [`docs.md`](docs.md) for the rationale and the recommended
  out-of-band pattern.
- TLS 1.2 and below (legacy fields are wired for compatibility only)
- A full **QUIC transport stack** (RFC 9000/9001). The in-repo `tls.quic`
  module completes the RFC 9001 handshake and now survives a lossy path: the
  transport-agnostic `Engine` runs packet (de)serialization, packet-number
  spaces, header protection, and CRYPTO reassembly, and additionally emits ACK
  frames, retransmits the handshake flight on a probe timeout, and fragments
  outbound CRYPTO to `Config.max_packet_size`; a socket-owning `quic.dial()`
  facade (`Conn`) drives that loop over a `net.UdpConn` to confirmation. The
  client advertises a complete RFC 9000 §18.2 transport-parameter set (its
  flow-control values are handshake-only placeholders). It
  needs only `tls.handshake` + `tls.pki` and never imports `tls`. What remains
  out is the *data plane*: streams, flow control, loss recovery and congestion
  control for application data, migration, Retry/0-RTT, and the 1-RTT Key
  Phase update. The engine loop is walked through in
  [`src/tls/handshake/QUIC.md`](src/tls/handshake/QUIC.md) and the core's seam
  in [`src/tls/handshake/CONTRACT.md`](src/tls/handshake/CONTRACT.md).
- A server mode — this library is client-only

## Testing

```
v test .
```

Covers the wire and record layers (framing bounds, AEAD round trips and
tamper detection), the RFC 8448 §3 key-schedule vectors, the handshake
message codecs and malformed-fixture negatives (extension strictness, key
share sizes, the full HRR state-machine path), X.509 decoding and the PKI
rules (name matching, Name Constraints, RSA strength, CertificateVerify
binding, secret zeroization), and TCP record (re)framing in the connection
layer.

The flight also runs end to end against an in-repo test-only fake TLS 1.3
server (`src/tls/fakeserver/`): byte-exact handshake assertions plus a live
loopback dial through `tls.dial()`, including HelloRetryRequest and the
negative paths. The fake server reimplements the key schedule locally and
imports only `tls.wire`/`tls.pki`, so it shares no code with the
implementation under test.

Honest limits: the RFC 8448 vectors pin the AES-128-GCM / SHA-256 path (the
ECDHE computation itself is not vector-pinned); the other suites are
verified by round trips and suite-parameter consistency. Real-server
behavior across all suites is what the demo
(`v run src/example/dial_example.v`) exercises.

## References

- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) — TLS 1.3
- [RFC 8448](https://www.rfc-editor.org/rfc/rfc8448) — test vectors
- [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) — TLS 1.3 over QUIC (the
  `tls.handshake` core is importable by a QUIC adapter; §4 CRYPTO framing, §4.1
  secret levels, §4.8 alert→error mapping, §6 Key Phase)
- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) — QUIC transport
  (CONNECTION_CLOSE frame types and packet-number spaces referenced by the QUIC
  walkthrough in `tls.handshake`)
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
