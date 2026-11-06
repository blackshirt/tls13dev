# tls

A **TLS 1.3 client library written in [V](https://vlang.io)**, implementing
[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) from the wire format up:
no bindings to OpenSSL — handshake messaging, record protection, key
schedule, and X.509 path validation are built from V standard/crypto modules.

Each module carries a README in its source directory (`src/tls/handshake/`,
`src/tls/pki/`, `src/tls/quic/`) with its layout, API surface, and invariants.

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
v run src/example/psk_connect.v         # PSK resumption: tickets → PSKs → second dial
v run src/example/trust_store_example.v # client supplying its own root_cas
v run src/example/quic_dial_example.v   # QUIC handshake with cloudflare-quic.com:443
v run src/example/ocsp_dial_example.v   # OCSP stapling: status_request + CertificateStatus
```

```v
import tls

mut conn := tls.dial('example.com:443', tls.default_config('example.com'))!
conn.write('GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n'.bytes())!
// conn.read(mut buf), conn.negotiated_alpn(), conn.close() ...
```

`Conn.close()` sends `close_notify` (when keys exist) then releases the TCP
socket; a peer `close_notify` makes `read()` return clean EOF and releases the
socket in the same step, so calling `close()` afterwards is a harmless no-op.

A `Conn` is single-thread-owned: it holds no locks and serializes nothing, so
one connection handle must not be driven from several threads at the same time.
`read()` blocks until a record arrives or the socket timeout fires; call it from
the thread that owns the connection, and `close()` from that same thread once the
reader returns. Use one `Conn` per thread when a program needs several connections.

`Config` is a `@[params]` struct: pass named arguments straight to `dial()`;
omitted fields keep their declared defaults (`default_config()` builds the same
value). Knobs: `server_name`, `hsk_options`, `root_cas`, `min_rsa_bits`, `psks`,
`timeout`, `insecure_skip_verify` (test/lab only — removes all authentication),
`revocation_checker`, and `request_ocsp_stapling`.

The `tls` module exports only `dial()`, `Conn`, `Config`, `default_config()`,
and `pki.TrustStore` (behind `Config.root_cas`); record layer and TCP transport
stay module-private. The importable `tls.handshake` core exposes a curated `pub`
seam so a non-TCP transport like QUIC can drive it without importing `tls`.

## Repository layout

```
src/
  example/
    simple_example.v      minimal client (handshake + HTTPS GET, no flags)
    trust_store_example.v minimal client with its own Config.root_cas
    dial_example.v        fuller demo (CLI args/flags, HTTP parsing, chunked bodies)
    psk_connect.v         PSK resumption demo (tickets → PSKs → second dial)
    quic_dial_example.v   QUIC handshake with cloudflare-quic.com:443
    ocsp_dial_example.v   OCSP stapling demo (status_request + CertificateStatus)
  tls/              module `tls`: record layer + public TCP client API
    handshake/      module `tls.handshake`: transport-neutral handshake core
    pki/            module `tls.pki`: X.509/ASN.1 parsing + chain validation
    wire/           module `tls.wire`: bounds-checked byte reader/writer
    quic/           module `tls.quic`: QUIC handshake engine (internal) + socket-owning dial() facade
    fakeserver/     module `tls.fakeserver`: test-only fake TLS 1.3 server
```

Each module keeps its `*_test.v` files alongside its sources. V resolves
submodules by directory path, so `v.mod` stays rooted at `tls` and child
directories become `tls.handshake`, `tls.pki`, `tls.quic`, `tls.wire`, and the
test-only `tls.fakeserver`. Demos live under `src/` because V resolves the bare
sibling import (`tls`) relative to the executable's own directory.

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
- **Pre-shared keys**: caller-supplied resumption/external PSKs with
  `psk_dhe_ke` (PSK + ECDHE) binders in the ClientHello, server PSK selection
  in ServerHello, and PSK-authenticated flights without CertificateVerify
  (RFC 8446 §4.2.11/§4.4.2); received tickets are stored and convertible into
  resumption PSKs via `Conn.resumption_psks()`, and a `Config.session_ticket_store`
  (the file-backed `FileTicketStore`) keeps ticket + PSK pairs across process
  restarts, offers them automatically, and retires the pair a resumption actually
  used (§8.6 single use)
- **Post-handshake**: `NewSessionTicket` collection, `KeyUpdate` handling
  (read keys update on receipt; a response is sent with correct §4.6.3
  old-key-before-new ordering when the server requests it), sender-side
  automatic rekey at the §5.5 per-key record limit, `close_notify`
- **Client authentication**: a server `CertificateRequest` is answered with the
  empty `Certificate` a credential-less client must send (RFC 8446 §4.4.2),
  bound into the transcript after the server flight is verified
- **Failure handling**: a failed handshake classifies its fatal alert (with
  the §6 `internal_error` catch-all where the cause is unknown) and sends it —
  plaintext before the ServerHello, under the handshake keys after — before
  destroying every derived secret (§7.5) and closing the socket

## Not (yet) implemented

- **0-RTT** early data (resumption itself is 1-RTT: a ticket store hands out
  the §7.2 PSKs the next ClientHello binds, but no `max_early_data` path exists)
- Ticket **ages rest on the local clock**: a ticket store folds the time a
  ticket has been held into its obfuscated age (§4.6.1) and drops one past its
  `ticket_lifetime` instead of re-offering it, so a skewed or rewound client
  clock makes the age wrong — a server reacts by falling back to a full
  handshake, never by failing
- Certificate **revocation** — CRL fetching is not implemented (no network
  dependencies), but a caller may supply a `pki.RevocationChecker` through
  `Config.revocation_checker` to reject revoked certificates at handshake time;
  the checker receives `RevocationContext` (certificate, chain position, and any
  stapled OCSP response) and returns `.good` / `.revoked` / an error (fail-closed).
  The default `NoCheck` checker accepts everything, matching prior behavior. OCSP
  stapling is available via `Config.request_ocsp_stapling`: the ClientHello offers
  `status_request`, the server's stapled OCSP response arrives in `CertificateStatus`,
  and is fed into the revocation checker before the chain is accepted or rejected.
  See [`tls.pki`](src/tls/pki/README.md).
- TLS 1.2 and below (legacy fields are wired for compatibility only)
- A full **QUIC transport stack** (RFC 9000/9001). The in-repo `tls.quic`
  module completes the RFC 9001 handshake and now survives a lossy path: its
  module-internal engine runs packet (de)serialization, packet-number spaces,
  header protection, and CRYPTO reassembly, and additionally emits ACK frames,
  retransmits the handshake flight on a probe timeout, and fragments outbound
  CRYPTO to `Config.max_packet_size`; the socket-owning `quic.dial()` facade
  (`Conn`) drives that loop over a `net.UdpConn` to confirmation. Only
  `quic.dial()`, `quic.Conn`, and `quic.Config` are public; the engine itself is
  internal. The client advertises a complete RFC 9000 §18.2 transport-parameter
  set (its flow-control values are handshake-only placeholders). It
  needs only `tls.handshake` + `tls.pki` and never imports `tls`. What remains
  out is the *data plane*: streams, flow control, loss recovery and congestion
  control for application data, migration, Retry/0-RTT, and the 1-RTT Key
  Phase update. The [`tls.quic`](src/tls/quic/README.md) module README orients
  you to its layout and public API surface.
- A server mode — this library is client-only

## Testing

```
v test .
```

Honest limits: the RFC 8448 vectors pin the AES-128-GCM / SHA-256 path (the
ECDHE computation itself is not vector-pinned); the other suites are verified
by round trips and suite-parameter consistency. Real-server behavior across all
suites is what the demo (`v run src/example/dial_example.v`) exercises.

## References

- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) — TLS 1.3
- [RFC 8448](https://www.rfc-editor.org/rfc/rfc8448) — test vectors
- [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) — TLS 1.3 over QUIC (the
  `tls.handshake` core is importable by a QUIC adapter; §4 CRYPTO framing, §4.1
  secret levels, §4.8 alert→error mapping, §6 Key Phase)
- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) — QUIC transport
  (CONNECTION_CLOSE frame types and packet-number spaces referenced by the
  `tls.quic` engine)
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) — X.509 profiles
- [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125) — hostname validation
- [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017) — RSA (PKCS#1 v1.5 / PSS)
- [RFC 7301](https://www.rfc-editor.org/rfc/rfc7301) — ALPN
- [RFC 5746](https://www.rfc-editor.org/rfc/rfc5746) — renegotiation_info

MIT licensed — see `v.mod`.
