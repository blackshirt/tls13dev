# `tls` — Module & API Documentation

![V](https://img.shields.io/badge/language-V-2d7dd2) ![TLS&nbsp;1.3](https://img.shields.io/badge/protocol-RFC_8446-2ea44f) ![client--only](https://img.shields.io/badge/role-client--only-6f42c1) ![no%20deps](https://img.shields.io/badge/OpenSSL--free-000000) ![status](https://img.shields.io/badge/status-experimental-e8930c)

A **<span style="color:#2d7dd2">TLS 1.3 client</span>** library written in [V](https://vlang.io),
implementing [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) directly on standard-library
crypto — no OpenSSL bindings, no third-party dependencies.

| | |
|---|---|
| **Protocol** | TLS 1.3 (RFC 8446) — client only; no TLS 1.2 fallback, resumption, or 0-RTT |
| **Implementation** | Pure V over the standard-library crypto stack; strict, bounds-checked parsing throughout |
| **API surface** | `dial()` · `Conn` · `Config` · `default_config()` · `pki.TrustStore` — plus the importable `tls.handshake` core for non-TCP transports; everything else is module-private |
| **Modules** | `tls` (record layer + TCP API) → `tls.handshake` (transport-neutral core) → `tls.pki` (trust & parsing) → `tls.wire` (byte codec) |
| **Trust model** | System CA bundle by default; custom roots via `Config.root_cas`; `insecure_skip_verify` test escape hatch |
| **Related docs** | [README.md](README.md) — feature scope, hardening notes, and testing coverage |

> [!WARNING]
> **Status: experimental.** Not audited; do not ship in production.

> [!NOTE]
> **Visual conventions** — <span style="color:#2ea44f">green</span> marks safety
> and robustness guarantees, <span style="color:#cf222e">red</span> marks
> dangerous options and rejected/error outcomes, amber marks cautions. Colors
> render fully in IDE Markdown preview; where inline styles are stripped, the
> badges and tinted callout boxes carry the same palette.

## Contents

- [1. Module architecture](#1-module-architecture)
  - [1.1 Public vs. private surface](#11-public-vs-private-surface)
  - [1.2 Layer map](#12-layer-map)
  - [1.3 Data flow of `dial()`](#13-data-flow-of-dial)
  - [1.4 Handshake sequence](#14-handshake-sequence)
  - [1.5 Adapter contract (`tls.handshake`)](#15-adapter-contract-tlshandshake)
- [2. API reference](#2-api-reference)
  - [2.1 `dial`](#21-dial)
  - [2.2 `Conn`](#22-conn)
  - [2.3 `Config`](#23-config)
  - [2.4 `default_config`](#24-default_config)
  - [2.5 `TrustStore`](#25-truststore)
- [3. Usage](#3-usage)
  - [3.1 Basic client](#31-basic-client)
  - [3.2 Private CA / pinned lab roots](#32-private-ca--pinned-lab-roots)
  - [3.3 Testing escape hatch](#33-testing-escape-hatch)
  - [3.4 HelloRetryRequest — handled transparently](#34-helloretryrequest--handled-transparently)
  - [3.5 Revocation is out of scope](#35-revocation-is-out-of-scope)
- [4. Error handling summary](#4-error-handling-summary)
  - [4.1 Connection lifecycle](#41-connection-lifecycle)
  - [4.2 Wire & handshake protocol violations](#42-wire--handshake-protocol-violations)
  - [4.3 Certificate & trust-policy rejections](#43-certificate--trust-policy-rejections)

---

## 1. Module architecture

The library is organized as six V modules under `src/tls/`, each declaring its
own `module` and importing only the layers beneath it:

| Module | Directory | Role |
|---|---|---|
| `tls` | `src/tls/` | TLS record layer + the public TCP client API |
| `tls.handshake` | `src/tls/handshake/` | Transport-neutral handshake core (importable by non-TCP transports such as QUIC) |
| `tls.pki` | `src/tls/pki/` | X.509 / ASN.1 parsing and chain validation |
| `tls.wire` | `src/tls/wire/` | Bounds-checked byte reader / writer |
| `tls.quic` | `src/tls/quic/` | QUIC client engine — the sibling of `tls` that drives the same core without importing it |
| `tls.fakeserver` | `src/tls/fakeserver/` | Test-only fake TLS 1.3 server flight; no role in the shipped library |

The dependency graph is strictly downward —
`tls → tls.handshake → tls.pki → tls.wire`, with `tls.quic` riding the same
rail on top of `tls.handshake` — so
<span style="color:#2ea44f">lower layers never reference higher ones</span>, and
the separation is enforced by the compiler rather than by convention alone.
In particular a grep gate over `src/tls/handshake/` proves the core owns no
record-layer token (`Record`, `TLSProtection`, `ContentType`,
`change_cipher_spec`, `record_header_len`), which is what makes `tls.handshake`
safe to import from a QUIC stack that has no record layer at all. Building such
a stack is covered end to end in
[`src/tls/handshake/QUIC.md`](src/tls/handshake/QUIC.md).

### 1.1 Public vs. private surface

For a TLS-over-TCP caller the entry point is `tls`, which exports only:

| Symbol | Kind | Purpose |
|---|---|---|
| `dial()` | function | Open a TCP connection and run the TLS 1.3 handshake |
| `Conn` | struct | The TCP protected stream (`read` / `write` / `close`) |
| `Config` | struct | Caller-facing dial options (`@[params]`) |
| `default_config()` | function | Explicit conservative `Config` constructor |
| `pki.TrustStore` | struct (`tls.pki`) | Custom root-CA set for `Config.root_cas` |

Within `tls`, the record layer, protection states, and TCP transport are
module-private implementation detail. The handshake core, by contrast, is a
deliberately **importable** module: `tls.handshake` exposes a small `pub` seam —
the [adapter contract](#15-adapter-contract-tlshandshake) below — so a QUIC
engine can drive the handshake without importing `tls`, pulling trust anchors
from `tls.pki`. `tls.wire` (`Reader`/`Writer`) is a lower-level shared utility;
its `pub` surface exists for the modules above it rather than as a documented
end-user API. `TrustStore` is public only because `Config.root_cas ?pki.TrustStore`
is a public field.

### 1.2 Layer map

Strict layering, bottom to top, enforced by the module boundaries. Each file
carries a doc preamble in its source with the authoritative description of its
role; this table summarizes it by owning module.

```text
   caller
      ▼
 ┌───────────────────────────────────────────────┐
 │ module tls         conn.v · record.v ·        │  public TCP API: dial() · Conn ·
 │                    record_protection.v        │  Config · record layer (§5) ·
 │                                               │  record protection · alert records
 ├───────────────────────────────────────────────┤
 │ module tls.handshake                          │  transport-neutral core (adapter
 │   state_machine.v · messages.v ·              │  contract): sequencing, §7.1
 │   key_schedule.v · transcript.v ·             │  ladder, codecs, AEAD ctors,
 │   aead.v · alert.v · certificate_verify.v ·   │  alert vocabulary, recordless
 │   passthrough.v                               │  CRYPTO-stream passthrough
 ├───────────────────────────────────────────────┤
 │ module tls.pki     validator.v · x509.v ·     │  chain of trust, DER decoding,
 │                    asn1.v · rsa.v ·           │  hostname matching, roots
 │                    hostname.v · trust_store.v │
 ├───────────────────────────────────────────────┤
 │ module tls.wire    reader.v · writer.v        │  bounds-checked wire codec
 └───────────────────────────────────────────────┘
```

The map draws the TLS-over-TCP stack only; `tls.quic` is a sibling of `tls`
plugging into the same `tls.handshake` core (walked through in
[`src/tls/handshake/QUIC.md`](src/tls/handshake/QUIC.md)) and `tls.fakeserver`
is test-only scaffolding — both are listed in the table below.

| Module | Files | Responsibility |
|---|---|---|
| `tls.wire` | `reader.v`, `writer.v` | Bounds-checked byte cursor / big-endian length-prefixed emitter. No TLS semantics, only framing arithmetic; every out-of-bounds access is an error, <span style="color:#2ea44f">never a panic</span>. |
| `tls.pki` | `x509.v`, `asn1.v`, `rsa.v`, `validator.v`, `hostname.v`, `trust_store.v` | Minimal strict DER reader and X.509 v3 decoding behind element-count guards, RFC 5280 chain building to a trusted root with name-constraint enforcement, RFC 6125 hostname matching, RSA/PSS/ECDSA/Ed25519 signature verification, and system trust-bundle loading. The rejection rules are enumerated in §4.3; `TrustStore` is public so `Config.root_cas` can be populated. |
| `tls.handshake` | `messages.v`, `transcript.v`, `key_schedule.v`, `aead.v`, `certificate_verify.v`, `alert.v`, `passthrough.v`, `state_machine.v`, `reassembly.v`, `flight.v`, `key_exchange.v`, `client_hello.v`, `server_hello.v`, `server_flight.v`, `post_handshake.v`, `tls_handshake.v`, `quic_handshake.v` | The transport-neutral core: RFC 8446 §4 message structures and the running Transcript-Hash (§4.4.1), the §7.1 HKDF ladder and phase derivations with the retained secret holders and their §7.5 lifecycle (`key_schedule.v`), AEAD constructors (`aead.v`), the CertificateVerify check (`certificate_verify.v`), the shared alert vocabulary with the RFC 9001 §4.8 mapping (`alert.v`), recordless CRYPTO-stream reassembly (`passthrough.v`), and post-handshake NewSessionTicket/KeyUpdate parsing (`post_handshake.v`). `state_machine.v` defines the shared `HandshakeCore` types, struct, constructor, the `HandshakeState` cursor (the RFC 8446 Appendix A.1 client states, plus an implementation `failed` terminal) and its terminal-failure primitives — with inbound byte reassembly in `reassembly.v`, the receive/dispatch routing and the ServerHello/HRR and encrypted-flight transitions in `flight.v`, and its ephemeral ECDHE methods in `key_exchange.v` and its derived-secret holders and lifecycle in `key_schedule.v` — and owns the key ratchet behind the `pub` seam; facade-exclusive methods live on the facades, never promoted from it — <span style="color:#2ea44f">it owns no record, cipher, or socket concept</span>. Facade choice at construction fixes the transport (§1.5); secret-hygiene timing is in §2.1 and the source preambles. |
| `tls` | `record.v`, `record_protection.v` | The TLS record layer (RFC 8446 §5): record framing and reassembly, the `ContentType`-tagged `Record` frame, per-direction AEAD key/IV/sequence state with §5.3 nonce construction and the §5.5 per-key record limit, and adapters hiding AES-GCM / ChaCha20-Poly1305 backends behind one seal/open interface. `record.v` keeps only the record-side framing helpers (`new_record`, `change_cipher_spec`) that stamp a `ContentType` onto an outbound message; the recordless CRYPTO-stream reassembly lives in the core's `passthrough.v`. |
| `tls` | `conn.v` | The public TCP adapter: `conn.v` owns `dial()`, the `Conn` type, the caller-facing `Config`/`default_config()`, its read/write/close path, and the `do_handshake` that drives the `tls.handshake` core — decrypt-then-route record handling, `TLSProtection` installation from `handshake_record_keys()` / `application_record_keys()` through the `tls_record_protection()` builder, and the §5.1 ServerHello record-boundary check all live here, alongside the framing/batching/CCS mechanics (reading records off the TCP stream, batching writes into a single `write(2)`, dummy-CCS validation, §5.5 send-side limits). |
| `tls.quic` | `engine.v`, `packet.v`, `packet_parse.v`, `protection.v`, `initial_keys.v`, `frame.v`, `varint.v`, `reasm.v`, `transport_params.v` | The QUIC client engine (RFC 9000/9001): the eight-step loop driving `tls.handshake` through the recordless `QuicHandshake` facade, long/short header (de)serialization and sample-based packet + header protection, Initial-key derivation from the original DCID, CRYPTO-stream reassembly, varints, frames, and the `original_destination_connection_id`-guarded transport parameters. Construction and the protection layers never import `tls`; see [`src/tls/handshake/QUIC.md`](src/tls/handshake/QUIC.md). |
| `tls.fakeserver` | `server.v`, `fixtures.v`, `keys.v` | Test-only adaptive TLS 1.3 server flight generator: builds a spec-conformant server response — full flight or HelloRetryRequest — from the client's actual ClientHello so the end-to-end tests can drive the real client byte by byte. Ships no library API. |

### 1.3 Data flow of `dial()`

```
TCP socket ──► read_raw_record() ──► state machine ──► validator (PKI)
   ▲                │                    │
   │          recv_buf framing     key_schedule / aead
   │                               transcript hash binding
write_records() ◄── followups / client flight / Finished
```

The TCP adapter (`conn.v`) is the only code that
touches the socket. The handshake loop accepts
dummy CCS (middlebox compatibility, §5), plaintext alerts (pre-key only),
handshake records, and encrypted records outer-typed as `application_data`
(§5.1/§5.2), and exits only when the state machine reports `.connected`. A
HelloRetryRequest round trip (new group, optional cookie echo,
`message_hash` transcript substitution) is handled transparently inside the
same loop — callers see a plain `dial()`.

> [!TIP]
> Every diagram in this section is strict bottom-to-top: a defect in any
> upper layer can never widen the attack surface of the layer below it.

### 1.4 Handshake sequence

The full exchange one successful `dial()` performs, in wire order:

```text
        Client                                          Server
  ─────────►  ClientHello          (key_share · supported_versions
  ◄─ ─ ─ ─    cipher_suites · SNI · ALPN · supported_groups)
             HelloRetryRequest?    ── only if the offered group is
  ─────────►  ClientHello (retry)     rejected; echoes cookie, new share
  ◄─────────  ServerHello           plaintext; ends the client's waiting
  ◄─ ─ ─ ─    (dummy ChangeCipherSpec — middlebox compatibility)
  ◄─────────  EncryptedExtensions   ┐ under handshake keys
  ◄─────────  CertificateRequest?   │ server requests client auth
  ◄─────────  Certificate           │ server's chain, in leaf-to-
  ◄─────────  CertificateVerify     │ issuer order
  ◄─────────  Finished              ┘ transcript-bound verify_data
  ─────────►  Certificate            empty, if a request was received
  ─────────►  Finished              client flight; both sides derive
                                    application keys on success
  ⇄ ⇄ ⇄ ⇄ ⇄   application_data …    records sealed with traffic keys
  ◄─────────  NewSessionTicket …    collected (capped at 32), not yet usable
  ◄─────────  KeyUpdate             read keys ratchet; response sent when
  ─────────►  KeyUpdate             requested (old-key-before-new order)
  ─────────►  close_notify          `Conn.close()`, then TCP FIN
```

Each `◄─ ─ ─` dummy ChangeCipherSpec is accepted and ignored (§5). The
handshake↔traffic key transition is derived inside the state machine and
installed by the adapter as records are processed; `dial()` returns only after
the client `Finished` is accepted by the server and the state reports
`.connected`. If the server sends a `CertificateRequest`, the client answers
with the empty `Certificate` a credential-less client must send (§4.4.2),
folded into the transcript before the server flight is verified — the library
has no client certificate to offer, so it declines rather than aborting.
Post-handshake messages (`NewSessionTicket`, `KeyUpdate`) are reassembled from
the decrypted record stream even when a single message is split across records
(the core's 1 MiB cap still bounds the buffer), and a ticket coalesced into the
same record as the server's `Finished` is drained to this reassembler at the end
of the handshake instead of orphaning in the core (§4.6.1).

### 1.5 Adapter contract (`tls.handshake`)

`tls.handshake` exposes separate `TLSHandshake` and `QuicHandshake`
facades over shared TLS 1.3 handshake logic. Framing and encryption decisions
stay adapter-side. The step-by-step walkthrough of the QUIC engine's side of
this contract — construction, CRYPTO-stream I/O, key derivation, confirmation
timing, alerts, Key Update/Phase, and post-handshake messages — lives in
[`src/tls/handshake/QUIC.md`](src/tls/handshake/QUIC.md), the dedicated guide to
building a QUIC adapter. The API contract is documented in
[`src/tls/handshake/CONTRACT.md`](src/tls/handshake/CONTRACT.md).

```v
// shared handshake driving (surfaced as curated `pub` forwarders on both facades)
// HandshakeOptions fields may be passed as optional named arguments.
new_tls_handshake(server_name string, options HandshakeOptions) !TLSHandshake
new_quic_handshake(server_name string, options HandshakeOptions) !QuicHandshake
(mut h) create_client_hello() ![]u8
(mut h) receive_initial_bytes(bytes []u8) ![]HandshakeMessage    // pre-ServerHello phase
(mut h) receive_handshake_bytes(bytes []u8) ![]HandshakeMessage  // handshake-key phase
     (h) state() HandshakeState   /   negotiated_alpn() string   /   negotiated_cipher_suite() CipherSuite
     (h) failure_alert() AlertDescription
(mut h) fail_and_zeroize_secrets()   // bulk, unguarded; wipes everything and parks .failed
(mut h) zeroize_handshake_secrets() !    // guarded teardown of the handshake-phase secrets
(mut h) zeroize_application_secrets() !  // guarded teardown of the application-phase secrets

// TLS record path (hooks defined on the TLSHandshake facade itself)
     (h) initial_backlog() int   /   (h) handshake_backlog() int   // §5.1 ServerHello record-boundary hook
     (h) handshake_record_keys() !HandshakeRecordKeys        // opaque RecordKeys handles, client and server, handshake phase
     (h) application_record_keys() !ApplicationRecordKeys     // same shape, application phase
(mut h) update_traffic_keys(is_server bool) !   // §7.2 key update: true = read/server leg, false = write/client leg

// QUIC path (accessors defined on the QuicHandshake facade itself)
     (h) peer_handshake_secrets() !([]u8, []u8)   /   (h) peer_application_secrets() !([]u8, []u8)   // raw client/server traffic secrets; the adapter expands RFC 9001 §5.1 packet keys itself

// outbound message routing (both transports)
     (m) is_initial() bool   // the only phase fact the public seam exposes: true = pre-ServerHello
```

- **The protection phases are module-private.** `EncryptionLevel`
  (`initial`/`handshake`/`application`) still gives handshake input and derived
  traffic secrets one shared vocabulary *inside* `tls.handshake`, but it is an
  implementation detail: the public seam names the phase in the method —
  `receive_initial_bytes()`, `handshake_record_keys()`, `peer_application_secrets()`,
  `zeroize_handshake_secrets()` — and, for the derived record keys, in the return type as
  well (`HandshakeRecordKeys` / `ApplicationRecordKeys`), so no adapter ever builds or
  matches on a level value. `HandshakeMessage.is_initial()` is the single phase fact
  adapters may read, and only to pick a transmit queue. The initial phase means the
  pre-ServerHello TLS handshake stage; it is not QUIC Initial packet
  protection. QUIC Initial packet keys derive from the destination connection ID and are
  not part of this TLS secret API.
- **Keys stay adapter-owned.** `TLSHandshake` caches each generation's record keys as
  an opaque phase-typed handle wrapping one `RecordKeys` per direction,
  and implements the TLS KeyUpdate derivation. `QuicHandshake` exposes TLS traffic
  secrets for RFC 9001 packet-key derivation; the QUIC engine owns packet keys
  and QUIC key updates.
- **Lifecycle and framing stay explicit.** Both facades share failure cleanup
  and handshake-secret zeroization. The reassembly counts the record adapter
  needs for the TLS ServerHello record-boundary rule live on the
  `TLSHandshake` facade as `initial_backlog()` / `handshake_backlog()` — they and
  `take_buffered_handshake_bytes()` have no QUIC caller; QUIC maps alert
  descriptions to QUIC connection errors.

---

## 2. API reference

Five exported symbols; the whole surface:

| Symbol | One-line summary | Reference |
|---|---|---|
| [`dial`](#21-dial) | Open a socket, run the full handshake, return a ready `Conn` | [§2.1](#21-dial) |
| [`Conn`](#22-conn) | The protected stream: `read` / `write` / `close` | [§2.2](#22-conn) |
| [`Config`](#23-config) | `@[params]` dial options — SNI, trust, timeout | [§2.3](#23-config) |
| [`default_config`](#24-default_config) | Explicit conservative `Config` constructor | [§2.4](#24-default_config) |
| [`TrustStore`](#25-truststore) | Custom root-CA set for `Config.root_cas` | [§2.5](#25-truststore) |

### 2.1 `dial`

```v
pub fn dial(address string, config Config) !&Conn
```

Connects to `address` (`"host:port"` or `"[ipv6]:port"`), runs the full TLS 1.3
client handshake, and returns a ready-to-use `Conn`. Because `Config` is a
`@[params]` struct and the last parameter, its fields may be passed as trailing
named arguments directly on `dial()` — omitted fields keep the defaults declared
on `Config`:

```v
import tls.handshake

mut conn := tls.dial('example.com:443',
	server_name: 'example.com'
	hsk_options: handshake.HandshakeOptions{
		alpn: ['h2', 'http/1.1']
	}
)!
```

Behavior and guarantees:

- **Server name resolution** — an explicit `server_name` wins; otherwise the
  host is derived from `address` so a bare `"host:port"` still supplies SNI and
  the name the certificate is verified against.
- **Timeouts** — `config.timeout` (or 30 s when unset/zero) is applied to both
  socket directions before the handshake, so a stalled peer cannot hang `dial()`.
  The handshake phase additionally carries a total deadline of 4× that per-operation
  timeout: a slow-loris peer dribbling valid bytes under every individual read
  timeout is still cut off, while post-handshake `read()` stays bound only by the
  per-operation timeout.
- **Server name gate** — a name over the 253-character DNS ceiling (RFC 1035 §2.3.4)
  or carrying stray whitespace is rejected before the socket opens, so the name
  dialed is always the name sent in SNI and the name verified.
- **Trust anchors, by precedence** — explicit `config.root_cas` is used as-is;
  else the system CA bundle is loaded — parsed once per process, then cached for
  every later `dial()` (a load failure is a dial error) — unless
  `insecure_skip_verify` is set, in which case an empty store suffices.
- <span style="color:#2ea44f">**No fd leaks**</span> — any handshake failure
  closes the socket it opened before
  returning the error; a half-connected `Conn` is never returned.
- <span style="color:#2ea44f">**Forward secrecy of retained secrets**</span> — the
  handshake secret and ephemeral X25519 / P-256 private keys are released when
  the state machine reaches `.connected`. Handshake traffic secrets remain
  until `zeroize_handshake_secrets()` because QUIC may still need them;
  application traffic secrets are released at `close()` or on a fatal alert.
  The §7.1 derivations also zeroize their own in-function intermediates — the
  Early and Master secrets, the `derived` seeds, every HKDF-Expand round input,
  and the single-use Finished MAC key — so no orphaned key material outlives
  the call that produced it.
- **ALPN is enforced** — a server selecting a protocol that wasn't offered aborts
  the handshake (RFC 7301 §3.1); an empty `alpn` list forbids any ALPN response.
- **Resource bounds** — a handshake message declaring more than 1 MiB is refused
  at its header before fragments accumulate; a `Certificate` list with more than
  32 entries is rejected during parsing (before each is ASN.1-decoded), and so are
  chains that long, CA RSA keys shorter than 2048 bits, and a leaf under the
  `min_rsa_bits` floor; at most two middlebox
  dummy ChangeCipherSpec records are tolerated during the handshake, so a streamed
  CCS flood cannot pin the loop, and the whole server flight is additionally capped
  at 64 records with empty inner-handshake payloads refused, so even state-neutral
  but decryptable records cannot burn AEAD work past a deterministic bound instead
  of only the monotonic handshake deadline; a HelloRetryRequest cookie longer than 8 KiB is
  refused at parse time so the echoing ClientHello stays frameable in one record;
  unconsumed framed bytes are capped at two maximal
  records plus one socket read while handshaking, so dribbled incomplete records
  cannot grow memory without bound; a single `read()` call skips at most 100
  tolerated records (zero-length padding or post-handshake messages) before
  failing, and one record may deliver at most 1000 complete post-handshake
  messages before their parse/rekey work is cut off, so a verified flood cannot
  starve the caller; the post-handshake `NewSessionTicket` backlog is
  capped at 32 stored tickets.

### 2.2 `Conn`

```v
@[noinit]
pub struct Conn {}
```

A TLS 1.3 client connection over TCP. `@[noinit]` prevents constructing one
without `dial()` supplying every field.

All `Conn` fields are module-private. The only connection identity surfaced to a
caller is the negotiated ALPN protocol, read through the `negotiated_alpn()`
accessor below; the SNI name and the verified host stay internal (a caller
already holds both in its own `Config`).

#### `read`

```v
pub fn (mut c Conn) read(mut buf []u8) !int
```

Decrypts application data into `buf` and returns the byte count. `0` means a
clean end of stream (peer `close_notify` or connection already closed).

- A decrypted record larger than `buf` is buffered internally; subsequent calls
  drain the remainder before reading new records — no plaintext is dropped or reordered.
- Zero-length (padding-only) records and inner-type-handshake records are skipped
  transparently, up to the per-`read()` tolerated-record bound (§2.1 Resource bounds);
  past it the connection fails closed with `unexpected_message`.
- **Plaintext hygiene** — the decrypted staging copy is scrubbed the moment its
  bytes are delivered, the undelivered `app_buf` remainder is zeroed when it
  drains or on terminal teardown, and post-handshake reassembly bytes are wiped
  when the connection dies (RFC 8446 §7.5 spirit: freed memory retains no plaintext).
- A **plaintext outer alert after the handshake is
  <span style="color:#2ea44f">rejected</span>**, and so is a
  plaintext ChangeCipherSpec record — RFC 8446 §5/§6 make both fatal
  (`unexpected_message`) once keys exist, preventing record injection.
- The receive side aborts if the peer exceeds the §5.5 per-key record limit
  without rekeying (2²⁴ records per key generation).
- Post-handshake encrypted records are demultiplexed by inner content type:
  `NewSessionTicket` messages are collected, `KeyUpdate` read-key updates are
  applied (a response is sent with the correct §4.6.3 old-key-before-new ordering
  when the server requests one, and §4.5's rule against more than one KeyUpdate
  in a row is enforced on receipt — a second consecutive one aborts before its
  rekey work is paid for), and encrypted `alert`s end the stream.
- Reading with an empty `buf` returns `0` without I/O.

#### `write`

```v
pub fn (mut c Conn) write(data []u8) !int
```

Encrypts and sends application data, returning the number of bytes accepted
(the full `data.len` on success). One call may emit many records: plaintext is
chunked at 2¹⁴ bytes, the TLS maximum (§5.1). Before a key generation crosses
the §5.5 record limit the client transparently rekeys — it fires at
`limit − 1`, reserving the one slot the KeyUpdate notice itself needs (its
encrypted record goes through the same send-side backstop that guards received
data, which would otherwise refuse the record at exactly the boundary), then
sends a `KeyUpdate (update_not_requested)` under the old keys and updates the
write keys, exactly as the §4.6.3 response path does. Writing on a closed
connection or before the handshake completes is an error — the state machine is
the gate, not caller ordering.

#### `close`

```v
pub fn (mut c Conn) close() !
```

Sends `close_notify` (encrypted with application keys when they exist, per
§5.2/§6.1), zeroizes the retained application traffic secrets, and closes the
TCP socket. <span style="color:#2ea44f">**Idempotent**</span>: a second
`close()` neither re-sends `close_notify` nor double-closes the socket, and
never errors. Use it in a `defer` block.
If the peer sends `close_notify`, `read()` returns `0` but leaves the TCP socket
open; call `close()` to release it.

#### `negotiated_alpn`

```v
pub fn (c Conn) negotiated_alpn() string
```

Returns the negotiated ALPN protocol, if any (`''` otherwise). Populated only
after the handshake has proven the server's choice was offered.

### 2.3 `Config`

```v
import time
import tls.handshake

@[params]
pub struct Config {
pub:
	server_name          string
	insecure_skip_verify bool
	root_cas             ?pki.TrustStore
	min_rsa_bits         int
	hsk_options handshake.HandshakeOptions = handshake.HandshakeOptions{}
	timeout              time.Duration = 30 * time.second
}
```

Caller-facing dial options. Fields are `pub:` — **read-only**: you cannot mutate
a `Config` after creation; customise it via named arguments on `dial()` (or
build one up front from `default_config()`).

| Field | Default | Description |
|---|---|---|
| `server_name` | `''` | SNI and certificate hostname verification target. Empty ⇒ derived from the dial address. Must match the server's certificate (SAN dNSName / IP, CN fallback per RFC 6125). |
| `insecure_skip_verify` | `false` | Disables chain **and** hostname validation. Removes all authentication the handshake provides — tests and pinned lab environments only, never shipped enabled. |
| `root_cas` | `none` | When set, used instead of the system trust store (private CAs, enterprise, testing). Otherwise the system bundle is used, parsed once per process and cached for every later `dial()`. |
| `min_rsa_bits` | `0` (⇒ 2048) | Minimum accepted RSA **leaf** key size in bits. Zero keeps the default floor (`pki.default_min_rsa_bits` = 2048); set lower only for interoperability with a legacy server. Chain (CA) RSA keys are floored at 2048 unconditionally. |
| `hsk_options` | defaults | ALPN protocols to offer, optional explicit validator, key-share group, and preference-ordered supported groups, cipher suites, and signature algorithms. An empty ALPN list offers no ALPN; the server's pick is verified against the offered list. Empty preference lists retain the defaults. Explicit random and legacy session-ID values are for deterministic test vectors only. In `dial()`, a validator in these options takes precedence over `root_cas` and `insecure_skip_verify`; otherwise the validator is built from the Config trust settings. |
| `timeout` | `30s` | Socket read/write timeout applied before the handshake; a zero value falls back to 30 s. |

> [!IMPORTANT]
> <span style="color:#cf222e">`insecure_skip_verify` removes all authentication</span>
> the handshake provides — chain *and* hostname checks. Tests and pinned lab
> environments only; it should be impossible to find enabled in shipped code.

### 2.4 `default_config`

```v
pub fn default_config(server_name string) Config
```

Builds a fully-populated, deliberately conservative `Config`: verification
strictly on, no ALPN offer (server picks its default), system roots (the
`root_cas` slot stays `none`; `dial()` uses the cached system bundle). `alpn` and
`timeout` inherit their declared field defaults.

```v
mut conn := tls.dial('example.com:443', tls.default_config('example.com'))!
```

### 2.5 `TrustStore`

> Lives in the `tls.pki` module — callers reach it as `pki.TrustStore` /
> `pki.new_trust_store()` (and add `import tls.pki`). It is documented here
> because it is part of the `dial()`/`Config` surface via `Config.root_cas`.

```v
@[noinit]
pub struct TrustStore {}
```

A set of trusted root CA certificates, assigned to `Config.root_cas`.
`@[noinit]` stops a bare `TrustStore{}` from existing with an uninitialized
internal slice — instances come from `new_trust_store()`.

`pki.default_validator()` builds a certificate validator from the cached system
root bundle and returns an error if no system bundle is available. Options-based
handshake constructors use this validator when `HandshakeOptions.validator` is
omitted; provide a validator explicitly to use private roots or custom policy.

#### `new_trust_store`

```v
pub fn new_trust_store() TrustStore
```

Creates an empty store.

#### `add_der`

```v
pub fn (mut ts TrustStore) add_der(der []u8) !
```

Parses and appends a single DER-encoded certificate. A malformed certificate is
an error (not a silent skip).

#### `add_pem`

```v
pub fn (mut ts TrustStore) add_pem(pem_content string) !int
```

Parses and appends every `-----BEGIN ... CERTIFICATE-----` block in a PEM
bundle; returns the number of certificates added. Unparseable blocks are
**skipped rather than failing the whole bundle**, since system bundles
occasionally contain unsupported formats.

#### `load_system_ca_bundle`

```v
pub fn (mut ts TrustStore) load_system_ca_bundle() !int
```

Probes known system bundle locations (there is no portable trust-store API) and
loads the first that yields certificates; returns the count, or errors if none
was found. Paths probed, in order:

| Path | Systems |
|---|---|
| `/etc/ssl/certs/ca-certificates.crt` | Debian/Ubuntu/Gentoo |
| `/etc/pki/tls/certs/ca-bundle.crt` | Fedora/RHEL/CentOS |
| `/etc/ca-certificates/extracted/tls-ca-bundle.pem` | Arch Linux |
| `/etc/ssl/ca-bundle.pem` | OpenSUSE |
| `/etc/pki/tls/cacert.pem` | OpenELEC |
| `/usr/local/share/certs/ca-root-nss.crt` | FreeBSD |
| `/etc/ssl/cert.pem` | Alpine / macOS |

`dial()` calls this automatically when `Config.root_cas` is unset and
verification is on — via a process-wide cache, so the bundle is parsed once
per process rather than once per connection.

---

## 3. Usage

Runnable recipes. Three runnable examples live alongside each other: a minimal
client (`v run src/example/simple_example.v`), a minimal trust-store demo
(`v run src/example/trust_store_example.v`) that supplies its own
`Config.root_cas`, and a fuller demo (`v run src/example/dial_example.v`) that
adds CLI arguments/flags, HTTP status/header parsing, and chunked-body decoding.

### 3.1 Basic client

```v
import tls
import tls.handshake

mut conn := tls.dial('example.com:443',
	server_name: 'example.com'
	hsk_options: handshake.HandshakeOptions{
		alpn: ['http/1.1']
	}
) or {
	eprintln('dial failed: ${err}')
	exit(1)
}
defer {
	conn.close() or {}
}

conn.write('GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n'.bytes())!

// A single read() returns at most one record's worth; loop until the response
// is complete. read() returns 0 on the peer's close_notify.
mut buf := []u8{len: 8192}
for {
	n := conn.read(mut buf) or { break }
	if n == 0 {
		break
	}
	print(buf[..n].bytestr())
}
println('ALPN: ${conn.negotiated_alpn()}')
```

### 3.2 Private CA / pinned lab roots

```v
import os
import tls.pki

mut store := pki.new_trust_store()
store.add_pem(os.read_file('my-root-ca.pem')!)!

mut conn := tls.dial('internal.example:443',
	server_name: 'internal.example'
	root_cas:    store
)!
```

### 3.3 Testing escape hatch

> [!WARNING]
> <span style="color:#cf222e">Skips all certificate verification.</span> The
> connection is encrypted but unauthenticated — trivially MITM'd. Never ship it.

```v
// Disables chain AND hostname validation — never ship enabled.
mut conn := tls.dial('self-signed.test:8443',
	server_name:          'self-signed.test'
	insecure_skip_verify: true
)!
```

### 3.4 HelloRetryRequest — handled transparently

If the server rejects the initial `key_share` guess (e.g. it wants P-256 but we
offered X25519 first), it replies with a HelloRetryRequest. No special caller
API exists for this: the plain `dial()` above already covers it — the state
machine switches to the server's requested group, regenerates the local share,
echoes any `cookie`, and re-sends a ClientHello. The transcript substitutes the
first HelloRetryRequest with its `message_hash` (§4.4.1) so Finished
verification binds the entire two-round exchange.

### 3.5 Revocation is out of scope

> [!IMPORTANT]
> <span style="color:#b26a00">This library does not consult CRLs or OCSP.</span>
> A certificate that is unexpired, correctly chained, and in policy is accepted
> even if the issuer has revoked it.

This is a deliberate scope decision, not an oversight. Revocation checking is
famously unreliable — soft-fail CRL/OCSP silently accepts when the responder is
unreachable, hard-fail turns a third-party outage into a client outage, OCSP
stapling requires the server to cooperate, and CRLs are large and stale. A
half-implemented check gives operators false confidence. There is also **no
callback hook**: a hook that runs after `dial()` returns is too late to stop the
handshake, and one that runs mid-handshake would have to be `pub` in the
transport-neutral core, dragging application policy into a module that owns no
socket concept.

If your threat model needs revocation:

1. Validate the leaf **out of band** before trusting the connection — fetch the
   issuer's CRL or an OCSP response, verify its signature and freshness, and
   check the leaf's serial number against it. Do this against the certificate
   the server presented, not a second one fetched independently.
2. Use short-lived leaf certificates so revocation windows are minutes, not
   months — the practical mitigation most large deployments rely on.
3. If you must bind it to the handshake, terminate TLS in a component that
   already does stapled-OCSP validation and treat this library's result as the
   transport beneath it.

---

## 4. Error handling summary

All fallible operations return `!` (V option/result errors); there are
<span style="color:#2ea44f">**no panics on malformed input**</span> — bad
framing, oversized records, duplicate or unpermitted extensions, truncated
certificates, and bad share sizes are
<span style="color:#2ea44f">handshake errors, never memory-safety events</span>.

When the handshake fails, `dial()` sends a fatal alert before closing: a
plaintext one before the ServerHello, and one sealed under the handshake keys
afterward. The alert is classified from the cause where it is known —
`unexpected_message` for a message out of sequence, `illegal_parameter` for a
bad share or malformed field, `decrypt_error` for a record that fails to
authenticate, `bad_certificate` for a certificate failure — and falls back to
the §6 catch-all `internal_error`. Immediately after, every secret the failing
attempt derived (handshake and application traffic secrets, cached traffic
keys, ephemeral private keys) is wiped, so a retained buffer cannot unlock a
recorded session (§7.5).

### 4.1 Connection lifecycle

| Situation | Result |
|---|---|
| DNS / TCP connect failure | <span style="color:#cf222e">`dial()` error</span> |
| Socket timeout (read or write) | `dial()` / `read()` / `write()` error after `Config.timeout` |
| Peer sends a fatal alert during handshake | <span style="color:#cf222e">`dial()` error</span> carrying the alert description |
| Peer `close_notify` while reading | <span style="color:#2ea44f">`read()` returns `0` (clean EOF); call `close()` to release the TCP socket</span> |
| Peer fatal alert (encrypted, post-handshake) | <span style="color:#cf222e">`read()` error</span> carrying the alert description |
| `write()` after `close()` or before handshake | error, nothing sent |
| `close()` twice | <span style="color:#2ea44f">no-op, no error, `close_notify` sent at most once</span> |
| Handshake failure inside `dial()` | error; a classified fatal alert is sent, secrets are wiped, and the socket is closed — no fd leak, no retained key material |

### 4.2 Wire & handshake protocol violations

| Situation | Result |
|---|---|
| Handshake message declaring > 1 MiB | <span style="color:#cf222e">`dial()` error</span> (reassembly cap) |
| Plaintext alert or ChangeCipherSpec post-handshake | <span style="color:#cf222e">`read()` error</span> (fatal `unexpected_message`; injection rejected) |
| More than two dummy ChangeCipherSpec records during the handshake | <span style="color:#cf222e">`dial()` error</span> (flood bound `max_compat_ccs_records`, `unexpected_message`) |
| More than 64 records consumed by one server flight, or an empty inner-handshake payload | <span style="color:#cf222e">`dial()` error</span> (flight bound `max_handshake_flight_records`, `unexpected_message`) |
| `HelloRetryRequest` cookie longer than 8 KiB | <span style="color:#cf222e">`dial()` error</span> (echo bound `max_hrr_cookie_len`, decode_error) |
| Peer exceeds §5.5 per-key record limit without rekeying | <span style="color:#cf222e">`read()` error</span> |
| `Certificate` list with more than 32 entries | <span style="color:#cf222e">`dial()` error</span> (rejected at parse, before decoding) |
| `NewSessionTicket` with trailing bytes after its extensions | <span style="color:#cf222e">`dial()` error</span> (decode_error) |
| X25519 shared secret of small order (0, 1, or p−1) | <span style="color:#cf222e">`dial()` error</span> (illegal_parameter) |
| P-256 `key_share` is the encoded point at infinity (`0x04 \|\| 0 \|\| 0`) | <span style="color:#cf222e">`dial()` error</span> (illegal_parameter, refused before scalar multiplication) |
| More than one consecutive `KeyUpdate` from the peer (§4.5) | <span style="color:#cf222e">`read()` error</span> (unexpected_message, aborted before the second rekey derivation) |
| Locally built ClientHello larger than one record (§5.1) | <span style="color:#cf222e">`dial()` error</span> — refused before framing a non-compliant record |
| Own `key_share` malformed: wrong size, missing `0x04` point marker, or group not in `supported_groups` (§4.2.8) | <span style="color:#cf222e">`dial()` error</span> at ClientHello build time |

### 4.3 Certificate & trust-policy rejections

| Situation | Result |
|---|---|
| Certificate chain / hostname / signature verification failure | <span style="color:#cf222e">`dial()` error</span> |
| Leaf/CA `keyUsage` present but forbidding its required use | <span style="color:#cf222e">`dial()` error</span> (digitalSignature / keyCertSign) |
| `basicConstraints` pathLenConstraint exceeded | <span style="color:#cf222e">`dial()` error</span> |
| CA RSA key < 2048 bits in the chain | <span style="color:#cf222e">`dial()` error</span> |
| Leaf RSA key below `Config.min_rsa_bits` (default 2048) | <span style="color:#cf222e">`dial()` error</span> (raise/lower via `min_rsa_bits`) |
| Leaf dNSName/iPAddress outside a CA's permitted Subtrees, or inside an excluded one | <span style="color:#cf222e">`dial()` error</span> (RFC 5280 §4.2.1.10) |
| No revocation information consulted (CRL/OCSP) | <span style="color:#b26a00">accepted — revocation is out of scope</span> |
| Unparseable certificate validity time | <span style="color:#cf222e">`dial()` error</span> (decode fails; expiry always enforced) |
| Non-minimal DER length or invalid RSA public exponent (`e` = 0, degenerate 1, or any even value such as 2) | <span style="color:#cf222e">`dial()` error</span> (decode rejected) |
| `TBSCertificate` missing mandatory fields — with or without the optional `version [0]` element | <span style="color:#cf222e">`dial()` error</span> (post-version element-count guard; a truncated v3 certificate fails the decode cleanly instead of indexing past the element array) |
| CertificateVerify scheme paired with the wrong leaf key type, or an ECDSA scheme with the wrong curve | <span style="color:#cf222e">`dial()` error</span> (§4.2.3 curve/scheme binding checked before any key material) |