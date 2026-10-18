# `tls` — Module & API Documentation

![V](https://img.shields.io/badge/language-V-2d7dd2) ![TLS&nbsp;1.3](https://img.shields.io/badge/protocol-RFC_8446-2ea44f) ![client--only](https://img.shields.io/badge/role-client--only-6f42c1) ![no%20deps](https://img.shields.io/badge/OpenSSL--free-000000) ![status](https://img.shields.io/badge/status-experimental-e8930c)

A **<span style="color:#2d7dd2">TLS 1.3 client</span>** library written in [V](https://vlang.io), implementing
[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) directly on standard-library
crypto — no OpenSSL bindings, no third-party dependencies.

| | |
|---|---|
| **Protocol** | TLS 1.3 (RFC 8446) — client only; no TLS 1.2 fallback, resumption, or 0-RTT |
| **Implementation** | Pure V over the standard-library crypto stack; strict, bounds-checked parsing throughout |
| **API surface** | `dial()` · `Conn` · `Config` · `default_config()` · `TrustStore` — everything else is module-private |
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
- [4. Error handling summary](#4-error-handling-summary)
  - [4.1 Connection lifecycle](#41-connection-lifecycle)
  - [4.2 Wire & handshake protocol violations](#42-wire--handshake-protocol-violations)
  - [4.3 Certificate & trust-policy rejections](#43-certificate--trust-policy-rejections)

---

## 1. Module architecture

Everything lives in a single module, `tls` (`src/tls/`). All files declare
`module tls`; there are no submodules and no cross-module imports. Internal
layers are separated **by convention**, not by the compiler: each file owns one
layer of the stack, and <span style="color:#2ea44f">lower layers never reference higher ones</span>.

### 1.1 Public vs. private surface

The module deliberately exports only:

| Symbol | Kind | Purpose |
|---|---|---|
| `dial()` | function | Open a connection and run the handshake |
| `Conn` | struct | The protected stream (`read` / `write` / `close`) |
| `Config` | struct | Caller-facing dial options (`@[params]`) |
| `default_config()` | function | Explicit conservative `Config` constructor |
| `TrustStore` | struct | Custom root-CA set for `Config.root_cas` |

Everything else — record layer, wire codec (`Reader`/`Writer`), message codecs,
key schedule, state machine, X.509/ASN.1 parsing, RSA, hostname matching,
validator, alerts, cipher state — is module-private implementation detail and
not part of the API contract. (`TrustStore` stays public only because
`Config.root_cas ?TrustStore` is a public field.)

### 1.2 Layer map

Strict layering, bottom to top. Each file carries a doc preamble in its source
with the authoritative description of its role; this table summarizes it.

```text
   caller
      ▼
 ┌───────────────────────────────┐
 │ conn.v · config.v             │  public API: dial() · Conn · Config
 ├───────────────────────────────┤
 │ state_machine.v               │  handshake sequencing, key ratchet
 ├───────────────────────────────┤
 │ validator · x509 · asn1 ·     │  chain of trust, DER decoding,
 │ rsa · hostname · trust_store  │  hostname matching, roots
 ├───────────────────────────────┤
 │ messages · transcript ·       │  RFC 8446 §4 structures, running
 │ certificate_verify ·          │  hash, signature verification,
 │ key_schedule · handshake_keys │  · HKDF §7.1 ladder
 │ · cipher_state · aead         │  · per-direction AEAD state
 ├───────────────────────────────┤
 │ record · alert                │  record framing & reassembly, alerts
 ├───────────────────────────────┤
 │ reader.v · writer.v           │  bounds-checked wire codec
 └───────────────────────────────┘
```

| Layer | Files | Responsibility |
|---|---|---|
| Wire codec | `reader.v`, `writer.v` | Bounds-checked byte cursor / big-endian length-prefixed emitter. No TLS semantics, only framing arithmetic; every out-of-bounds access is an error, <span style="color:#2ea44f">never a panic</span>. |
| Record layer | `record.v`, `alert.v`, `cipher_state.v`, `aead.v` | Record framing and reassembly (§5), alert protocol enums + wire encoding (§6), per-direction AEAD key/IV/sequence state with §5.3 nonce construction and the §5.5 per-key record limit, adapters hiding AES-GCM / ChaCha20-Poly1305 backends behind one seal/open interface. |
| Handshake messaging | `messages.v`, `transcript.v` | RFC 8446 §4 structures (ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished, extensions) and the running Transcript-Hash (§4.4.1), kept as raw messages so the HelloRetryRequest checkpoint can rewrite history. |
| Key schedule | `key_schedule.v`, `handshake_keys.v` | HKDF-Extract/Expand ladder over (EC)DHE and traffic-secret stages (§7.1); `handshake_keys.v` adapts those pure derivations plus the offered-group policy to the handshake flow — it never touches the transcript or advances state. |
| Signature check | `certificate_verify.v` | Verifies the server's CertificateVerify over the §4.4.3 transcript content; a pure function of (leaf key, signature, content). |
| PKI | `x509.v`, `asn1.v`, `rsa.v`, `validator.v`, `hostname.v`, `trust_store.v` | Minimal DER reader (strict on non-minimal lengths), X.509 v3 decoding (validity, keyUsage, basicConstraints + pathLen, EKU, SAN) behind element-count guards that fail truncated certificates — including the optional-version-shifted ones — as decode errors rather than indexing past the array, raw RSA (odd exponents only) / PKCS#1 v1.5 verification, RFC 5280 chain building to a trusted root, RFC 6125 hostname matching (SAN-over-CN precedence enforced internally), system trust bundle loading. |
| State machine | `state_machine.v` | Sequences the client handshake: drives codecs, AEAD, key schedule, signature verification, and the validator; owns no socket — `conn.v` feeds records through it. Scrubs handshake secrets and both ephemeral private keys the moment `.connected` makes them dead weight, and application traffic secrets at teardown (RFC 8446 §1.3.1/§7.5 forward-secrecy hygiene). |
| Public API | `conn.v`, `config.v` | `dial()` + `Conn` (socket I/O, record buffering, post-handshake handling) and `Config` options. |

### 1.3 Data flow of `dial()`

```
TCP socket ──► read_raw_record() ──► state machine ──► validator (PKI)
   ▲                │                    │
   │          recv_buf framing     key_schedule / aead
   │                               transcript hash binding
write_records() ◄── followups / client flight / Finished
```

`conn.v` is the only file that touches the socket. The handshake loop accepts
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
  ◄─────────  Certificate           │ server's chain, in leaf-to-
  ◄─────────  CertificateVerify     │ issuer order
  ◄─────────  Finished              ┘ transcript-bound verify_data
  ─────────►  Finished              client flight; both sides derive
                                    application keys on success
  ⇄ ⇄ ⇄ ⇄ ⇄   application_data …    records sealed with traffic keys
  ◄─────────  NewSessionTicket …    collected (capped at 32), not yet usable
  ◄─────────  KeyUpdate             read keys ratchet; response sent when
  ─────────►  KeyUpdate             requested (old-key-before-new order)
  ─────────►  close_notify          `Conn.close()`, then TCP FIN
```

Each `◄─ ─ ─` dummy ChangeCipherSpec is accepted and ignored (§5). The
handshake↔traffic key transition happens inside the state machine as records
are processed; `dial()` returns only after the client `Finished` is accepted
by the server and the state reports `.connected`.

---

## 2. API reference

Five exported symbols; the whole surface:

| Symbol | One-line summary | Reference |
|---|---|---|
| [`dial`](#21-dial) | Open a socket, run the full handshake, return a ready `Conn` | [§2.1](#21-dial) |
| [`Conn`](#22-conn) | The protected stream: `read` / `write` / `close` | [§2.2](#22-conn) |
| [`Config`](#23-config) | `@[params]` dial options — SNI, ALPN, trust, timeout | [§2.3](#23-config) |
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
mut conn := tls.dial('example.com:443',
	server_name: 'example.com'
	alpn:        ['h2', 'http/1.1']
)!
```

Behavior and guarantees:

- **Server name resolution** — an explicit `server_name` wins; otherwise the
  host is derived from `address` so a bare `"host:port"` still supplies SNI and
  the name the certificate is verified against.
- **Timeouts** — `config.timeout` (or 30 s when unset/zero) is applied to both
  socket directions before the handshake, so a stalled peer cannot hang `dial()`.
- **Trust anchors, by precedence** — explicit `config.root_cas` is used as-is;
  else the system CA bundle is loaded (a load failure is a dial error), unless
  `insecure_skip_verify` is set, in which case an empty store suffices.
- <span style="color:#2ea44f">**No fd leaks**</span> — any handshake failure closes the socket it opened before
  returning the error; a half-connected `Conn` is never returned.
- <span style="color:#2ea44f">**Forward secrecy of retained secrets**</span> — the handshake-stage traffic secrets
  and the ephemeral X25519 / P-256 private keys are released the instant the
  state machine reaches `.connected` (nothing reads them again), and the
  application traffic secrets are released at `close()` or on a fatal alert, so
  a later memory exposure cannot unlock a previously recorded session.
- **ALPN is enforced** — a server selecting a protocol that wasn't offered aborts
  the handshake (RFC 7301 §3.1); an empty `alpn` list forbids any ALPN response.
- **Resource bounds** — a handshake message declaring more than 1 MiB is refused
  at its header before fragments accumulate; a `Certificate` list with more than
  32 entries is rejected during parsing (before each is ASN.1-decoded), and so are
  chains that long and CA RSA keys shorter than 2048 bits; at most two middlebox
  dummy ChangeCipherSpec records are tolerated during the handshake, so a streamed
  CCS flood cannot pin the loop; the post-handshake `NewSessionTicket` backlog is
  capped at 32 stored tickets.

### 2.2 `Conn`

```v
@[noinit]
pub struct Conn {}
```

A TLS 1.3 client connection over TCP. `@[noinit]` prevents constructing one
without `dial()` supplying every field.

**Accessible fields** (set at dial time, read-only by contract):

| Field | Type | Meaning |
|---|---|---|
| `server_name` | `string` | SNI value sent and the name the certificate was checked against |
| `negotiated_alpn` | `string` | The server's ALPN pick — always one of `Config.alpn`, or `''` if none |

#### `read`

```v
pub fn (mut c Conn) read(mut buf []u8) !int
```

Decrypts application data into `buf` and returns the byte count. `0` means a
clean end of stream (peer `close_notify` or connection already closed).

- A decrypted record larger than `buf` is buffered internally; subsequent calls
  drain the remainder before reading new records — no plaintext is dropped or reordered.
- Zero-length (padding-only) records are skipped transparently.
- A **plaintext outer alert after the handshake is
  <span style="color:#2ea44f">rejected</span>**, and so is a
  plaintext ChangeCipherSpec record — RFC 8446 §5/§6 make both fatal
  (`unexpected_message`) once keys exist, preventing record injection.
- The receive side aborts if the peer exceeds the §5.5 per-key record limit
  without rekeying (2²⁴ records per key generation).
- Post-handshake encrypted records are demultiplexed by inner content type:
  `NewSessionTicket` messages are collected, `KeyUpdate` read-key ratchets are
  applied (a response is sent with the correct §4.6.3 old-key-before-new ordering
  when the server requests one), and encrypted `alert`s end the stream.
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
sends a `KeyUpdate (update_not_requested)` under the old keys and ratchets the
write keys, exactly as the §4.6.3 response path does. Writing on a closed
connection or before the handshake completes is an error — the state machine is
the gate, not caller ordering.

#### `close`

```v
pub fn (mut c Conn) close() !
```

Sends `close_notify` (encrypted with application keys when they exist, per
§6.1/§A.4), zeroizes the retained application traffic secrets, and closes the
TCP socket. <span style="color:#2ea44f">**Idempotent**</span>: a second `close()` neither re-sends `close_notify`
nor double-closes the socket, and never errors. Use it in a `defer` block.

#### `negotiated_alpn`

```v
pub fn (c Conn) negotiated_alpn() string
```

Returns the negotiated ALPN protocol, if any (`''` otherwise). Populated only
after the handshake has proven the server's choice was offered.

### 2.3 `Config`

```v
import time

@[params]
pub struct Config {
pub:
	server_name          string
	alpn                 []string = []string{}
	insecure_skip_verify bool
	root_cas             ?TrustStore
	timeout              time.Duration = 30 * time.second
}
```

Caller-facing dial options. Fields are `pub:` — **read-only**: you cannot mutate
a `Config` after creation; customise it via named arguments on `dial()` (or
build one up front from `default_config()`).

| Field | Default | Description |
|---|---|---|
| `server_name` | `''` | SNI and certificate hostname verification target. Empty ⇒ derived from the dial address. Must match the server's certificate (SAN dNSName / IP, CN fallback per RFC 6125). |
| `alpn` | `[]` (none offered) | Application protocols to offer, in preference order (e.g. `['h2', 'http/1.1']`). The server's pick is verified against this list. |
| `insecure_skip_verify` | `false` | Disables chain **and** hostname validation. Removes all authentication the handshake provides — tests and pinned lab environments only, never shipped enabled. |
| `root_cas` | `none` | When set, used instead of the system trust store (private CAs, enterprise, testing). |
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
`root_cas` slot stays `none`; `dial()` loads the OS bundle). `alpn` and
`timeout` inherit their declared field defaults.

```v
mut conn := tls.dial('example.com:443', tls.default_config('example.com'))!
```

### 2.5 `TrustStore`

```v
@[noinit]
pub struct TrustStore {}
```

A set of trusted root CA certificates, assigned to `Config.root_cas`.
`@[noinit]` stops a bare `TrustStore{}` from existing with an uninitialized
internal slice — instances come from `new_trust_store()`.

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
verification is on.

---

## 3. Usage

Runnable recipes; a full end-to-end demo (`v run src/example/dial_example.v`)
lives in `src/example/dial_example.v`.

### 3.1 Basic client

```v
import tls

mut conn := tls.dial('example.com:443',
	server_name: 'example.com'
	alpn:        ['http/1.1']
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

mut store := tls.new_trust_store()
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

---

## 4. Error handling summary

All fallible operations return `!` (V option/result errors); there are
<span style="color:#2ea44f">**no panics on malformed input**</span> — bad framing, oversized records, duplicate or
unpermitted extensions, truncated certificates, and bad share sizes are
<span style="color:#2ea44f">handshake errors, never memory-safety events</span>.

### 4.1 Connection lifecycle

| Situation | Result |
|---|---|
| DNS / TCP connect failure | <span style="color:#cf222e">`dial()` error</span> |
| Socket timeout (read or write) | `dial()` / `read()` / `write()` error after `Config.timeout` |
| Peer sends a fatal alert during handshake | <span style="color:#cf222e">`dial()` error</span> carrying the alert description |
| Peer `close_notify` while reading | <span style="color:#2ea44f">`read()` returns `0` (clean EOF)</span> |
| Peer fatal alert (encrypted, post-handshake) | <span style="color:#cf222e">`read()` error</span> carrying the alert description |
| `write()` after `close()` or before handshake | error, nothing sent |
| `close()` twice | <span style="color:#2ea44f">no-op, no error, `close_notify` sent at most once</span> |
| Handshake failure inside `dial()` | error; the socket is closed — no fd leak |

### 4.2 Wire & handshake protocol violations

| Situation | Result |
|---|---|
| Handshake message declaring > 1 MiB | <span style="color:#cf222e">`dial()` error</span> (reassembly cap) |
| Plaintext alert or ChangeCipherSpec post-handshake | <span style="color:#cf222e">`read()` error</span> (fatal `unexpected_message`; injection rejected) |
| More than two dummy ChangeCipherSpec records during the handshake | <span style="color:#cf222e">`dial()` error</span> (flood bound `max_compat_ccs_records`, `unexpected_message`) |
| Peer exceeds §5.5 per-key record limit without rekeying | <span style="color:#cf222e">`read()` error</span> |
| `Certificate` list with more than 32 entries | <span style="color:#cf222e">`dial()` error</span> (rejected at parse, before decoding) |
| `NewSessionTicket` with trailing bytes after its extensions | <span style="color:#cf222e">`dial()` error</span> (decode_error) |
| X25519 shared secret of small order (0, 1, or p−1) | <span style="color:#cf222e">`dial()` error</span> (illegal_parameter) |

### 4.3 Certificate & trust-policy rejections

| Situation | Result |
|---|---|
| Certificate chain / hostname / signature verification failure | <span style="color:#cf222e">`dial()` error</span> |
| Leaf/CA `keyUsage` present but forbidding its required use | <span style="color:#cf222e">`dial()` error</span> (digitalSignature / keyCertSign) |
| `basicConstraints` pathLenConstraint exceeded | <span style="color:#cf222e">`dial()` error</span> |
| CA RSA key < 2048 bits in the chain | <span style="color:#cf222e">`dial()` error</span> |
| Unparseable certificate validity time | <span style="color:#cf222e">`dial()` error</span> (decode fails; expiry always enforced) |
| Non-minimal DER length or invalid RSA public exponent (`e` = 0, degenerate 1, or any even value such as 2) | <span style="color:#cf222e">`dial()` error</span> (decode rejected) |
| `TBSCertificate` missing mandatory fields — with or without the optional `version [0]` element | <span style="color:#cf222e">`dial()` error</span> (post-version element-count guard; a truncated v3 certificate fails the decode cleanly instead of indexing past the element array) |
| CertificateVerify scheme paired with the wrong leaf key type, or an ECDSA scheme with the wrong curve | <span style="color:#cf222e">`dial()` error</span> (§4.2.3 curve/scheme binding checked before any key material) |