# tls.handshake

The transport-neutral TLS 1.3 handshake core ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)):
ClientHello/ServerHello, the §7.1 key schedule, the running transcript, the encrypted flight, and
secret lifecycle. It does **not** frame or encrypt transport records or packets — that belongs to
the adapters. Keeping this core importable is what lets both a TCP client (`tls.Conn`) and a QUIC
engine drive the same state machine without importing each other's transport.

This file orients you to the layout. The QUIC adapter that drives this core over the
`pub` seam is documented in the [`tls.quic`](../quic/README.md) module README.

## One core, one type, two guarded surfaces

There is a single `HandshakeCore` holding the shared TLS semantics and both transport surfaces.
It is a private type, but its curated entry points are `pub` directly on it; the two constructors
fix the transport mode once, at construction:

- **`new_tls_handshake(server_name, options)`** — TLS-over-TCP record mode (`is_quic false`). Answers the shared key accessors with record legs (hp empty) and implements the TLS
  KeyUpdate ratchet, returning the generation it ratcheted to.
- **`new_quic_handshake(server_name, options)`** — QUIC mode (`is_quic true`). Answers the same
  accessors with RFC 9001 packet legs — key, iv and hp filled — handed out in the same
  `TrafficKeys`/`KeyMaterial` handle shape; QUIC packet types and CRYPTO
  reassembly live in the QUIC engine, not here.

A caller still picks its transport at construction, but the mode is now a runtime flag: the
key accessor (`traffic_keys()`) is shared — both modes answer it, in their own leg shape.
What remains transport-specific guards itself:
a TLS-record-only call on a QUIC-mode core (`next_application_key_material()`,
`take_buffered_handshake_bytes()`) and a QUIC-only call on a TLS-mode core
(`peer_transport_parameters()`, `is_hello_retry_request_received()`) each return a plain
error without touching state or keys, the same convention as the out-of-phase guards.

```v
mut hs := new_tls_handshake(server_name, opts)!   // or new_quic_handshake(...)
client_hello := hs.create_client_hello()!
messages := hs.receive_initial_bytes(bytes)!   // or hs.receive_handshake_bytes(bytes)!
state := hs.state()
```

`HandshakeOptions` (defined in `state_machine.v`) configures ALPN, the certificate validator, the
initial and preference-ordered supported groups, cipher suites, and signature algorithms. Empty
lists keep the built-in defaults; if no validator is supplied the constructors use the system root
CA bundle.

## Pre-shared keys

PSK support ([RFC 8446 §4.2.11](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.11)) is configured through `HandshakeOptions.psks`
(and `tls.Conn.Config.psks`). A PSK is constructed through the curated API rather than a struct
literal: its fields are module-private, so callers cannot fabricate or mutate them directly.

```v
psk := handshake.new_psk(identity, key)!   // identity: ticket bytes; key: shared material
assert psk.identity() == identity
assert psk.key() == key
```

`new_psk` rejects an empty identity, an identity past the `opaque<0..2^16-1>`
wire limit, or a key outside the 32–1024 byte window (see the `psk_*_len` consts
in `psk.v`), and copies both inputs into the handle so later caller-side mutation
cannot reach the bytes the handshake binds over.

Only `identity` (ticket bytes sent in the ClientHello) and `key` (the shared key material) are
publicly readable. `obfuscated_ticket_age`, `external`, and `hash_algo` default to zero (a fresh
ticket, the resumption "res binder" label, SHA-256); none of them can be set from outside the
module — external PSKs and per-PSK hashes are configured internally by the module. Once
constructed, a `Psk` is immutable to callers.

`PskIdentity`, `PskBinderEntry`, `PskKeyExchangeMode`, and the `build_pre_shared_key_*`
wire-codec helpers live in `psk.v`, are module-private, and callers never construct
them by hand.

### Resumption

RFC 8446 §7.2 resumption is wired end-to-end: at .connected the core derives
a `resumption_master_secret` from the Master Secret over the transcript that
includes the client Finished, and retains it until `zeroize_traffic_secrets()`
at teardown. Callers never see the raw value — `HandshakeCore.resumption_psk(&
NewSessionTicket) !Psk` returns a fully-populated `Psk` handle whose key is
`HKDF-Expand-Label(RMS, "resumption", ticket_nonce)` and whose identity is
the opaque ticket bytes. `tls.Conn.resumption_psks() ![]handshake.Psk` walks
the backlog the same way. The next ClientHello's binder, Early Secret, and
handshake traffic keys then follow the standard §7.1 ladder; when the server
selects a PSK, `is_handshake_message_accepted` shortens the flight to
EncryptedExtensions / Finished with no Certificate or CertificateVerify.

`HandshakeCore.selected_psk_index() ?u16` reports which identity the peer
picked (or `none` when every offer was declined); `tls.Conn.negotiated_psk_index()
?u16` mirrors it. The value is not secret material — the identity bytes travel
in the clear — so it stays readable after `zeroize_traffic_secrets()`.

## File map

```
state_machine.v       the unified core vocabulary + HandshakeCore: states,
                      HandshakeOptions, the struct + constructors, the state cursor,
                      create_client_hello, the receive lifecycle, and the ServerHello/HRR
                      and encrypted-flight phase transitions
state_machine_extra.v the core's intake plumbing + terminal-failure primitives: the
                      reassembly buffer, next_unframed_message, the
                      receive/dispatch routing, and
                      classify_failure / fail_with / failure_alert
key_exchange.v        the core's ECDHE methods: key share, public share,
                      peer-share validation and secret derivation
core_guarded.v        One-sided surfaces of the core (is_quic-guarded): TLS-record side
                      — reassembly_len accessor and the KeyUpdate ratchet that
                      returns the next generation's key material; QUIC side — peer
                      transport params and the HRR flag (the key accessors are shared)
client_hello.v        validate options, build the §4.1.2 ClientHello (PSK identities/binders)
psk.v                 the pre-shared key surface: Psk/PskIdentity/PskBinderEntry, the
                      binder key and computation, and the pre_shared_key /
                      psk_key_exchange_modes wire codecs
server_hello.v        decode ServerHello / HelloRetryRequest + agreement checks, PSK selection
server_flight.v       decode EncryptedExtensions/Certificate/CertificateVerify/Finished
certificate_verify.v  verify the §4.4.3 CertificateVerify (pure, no state change)
key_schedule.v        §7.1 HKDF ladder, HashAlgorithm, phase secret derivations,
                      the shared KeyMaterial/TrafficKeys handles, the public
                      traffic_keys() accessor, and the
                      retained secret holders with their §7.5 lifecycle
transcript.v          running transcript the schedule and CertificateVerify hash over
messages.v            HandshakeType/NamedGroup/SignatureScheme/CipherSuite + header
                      encoding and the shared framing/extension codecs; PSK types
                      and wire codecs live in psk.v
aead.v                cipher-suite → AEAD/hash helpers
alert.v               §6 alert vocabulary; quic_connection_error (§4.8) mapping
post_handshake.v      NewSessionTicket and KeyUpdate parsing
```

Each `*_test.v` sits beside its source.

## Lifecycle and safety invariants

- **Secret zeroization.** Every terminal path funnels through one teardown that pairs
  `fail_and_zeroize_secrets()` with a wipe of the adapter's own key holders, so no path wipes one
  layer and forgets the other. Clearing verbs form four tiers: `release_*` (drop a whole
  handle/slot/buffer not itself scrubbed), `wipe_*` (zero bytes/handles then drop), `zeroize_*`
  (secret material under §7.5 lifecycle rules), `destroy_*` (whole-adapter teardown); `take_*`
  is orthogonal (an ownership move, not a clear).
- **Atomic failure classification.** The private `classify_failure(alert, message)` pins the alert
  `failure_alert()` will surface, zeroizes secrets, and returns the error — a peer-triggered decode
  error always both tears down and reports the RFC-correct alert, never a stale default. `fail_with()`
  is the `err.msg()`-unwrapping shorthand used by parse sites.
- **Named phase material.** Handshake and application traffic secrets are stored as flat
  `[]u8` fields on the core keyed by direction and phase (`c_hsk_tsec`/`s_hsk_tsec`, `c_app_tsec`/`s_app_tsec`); the core's
  TLS-record side derives the record keys on demand, one `KeyMaterial` handle per direction,
  returned as a single `TrafficKeys` generation the caller owns — the same shape a QUIC-mode
  core returns for the same calls, with the header-protection slot filled. Inbound bytes
  share one reassembly buffer across both phases. Per-phase wipe and install helpers take a whole
  phase's two directions (and each key with its nonce base) together, so they cannot be cleared or
  advanced independently — and because the phase is fixed by which accessor produced the
  generation, a wrong-phase install is not expressible at all.
- **One state machine.** `HandshakeState` is the single public enum, mirroring the client
  states of RFC 8446 Appendix A.1 (`start`, `wait_sh`, `wait_ee`, `wait_cert_cr`, `wait_cert`,
  `wait_cv`, `wait_finished`, `connected`, plus an implementation `failed`). It is itself the
  ordering cursor: `is_handshake_message_accepted()` gates the encrypted flight — EncryptedExtensions,
  optional CertificateRequest, Certificate, CertificateVerify, Finished — so handlers only parse and
  transition, and `state()` returns the cursor directly.
- **Key-material readiness** is inferred from `state()`: handshake keys are installable once the
  core leaves `start`/`wait_sh`, and application keys at `connected`. A `.failed` handshake has
  already wiped its schedule, so it never presents stale readiness.
- **Phase-checked input.** `receive_initial_bytes()` accepts input only in
  `wait_sh` and `receive_handshake_bytes()` only while the flight is in progress (`wait_ee` through
  `wait_finished`); out-of-phase calls are rejected without consuming input or discarding usable
  keys. The entry points carry the phase in their names rather than as an argument, and the
  returned `HandshakeMessage` does not store it.
- **Transcript bound.** `transcript.v` caps the running transcript (`max_transcript_len`) so a peer
  cannot grow the buffer indefinitely with legal-size records that never complete the flight.

The core owns handshake ordering, transcript updates, certificate validation (via `tls.pki`), the
key schedule, and the reassembly buffer. It delegates certificate trust decisions entirely to
`tls.pki` and never touches records or packets.

## Testing

```
v test src/tls/handshake/
```

Covers the RFC 8448 §3 key-schedule and transcript vectors, ServerHello/HRR codecs against
hand-built and malformed fixtures, the full HRR state-machine path (group change, cookie echo,
cipher-suite binding, replay rejection), alert classification, and CertificateVerify
scheme-vs-key-type and curve binding. The complete flight is exercised end to end against the
in-repo fake server (`src/tls/fakeserver/`). See the [`tls.quic`](../quic/README.md) README
for how the QUIC engine drives this same core.
