# tls.handshake

The transport-neutral TLS 1.3 handshake core ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)):
ClientHello/ServerHello, the §7.1 key schedule, the running transcript, the encrypted flight, and
secret lifecycle. It does **not** frame or encrypt transport records or packets — that belongs to
the adapters. Keeping this core importable is what lets both a TCP client (`tls.Conn`) and a QUIC
engine drive the same state machine without importing each other's transport.

This file orients you to the layout. The transport-facing contract is documented in depth in
[`CONTRACT.md`](./CONTRACT.md), and the eight-step QUIC engine loop over the seam is walked
through in [`QUIC.md`](./QUIC.md).

## One core, two facades

There is a single private `HandshakeCore` holding the shared TLS semantics, promoted through two
public transport facades:

- **`TLSHandshake`** (`new_tls_handshake(server_name, options)`) — the record adapter for
  TLS-over-TCP. Also derives and owns the cached TLS `TrafficKeys` and implements the TLS KeyUpdate
  derivation.
- **`QuicHandshake`** (`new_quic_handshake(server_name, options)`) — the QUIC adapter. Exposes raw
  traffic secrets for RFC 9001 key expansion instead of record keys; QUIC packet levels and CRYPTO
  reassembly live in the QUIC engine, not here.

A caller picks its transport at construction; there is no runtime mode flag and no wrong-transport
call that only fails at runtime. QUIC-only methods (record boundary, TLS KeyUpdate) are simply
absent from `QuicHandshake`.

```v
mut hs := new_tls_handshake(server_name, opts)!   // or new_quic_handshake(...)
client_hello := hs.create_client_hello()!
messages := hs.receive_msgs_at_level(.initial, bytes)!
state := hs.state()
```

`HandshakeOptions` (defined in `state_machine.v`) configures ALPN, the certificate validator, the
initial and preference-ordered supported groups, cipher suites, and signature algorithms. Empty
lists keep the built-in defaults; if no validator is supplied the constructors use the system root
CA bundle.

## File map

```
state_machine.v       private HandshakeCore: states, EncryptionLevel,
                      HandshakeOptions, create_client_hello, receive_msgs_at_level
tls_handshake.v       TLS record facade: cached TrafficKeys, KeyUpdate
quic_handshake.v      QUIC facade: exposes traffic secrets, peer transport params
secret_lifecycle.v    fail_and_zeroize_secrets / zeroize_traffic_secrets (§7.5)
client_hello.v        validate options, build the §4.1.2 ClientHello
server_hello.v        decode ServerHello / HelloRetryRequest + agreement checks
server_hello_flow.v   ServerHello/HRR transition, transcript rewrite, retried CH
encrypted_flight.v    process the encrypted flight, emit the client Finished
server_flight.v       decode EncryptedExtensions/Certificate/CertificateVerify/Finished
certificate_verify.v  verify the §4.4.3 CertificateVerify (pure, no state change)
key_exchange.v        ephemeral ECDHE shared secret (X25519, P-256)
key_schedule.v        §7.1 HKDF-Expand-Label, HashAlgorithm
handshake_keys.v      adapt §7.1 derivations to the flow
transcript.v          running transcript the schedule and CertificateVerify hash over
messages.v            HandshakeType/NamedGroup/SignatureScheme/CipherSuite + header
aead.v                cipher-suite → AEAD/hash helpers
alert.v               §6 alert vocabulary; quic_connection_error (§4.8) mapping
post_handshake.v      NewSessionTicket and KeyUpdate parsing
passthrough.v         recordless message-framing helper
```

Each `*_test.v` sits beside its source.

## Lifecycle and safety invariants

- **Secret zeroization.** Every terminal path funnels through one teardown that pairs
  `fail_and_zeroize_secrets()` with a wipe of the adapter's own key holders, so no path clears one
  layer and forgets the other. Clearing verbs are tiered: `wipe_*` (zero bytes/handles), `zeroize_*`
  (secret material under §7.5 lifecycle rules), `destroy_*` (whole-adapter teardown).
- **Atomic failure classification.** The private `classify_failure(alert, message)` pins the alert
  `failure_alert()` will surface, zeroizes secrets, and returns the error — a peer-triggered decode
  error always both tears down and reports the RFC-correct alert, never a stale default.
- **Key-material readiness** is queried via `available_secret_phases()` rather than inferred from
  `state()`, so a `.failed` handshake (schedule wiped) never presents stale readiness.
- **Phase-checked input.** `receive_msgs_at_level()` accepts initial-level input only while awaiting
  ServerHello and handshake-level input only after it and before Finished; out-of-phase calls are
  rejected without consuming input or discarding usable keys.
- **Transcript bound.** `transcript.v` caps the running transcript (`max_transcript_len`) so a peer
  cannot grow the buffer indefinitely with legal-size records that never complete the flight.

The core owns handshake ordering, transcript updates, certificate validation (via `tls.pki`), the
key schedule, and per-level reassembly buffers. It delegates certificate trust decisions entirely to
`tls.pki` and never touches records or packets.

## Testing

```
v test src/tls/handshake/
```

Covers the RFC 8448 §3 key-schedule and transcript vectors, ServerHello/HRR codecs against
hand-built and malformed fixtures, the full HRR state-machine path (group change, cookie echo,
cipher-suite binding, replay rejection), alert classification, and CertificateVerify
scheme-vs-key-type and curve binding. The complete flight is exercised end to end against the
in-repo fake server (`src/tls/fakeserver/`). See [`QUIC.md`](./QUIC.md) for how a QUIC engine
drives this same core.
