# Handshake adapter contract

The `tls.handshake` module has one private `HandshakeCore` for shared TLS 1.3
semantics and two public facades for its transport adapters:

- `TLSHandshake` for the TLS record adapter (`tls.Conn`).
- `QuicHandshake` for the QUIC adapter (`tls.quic.Conn`).

The facades contain the shared core but expose different transport-specific
operations. A caller chooses its transport at construction, and does not need a
runtime mode flag or a wrong-transport call that fails at runtime.
Shared public core methods are promoted through the embedded core instead of
being duplicated as forwarding methods on each facade. Facade methods remain
where they add transport-specific behavior or expose transport-only operations.

The implementation is split by ownership:

- [`state_machine.v`](./state_machine.v) contains the private shared core.
- [`tls_handshake.v`](./tls_handshake.v) defines and implements the
  record facade and its cached TLS keys and KeyUpdate ratchets.
- [`quic_handshake.v`](./quic_handshake.v) defines and implements the QUIC
  facade and exposes TLS traffic secrets without deriving record keys.

## Shared behavior

Both facades expose the same handshake operations:

```v
mut hs := new_tls_handshake(server_name)! // or new_quic_handshake(...)
client_hello := hs.create_client_hello()!
messages := hs.receive(level, bytes)!
state := hs.state()
alpn := hs.negotiated_alpn()
suite := hs.negotiated_cipher_suite()
alert := hs.failure_alert()
hs.fail_and_destroy_secrets()
hs.zeroize_app_secrets()
```

`fail_and_destroy_secrets()` marks the handshake failed and destroys its derived
secrets; it does not close a socket or QUIC connection. `TLSHandshake` also
wipes its cached record keys during failure cleanup.

`create_client_hello()` returns the initial, complete handshake message.
The constructors require only `server_name`. Optional named
`HandshakeOptions` fields can be passed to `new_tls_handshake()` or
`new_quic_handshake()` to configure ALPN, certificate validation,
the initial key-share group, preference-ordered supported groups, TLS 1.3
cipher suites, and signature algorithms. If no validator is supplied, the
constructors use the system root CA bundle; callers can supply a custom
validator for private trust roots or test setups. Empty preference lists
preserve the built-in defaults. An initial key-share group must also appear in
`supported_groups`; a HelloRetryRequest may select another configured supported
group. Explicit `legacy_session_id` and `random` values are intended only for
deterministic test vectors.
`receive()` accepts bytes at an `EncryptionLevel` (`initial` or `handshake`),
reassembles complete messages, and returns outbound `HandshakeMessage` values
tagged with that TLS phase. QUIC packet levels are translated by its engine;
they are not part of the shared handshake API. The same `EncryptionLevel`
(`handshake` or `application`) selects TLS-derived secrets; `initial` has none.
Here `initial` denotes the initial TLS handshake phase, not QUIC Initial packet
protection.
Each handshake core owns its phase-specific reassembly buffers and
consumes complete TLS messages. An empty result can mean that input is
incomplete or that a message advanced the state without producing output;
adapters use `state()` to observe progress and errors to detect invalid input.

## Record-only operations

`TLSHandshake` exposes operations needed by TLS over TCP:

- `record_traffic_keys()` returns derived record keys.
- `record_unconsumed_bytes()` lets the record adapter enforce the
  ServerHello record-boundary rule.
- `record_update_read_traffic_keys()` and
  `record_update_write_traffic_keys()` implement TLS KeyUpdate.
- `zeroize_handshake_traffic_secrets()` destroys handshake traffic secrets once
  the adapter no longer needs them; the record facade also wipes its cached
  handshake keys. This is cleanup, not a handshake-confirmation signal.

## QUIC-only operations

`QuicHandshake` exposes `quic_traffic_secrets()` instead of record keys. It
delegates to the core's private level-aware traffic-secret accessor, so both
facades share one availability check while only the QUIC facade exports raw
secrets; `TLSHandshake` cannot expose that accessor. The QUIC adapter expands
these secrets with the RFC 9001 `quic key`, `quic iv`, and `quic hp` labels. It
calls `zeroize_handshake_traffic_secrets()` only when QUIC no longer needs the
handshake keys, which may be after the handshake is confirmed.

QUIC has no record-boundary accessor or TLS KeyUpdate operations. Those methods
are absent from `QuicHandshake`, rather than present as runtime-rejected calls.

## Ownership boundary

The core owns TLS handshake ordering, transcript updates, certificate
validation, the TLS key schedule, shared traffic secrets, and per-level TLS
message reassembly buffers.
`TLSHandshake` derives and owns the cached TLS `TrafficKeys`; `QuicHandshake`
only exposes traffic secrets for QUIC key derivation. The record adapter owns
TLS records and record protection. The QUIC adapter owns CRYPTO offset
reassembly, packets, packet protection, and QUIC key updates. The core does not
frame or encrypt transport records or packets.

## Future API work

`receive()` still returns only outbound messages. Adapters continue to observe
`state()` to determine milestones such as handshake-key readiness. A structured
progress result could make those milestones explicit later, once both adapters
can migrate without changing message ordering, alert classification, or secret
lifetimes.
