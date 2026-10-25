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
  record facade and its cached TLS keys and the TLS KeyUpdate derivation.
- [`quic_handshake.v`](./quic_handshake.v) defines and implements the QUIC
  facade and exposes TLS traffic secrets without deriving record keys.

## Shared behavior

Both facades expose the same handshake operations:

```v
mut hs := new_tls_handshake(server_name)! // or new_quic_handshake(...)
client_hello := hs.create_client_hello()!
messages := hs.receive_msgs_at_level(level, bytes)!
state := hs.state()
alpn := hs.negotiated_alpn()
suite := hs.negotiated_cipher_suite()
alert := hs.failure_alert()
hs.fail_and_zeroize_secrets()
hs.zeroize_traffic_secrets(.application)!
```

`fail_and_zeroize_secrets()` marks the handshake failed and zeroizes its derived
secrets; it does not close a socket or QUIC connection. `TLSHandshake` also
wipes its cached record keys during failure cleanup. `zeroize_traffic_secrets(level)`
is a fallible teardown operation and is accepted only after `.connected`, so
an out-of-phase call cannot discard traffic material needed to finish a handshake.
Adapters call these lifecycle operations when aborting or tearing down; callers
driving a handshake normally need only construct, send the ClientHello, feed
peer messages, and observe the resulting state.
Each adapter funnels every terminal path through one internal teardown that pairs a
core call above with a wipe of its *own* key holders, so no code path can clear one
layer and forget the other: `tls.Conn` wipes its four `TLSProtection`s, and the QUIC
engine zeroes each `ProtectionState` (AEAD key, IV, header-protection key) before
releasing it. Both use the same module-private, idempotent `holder.wipe()` mechanism;
users never call it — the only public terminal action is the adapter's `close()` or
failure handling. Clearing verbs are tiered: `wipe_*` zeroes bytes or handles (the
mechanism), `zeroize_*` clears secret material under lifecycle guard rules (RFC 8446
§7.5), and `destroy_*` tears down a whole adapter connection.

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
`receive_msgs_at_level()` accepts bytes at an `EncryptionLevel` (`initial` or `handshake`),
reassembles complete messages, and returns outbound `HandshakeMessage` values
tagged with that TLS phase. QUIC packet levels are translated by its engine;
they are not part of the shared handshake API. The same `EncryptionLevel`
(`handshake` or `application`) selects TLS-derived secrets; `initial` has none.
Here `initial` denotes the initial TLS handshake phase, not QUIC Initial packet
protection.
Initial-level input is accepted only while awaiting ServerHello; handshake-level
input is accepted only after ServerHello and before Finished. Out-of-phase API
calls are rejected without consuming input or changing handshake state.
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
  `record_update_write_traffic_keys()` implement TLS KeyUpdate and are valid
  only after the handshake reaches `.connected`.
- `zeroize_traffic_secrets(level)` destroys the traffic secrets for one
  encryption level once the adapter no longer needs them; valid only after
  `.connected`, and the record facade also wipes that level's cached record
  keys. `.handshake` is cleanup, not a handshake-confirmation signal; the
  `.initial` level has no secrets and is refused.

## QUIC-only operations

`QuicHandshake` exposes `quic_traffic_secrets()` instead of record keys. It
delegates to the core's private level-aware traffic-secret accessor, so both
facades share one availability check while only the QUIC facade exports raw
secrets; `TLSHandshake` cannot expose that accessor. The QUIC adapter expands
these secrets with the RFC 9001 `quic key`, `quic iv`, and `quic hp` labels. It
calls `zeroize_traffic_secrets(.handshake)` only when QUIC no longer needs the
handshake keys, which may be after the handshake is confirmed.
`peer_transport_parameters()` returns the server's opaque extension bytes once
received, and `hello_retry_request_received()` reports whether a retry occurred.
Application teardown calls the same inherited `zeroize_traffic_secrets(.application)`;
both levels come from the shared core rather than a QUIC-facade declaration.

QUIC has no record-boundary accessor or TLS KeyUpdate operations. Those methods
are absent from `QuicHandshake`, rather than present as runtime-rejected calls.

## Supporting protocol helpers

The module also exposes lower-level helpers used by adapters that implement
post-handshake handling or transport key setup: `next_recordless_message()`,
`parse_new_session_ticket()`, `parse_key_update()`, `quic_connection_error()`,
`hkdf_expand_label()`, `suite_hash_algo()`, `suite_key_len()`, and
`new_aead_for_suite()`. These are protocol building blocks, not alternatives
to the facade's phase-checked handshake entry points.

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

`receive_msgs_at_level()` still returns only outbound messages. Adapters continue to observe
`state()` to determine milestones such as handshake-key readiness. A structured
progress result could make those milestones explicit later, once both adapters
can migrate without changing message ordering, alert classification, or secret
lifetimes.
