# Handshake adapter contract

The `tls.handshake` module has one private `HandshakeCore` for shared TLS 1.3
semantics and two public facades for its transport adapters:

- `RecordHandshaker` for the TLS record adapter (`tls.Conn`).
- `QuicHandshaker` for the QUIC adapter (`tls.quic.ClientEngine`).

The facades contain the shared core but expose different transport-specific
operations. A caller chooses its transport at construction, and does not need a
runtime mode flag or a wrong-transport call that fails at runtime.
Shared public core methods are promoted through the embedded core instead of
being duplicated as forwarding methods on each facade. Facade methods remain
where they add transport-specific behavior or expose transport-only operations.

The implementation is split by ownership:

- [`state_machine.v`](./state_machine.v) contains the private shared core.
- [`record_handshaker.v`](./record_handshaker.v) defines and implements the
  record facade and its cached TLS keys and KeyUpdate ratchets.
- [`quic_handshaker.v`](./quic_handshaker.v) defines and implements the QUIC
  facade and exposes TLS traffic secrets without deriving record keys.

## Shared behavior

Both facades expose the same handshake operations:

```v
mut hs := new_record_handshake(server_name, alpn, validator)! // or new_quic_handshake(...)
client_hello := hs.create_client_hello()!
messages := hs.receive(level, bytes)!
state := hs.state()
alpn := hs.negotiated_alpn()
suite := hs.negotiated_cipher_suite()
alert := hs.failure_alert()
hs.fail_and_destroy_secrets()
hs.zeroize_app_secrets()
```

`fail_and_destroy_secrets()` marks the handshake failed and destroys derived
secrets; it does not close a socket or QUIC connection. `RecordHandshaker`
overrides the shared operation to also wipe its cached record keys.

`create_client_hello()` returns the initial, complete handshake message.
`receive()` accepts bytes at a TLS encryption level, reassembles complete
messages, and returns outbound `HandshakeMessage` values tagged with their
encryption level. Each handshake core owns its per-level reassembly buffers and
consumes complete TLS messages. An empty result can mean that input is
incomplete or that a message advanced the state without producing output;
adapters use `state()` to observe progress and errors to detect invalid input.

## Record-only operations

`RecordHandshaker` exposes operations needed by TLS over TCP:

- `record_traffic_keys()` returns derived record keys.
- `record_unconsumed_bytes()` lets the record adapter enforce the
  ServerHello record-boundary rule.
- `record_update_read_traffic_keys()` and
  `record_update_write_traffic_keys()` implement TLS KeyUpdate.
- `on_handshake_confirmed()` releases handshake-stage material at the record
  adapter's confirmation point.

## QUIC-only operations

`QuicHandshaker` exposes `quic_traffic_secrets()` instead of record keys. The
method is implemented on the QUIC facade; the shared core contains only
transport-independent TLS handshake logic. `RecordHandshaker` therefore does
not expose QUIC-specific secret access. The QUIC adapter expands these secrets
with the RFC 9001 `quic key`, `quic iv`, and `quic hp` labels. It calls
`on_handshake_confirmed()` only after QUIC confirms the handshake, so handshake
keys remain available for the required period.

QUIC has no record-boundary accessor or TLS KeyUpdate operations. Those methods
are absent from `QuicHandshaker`, rather than present as runtime-rejected calls.

## Ownership boundary

The core owns TLS handshake ordering, transcript updates, certificate
validation, the TLS key schedule, shared traffic secrets, and per-level TLS
message reassembly buffers.
`RecordHandshaker` derives and owns the cached TLS `TrafficKeys`; `QuicHandshaker`
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
