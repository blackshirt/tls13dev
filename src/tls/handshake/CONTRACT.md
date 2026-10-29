# Handshake adapter contract

The `tls.handshake` module has one private `HandshakeCore` for shared TLS 1.3
semantics and two public facades for its transport adapters:

- `TLSHandshake` for the TLS record adapter (`tls.Conn`).
- `QuicHandshake` for the QUIC adapter (`tls.quic.Conn`).

The facades contain the shared core but expose different transport-specific
operations. A caller chooses its transport at construction, and does not need a
runtime mode flag or a wrong-transport call that fails at runtime.
The shared core is a private type with module-private methods, so nothing leaks
through embedded promotion; each facade re-exports only what its adapter calls,
as curated `pub` forwarders over the core. A facade still defines a method
itself where it adds transport-specific behavior or exposes a transport-only
operation.

The implementation is split by ownership:

- [`state_machine.v`](./state_machine.v) contains the private shared core: its types,
  the `HandshakeCore` struct and constructor, the state cursor, and the
  ServerHello/HelloRetryRequest and encrypted-flight phase transitions, with inbound
  byte reassembly, the receive/dispatch routing and the terminal-failure primitives in
  [`state_machine_extra.v`](./state_machine_extra.v).
- [`key_schedule.v`](./key_schedule.v) runs the §7.1 HKDF ladder and holds the
  core's flat derived-secret fields (`c_hsk_tsec`/`s_hsk_tsec`/`c_app_tsec`/`s_app_tsec`) and the
  `SecretPhases` readiness type, with the §7.5 wiping and zeroization lifecycle methods.
- [`key_exchange.v`](./key_exchange.v) implements the core's ephemeral ECDHE
  methods: per-group key generation, the public share, and the peer-share
  validation and secret derivation.
- [`tls_handshake.v`](./tls_handshake.v) defines and implements the
  record facade and its cached TLS keys and the TLS KeyUpdate derivation.
- [`quic_handshake.v`](./quic_handshake.v) defines and implements the QUIC
  facade and exposes TLS traffic secrets without deriving record keys.

## Shared behavior

Both facades expose the same handshake operations:

```v
mut hs := new_tls_handshake(server_name)! // or new_quic_handshake(...)
client_hello := hs.create_client_hello()!
messages := hs.receive_initial_bytes(bytes)!   // pre-ServerHello phase
messages := hs.receive_handshake_bytes(bytes)! // handshake-key phase
state := hs.state()
alpn := hs.negotiated_alpn()
suite := hs.negotiated_cipher_suite()
alert := hs.failure_alert()
hs.fail_and_zeroize_secrets()
hs.zeroize_application_secrets()!
```

`state()` reports the client's position in a single `HandshakeState` enum that
mirrors the client state machine of RFC 8446 Appendix A.1 (`start`, `wait_sh`,
`wait_ee`, `wait_cert_cr`, `wait_cert`, `wait_cv`, `wait_finished`, `connected`,
plus an implementation `failed`). Encrypted-flight ordering is enforced by that
same public state; key-material readiness is still polled via
`available_secret_phases()` rather than inferred from `state()`, so a `.failed`
handshake never presents stale readiness.

`fail_and_zeroize_secrets()` marks the handshake failed and zeroizes its derived
secrets; it does not close a socket or QUIC connection. `TLSHandshake` also
wipes its cached record keys during failure cleanup. `zeroize_handshake_secrets()`
and `zeroize_application_secrets()` are fallible teardown operations, accepted only
after `.connected`, so an out-of-phase call cannot discard traffic material needed
to finish a handshake.
Adapters call these lifecycle operations when aborting or tearing down; callers
driving a handshake normally need only construct, send the ClientHello, feed
peer messages, and observe the resulting state.
Each adapter funnels every terminal path through one internal teardown that pairs a
core call above with a wipe of its *own* key holders, so no code path can wipe one
layer and forget the other: `tls.Conn` wipes its four `TLSProtection`s, and the QUIC
engine zeroes each `ProtectionState` (AEAD key, IV, header-protection key) before
releasing it. Both use the same module-private, idempotent `holder.wipe()` mechanism;
users never call it — the only public terminal action is the adapter's `close()` or
failure handling. Clearing verbs form four tiers: `release_*` drops a whole handle,
slot, or buffer that is not individually scrubbed (`release_ephemeral_keys`,
`ReassemblyBuffers.release_buffers`); `wipe_*` / `.wipe()` zeroes bytes then drops
them (secret material and decrypted plaintext, e.g. `Conn.wipe_app_buf`);
`zeroize_*` clears secret material under lifecycle guard rules (RFC 8446 §7.5);
and `destroy_*` tears down a whole adapter connection. `take_*` is orthogonal to
all four: it moves ownership out of a handle rather than clearing it. Some facade
forwarders are deliberately kept as pure pass-throughs because V will not expose a
module-private `HandshakeCore` method to another module except through a `pub`
wrapper (e.g. `QuicHandshake.fail_and_zeroize_secrets`).

Within the core, a classified handshake failure is one atomic concept: the private
`classify_failure(alert, message)` primitive pins the alert `failure_alert()` will
surface, calls `fail_and_zeroize_secrets()` to zeroize the derived secrets and park
the machine in `.failed`, and returns the `IError` to propagate. No call site can
produce one of those steps without the others, so a peer-triggered decode error both
tears down and reports the RFC-correct alert (e.g. `decode_error` for a malformed
message) rather than a stale default. Every handshake-level and ServerHello-path
parse/framing failure routes through it; `append_and_drain_at()` keeps an
`or { fail_and_zeroize_secrets() }` safety net for any non-classified internal error
(teardown is idempotent, so the belt-and-suspenders call is harmless). On the record
facade this still triggers the cached-record-key wipe: `TLSHandshake`'s phase-named
receive methods detect the `.failed` state and drop their cached record keys.
Out-of-phase API guards in the core's receive entry point deliberately return a
plain error *without* `classify_failure`, so a rejected mis-ordered call cannot
discard usable keys.

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
The two receive entry points name the phase instead of taking a phase argument:
`receive_initial_bytes()` takes the pre-ServerHello bytes and
`receive_handshake_bytes()` the bytes protected by handshake keys. Each reassembles
complete messages and returns outbound `HandshakeMessage` values tagged internally
with that TLS phase. The phase itself is a module-private `EncryptionLevel` — no
public signature names it, and QUIC packet types are mapped to these entry points
by the QUIC engine. `HandshakeMessage.is_initial()` is the only phase fact adapters
may read, and only to choose a transmit queue. The same phase names select
TLS-derived secrets for key export; the initial phase has none. Here `initial`
denotes the initial TLS handshake phase, not QUIC Initial packet protection.
Initial-phase input is accepted only while awaiting ServerHello; handshake-phase
input is accepted only after ServerHello and before Finished. Out-of-phase API
calls are rejected without consuming input or changing handshake state.
Each handshake core owns its phase-specific reassembly buffers and
consumes complete TLS messages. An empty result can mean that input is
incomplete or that a message advanced the state without producing output;
adapters use `state()` to observe progress and errors to detect invalid input.
Key-material readiness, however, is queried through `available_secret_phases()`
rather than inferred from `state()`: it reports which traffic-secret phases the
core currently holds (`handshake`, `application`), returning false for a phase
whose secrets are absent or already zeroized. Both the record and QUIC adapters
call it to decide when to install transport keys, so that decision lives in one
place and a `.failed` handshake (whose schedule is wiped) never presents stale
readiness.

## Record-only operations

`TLSHandshake` exposes operations needed by TLS over TCP:

- `handshake_record_keys()` and `application_record_keys()` return the derived record
  keys for their phase as opaque handles — `HandshakeRecordKeys` and
  `ApplicationRecordKeys`, each holding one `RecordKeys` handle per direction. The type
  names the phase and the field names the direction, so the values no longer
  travel as a positional `(client_key, client_iv, server_key, server_iv)` tuple.
  A returned generation is an independent copy the caller owns: `take_client()` /
  `take_server()` move one direction's key-and-IV pair out of it, and `wipe()` scrubs
  whatever is left, so no copy of the material escapes unscrubbed. The initial phase has
  no record keys and no accessor either — asking for them is not expressible, rather
  than refused at run time.
- `initial_backlog()` and `handshake_backlog()` report the unconsumed bytes parked
  at each phase — `initial_backlog()` lets the record adapter enforce the
  ServerHello record-boundary rule, `handshake_backlog()` the coalesced-flight
  drain check. They and `take_buffered_handshake_bytes()`
  are defined on the facade itself, called directly by `tls.Conn` (only the
  record layer feeds through TLS record framing, so the pair has no QUIC
  caller).
- `take_buffered_handshake_bytes()` moves any handshake-level bytes the core
  still held at `.connected` (a server ticket coalesced after its `Finished`,
  §4.6.1) into the record adapter's post-handshake reassembler and wipes the
  core copy.
- `update_traffic_keys(is_server)` implements TLS KeyUpdate — the read leg
  (`true`, server keys, after receiving) and the write leg (`false`, client
  keys, before sending) — and is valid only after the handshake reaches
  `.connected`.
- `zeroize_handshake_secrets()` and `zeroize_application_secrets()` destroy the
  traffic secrets for one phase once the adapter no longer needs them; valid only
  after `.connected`, and the record facade also wipes that phase's cached record
  keys. Handshake cleanup is not a handshake-confirmation signal. The initial
  phase has no secrets, so the core entry point behind this pair refuses it.

## QUIC-only operations

`QuicHandshake` defines `peer_handshake_secrets()` and `peer_application_secrets()`
on the facade itself and exposes raw traffic secrets instead of record keys:
raw-secret export has no TLS caller — the record adapter keeps its cached-key surface
(`handshake_record_keys()` / `application_record_keys()`) and never reads the secrets.
The QUIC adapter expands these secrets with the RFC 9001 `quic key`, `quic iv`, and
`quic hp` labels. It calls `zeroize_handshake_secrets()` only when QUIC no longer
needs the handshake keys, which may be after the handshake is confirmed.
`peer_transport_parameters()` returns the server's opaque extension bytes once
received, and `hello_retry_request_received()` reports whether a retry occurred.
Application teardown calls `zeroize_application_secrets()`, a `pub` forwarder on the
`QuicHandshake` facade over the shared core — each phase is reached through the
facade's curated forwarders, never embedded promotion.

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
validation, the TLS key schedule, shared traffic secrets, and per-phase TLS
message reassembly buffers.
`TLSHandshake` derives and owns the cached TLS record keys; `QuicHandshake`
only exposes traffic secrets for QUIC key derivation. The record adapter owns
TLS records and record protection. The QUIC adapter owns CRYPTO offset
reassembly, packets, packet protection, and QUIC key updates. The core does not
frame or encrypt transport records or packets.

## Future API work

The phase-named receive methods still return only outbound messages. Handshake-key
readiness is no longer inferred from `state()` — both adapters now use the
centralized `available_secret_phases()` query — but a full structured progress
*return value* (naming milestones such as ServerHello-done or connected as part of
each receive) remains future work, to be added only if both adapters can migrate
without changing message ordering, alert classification, or secret lifetimes.
