# Handshake adapter contract

The `tls.handshake` module has one public `HandshakeCore` that carries the shared
TLS 1.3 semantics *and* both transport surfaces. The transport mode is chosen at
construction and stored as the `is_quic` flag:

- `new_tls_handshake(...)` — record mode (`is_quic false`) for the TLS record adapter (`tls.Conn`).
- `new_quic_handshake(...)` — QUIC mode (`is_quic true`) for the QUIC adapter (`tls.quic.Conn`).

The mode does not split the type: transport-specific entry points exist on both
modes and guard themselves. A TLS-record-only call on a QUIC-mode core, and a
QUIC-only call on a TLS-mode core, return a plain error without touching state or
key material — the same convention as the out-of-phase API guards — rather than
being absent from the surface. The shared core is still a private type: only the
curated `pub` entry points are reachable from another module; the routing bodies
and the seams below stay module-private.

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
- [`core_guarded.v`](./core_guarded.v) defines and implements the core's one-sided
  methods — each guarded by `is_quic` and refusing the wrong-mode core with a plain
  error. TLS-record side: the backlog accessors and the TLS KeyUpdate ratchet —
  which returns the very generation it just derived, so a secret can never advance
  without its keys coming along. QUIC side: the opaque transport parameters and the
  HelloRetryRequest flag. The per-phase key accessors are not here; they are shared
  and live in `key_schedule.v`.

## Shared behavior

`HandshakeCore` exposes the same handshake operations in both modes:

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
secrets; it does not close a socket or QUIC connection. The record keys are derived
from those secrets on demand, so wiping the secrets retires them. `zeroize_handshake_secrets()`
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
all four: it moves ownership out of a handle rather than clearing it.

Within the core, a classified handshake failure is one atomic concept: the private
`classify_failure(alert, message)` primitive pins the alert `failure_alert()` will
surface, calls `fail_and_zeroize_secrets()` to zeroize the derived secrets and park
the machine in `.failed`, and returns the `IError` to propagate. No call site can
produce one of those steps without the others, so a peer-triggered decode error both
tears down and reports the RFC-correct alert (e.g. `decode_error` for a malformed
message) rather than a stale default. Every handshake-level and ServerHello-path
parse/framing failure routes through it; `append_and_consume_msgs_at()` keeps an
`or { fail_and_zeroize_secrets() }` safety net for any non-classified internal error
(teardown is idempotent, so the belt-and-suspenders call is harmless). The record
keys need no separate wipe because they are derived from the secrets these calls
already clear.
Out-of-phase API guards — and the wrong-transport `is_quic` guards — deliberately
return a plain error *without* `classify_failure`, so a rejected mis-ordered or
wrong-mode call cannot discard usable keys.

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

## Key generation accessors (shared by both modes)

`handshake_traffic_keys()` and `application_traffic_keys()` are transport-neutral:
each derives its phase's key generation on demand from the retained traffic secrets
and returns it as an opaque `TrafficKeys` handle holding one `KeyMaterial` per
direction. The core's mode — not the accessor name — selects the leg shape: record
legs leave the handle's header-protection slot empty (TLS protects record bodies, not
record headers), packet legs fill all three slots (RFC 9001 §5.1). The accessor names
the phase and the field names the direction, so the values never travel as a
positional `(client_key, client_iv, server_key, server_iv)` tuple.
Each call derives a fresh generation the caller owns: `take_client_material()` /
`take_server_material()` move one direction's material out of it, and `wipe()` scrubs
whatever is left, so no copy of the material escapes unscrubbed. The initial phase has
no keys and no accessor either — asking for them is not expressible, rather
than refused at run time.

## Record-only operations

The TLS-record entry points below serve `tls.Conn` and refuse a QUIC-mode core
with a plain error:

- `initial_backlog()` and `handshake_backlog()` report the unconsumed byte count
  parked at each phase — `initial_backlog()` lets the record adapter enforce the
  ServerHello record-boundary rule, `handshake_backlog()` the coalesced-flight
  drain check. They and `take_buffered_handshake_bytes()` are fallible, partly
  for the `is_quic` guard: only the record layer feeds through TLS record
  framing, so the trio has no QUIC caller.
- `take_buffered_handshake_bytes()` moves any handshake-level bytes the core
  still held at `.connected` (a server ticket coalesced after its `Finished`,
  §4.6.1) into the record adapter's post-handshake reassembler and wipes the
  core copy.
- `next_application_key_material(is_server_leg)` implements the TLS KeyUpdate
  ratchet — the read leg (`true`, server keys, after receiving) and the write leg
  (`false`, client keys, before sending) — and is valid only after the handshake reaches
  `.connected`. It ratchets the selected leg's secret and returns that leg's next
  `KeyMaterial` in one call, so the adapter cannot install a generation that does not match
  the stored secret. `application_traffic_keys()` stays the initial-install accessor;
  rekeying never goes through it.
- `zeroize_handshake_secrets()` and `zeroize_application_secrets()` destroy the
  traffic secrets for one phase once the adapter no longer needs them; valid only
  after `.connected`. Because the record keys derive from those secrets, wiping a
  phase's secrets retires its keys too. Handshake cleanup is not a handshake-confirmation
  signal. The initial
  phase has no secrets, so the entry point behind this pair refuses it.

## QUIC-only operations

The QUIC entry points below refuse a TLS-mode core with a plain error:
`peer_transport_parameters()` returns the server's opaque extension bytes (empty
until EncryptedExtensions arrives), and `is_hello_retry_request_received()` reports
whether a retry occurred. Packet protection comes from the shared accessors above:
on a QUIC-mode core they run the RFC 9001 `quic key`, `quic iv`, and `quic hp`
expansions inside the core and hand out filled legs — raw traffic secrets never
leave the core in either mode (the earlier QUIC-only secret export was retired when
the derivation moved in). The QUIC adapter calls `zeroize_handshake_secrets()` only
when it no longer needs the handshake keys, which may be after the handshake is
confirmed. Application teardown calls `zeroize_application_secrets()`, shared by
both modes through the core's phase-named entry points.

QUIC has no record-boundary accessor or TLS KeyUpdate operations. Those methods
exist on the type but are runtime-rejected on a QUIC-mode core by the `is_quic`
guards, which change no state and zeroize nothing.

## Supporting protocol helpers

The module also exposes lower-level helpers used by adapters that implement
post-handshake handling or transport key setup: `next_recordless_message()`,
`parse_new_session_ticket()`, `parse_key_update()`, `quic_connection_error()`,
`hkdf_expand_label()`, `suite_hash_algo()`, `suite_key_len()`, and
`new_aead_for_suite()`. These are protocol building blocks, not alternatives
to the core's phase-checked handshake entry points.

## Ownership boundary

The core owns TLS handshake ordering, transcript updates, certificate
validation, the TLS key schedule, shared traffic secrets, and per-phase TLS
message reassembly buffers. `HandshakeCore` in record mode derives TLS record keys on
demand from its retained traffic secrets; in QUIC mode it only exposes traffic secrets for QUIC key
derivation. The record adapter owns
TLS records and record protection — in this stack the `RecordLayer` facade
(`tls/record_layer.v`) holds the four protection states and the KeyUpdate policy built
on them. The QUIC adapter owns CRYPTO offset
reassembly, packets, packet protection, and QUIC key updates. The core does not
frame or encrypt transport records or packets.

## Future API work

The phase-named receive methods still return only outbound messages. Handshake-key
readiness is no longer inferred from `state()` — both adapters now use the
centralized `available_secret_phases()` query — but a full structured progress
*return value* (naming milestones such as ServerHello-done or connected as part of
each receive) remains future work, to be added only if both adapters can migrate
without changing message ordering, alert classification, or secret lifetimes.
