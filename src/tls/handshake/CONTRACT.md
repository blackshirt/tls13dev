# Making the handshake adapter contract easier to use (proposal)

**Status: naming pass and transport-mode guard done; the event stream is still a
proposal.**

The rename in the table below and the `TransportMode` guard (see below) are in
the code. The larger changes (an event stream, or the four smaller additions)
are not implemented yet.

The `tls.handshake` core is driven through a small public API. It works, but it
is not obvious to use: you have to already know *when* to call things and *why*
the calls return what they do. This document explains the problem in plain
terms and proposes a clearer contract.

---

## The problem

Here is what an adapter has to do today, using the real TCP loop as an example:

```v
ch := hs.create_client_hello()!        // returns raw bytes
send(ch)

for hs.state() != .connected {          // check state to know when we're done
    rec := read_record()
    msgs := hs.receive(.initial, rec)!
    if hs.record_unconsumed_bytes(.initial) != 0 { fail() }   // check: bad framing?
    if msgs.len == 0 && hs.state() == .wait_server_hello { fail() }
    if hs.state() == .wait_encrypted_extensions { install_keys() }  // check: install now?
    for m in msgs { send(m.msg) }
}
hs.on_handshake_confirmed()!                 // must be called at the right time
```

Nothing here is wrong, but it is hard to learn from the signatures alone. The
main annoyances:

1. **`receive()` returns a list, but not the reason.** When it returns nothing you
   must check `state()` and `record_unconsumed_bytes()` to find out why.
2. **Two output shapes.** The first message is plain `[]u8`; later ones are a
   tagged struct. You special-case the first.
3. **Two key accessors that look the same.** `record_traffic_keys()` and
   `quic_traffic_secrets()` both take a level and both return a client/server
   pair. *(partly fixed: the transport mode now rejects the wrong one.)*
4. **Timing you must remember.** `on_handshake_confirmed()` is right for TCP but
   wrong for QUIC; `record_traffic_keys` works after ServerHello but not after
   `on_handshake_confirmed`. The types don't say any of this.
5. **Failure is in three places.** The error, `state() == .failed`, and
   `failure_alert()`.
6. **`record_unconsumed_bytes()` is a TCP-only concern** (the ServerHello record
   boundary) sitting in the shared API. *(partly fixed: it is now a no-op off
   the record path.)*

---

## The idea

Let `receive()` tell the adapter what to do, instead of making the adapter ask.

```v
pub enum HandshakeEvent {
    send     HandshakeMessage // put msg.msg on the wire at msg.level
    keys     KeyStage         // install protection for this stage
    complete                  // handshake done; application secrets are ready
}
```

The loop then reads like a recipe, with no state poking:

```v
for ev in hs.begin() {
    if ev is .send { send(ev.msg) }
}

for {
    rec := read_record()
    for ev in hs.receive(.initial, rec) {
        match ev {
            .send { send(ev.msg) }
            .keys { stage } { install(stage) }  // fires once per stage
            .complete { done() }
        }
    }
}
```

This fixes points 1, 2, and 4 in one move: one output shape, and the events
carry the "why".

---

## Smaller changes (if the rewrite is too big)

If changing `receive()`'s return type is too much for a tested core, these four
additions remove most of the pain without touching existing calls:

1. **`pending_key_stage() ?KeyStage`** — read why `receive()` advanced, instead of
   comparing `state()` to enum values.
2. **`create_client_hello_message() !HandshakeMessage`** — same shape as
   everything else; keep the old `[]u8` version as a thin wrapper.
3. **Transport-named key accessors** — renaming `traffic_keys` →
   `record_traffic_keys` and `exported_secrets` → `quic_traffic_secrets` puts
   the intended consumer in the name. *(done)*
4. **`failure() ?HandshakeFailure`** — one accessor giving the alert and the
   message, instead of three checks.

---

## Naming

**Applied.** These renames are in the code now:

| Was | Now | Why |
|---|---|---|
| `feed` | `receive` | says the direction |
| `traffic_keys` | `record_traffic_keys` | names the consumer |
| `exported_secrets` | `quic_traffic_secrets` | names the consumer |
| `confirm_handshake` | `on_handshake_confirmed` | it's a notification, not an action |
| `buffered_bytes` | `record_unconsumed_bytes` | "unconsumed input" is clearer |
| `update_read_traffic_keys` | `record_update_read_traffic_keys` | names the record path |
| `update_write_traffic_keys` | `record_update_write_traffic_keys` | names the record path |
| `RecordCipherState` | `RecordProtector` | it protects records, it is not the layer |
| `cipher_from_keys` | `record_protector_from_keys` | says what it builds |

---

## Transport mode guard

**Applied.** The mode-specific half of the API is now gated instead of being
documented-only. `TransportMode { record, quic }` is fixed at construction and
enforced at every mode-specific call:

```v
new_record_handshake(server_name, alpn, validator) !ClientHandshake  // .record
new_quic_handshake(server_name, alpn, validator) !ClientHandshake    // .quic
(h) mode() TransportMode
```

- `.record` allows `record_traffic_keys()`, `record_unconsumed_bytes()`,
  `record_update_read_traffic_keys()`, `record_update_write_traffic_keys()` and
  refuses `quic_traffic_secrets()`.
- `.quic` allows `quic_traffic_secrets()` and refuses every `record_*` accessor;
  `record_unconsumed_bytes()` is a no-op returning `0`.

This turns points 3 and 6 from "remember which one to call" into a rejected call,
without the larger event-stream rewrite. `conn.v` builds with
`new_record_handshake`; `quic.ClientEngine` with `new_quic_handshake`.

---

## What stays the same

Everything security-related: message ordering, transcript binding, size caps,
alert classification, and the secret-zeroization lifecycle. This is only about
how the same machine is presented to the adapter.

---

## Recommendation

- Do the **naming pass** now — cheap and clear.
- Do the **four smaller additions** next, and update `conn.v` and the tests.
- Treat the **event stream** as the eventual goal once one adapter has used it.

## Questions

1. Event stream, or are the four smaller additions enough?
2. Should `create_client_hello` keep returning raw bytes for anyone who wants
   them?
3. Rename now, or wait and rename everything together with the event stream?
