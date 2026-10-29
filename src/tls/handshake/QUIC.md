# Driving the handshake core over QUIC

This document explains **how the TLS 1.3 handshake in this repository is
structured**, **how support for QUIC (RFC 9001) was adapted into it**, and
**how to write a QUIC adapter** that drives the core — without importing the
`tls` record layer, without touching a socket, and without reimplementing the
TLS state machine.

The module it describes is `tls.handshake` (`src/tls/handshake/`). Everything
`pub` in that module is the adapter contract; everything else is private. This
file is the long-form guide to the QUIC facade in `quic_handshake.v` and shared
handshake engine in `state_machine.v`.

---

## 1. What "transport-neutral" means here

TLS 1.3 is defined as a sequence of **handshake messages** bound to a running
transcript, plus a **key schedule** that turns a shared secret into traffic
secrets. Everything else — records, AEAD framing, sequence numbers, sockets —
is how those messages and secrets are *carried*. RFC 9001 (TLS over QUIC)
changes the carrier completely: handshake messages ride QUIC **CRYPTO frames**
on three packet levels, and packet protection is a QUIC concern, not a TLS
record concern.

The core was therefore split so that the carrier is always someone else's job:

```
   ┌──────────────────────────── tls.handshake (this module) ───────────────────────────┐
   │  Shared core: state_machine.v + state_machine_extra.v + key_exchange.v         │
   │  Key schedule: key_schedule.v (holders + §7.5 lifecycle)                       │
   │  Codecs: messages.v / client_hello.v / server_hello.v / server_flight.v        │
   │          post_handshake.v / transcript.v                                       │
   │  Record facade: tls_handshake.v owns TLS record keys and the KeyUpdate path    │
   │  QUIC facade: quic_handshake.v exports TLS traffic secrets                     │
   │  aead.v / certificate_verify.v / alert.v / passthrough.v                       │
   └────────────────────────────────────────────────────────────────────────────────────┘
        ▲                                     ▲                                     ▲
        │ receive_initial_bytes                │ handshake keys / secrets             │ create_client_hello /
        │ receive_handshake_bytes              │ application key/secrets              │ phase-named receives
        │                                      │                                      │
   ┌────┴──────────────┐              ┌───────┴───────────┐               ┌─────────┴──────────┐
   │ tls TCP adapter   │              │ a QUIC engine     │               │ tests / other      │
   │ conn.v            │              │ (RFC 9001)        │               │ transports         │
   │ records + sockets │              │ CRYPTO frames +   │               │                    │
   │                   │              │ packet protection │               │                    │
   └───────────────────┘              └───────────────────┘               └────────────────────┘
```

Two properties make this work:

1. **The core owns no record, cipher, or socket concept.** A grep gate over
   `src/tls/handshake/` (`Record`, `TLSProtection`, `ContentType`,
   `change_cipher_spec`, `record_header_len`) keeps it that way. The core never
   encrypts, never frames a record, and never calls `read(2)`/`write(2)`.

2. **The public boundary is a small, phase-named seam.** The unit the adapter
   exchanges with the core is a `HandshakeMessage` — a complete handshake
   message (4-byte header included) whose TLS protection phase is a
   module-private tag. Framing (records vs. CRYPTO frames) and protection (AEAD
   records vs. QUIC packet protection) are entirely adapter-side.

The phase vocabulary is transport-neutral but stays inside the module:

```v
enum EncryptionLevel { // module-private — no public signature names it
    initial      // initial TLS handshake messages before handshake keys are installed
    handshake    // messages protected with handshake traffic keys
    application  // application traffic keys/secrets
}
```

Here the initial phase names the pre-ServerHello TLS handshake stage, not QUIC
Initial packet protection. The QUIC engine routes Initial packet CRYPTO to
`receive_initial_bytes()` and Handshake packet CRYPTO to
`receive_handshake_bytes()`; it rejects 1-RTT CRYPTO because
post-handshake messages are handled separately. The TCP adapter routes plaintext
handshake records to `receive_initial_bytes()` and decrypted handshake records to
`receive_handshake_bytes()`. QUIC packet levels and packet-number spaces remain
adapter-side.

QUIC handshakes include the TLS `quic_transport_parameters` extension
(RFC 9001 §8.2). The core treats its content as opaque bytes: it rules only on
placement — required when the connection is QUIC, rejected on a record transport
— and carries the value out and back in untouched. Encoding this endpoint's own
parameters and decoding a peer's id/length/value triplets lives above the
handshake, in `tls.quic` (`transport_params.v`): the engine advertises
`initial_source_connection_id` from its source connection ID, and requires a
server to declare both `initial_source_connection_id` and
`original_destination_connection_id`, checking each against the connection IDs
it actually saw on the wire (RFC 9000 §7.3). Parameters outside that set reach
the adapter intact and are ignored there.

---

## 2. The handshake the core performs

The core is a **client** state machine. Its public `HandshakeState` is a single
enum mirroring the client state machine of RFC 8446 Appendix A.1; it is itself the
ordering cursor that enforces the fixed post-ServerHello order of §4.1:

```
start
  └─ create_client_hello() ─▶ wait_sh
        │  ServerHello (or HelloRetryRequest → re-send ClientHello, back to wait_sh)
        ▼
  wait_ee                      (handshake keys installed)
        │  EncryptedExtensions   (ALPN/SNI checks happen here)
        ▼
  wait_cert_cr                 (CertificateRequest or Certificate)
        │  CertificateRequest?   (optional, §4.3.2; client answers with an empty Certificate, §4.4.2)
        ▼
  wait_cert                    (Certificate)
        │  Certificate           (chain parsed + validated against the injected pki.Validator)
        ▼
  wait_cv                      (CertificateVerify)
        │  CertificateVerify     (server signature over the §4.4.3 content)
        ▼
  wait_finished                (Finished)
        │  Finished              (transcript-bound verify_data)
        ▼
  connected                    (client Finished emitted; application secrets live)
```

`state()` reports the exact cursor position and rejects an out-of-order
encrypted-flight message, advancing only as each message is handled; adapters may
poll any of these states — `conn.v` keys its record routing on `wait_sh`,
`connected`, and `failed` — while key-material readiness comes from
`available_secret_phases()`. `failed` is terminal: once reached,
the phase-named receives refuse further input. A protocol violation moves the
machine to `failed` and wipes all derived material (see
`fail_and_zeroize_secrets()` in [CONTRACT.md](./CONTRACT.md)). The public
accessors `state()`, `negotiated_alpn()`, and `negotiated_cipher_suite()` let an
adapter poll progress and outcome.

### The ClientHello and HelloRetryRequest

`create_client_hello()` builds the first ClientHello with a key share for the
configured initial group (X25519 by default), the configured cipher suites (or
the built-in TLS 1.3 defaults), `supported_groups`, `signature_algorithms`, and
`supported_versions`. `SNI` is included for a DNS server name, and `ALPN` when
protocols are configured.
A HelloRetryRequest is fed as plaintext handshake input; the core switches to
the requested group, regenerates the share, echoes any cookie, and the receive
**returns the second ClientHello** (an initial-phase message, so it goes back on
the Initial/plaintext path) for the adapter to send.
The transcript substitutes the first ClientHello with its
`message_hash` (§4.4.1) so the Finished binds the whole two-round exchange.
The retry suite is remembered (`hrr_cipher_suite`) and the final ServerHello
must reuse it (§4.1.4).

No dummy ChangeCipherSpec is ever produced: that is a TCP middlebox
compatibility hack (RFC 8446 App. D.4), and QUIC packets are already opaque
(RFC 9001 §4.1.3).

### Client authentication

If the server requests the client's certificate, the core accepts the
`CertificateRequest` and emits an **empty `Certificate`** (§4.4.2) — this
library has no client credential to offer, so it declines rather than aborting.
That empty Certificate is folded into the transcript before the server flight
is verified.

---

## 3. How QUIC support was adapted in

The integration is **not a separate handshake implementation**. A
`QuicHandshake` facade drives the same private TLS handshake core as the
`TLSHandshake` used by `tls.Conn`. The separate facade types make the
transport-specific API explicit while sharing TLS message processing, transcript
and key-schedule state.

### 3.1 Initial secrets are not the core's business

QUIC derives its **Initial** packet keys from the destination connection ID
(RFC 9001 §5.2), not from the TLS key schedule. Those packet keys are outside
the core's phase vocabulary; the engine derives them itself, below this
layer. The shared handshake API starts with plaintext ServerHello processing.

### 3.2 Secrets, not record keys, cross the boundary

A QUIC engine needs the raw §7.1 **traffic secrets** so it can run the
RFC 9001 §5.1 expansions itself:

| Label      | Purpose                       |
|------------|-------------------------------|
| `quic key` | AEAD key for packet protection |
| `quic iv`  | packet-number nonce base       |
| `quic hp`  | header-protection key          |

`peer_handshake_secrets()` and `peer_application_secrets()` (defined on the
`QuicHandshake` facade itself) hand out `(client, server)` clones of those
secrets; the phase is in the method name, never an argument.
`handshake_record_keys()` / `application_record_keys()` are provided by
`TLSHandshake`, where each phase's generation is its own opaque handle type; a
`QuicHandshake` does not expose them. A QUIC engine uses
the peer-secret accessors + the public `hkdf_expand_label()`.

### 3.3 Handshake keys survive until no longer needed

A QUIC server may keep sending Handshake packets until the client
confirms the handshake with `HANDSHAKE_DONE` (RFC 9001 §4.1.2), not merely
until the client sends its Finished. So the core deliberately retains the
handshake traffic secrets past `.connected`; the engine owns its derived packet
keys and, when it processes `HANDSHAKE_DONE` (§4.9.2), calls `release_handshake_keys()`
— a single step that zeroizes the core's `.handshake` traffic secrets *and* zeroes
the Handshake packet-protection states together, so neither half can be forgotten.
The TCP adapter reaches the same `zeroize_handshake_secrets()` after sending
its Finished because record-based TLS has no such window; **a QUIC engine must not**
release them before it has finished using the Handshake packet keys. Terminal cleanup
is centralized in `close()`, which seals the final `CONNECTION_CLOSE` first and only
then zeroizes the core secrets and every remaining packet key (`destroy_on_close()`).

### 3.4 KeyUpdate is replaced by Key Phase

Over QUIC, TLS KeyUpdate does not exist: an endpoint MUST NOT send one and MUST
treat a received one as a connection error (RFC 9001 §6). The next generation
of 1-RTT secrets is derived engine-side with the `quic ku` label
(§6.1) — **not** via `update_traffic_keys(is_server)`,
whose `traffic upd` label is the TLS record path's. The header-protection key
never updates.

### 3.5 Alerts never ride CRYPTO

An alert over QUIC is not a handshake message; it becomes a **connection
error** whose code is `0x100 + AlertDescription` (CRYPTO_ERROR, RFC 9001 §4.8).
`quic_connection_error()` does that mapping. The core's shared
`AlertDescription` vocabulary (including the classified `failure_alert()` a
failed handshake exposes) is therefore reusable by a QUIC adapter with no
CRYPTO alert path at all.

### 3.6 CRYPTO reassembly

Within a phase the CRYPTO stream is self-framed handshake messages
(type ∥ u24 length). `next_recordless_message()` — the recordless twin of the
record layer's parser — extracts one complete message from the front of a byte
buffer, capping the declared length at `max_handshake_message_len` (1 MiB) from
the header alone so a hostile peer cannot make the adapter buffer indefinitely.
It is public precisely so an engine can reuse it engine-side. The shared core
owns the initial- and handshake-phase reassembly buffers for each handshake instance.

---

## 4. Writing a QUIC adapter: the engine loop

An engine imports **`tls.handshake`** and never imports `tls`. Certificate
validation defaults to the system root bundle; provide a `pki.Validator` in
`HandshakeOptions` when using private roots or custom validation policy. The
whole integration is this loop:

```v
import tls.handshake

// The omitted validator uses the system root CA bundle.
mut hs := handshake.new_quic_handshake('example.com', handshake.HandshakeOptions{
	alpn: ['h3']
})!

// 1. First ClientHello. `ch1` is a complete handshake message; place it into a
//    CRYPTO frame in an Initial packet (which YOU protect with Initial keys
//    derived from the destination connection ID, RFC 9001 §5.2).
ch1 := hs.create_client_hello()!

// 2. Send ch1 in Initial CRYPTO; read Initial packets; strip Initial protection;
//    concatenate CRYPTO frame payloads into `initial_stream`.

// 3. Feed the ServerHello (ServerHello rides Initial; HRR also rides Initial).
msgs := hs.receive_initial_bytes(initial_stream)!
for m in msgs {
    // The only initial-phase output here is the retry ClientHello after a
    // HelloRetryRequest — send it in an Initial CRYPTO frame and loop.
    _ = m
}

// 4. Now derive Handshake keys from the exported secrets and protect Handshake
//    packets with them; the server flight (EE, [CertReq], Cert, CV, Finished)
//    rides Handshake CRYPTO.
(ck, sk) := hs.peer_handshake_secrets()!
suite := hs.negotiated_cipher_suite()
hash := handshake.suite_hash_algo(suite)
key_len := handshake.suite_key_len(suite)
qkey := handshake.hkdf_expand_label(hash, ck, 'quic key', []u8{}, key_len)!
// ... 'quic iv' (12 bytes) and 'quic hp' (key_len) likewise ...

// 5. Feed the reassembled Handshake CRYPTO stream. The return carries the
//    client Finished (a handshake-phase message) once the server flight verifies.
flight := hs.receive_handshake_bytes(handshake_stream)!
for m in flight {
    if !m.is_initial() {
        // Send m.msg in a Handshake CRYPTO frame, protected with the client
        // Handshake keys. (The TCP adapter sends a dummy CCS here; QUIC does not.)
    }
}

// 6. Application secrets are live at .connected. Derive 1-RTT packet keys with
//    the 'quic key'/'quic iv'/'quic hp' labels from peer_application_secrets().
(cap, sap) := hs.peer_application_secrets()!

// 7. For a custom client adapter, release handshake-stage material after
//    receiving HANDSHAKE_DONE. Conn does this automatically.
hs.zeroize_handshake_secrets()!

// 8. Post-handshake: NewSessionTicket rides the 1-RTT CRYPTO stream. Reassemble
//    with next_recordless_message and decode with parse_new_session_ticket.
//    A KeyUpdate here is a connection error (RFC 9001 §6) — do NOT feed keys.
```

### Notes on each step

- The shared API sequence, phase guards, and TLS-only operations are specified
  in the [handshake adapter contract](./CONTRACT.md). For QUIC, queue every
  returned message by phase — `m.is_initial()` is the only phase fact the public
  seam exposes: true means Initial CRYPTO, false means Handshake CRYPTO.
- The QUIC engine rejects CRYPTO data carried in 1-RTT packets. Handle
  post-handshake CRYPTO separately with `next_recordless_message()` and
  `parse_new_session_ticket()`.
- `negotiated_alpn()` returns the server's selection (`''` if none); the shared
  core verifies that any selection was offered (RFC 7301 §3.1).

---

## 5. API reference

The canonical list of shared and transport-specific methods, lifecycle rules,
and public helper APIs is in the [handshake adapter contract](./CONTRACT.md).
This guide focuses on QUIC behavior and adapter sequencing rather than
repeating that API inventory.

The validator in `HandshakeOptions` is optional. If omitted, construction uses
`pki.default_validator()` and propagates an error if the system root bundle
cannot be loaded. Supply a custom `pki.Validator` to use private trust roots or
custom validation policy. The QUIC client constructor requires `server_name`;
its optional TLS settings are supplied through `quic.Config.hsk_options`.
For example:

```v
mut conn := quic.new_client_engine('example.com', quic.Config{
	hsk_options: handshake.HandshakeOptions{ alpn: ['h3'] }
})!
```

---

## 6. What this module does *not* give you

The handshake core is complete, but a QUIC stack is more than the handshake.
The following are outside `tls.handshake`; some packet-level handshake
functionality is provided separately by this repository's
`tls.quic.Conn`:

- **General packet handling** — the engine builds and parses packets for its
  handshake flow, but does not provide a complete QUIC packet stack.
- **Key Phase** — the 1-RTT key update mechanism that replaces TLS KeyUpdate
  (RFC 9001 §6); the engine does not implement key updates.
- **Full connection machinery** — streams, flow control, loss recovery,
  congestion control, migration, and Retry/0-RTT. The engine handles ACK and
  CONNECTION_CLOSE frames during its handshake flow; it parses ACKs but does
  not track acknowledgments or provide loss recovery.

What the module *does* give you: the entire TLS 1.3 state machine, transcript,
key schedule, certificate validation hook, alert vocabulary, and the
phase-named seam to plug them into your packet layer — so your adapter only
has to be a transport.

---

## 7. See also

- `src/tls/handshake/CONTRACT.md` — the shared-core and transport-facade
  contract, including the remaining opportunity to report handshake milestones
  through structured progress results.
- `src/tls/handshake/state_machine.v` — private shared TLS handshake core.
- `src/tls/handshake/tls_handshake.v` — record-layer facade and record-key
  lifecycle.
- `src/tls/handshake/quic_handshake.v` — QUIC facade and exported-secret
  lifecycle.
- `src/tls/handshake/passthrough.v` — CRYPTO-stream reassembly (RFC 9001 §4).
- `src/tls/handshake/alert.v` — `AlertDescription` + `quic_connection_error()`.
- `src/tls/handshake/key_schedule.v` — `hkdf_expand_label`, the §7.1 ladder.
- `src/tls/conn.v` — the reference TCP adapter: the
  same seam driven over records and sockets, useful as a worked example of every
  adapter responsibility.
- RFC 9001 §4 (carrying TLS), §4.1 (interface), §4.8 (alerts), §5 (packet
  protection), §6 (Key Phase).
