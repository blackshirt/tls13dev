# Driving the handshake core over QUIC

This document explains **how the TLS 1.3 handshake in this repository is
structured**, **how support for QUIC (RFC 9001) was adapted into it**, and
**how to write a QUIC adapter** that drives the core — without importing the
`tls` record layer, without touching a socket, and without reimplementing the
TLS state machine.

The module it describes is `tls.handshake` (`src/tls/handshake/`). Everything
`pub` in that module is the adapter contract; everything else is private. This
file is the long-form guide to the QUIC facade in `quic_handshaker.v` and shared
handshake engine in `state_machine.v`.

---

## 1. What "transport-neutral" means here

TLS 1.3 is defined as a sequence of **handshake messages** bound to a running
transcript, plus a **key schedule** that turns a shared secret into traffic
secrets. Everything else — records, AEAD framing, sequence numbers, sockets —
is how those messages and secrets are *carried*. RFC 9001 (TLS over QUIC)
changes the carrier completely: handshake messages ride QUIC **CRYPTO frames**
on three encryption levels, and packet protection is a QUIC concern, not a TLS
record concern.

The core was therefore split so that the carrier is always someone else's job:

```
   ┌──────────────────────────── tls.handshake (this module) ───────────────────────────┐
   │  Shared core: state_machine.v sequences TLS messages and the key schedule          │
   │  Record facade: record_handshaker.v owns TLS TrafficKeys and KeyUpdate ratchets    │
   │  QUIC facade: quic_handshaker.v exports TLS traffic secrets                       │
   │  messages.v / transcript.v / key_schedule.v / handshake_keys.v                    │
   │  aead.v / certificate_verify.v / alert.v / passthrough.v                           │
   └────────────────────────────────────────────────────────────────────────────────────┘
        ▲                                     ▲                                     ▲
        │ receive(level, bytes)                │ record_traffic_keys /                │ create_client_hello /
        │                                      │ quic_traffic_secrets                 │ receive
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
   `src/tls/handshake/` (`Record`, `RecordProtector`, `ContentType`,
   `change_cipher_spec`, `record_header_len`) keeps it that way. The core never
   encrypts, never frames a record, and never calls `read(2)`/`write(2)`.

2. **The public boundary is a small, level-tagged seam.** The unit the adapter
   exchanges with the core is a `HandshakeMessage` — a complete handshake
   message (4-byte header included) tagged with the `HandshakeLevel` it belongs
   to. Framing (records vs. CRYPTO frames) and protection (AEAD records vs.
   QUIC packet protection) are entirely adapter-side.

`HandshakeLevel` is transport-neutral:

```v
pub enum HandshakeLevel {
    plaintext    // handshake messages before handshake traffic keys are installed
    handshake    // messages protected with handshake traffic keys
}
```

The QUIC engine maps Initial packet CRYPTO to `.plaintext` and Handshake packet
CRYPTO to `.handshake`; it rejects 1-RTT CRYPTO because post-handshake messages
are handled separately. The TCP adapter maps plaintext handshake records to
`.plaintext` and decrypted handshake records to `.handshake`. QUIC packet
levels and packet-number spaces remain adapter-side.

---

## 2. The handshake the core performs

The core is a **client** state machine. One successful run walks these states
(`HandshakeState`), which mirror the fixed post-ServerHello order of RFC 8446
§4.1:

```
start
  └─ create_client_hello() ─▶ wait_server_hello
        │  ServerHello (or HelloRetryRequest → re-send ClientHello, back to wait_server_hello)
        ▼
  wait_encrypted_extensions
        │  EncryptedExtensions   (ALPN/SNI checks happen here)
        ▼
  wait_certificate_request      (optional: a CertificateRequest may precede the Certificate, §4.3.2)
        │  CertificateRequest (client answers with an empty Certificate, §4.4.2)
        ▼
  wait_certificate
        │  Certificate            (chain parsed + validated against the injected pki.Validator)
        ▼
  wait_certificate_verify
        │  CertificateVerify      (server signature over the §4.4.3 content)
        ▼
  wait_server_finished
        │  Finished               (transcript-bound verify_data)
        ▼
  connected                     (client Finished emitted; application secrets live)
```

`failed` is terminal: once reached, `receive()` refuses further input. A protocol
violation moves the machine to `failed` and wipes all derived material (see
§5). The public accessors `state()`, `negotiated_alpn()`, and
`negotiated_cipher_suite()` let an adapter poll progress and outcome.

### The ClientHello and HelloRetryRequest

`create_client_hello()` builds the first ClientHello: an X25519 `key_share`
(mandatory to implement, §9.1), the three supported cipher suites, `SNI`,
`ALPN`, `supported_groups`, `signature_algorithms`, and `supported_versions`.
A HelloRetryRequest is fed as plaintext handshake input; the core switches to
the requested group, regenerates the share, echoes any cookie, and `receive()`
**returns the second ClientHello** (tagged `.plaintext`) for the adapter to send.
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
`QuicHandshaker` facade drives the same private TLS handshake core as the
`RecordHandshaker` used by `tls.Conn`. The separate facade types make the
transport-specific API explicit while sharing TLS message processing, transcript
and key-schedule state.

### 3.1 Initial secrets are not the core's business

QUIC derives its **Initial** packet keys from the destination connection ID
(RFC 9001 §5.2), not from the TLS key schedule. Those packet keys are not
represented by `TrafficSecretLevel`; the engine derives them itself, below this
layer. The shared handshake API starts with plaintext ServerHello processing.

### 3.2 Secrets, not TrafficKeys, cross the boundary

A QUIC engine needs the raw §7.1 **traffic secrets** so it can run the
RFC 9001 §5.1 expansions itself:

| Label      | Purpose                       |
|------------|-------------------------------|
| `quic key` | AEAD key for packet protection |
| `quic iv`  | packet-number nonce base       |
| `quic hp`  | header-protection key          |

`quic_traffic_secrets(level)` hands out `(client, server)` clones of those secrets.
`record_traffic_keys(level)` is provided by `RecordHandshaker`; a
`QuicHandshaker` does not expose it. A QUIC engine uses
`quic_traffic_secrets()` + the public `hkdf_expand_label()`.

### 3.3 Handshake keys survive until no longer needed

A QUIC peer may keep sending at the Handshake level **until the handshake is
confirmed** (HANDSHAKE_DONE or a 1-RTT acknowledgment, RFC 9001 §4.1.2), not
merely until the client sends its Finished. So the core deliberately retains
the handshake traffic secrets past `.connected`; the engine owns its derived
packet keys and calls `zeroize_handshake_traffic_secrets()` when QUIC no longer
needs the TLS handshake traffic secrets (§4.9.2), usually after confirmation.
The TCP adapter calls `zeroize_handshake_traffic_secrets()` after sending its
Finished because record-based TLS has no such window; **a QUIC engine must not**
zeroize them before it has finished using the Handshake packet keys.

### 3.4 KeyUpdate is replaced by Key Phase

Over QUIC, TLS KeyUpdate does not exist: an endpoint MUST NOT send one and MUST
treat a received one as a connection error (RFC 9001 §6). The next generation
of 1-RTT secrets is derived engine-side with the `quic ku` label
(§6.1) — **not** via `record_update_read_traffic_keys()`/`record_update_write_traffic_keys()`,
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

Within a level the CRYPTO stream is self-framed handshake messages
(type ∥ u24 length). `next_passthrough_message()` — the recordless twin of the
record layer's parser — extracts one complete message from the front of a byte
buffer, capping the declared length at `max_handshake_message_len` (1 MiB) from
the header alone so a hostile peer cannot make the adapter buffer indefinitely.
It is public precisely so an engine can reuse it engine-side. The shared core
owns the TLS plaintext and Handshake message buffers for each handshake instance.

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

// 2. First ClientHello. `ch1` is a complete handshake message; place it into a
//    CRYPTO frame in an Initial packet (which YOU protect with Initial keys
//    derived from the destination connection ID, RFC 9001 §5.2).
ch1 := hs.create_client_hello()!

// 3. Send ch1 in Initial CRYPTO; read Initial packets; strip Initial protection;
//    concatenate CRYPTO frame payloads into `initial_stream`.

// 4. Feed the ServerHello (ServerHello rides Initial; HRR also rides Initial).
msgs := hs.receive(.plaintext, initial_stream)!
for m in msgs {
    // The only .plaintext output here is the retry ClientHello after a
    // HelloRetryRequest — send it in an Initial CRYPTO frame and loop.
    _ = m
}

// 5. Now derive Handshake keys from the exported secrets and protect Handshake
//    packets with them; the server flight (EE, [CertReq], Cert, CV, Finished)
//    rides Handshake CRYPTO.
(ck, sk) := hs.quic_traffic_secrets(.handshake)!
suite := hs.negotiated_cipher_suite()
hash := handshake.suite_hash_algo(suite)
key_len := handshake.suite_key_len(suite)
qkey := handshake.hkdf_expand_label(hash, ck, 'quic key', []u8{}, key_len)!
// ... 'quic iv' (12 bytes) and 'quic hp' (key_len) likewise ...

// 6. Feed the reassembled Handshake CRYPTO stream. The return carries the
//    client Finished (tagged .handshake) once the server flight verifies.
flight := hs.receive(.handshake, handshake_stream)!
for m in flight {
    if m.level == .handshake {
        // Send m.msg in a Handshake CRYPTO frame, protected with the client
        // Handshake keys. (The TCP adapter sends a dummy CCS here; QUIC does not.)
    }
}

// 7. Application secrets are live at .connected. Derive 1-RTT packet keys with
//    the 'quic key'/'quic iv'/'quic hp' labels from quic_traffic_secrets(.application).
(cap, sap) := hs.quic_traffic_secrets(.application)!

// 8. Confirm the handshake only when QUIC says so (HANDSHAKE_DONE / 1-RTT ack),
//    then release the handshake-stage material.
hs.zeroize_handshake_traffic_secrets()!

// 9. Post-handshake: NewSessionTicket rides the 1-RTT CRYPTO stream. Reassemble
//    with next_passthrough_message and decode with parse_new_session_ticket.
//    A KeyUpdate here is a connection error (RFC 9001 §6) — do NOT feed keys.
```

### Notes on each step

- **`receive()` is the single inbound entry point.** It appends bytes to that
  handshake core's level-specific reassembly buffer and consumes every complete
  message immediately. Separate handshaker instances have separate core state.
  Returned messages are the outbound follow-ups triggered by the peer's bytes.
  Contract misuse (feeding before `create_client_hello()`, plaintext bytes
  outside the ServerHello wait, anything after `failed`) is refused with the state left
  untouched so you can fix your sequencing.
- **`record_unconsumed_bytes(level)`** is available only on `RecordHandshaker`.
  The TCP adapter uses it for the §5.1 ServerHello record-boundary rule. The
  `QuicHandshaker` has no record-boundary accessor.
- **`negotiated_alpn()`** returns the server's ALPN pick (`''` if none). The
  core already verified it was one you offered (RFC 7301 §3.1).
- The shared `receive()` API only accepts `.plaintext` and `.handshake` TLS
  phases. The QUIC engine rejects CRYPTO data carried in 1-RTT packets; reassemble
  post-handshake CRYPTO and decode it with `next_passthrough_message` +
  `parse_new_session_ticket`.

---

## 5. Failure handling

When the core kills a handshake it takes two actions an adapter must respect:

1. **It classifies an alert.** `failure_alert()` returns the `AlertDescription`
   to send. RFC 8446 §6 makes `internal_error` a legal catch-all (the default);
   where the cause is knowable the core sets `unexpected_message`,
   `illegal_parameter`, `decrypt_error`, or `bad_certificate`. Over QUIC, map it
   with `quic_connection_error()` and raise a `CONNECTION_CLOSE` of type `0x1c`
   (RFC 9001 §4.8). There is no CRYPTO alert path.

2. **It wipes every secret.** Any error that drives the machine to `failed`
   calls `fail_and_destroy_secrets()`: the Handshake Secret, both traffic-secret generations, and
   both ephemeral ECDHE private halves are destroyed (RFC 8446 §1.3.1/§7.5).
   `RecordHandshaker` also wipes its cached record keys; a QUIC adapter wipes
   its packet-protection state. `fail_and_destroy_secrets()` parks the core in
   `.failed`. The success path wipes at `.connected`
   (`zeroize_handshake_secrets`) and at teardown (`zeroize_app_secrets`), with
   the handshake stage deferred to `zeroize_handshake_traffic_secrets()` per §3.3 above.

Your adapter should: read `failure_alert()`, convert it to a QUIC connection
error, close the connection, and drop its own per-level protection state.

---

## 6. The public API at a glance

```v
// Construction and shared handshake operations
new_quic_handshake(server_name string) !QuicHandshaker
new_record_handshake(server_name string) !RecordHandshaker
new_client_engine_with_options(server_name string, HandshakeOptions) !ClientEngine
(mut h) create_client_hello() ![]u8
(mut h) receive(level HandshakeLevel, bytes []u8) ![]HandshakeMessage

// Observation
(h) state() HandshakeState
(h) negotiated_alpn() string
(h) negotiated_cipher_suite() CipherSuite
(h) failure_alert() AlertDescription

// QUIC facade only
(h &QuicHandshaker) quic_traffic_secrets(level TrafficSecretLevel) !([]u8, []u8) // (client, server)
(mut h QuicHandshaker) zeroize_handshake_traffic_secrets() !

// Record facade only
(h &RecordHandshaker) record_traffic_keys(level TrafficSecretLevel) !(TrafficKeys, TrafficKeys)
(h &RecordHandshaker) record_unconsumed_bytes(level HandshakeLevel) int
(mut h RecordHandshaker) record_update_read_traffic_keys() !
(mut h RecordHandshaker) record_update_write_traffic_keys() !
(mut h RecordHandshaker) zeroize_handshake_traffic_secrets() !

// Shared lifecycle
(mut h) fail_and_destroy_secrets()      // → .failed, wipes TLS handshake secrets
(mut h) zeroize_app_secrets()

// Recordless framing + alert mapping
next_passthrough_message(mut buf []u8) ![]u8
max_handshake_message_len                                 // = 1 << 20
(d AlertDescription) quic_connection_error() u32          // 0x100 + description
hkdf_expand_label(hash HashAlgorithm, secret []u8, label string, context []u8, length int) ![]u8
parse_new_session_ticket(body []u8) !NewSessionTicket
parse_key_update(body []u8) !bool

// Supporting types
HandshakeLevel { plaintext, handshake }
TrafficSecretLevel { handshake, application }
HandshakeMessage { level HandshakeLevel  msg []u8 }          // msg = full message, header included
```

The validator in `HandshakeOptions` is optional. If omitted, construction uses
`pki.default_validator()` and propagates an error if the system root bundle
cannot be loaded. Supply a custom `pki.Validator` to use private trust roots or
custom validation policy. Other `HandshakeOptions` fields can be supplied by
name, for example `new_quic_handshake('example.com', alpn: ['h3'])`.

---

## 7. What this module does *not* give you

The handshake core is complete, but a QUIC stack is more than the handshake.
Out of scope for this module (and for this repository):

- **Packet building and packet-number spaces** — QUIC long/short headers,
  packet number encoding, coalescing (RFC 9000).
- **Header protection** — deriving and applying the `quic hp` mask; the core
  gives you the secret, you do the masking (RFC 9001 §5.4).
- **Initial key derivation** — from the destination connection ID (§5.2), the
  engine's job by design.
- **Key Phase** — the 1-RTT key update mechanism that replaces TLS KeyUpdate
  (§6); derive `quic ku` yourself.
- **Connections, streams, flow control, loss recovery, ACK handling,
  CONNECTION_CLOSE frames** — all RFC 9000.

What the module *does* give you: the entire TLS 1.3 state machine, transcript,
key schedule, certificate validation hook, alert vocabulary, and the
level-tagged seam to plug them into your packet layer — so your adapter only
has to be a transport.

---

## 8. See also

- `src/tls/handshake/CONTRACT.md` — the shared-core and transport-facade
  contract, including the remaining opportunity to report handshake milestones
  through structured progress results.
- `src/tls/handshake/state_machine.v` — private shared TLS handshake core.
- `src/tls/handshake/record_handshaker.v` — record-layer facade and record-key
  lifecycle.
- `src/tls/handshake/quic_handshaker.v` — QUIC facade and exported-secret
  lifecycle.
- `src/tls/handshake/passthrough.v` — CRYPTO-stream reassembly (RFC 9001 §4).
- `src/tls/handshake/alert.v` — `AlertDescription` + `quic_connection_error()`.
- `src/tls/handshake/key_schedule.v` — `hkdf_expand_label`, the §7.1 ladder.
- `src/tls/conn.v` — the reference TCP adapter: the
  same seam driven over records and sockets, useful as a worked example of every
  adapter responsibility.
- RFC 9001 §4 (carrying TLS), §4.1 (interface), §4.8 (alerts), §5 (packet
  protection), §6 (Key Phase).
