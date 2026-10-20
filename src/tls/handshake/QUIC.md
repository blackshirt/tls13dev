# Driving the handshake core over QUIC

This document explains **how the TLS 1.3 handshake in this repository is
structured**, **how support for QUIC (RFC 9001) was adapted into it**, and
**how to write a QUIC adapter** that drives the core — without importing the
`tls` record layer, without touching a socket, and without reimplementing the
TLS state machine.

The module it describes is `tls.handshake` (`src/tls/handshake/`). Everything
`pub` in that module is the adapter contract; everything else is private. This
file is the long-form companion to the walkthrough in the `state_machine.v`
file preamble.

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
   │  messages.v   wire codecs for handshake messages (RFC 8446 §4)                     │
   │  transcript.v running Transcript-Hash (§4.4.1), rewindable at the HRR checkpoint   │
   │  key_schedule.v + handshake_keys.v   §7.1 HKDF ladder, offered-group policy         │
   │  aead.v        suite → (hash, key length, AEAD constructor)                         │
   │  certificate_verify.v   server signature check over the §4.4.3 content              │
   │  alert.v       AlertDescription vocabulary + quic_connection_error() mapping        │
   │  passthrough.v recordless CRYPTO-stream reassembly (RFC 9001 §4)                    │
   │  state_machine.v  sequences all of the above; speaks raw, level-tagged messages     │
   └────────────────────────────────────────────────────────────────────────────────────┘
        ▲                                     ▲                                     ▲
        │ feed(level, bytes)                  │ traffic_keys / exported_secrets      │ create_client_hello / feed
        │                                     │                                     │
   ┌────┴──────────────┐              ┌───────┴───────────┐               ┌─────────┴──────────┐
   │ tls TCP adapter   │              │ a QUIC engine     │               │ tests / other      │
   │ conn.v +          │              │ (RFC 9001)        │               │ transports         │
   │ tcp_transport.v   │              │ CRYPTO frames +   │               │                    │
   │ records + sockets │              │ packet protection │               │                    │
   └───────────────────┘              └───────────────────┘               └────────────────────┘
```

Two properties make this work:

1. **The core owns no record, cipher, or socket concept.** A grep gate over
   `src/tls/handshake/` (`Record`, `RecordCipherState`, `ContentType`,
   `change_cipher_spec`, `record_header_len`) keeps it that way. The core never
   encrypts, never frames a record, and never calls `read(2)`/`write(2)`.

2. **The public boundary is a small, level-tagged seam.** The unit the adapter
   exchanges with the core is a `HandshakeMessage` — a complete handshake
   message (4-byte header included) tagged with the `SecretLevel` it belongs
   to. Framing (records vs. CRYPTO frames) and protection (AEAD records vs.
   QUIC packet protection) are entirely adapter-side.

`SecretLevel` comes straight from RFC 9001 §4.1:

```v
pub enum SecretLevel {
    initial      // CRYPTO carried in Initial packets
    handshake    // CRYPTO carried in Handshake packets
    application  // CRYPTO carried in 1-RTT packets (post-handshake only)
}
```

The TCP adapter collapses all three onto its single ordered record stream
(always `.handshake` practically). QUIC keeps them distinct because each level
has its own packet-number space and its own keys.

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

`failed` is terminal: once reached, `feed()` refuses further input. A protocol
violation moves the machine to `failed` and wipes all derived material (see
§5). The public accessors `state()`, `negotiated_alpn()`, and
`negotiated_cipher_suite()` let an adapter poll progress and outcome.

### The ClientHello and HelloRetryRequest

`create_client_hello()` builds the first ClientHello: an X25519 `key_share`
(mandatory to implement, §9.1), the three supported cipher suites, `SNI`,
`ALPN`, `supported_groups`, `signature_algorithms`, and `supported_versions`.
A HelloRetryRequest arrives as a pseudo-ServerHello at `.initial`; the core
switches to the requested group, regenerates the share, echoes any cookie, and
`feed()` **returns the second ClientHello** (tagged `.initial`) for the adapter
to send. The transcript substitutes the first ClientHello with its
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

The integration is **not a separate code path**. It is the same `ClientHandshake`
driven through the same `pub` seam, with three deliberate design decisions that
make QUIC correct:

### 3.1 Initial secrets are not the core's business

QUIC derives its **Initial** keys from the destination connection ID
(RFC 9001 §5.2), not from the TLS key schedule. So the core exposes no initial
material: `traffic_keys(.initial)` and `exported_secrets(.initial)` both
refuse. The engine derives Initial keys itself, below this layer.

### 3.2 Secrets, not TrafficKeys, cross the boundary

A QUIC engine needs the raw §7.1 **traffic secrets** so it can run the
RFC 9001 §5.1 expansions itself:

| Label      | Purpose                       |
|------------|-------------------------------|
| `quic key` | AEAD key for packet protection |
| `quic iv`  | packet-number nonce base       |
| `quic hp`  | header-protection key          |

`exported_secrets(level)` hands out `(client, server)` clones of those secrets.
`traffic_keys(level)` is provided for the record layer (and for tests) but a
QUIC engine should use `exported_secrets()` + the public `hkdf_expand_label()`.

### 3.3 Handshake keys survive until confirmation

A QUIC peer may keep sending at the Handshake level **until the handshake is
confirmed** (HANDSHAKE_DONE or a 1-RTT acknowledgment, RFC 9001 §4.1.2), not
merely until the client sends its Finished. So the core deliberately retains
the handshake traffic secrets and cached keys past `.connected`, and discards
them only when the adapter calls `confirm_handshake()` — the §4.9.2 behavior.
The TCP adapter calls `confirm_handshake()` right after sending its Finished
because record-based TLS has no such window; **a QUIC engine must not**, or it
will strand keys it still needs.

### 3.4 KeyUpdate is replaced by Key Phase

Over QUIC, TLS KeyUpdate does not exist: an endpoint MUST NOT send one and MUST
treat a received one as a connection error (RFC 9001 §6). The next generation
of 1-RTT secrets is derived engine-side with the `quic ku` label
(§6.1) — **not** via `update_read_traffic_keys()`/`update_write_traffic_keys()`,
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
It is public precisely so an engine can reuse it engine-side.

---

## 4. Writing a QUIC adapter: the engine loop

An engine imports **`tls.handshake`** and **`tls.pki`** (for `TrustStore`) and
never imports `tls`. The whole integration is this loop:

```v
import tls.handshake
import tls.pki

// 0. Trust anchors (system bundle, or your own pinned roots).
mut store := pki.new_trust_store()
store.load_system_ca_bundle()!

// 1. Construct — same call conn.v makes. X25519 share generated here.
mut hs := handshake.new_client_handshake('example.com', ['h3'], pki.new_validator(store, false))!

// 2. First ClientHello. `ch1` is a complete handshake message; place it into a
//    CRYPTO frame in an Initial packet (which YOU protect with Initial keys
//    derived from the destination connection ID, RFC 9001 §5.2).
ch1 := hs.create_client_hello()!

// 3. Send ch1 in Initial CRYPTO; read Initial packets; strip Initial protection;
//    concatenate CRYPTO frame payloads into `initial_stream`.

// 4. Feed the ServerHello (ServerHello rides Initial; HRR also rides Initial).
msgs := hs.feed(.initial, initial_stream)!
for m in msgs {
    // The only .initial output the core ever produces is the retry ClientHello
    // after a HelloRetryRequest — send it in an Initial CRYPTO frame and loop.
    _ = m
}

// 5. Now derive Handshake keys from the exported secrets and protect Handshake
//    packets with them; the server flight (EE, [CertReq], Cert, CV, Finished)
//    rides Handshake CRYPTO.
(ck, sk) := hs.exported_secrets(.handshake)!
suite := hs.negotiated_cipher_suite()
hash := handshake.suite_hash_algo(suite)
key_len := handshake.suite_key_len(suite)
qkey := handshake.hkdf_expand_label(hash, ck, 'quic key', []u8{}, key_len)!
// ... 'quic iv' (12 bytes) and 'quic hp' (key_len) likewise ...

// 6. Feed the reassembled Handshake CRYPTO stream. The return carries the
//    client Finished (tagged .handshake) once the server flight verifies.
flight := hs.feed(.handshake, handshake_stream)!
for m in flight {
    if m.level == .handshake {
        // Send m.msg in a Handshake CRYPTO frame, protected with the client
        // Handshake keys. (The TCP adapter sends a dummy CCS here; QUIC does not.)
    }
}

// 7. Application secrets are live at .connected. Derive 1-RTT packet keys with
//    the 'quic key'/'quic iv'/'quic hp' labels from exported_secrets(.application).
(cap, sap) := hs.exported_secrets(.application)!

// 8. Confirm the handshake only when QUIC says so (HANDSHAKE_DONE / 1-RTT ack),
//    then release the handshake-stage material.
hs.confirm_handshake()!

// 9. Post-handshake: NewSessionTicket rides the 1-RTT CRYPTO stream. Reassemble
//    with next_passthrough_message and decode with parse_new_session_ticket.
//    A KeyUpdate here is a connection error (RFC 9001 §6) — do NOT feed keys.
```

### Notes on each step

- **`feed()` is the single inbound entry point.** It appends bytes to that
  level's reassembly buffer and consumes every complete message immediately.
  Returned messages are the outbound follow-ups triggered by the peer's bytes.
  Contract misuse (feeding before `create_client_hello()`, Initial bytes outside
  the ServerHello wait, anything after `failed`) is refused with the state left
  untouched so you can fix your sequencing.
- **`buffered_bytes(level)`** reports incomplete bytes parked in a level's
  buffer. The TCP adapter uses it for the §5.1 ServerHello record-boundary rule;
  that rule is meaningless over QUIC, so the core does not own it — but the
  accessor is there if you need visibility.
- **`negotiated_alpn()`** returns the server's ALPN pick (`''` if none). The
  core already verified it was one you offered (RFC 7301 §3.1).
- **`feed(.application, …)` refuses by contract**: application data never
  rides CRYPTO (RFC 9001 §4.1.3). Reassemble post-handshake CRYPTO and decode it
  yourself with `next_passthrough_message` + `parse_new_session_ticket`.

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
   calls `abort()`: the Handshake Secret, both traffic-secret generations, all
   cached `TrafficKeys`, and both ephemeral ECDHE private halves are destroyed
   (RFC 8446 §1.3.1/§7.5). `abort()` is the only legal way for an adapter to
   reach `.failed`. The success path wipes at `.connected`
   (`zeroize_handshake_secrets`) and at teardown (`zeroize_app_secrets`), with
   the handshake stage deferred to `confirm_handshake()` per §3.3 above.

Your adapter should: read `failure_alert()`, convert it to a QUIC connection
error, close the connection, and drop its own per-level protection state.

---

## 6. The public API at a glance

```v
// Construction and driving
new_client_handshake(server_name string, alpn []string, pki.Validator) !ClientHandshake
(mut h) create_client_hello() ![]u8
(mut h) feed(level SecretLevel, bytes []u8) ![]HandshakeMessage

// Observation
(h) state() HandshakeState
(h) negotiated_alpn() string
(h) negotiated_cipher_suite() CipherSuite
(h) buffered_bytes(level SecretLevel) int
(h) failure_alert() AlertDescription

// Key material (secrets for QUIC; keys for the record layer)
(h) exported_secrets(level SecretLevel) !([]u8, []u8)     // (client, server)
(h) traffic_keys(level SecretLevel) !(TrafficKeys, TrafficKeys)

// Lifecycle
(mut h) confirm_handshake() !                            // QUIC: at handshake confirmation
(mut h) update_read_traffic_keys() !                     // TLS record path only
(mut h) update_write_traffic_keys() !                    // TLS record path only
(mut h) abort()                                          // → .failed, wipes all secrets

// Recordless framing + alert mapping
next_passthrough_message(mut buf []u8) ![]u8
max_handshake_message_len                                 // = 1 << 20
(d AlertDescription) quic_connection_error() u32          // 0x100 + description
hkdf_expand_label(hash HashAlgorithm, secret []u8, label string, context []u8, length int) ![]u8
parse_new_session_ticket(body []u8) !NewSessionTicket
parse_key_update(body []u8) !bool

// Supporting types
SecretLevel { initial, handshake, application }
HandshakeMessage { level SecretLevel  msg []u8 }          // msg = full message, header included
```

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

- `src/tls/handshake/state_machine.v` — the `pub` seam; its preamble carries
  the condensed 8-step QUIC walkthrough.
- `src/tls/handshake/passthrough.v` — CRYPTO-stream reassembly (RFC 9001 §4).
- `src/tls/handshake/alert.v` — `AlertDescription` + `quic_connection_error()`.
- `src/tls/handshake/key_schedule.v` — `hkdf_expand_label`, the §7.1 ladder.
- `src/tls/conn.v` / `src/tls/tcp_transport.v` — the reference TCP adapter: the
  same seam driven over records and sockets, useful as a worked example of every
  adapter responsibility.
- RFC 9001 §4 (carrying TLS), §4.1 (interface), §4.8 (alerts), §5 (packet
  protection), §6 (Key Phase).
