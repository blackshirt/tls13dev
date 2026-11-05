# tls.quic

A QUIC client engine for the TLS 1.3 handshake over QUIC ([RFC 9001](https://www.rfc-editor.org/rfc/rfc9001)),
driving the transport-neutral [`tls.handshake`](./handshake/) state machine over protected QUIC packets
without importing the TLS record layer (`tls`). It is a **handshake engine, not a full QUIC stack**:
there are no streams, flow control, congestion control, migration, Retry/0-RTT, or Key Phase.

This module completes the RFC 9001 handshake against a real server and survives a lossy path:
it emits ACK frames (piggybacked and bare), retransmits the handshake flight on a probe-timeout
clock, and fragments outbound CRYPTO to `Config.max_packet_size`. A socket-owning `quic.dial()`
facade runs the whole loop to confirmation over a `net.UdpConn`.

The public entry point is `quic.dial()`. Behind it, `quic.Engine` is module-internal —
it builds and protects packets in memory but owns no socket. Users who want a non-socket
transport should drive the public `tls.handshake` core directly instead (see the
[`tls.handshake`](../handshake/README.md) README).

```v
import tls.handshake
import tls.quic

mut conn := quic.dial('example.com:443', quic.Config{
	server_name:  'example.com'
	hsk_options:  handshake.HandshakeOptions{ alpn: ['h3'] }
})!
defer {
	conn.close() or {}
}
println(conn.negotiated_alpn())
println(conn.negotiated_cipher_suite())
```

## Public API

Only `dial()`, `Conn`, `negotiated_alpn()`, `negotiated_cipher_suite()`, `close()`, and `Config`
are public. Everything else in the module — including `Engine` — is internal.

| Symbol | Kind | Purpose |
|--------|------|---------|
| `quic.dial()` | function | Open a UDP socket, run the RFC 9001 handshake, return a confirmed `Conn` |
| `quic.Conn` | struct | Confirmed QUIC connection owning a UDP socket (fields module-private) |
| `Conn.negotiated_alpn()` | method | Negotiated ALPN protocol (`''` if none) |
| `Conn.negotiated_cipher_suite()` | method | Negotiated TLS 1.3 cipher suite |
| `Conn.close()` | method | Send `CONNECTION_CLOSE` (best effort) and release the socket |
| `quic.Config` | struct (`@[params]`) | Dial options: `hsk_options`, `server_name`, `timeout`, `max_packet_size` |

```v
@[params]
pub struct Config {
pub:
	hsk_options handshake.HandshakeOptions = handshake.HandshakeOptions{}
	server_name string
	timeout     time.Duration = 30 * time.second
	max_packet_size int = 1200
}
```

`server_name` falls back to the dial address host when empty. A name over 253 characters
or carrying stray whitespace is rejected before the socket opens. The handshake carries
a total deadline of `4 × timeout`; a stalled peer dribbling valid bytes under every
individual read timeout is still cut off.

## File map

```
engine.v        transport-agnostic QUIC handshake engine (module-internal): drives
                the tls.handshake core over protected packets; per-level packet-number
                spaces, packet protection, CRYPTO frame packing, offset-ordered
                reassembly, ACK emission, handshake retransmission, datagram fragmentation
client.v        socket-owning facade: quic.dial() opens a UDP socket, drives the
                engine to confirmation under Config.timeout, returns a quic.Conn
packet.v        QUIC packet types, long/short header encoding/decoding, version negotiation
packet_parse.v  long-header and short-header parsing, connection-ID and token extraction
protection.v    packet protection (AEAD seal/open) and header protection per RFC 9001 §5
initial_keys.v  QUIC Initial packet key derivation from the destination connection ID (§5.2)
frame.v         QUIC frame encoding/decoding (ACK, CONNECTION_CLOSE, CRYPTO, etc.)
varint.v        QUIC variable-length integer encoding/decoding (§16)
reasm.v         CRYPTO-stream offset-ordered reassembly per packet-number space
transport_params.v  RFC 9000 §18.2 transport-parameter id/length/value encoding
```

Each `*_test.v` sits beside its source.

## Lifecycle and safety invariants

- **Handshake ordering.** `dial()` sends the initial ClientHello, then pumps datagrams:
  read → feed engine → write returned datagrams, until HANDSHAKE_DONE is processed and
  the core reports `.connected`. A read timeout advances the engine's retransmit clock
  instead of failing (RFC 9000 §6.2.1), so lossy paths still complete.
- **Confirmation.** `is_confirmed()` requires both the HANDSHAKE_DONE frame flag *and*
  the core being `.connected` — a forged HANDSHAKE_DONE in a non-1-RTT packet type
  (whose Initial keys are public, RFC 9001 §5.2) cannot make `dial()` return
  unauthenticated (RFC 9000 §19.20).
- **Connection IDs.** The engine generates random destination and source CIDs (8 bytes
  each, RFC 9000 §5.1). Initial keys derive from the original DCID (§5.2); on a
  HelloRetryRequest, keys are re-derived from the server-chosen ID (§5.5).
- **No fd leaks.** Any handshake failure closes the socket `dial()` opened before
  returning the error; a half-connected `Conn` is never returned.
- **Close.** `close()` seals a `CONNECTION_CLOSE` while packet keys are still present,
  sends it best-effort, then releases the socket. Idempotent: a second `close()` is a
  no-op and never errors.
- **No data plane.** There are no streams, flow control, loss recovery beyond the
  handshake flight, congestion control, migration, Retry/0-RTT, or Key Phase. After
  confirmation `dial()` returns a `Conn` exposing only the negotiated parameters.

## What this module does *not* give you

- **Key Phase** — the 1-RTT key update mechanism (RFC 9001 §6); the engine does not
  implement key updates.
- **Full connection machinery** — streams, flow control, loss recovery for application
  data, congestion control, connection migration, Retry/0-RTT. The engine retransmits
  only the handshake flight, not a general data plane.
- **TLS KeyUpdate** — over QUIC, TLS KeyUpdate does not exist; an endpoint MUST NOT send
  one and MUST treat a received one as a connection error (RFC 9001 §6).

## Testing

```
v test src/tls/quic/
```

Covers packet protection seal/open symmetry, long/short header (de)serialization,
varint encoding, frame parsing, CRYPTO reassembly, transport-parameter encoding,
the full RFC 9001 handshake against an in-repo ferry server, and the ACK/retransmit
clock. The engine's file preambles describe the loop it walks over the
`tls.handshake` seam.
