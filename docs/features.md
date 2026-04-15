# Features

Current coverage of the `masque` library against the relevant RFCs.

## RFCs

| RFC | Scope | Status |
| --- | --- | --- |
| 9298 §3 - Extended CONNECT handshake | `:method=CONNECT`, `:protocol=connect-udp` | Implemented |
| 9298 §3 - URI template | `.well-known/masque/udp/{host}/{port}/` expansion + match | Implemented (`masque_uri`) |
| 9298 §5 - Context-ID framing | Context 0 for UDP payloads; extension contexts pass through | Implemented (`masque_datagram`) |
| 9298 §7 - Capsules | Stream-body capsule dispatch with `handle_capsule/3` callback | Implemented (`masque_capsule`) |
| 9297 - HTTP Datagrams | Quarter-stream-id encoding and settings | Delegated to `quic_h3` |
| 9220 - Extended CONNECT in HTTP/3 | `:protocol` negotiation and `SETTINGS_ENABLE_CONNECT_PROTOCOL` | Delegated to `quic_h3` |

## Delivered in v0.1

1. Repo bootstrap + rebar3 toolchain
2. URI template, datagram, and capsule codecs (pure, property-tested)
3. Server handshake and error-code mapping
4. Client handshake and gen_statem session lifecycle
5. Datagram relay - both message-mode and blocking `recv_packet`
6. Built-in UDP proxy handler with `allow` / `resolver` policy hooks
7. Capsule extension dispatch (in + out, both sides)
8. Graceful close, oversize-payload protection, stream-reset handling
9. Compliance CT suite (handshake, echo, UDP proxy round-trip,
   capsules, concurrency, load, boundary)
10. External-peer interop suite scaffolding (skippable)
11. Two runnable examples

## Deferred to follow-up releases

- **Proxy chaining + authorization hooks** - client option to dial one
  proxy through another; per-tunnel auth callback. Pencilled in for
  v0.2.
- **RFC 9484 (Proxying IP in HTTP)** - distinct protocol, separate
  library on top of `masque`.
- **HTTP/2 fallback** - RFC 9298 targets HTTP/3 here; HTTP/2 datagram
  support (RFC 9297 §2.2) is not planned.
