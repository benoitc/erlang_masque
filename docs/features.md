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
| 9297 §3.2 - DATAGRAM capsule on HTTP/2 | UDP payloads as capsules on the request body stream | Implemented (`masque_h2_*`) |
| 9220 - Extended CONNECT in HTTP/3 | `:protocol` negotiation and `SETTINGS_ENABLE_CONNECT_PROTOCOL` | Delegated to `quic_h3` |
| 8441 - Extended CONNECT in HTTP/2 | `:protocol` negotiation | Delegated to `erlang_h2` |

## Delivered in v0.4

- CONNECT-TCP (draft-ietf-httpbis-connect-tcp): TCP tunneling alongside
  UDP. One listener serves both protocols via `:protocol` dispatch.
- Unified API: `masque:send/2`, `masque:recv/2`, `{masque_data, Sess, Data}`
  for both UDP and TCP tunnels.
- `masque_tcp_proxy_handler`: bridges CONNECT-TCP tunnels to real TCP
  connections via `gen_tcp`.
- `masque_tcp_client_session` + `masque_tcp_server_session` for TCP.
- Scaling: configurable h2 `acceptors`, h3 `reuseport`, per-protocol
  session supervisors.
- Dual-protocol h2 server dispatch.

## Delivered in v0.3

- Server-side proxy chaining (`masque_chain_handler`): an Ingress
  listener opens a MASQUE client session to an upstream Egress proxy
  and relays datagrams both ways. Enables Private Relay-style two-hop
  tunnels with zero client-side changes.

## Delivered in v0.2

- HTTP/2 transport: client session (`masque_h2_client_session`),
  server + per-tunnel session (`masque_h2_server`,
  `masque_h2_server_session`), supervised under
  `masque_h2_session_sup`.
- Apple-style transport racing (`masque_racer`): h3 head-start,
  h2 fallback, first 2xx wins.
- `masque:start_listener_h2/2` and `masque:h2_handlers/1` for h2
  listeners and integration with user-owned h2 servers.

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

## Security posture (v0.1)

- Handler `init/2` runs before the `200` handshake response, so a
  tunnel only commits once DNS and socket setup have succeeded.
- `masque_udp_proxy_handler` calls `gen_udp:connect/3` on the target
  so the kernel drops any packet whose source does not match.
- UDP payloads are clamped to the RFC 9298 §5 limit of 65527 bytes
  in both directions.
- Malformed or truncated capsules trigger an HTTP/3 stream reset
  with `H3_MESSAGE_ERROR` (RFC 9297 §3.3) instead of a silent close.
- The incoming capsule buffer is bounded (default 1 MiB, tunable
  via `handler_opts.max_capsule_size`).
- Rejected handshakes carry a `Proxy-Status` header (RFC 9209)
  naming the failure class (`dns_error`, `connection_timeout`,
  `destination_ip_prohibited`, `http_protocol_error`, ...).
- Client validates the handshake response: a 2xx carrying
  `content-length` or `content-type` is rejected as malformed per
  RFC 9297 §3.4.

## Deferred to follow-up releases

- **Per-tunnel authorization hooks** - pluggable auth callback
  beyond `accept/1` (e.g. Privacy Pass token verification).
- **Client-side proxy chaining** - client controls both hops via a
  virtual-transport adapter (server-side chaining is done in v0.3).
- **RFC 9484 (Proxying IP in HTTP)** - distinct protocol, separate
  library on top of `masque`.
- **Private Relay-style relay** - separate application on top of
  `masque` with two-hop wiring, Privacy Pass auth, policy engine.
- **HTTP/1.1 Upgrade** - RFC 9298 also defines an HTTP/1.1 path;
  this library covers h3 and h2 only.
