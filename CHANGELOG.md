# Changelog

All notable changes to `masque` are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [0.4.0] - 2026-04-17

### Added

- CONNECT-TCP (draft-ietf-httpbis-connect-tcp) alongside CONNECT-UDP.
  One listener serves both protocols; the `:protocol` pseudo-header
  selects the handler. Client picks `protocol => tcp | udp` in opts.
- Unified API: `masque:send/2`, `masque:recv/2`, `{masque_data, Sess, Data}`
  for both protocols. No backward-compat aliases.
- `masque_tcp_proxy_handler`: bridges CONNECT-TCP tunnels to real
  TCP connections via `gen_tcp`.
- `masque_tcp_client_session`: client TCP session over h3 or h2.
- `masque_tcp_server_session`: per-tunnel TCP server session.
- 4 new CT cases: `tcp_echo_round_trip`, `tcp_large_transfer`,
  `tcp_target_closes`, `tcp_and_udp_same_listener`.

### Changed

- `send_packet`/`recv_packet`/`{masque_packet,...}` replaced by
  `send`/`recv`/`{masque_data,...}` everywhere. Breaking change.
- Server dispatches by `:protocol` to `udp_handler` or `tcp_handler`.

## [0.3.0] - 2026-04-17

### Added

- Server-side proxy chaining: `masque_chain_handler` relays each
  tunnel through an upstream MASQUE proxy, enabling two-hop
  topologies (Private Relay pattern). Convenience wrapper
  `masque:start_chain_listener/2`.
- 2 new CT cases: `chain_round_trip` (full Client-Ingress-Egress-UDP
  path) and `chain_upstream_failure_returns_502`.

## [0.2.0] - 2026-04-17

### Added

- HTTP/2 transport (`masque_h2_client_session`, `masque_h2_server`,
  `masque_h2_server_session`) using Extended CONNECT (RFC 8441) and
  DATAGRAM capsules (RFC 9297 S3.2) on the request-body stream.
- Apple-style transport racing: `masque:connect/3` accepts
  `transports => [h3, h2]` (default) and gives h3 a 250 ms head
  start before launching h2 in parallel. First 2xx wins; the loser
  is cancelled. Tunable via `prefer_timeout_ms`.
- `masque:start_listener_h2/2` and `masque:h2_handlers/1` for
  dedicated h2 listeners and integration into user-owned h2 servers.
- `masque_h2_session_sup` (simple_one_for_one under `masque_sup`)
  for proper OTP supervision of h2 server sessions.
- `set_owner/2` gen_statem call on both session modules so the
  transport racer can transfer ownership after a winning handshake.
- `erlang_h2` 0.4.0 as a required dependency (tag-pinned).

## [0.1.0] - 2026-04-16

First release. RFC 9298 CONNECT-UDP over HTTP/3, client + server.

### Added

- RFC 9298 Extended CONNECT handshake server and client, built on
  `erlang_quic`'s `quic_h3` stack.
- Client API on `masque`: `connect/2,3`, `send_packet/2,3`,
  `recv_packet/2`, `send_capsule/3`, `set_active/2`, `close/1`,
  `info/1`. Dual delivery modes: message (`{masque_packet, Sess, Data}`)
  and blocking queue.
- Server API: `start_listener/2` for a dedicated listener, plus
  `h3_handlers/1` returning `handler` and `connection_handler` funs
  for embedding MASQUE inside a user-owned `quic_h3:start_server/3`
  call. Optional `fallback` fun routes non-MASQUE requests to the
  caller.
- `masque_handler` behaviour: `accept/1` gate, `init/2`,
  `handle_packet/2`, `handle_capsule/3`, `handle_info/2`,
  `terminate/2`; actions include `send_packet`, `send_capsule`,
  `close_session`.
- Built-in `masque_udp_proxy_handler` that bridges tunnels to real
  UDP flows. Knobs: `allow`, `resolver`, `family`, `port`,
  `socket_opts`, `max_capsule_size`.
- URI template module accepting absolute `http(s)://…` or
  path-shaped templates; host validated as IPv4, IPv6, or LDH
  registered name (IPv6 zone IDs rejected).
- Per-HTTP/3-connection router (`masque_server_connection`) demuxing
  HTTP Datagrams and stream bytes to per-tunnel session processes
  keyed by stream-id; many tunnels per connection.
- Capsule protocol (RFC 9297) on both sides, with bounded incoming
  buffer (default 1 MiB).
- `Proxy-Status` (RFC 9209) header on handshake rejections
  (`dns_error`, `connection_timeout`, `destination_ip_prohibited`,
  `http_protocol_error`, …).
- Documentation: `README.md`, `docs/usage.md` (client modes, multiple
  tunnels, integration with an existing `quic_h3` server, handler
  lifecycle, error-code table), `docs/features.md` (RFC coverage
  matrix and security posture).
- Examples: `examples/udp_echo_proxy.erl`, `examples/udp_dig_client.erl`.
- Tests: 23 common_test cases (handshake, echo, real UDP round-trip,
  capsules, concurrency, load, boundary, integration, spoofing,
  oversize), 33 eunit cases, 3 PropEr properties on the codecs,
  skippable external-peer interop suite driven by `MASQUE_GO_BIN`.

### Security

- Handler `init/2` runs before the 2xx handshake response, so a
  tunnel only commits once DNS and socket setup have succeeded.
  Failures surface to the client as 502 instead of a silent broken
  tunnel.
- `masque_udp_proxy_handler` calls `gen_udp:connect/3` on the target
  so the kernel drops any inbound packet whose source does not match.
  A defensive application-level source check is in place as well.
- UDP payloads are clamped to the RFC 9298 §5 ceiling of 65527 bytes
  in both directions.
- Malformed or truncated capsules abort the HTTP/3 stream with
  `H3_MESSAGE_ERROR` (RFC 9297 §3.3).
- Client rejects 2xx handshake responses that carry `content-length`
  or `content-type`, or that drop the requested
  `capsule-protocol: ?1` header.
- UDP `udp_error` / `udp_closed` events, and terminal send failures
  (`closed`, `einval`, `enotconn`), close the tunnel promptly.

### Known limitations

- HTTP/3 only. HTTP/1.1 Upgrade and HTTP/2 transports are out of
  scope for v0.1.
- One QUIC connection per client session; multiplexing many tunnels
  through a single client-side QUIC handshake is a v0.2 item.
- MASQUE takes the H3 connection's `owner` slot, so it cannot share
  a single listener with another extension that also needs the
  owner (e.g. WebTransport). Use separate listeners on separate
  ports.
- Proxy chaining and per-tunnel authorization hooks deferred to
  v0.2.
- RFC 9484 (Proxying IP) will live in a separate library on top of
  `masque`, not here.
