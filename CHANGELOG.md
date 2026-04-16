# Changelog

All notable changes to `masque` are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

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
