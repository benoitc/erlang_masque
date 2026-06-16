# Changelog

All notable changes to `masque` are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Bumped `h2` 0.9.0 -> 0.10.2.
- The h2 server now reads `:authority` and `:scheme` from the request
  headers and no longer falls back to the `host` header or a hard-coded
  `https` scheme. Both pseudo-headers are required, matching the h3 server.

## [0.7.0] - 2026-06-13

### Added

- HTTP/1.1 fallback for all three tunnel protocols. CONNECT-UDP
  (RFC 9298) and CONNECT-IP (RFC 9484) use HTTP Upgrade +
  RFC 9297 capsules; CONNECT-TCP uses classic HTTP CONNECT
  (RFC 9110 §9.3.6). Opt in per client call with
  `masque:connect(URL, Target, #{transports => [h3, h2, h1], ...})`
  and on the server with `masque:start_listener_h1/2`. The racer
  stages a tertiary h1 attempt after `h1_prefer_timeout_ms`
  (default 500 ms) behind the existing h2 head-start, giving
  Apple-style transport racing over classic HTTPS paths.
- `proxy_authorization` client opt for classic CONNECT-TCP over h1
  (`Proxy-Authorization` header passthrough).
- `masque_uri:build_authority/2` and `masque_uri:parse_authority_form/1`
  helpers. IPv6 literals get bracketed on outbound authorities and
  unwrapped on CONNECT request-targets.
- `masque:start_chain_listener_h2/2` and `start_chain_listener_h1/2`
  complete the chain-listener trio (h3 was already there). A
  Private-Relay-shaped ingress now takes the same one-liner shape
  on every transport.
- CONNECT-IP support in `masque_chain_handler`. Ingress tunnels with
  `protocol => ip` forward IP packets both ways, forward the
  egress's initial `ROUTE_ADVERTISEMENT`, and forward unprompted
  `ADDRESS_ASSIGN` entries (request_id = 0). Prompted ADDRESS_ASSIGN
  forwarding requires request-id remapping and stays out of this
  change; a client that expects the chain to round-trip a
  client-initiated `ADDRESS_REQUEST` has to wait for that follow-up.
- `examples/two_hop_relay.erl`: a standalone runnable two-hop relay
  (ingress + egress on loopback, self-signed certs, all three
  transports, UDP + TCP round-trip helpers). Demonstrates the
  Apple-Private-Relay shape as a 300-line reference.
- Opt-in upstream connection pooling for h2 / h3 MASQUE tunnels.
  Pass `upstream_pool => true` in `connect_opts()` (or in
  `upstream_opts` on `masque_chain_handler`) to share one pooled
  transport connection across many tunnels; each tunnel rides a
  fresh stream. h3 conns are always opened datagram-capable so
  CONNECT-UDP / -TCP / -IP can coexist on a single QUIC owner.
  Pool keys fingerprint `verify` / `cacerts` / `ssl_opts` / `alpn`
  so callers with different trust or ALPN stay isolated. h1
  bypasses the pool (1-tunnel-per-socket). Default behaviour is
  unchanged when the flag is absent.
- Client-side `request_headers` option on `masque:connect/3`.
  Prepends caller-supplied headers to the CONNECT (or GET+Upgrade
  on h1) request, so auth schemes that ride on the handshake
  (Privacy Pass `Authorization: PrivateToken ...`, proxy metadata)
  have a library-native hook. Reserved pseudo-headers are dropped
  and CR/LF in h1 values is refused to prevent header injection.
- Handler-side `{reject, Error, ExtraHeaders}` return form from
  `accept/1`. Lets an ingress attach challenge headers to rejected
  handshakes (`WWW-Authenticate: PrivateToken ...`, `Retry-After`,
  etc.) without leaving the library contract. Caller-supplied
  headers override the library's defaults on key collision. Works
  on all three transports.

### Changed

- `masque:start_chain_listener/2` now also sets the `tcp_handler`
  and `ip_handler` to `masque_chain_handler` so every protocol the
  client might pick is chained upstream. Previously only the UDP
  path was chained and TCP / IP fell through to the direct
  proxy handlers; callers that want the old split behaviour can
  still call `masque:start_listener/2` directly and set each
  handler. Same change applies to the new `_h2' and `_h1'
  wrappers.
- Build and test suite now run on OTP 29. The deprecated prefix
  `catch` operator was migrated to `try ... catch ... end` across
  the session modules. Dependencies bumped: `h1` moved to the hex
  `erlang_h1` 0.6.2 package, `h2` to 0.9.0, `instrument` to v1.1.3
  (OTP 29 support), `hackney` to 4.3.0, and `proper` to 1.5.0 for
  tests.

### Fixed

- Chained CONNECT-IP no longer drops the egress's initial
  `ROUTE_ADVERTISEMENT`. The ingress IP server session could
  forward the advertisement before it sent its own 200 and claimed
  the downstream stream, so the capsule went to a not-yet-open
  stream and was lost. Handler actions produced before finalize are
  now buffered and flushed in order once the stream is open.

## [0.5.0] - 2026-04-19

### Added

- **CONNECT-IP (RFC 9484)** over HTTP/3 and HTTP/2. One listener can
  now serve CONNECT-UDP, CONNECT-TCP, and CONNECT-IP simultaneously;
  each has its own handler/template option pair (`ip_handler` +
  `ip_uri_template`).
- Bidirectional control plane per RFC 9484 §5 (both endpoints can
  send every capsule; site-to-site pattern from §8.2 works without
  workarounds): `masque:send_ip_packet/2`,
  `masque:request_addresses/2`, `masque:assign_addresses/2`,
  `masque:advertise_routes/2`, `masque:ip_info/1`.
- `masque_ip_capsule`: codec for `ADDRESS_ASSIGN` (0x01),
  `ADDRESS_REQUEST` (0x02), `ROUTE_ADVERTISEMENT` (0x03) with full
  §4.7.3 validation (ordering, disjointness, protocol-0 overlap).
- Generic URI-template engine `masque_uri_template` (Level-1 path
  placeholders, Level-3 `{?var1,var2}` query form, absolute-URI
  awareness); `masque_uri` re-seated on it with unchanged public
  API; new `masque_uri_ip` for CONNECT-IP (client-absolute,
  server-side path+query match pattern).
- Transport-generic IP sessions
  (`masque_ip_client_session`, `masque_ip_server_session`) that
  dispatch H2 / H3 on a single `transport` field, mirroring the TCP
  session architecture rather than cloning per transport.
- Default `masque_ip_proxy_handler`: round-robin address-pool
  allocator, listener-owned DNS resolution before `accept/1`
  (hostnames resolved, addresses stitched into `req()`,
  SSRF/BCP-38 policy runs on the resolved list), initial
  `ROUTE_ADVERTISEMENT` from config + resolution, BCP-38
  source-address filter on the inbound data plane, pluggable
  `forward_fun`.
- `masque_icmp`: RFC 792 + RFC 4443 error builders with correct
  invoking-packet truncation (548 B ICMPv4, 1232 B ICMPv6) and
  IPv6 pseudo-header checksum. Session `{icmp_error, ...}` action
  emits the resulting IP packet as a context-0 datagram.
- RFC 9484 §8 MTU check on the H3 client handshake — aborts with
  `{mtu_too_low, Got, 1280}` if the negotiated QUIC datagram size
  can't carry a 1280-byte IPv6 packet.
- Client `connect/3` validates target shape vs. protocol and
  forces `capsule-protocol: ?1` on CONNECT-IP (no way to accidentally
  dial without it).
- 9 ICMP eunit tests, 29 URI eunit tests, 24 capsule/datagram
  eunit tests, 3 CT cases for H3 CONNECT-IP, 3 CT cases for H2
  CONNECT-IP, 7 CT cases for RFC 9484 normative compliance.
- `docs/connect_ip.md` usage guide with the §-mapped compliance
  table; `examples/ip_echo.erl` runnable sample.

### Changed

- `listener_opts()` public type corrected: `cert` / `key` instead
  of the stale `certfile` / `keyfile` (the real listeners have
  read the former for several releases).
- `masque_handler:req()` extended with `protocol => ip`,
  `ip_target`, `ip_ipproto`, `resolved_addresses` keys.
- `masque_h2_session_sup` grew an IP branch so H2 CONNECT-IP
  tunnels land on the IP session module (previously defaulted to
  the UDP session, which silently dropped IP capsules).

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

