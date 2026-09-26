# Changelog

All notable changes to `masque` are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- TLS: every client transport (h2, udp-bind on h1/h2/h3, pooled h2 in
  the racer, chain upstreams) now uses `verify_peer` with the system CA
  store, hostname check and SNI by default. **Breaking**: self-signed
  setups need `verify => verify_none` or `cacerts`.
- TLS: `cacerts` is honoured on h1 clients.
- CONNECT-IP: `'*'` and private prefix targets are rejected unless
  `allow_private => true`. **Breaking** default.
- CONNECT-IP: prefix targets drop packets to private destinations;
  hostname targets only reach their advertised routes.
- CONNECT-IP: packets from unassigned sources are dropped unless
  `allow_private`; sources are matched against the whole assigned
  prefix.
- CONNECT-IP: `masque_ip:is_public/1` also rejects `::/96`, `2002::/16`,
  `fec0::/10`, `3fff::/20` and `5f00::/16`.
- CONNECT-IP: the h1 listener resolves hostname targets like h3 and h2.
- udp-bind: the default peer filter uses `masque_ip:is_public/1`;
  loopback is dropped unless `allow_loopback`, other non-public peers
  unless `allow_private`; IPv4-mapped peers are checked as IPv4.
  **Breaking** default.
- Chain: relay loops are detected through a `via` header and rejected
  with 508 and Proxy-Status `proxy_loop_detected`.
- URI parsing: strict dotted-quad IPv4, no zone ids, digits-only ports,
  ipproto and prefix lengths, numeric-looking hostnames rejected, no
  double decoding of `%2A`.
- At most 64 pending ADDRESS_REQUEST ids per CONNECT-IP session.

### Changed

- Documentation reorganised into Understand / Use / Change / Reference
  levels under `docs/`, with new concept, architecture, internals,
  testing, debugging and how-to pages, `CONTRIBUTING.md` and
  `test/README.md`. `docs/design.md`, `usage.md`, `api.md`,
  `connect_ip.md`, `connect_udp_bind.md`, `features.md` and `relay.md`
  are replaced by the new pages; version history from `features.md`
  moved here.
- Module docs are `-moduledoc` / `-doc` attributes in Markdown. Only
  `masque`, the handler behaviour and built-in handlers, the codecs, the
  URI modules, `masque_ip`, `masque_metrics` and `masque_errors` appear
  in the generated docs; the other modules are internal. `masque`
  exports the `h3_handler_fun()` and `connection_handler_fun()` types.
- Erlang/OTP 29 is now the only supported release (`minimum_otp_vsn`
  in `rebar.config`); CI runs tests, lint and dialyzer on OTP 29 only.
- Bumped `quic` 1.3.0 -> 2.0.1 and `h1` (erlang_h1) 0.6.2 -> 0.9.1.
- Bumped `h2` 0.9.0 -> 0.12.3.
- Bumped `instrument` 1.1.3 -> 1.1.5.
- Removed the unused `hackney` dependency.
- A handler callback that raises after `init/2` stops the session with
  `{handler_crash, Reason}` and resets the stream (closes the socket on
  h1), instead of logging and keeping the old handler state. Handler
  crashes are logged through `logger`. **Breaking**.
- `masque.tunnels.total`, `masque.tunnels.active` and
  `masque.tunnel.duration_ms` cover every server session (UDP, TCP, IP
  and udp-bind on h3, h2 and h1).
- Every listener copies the same top-level options into `handler_opts`
  (`handler_opt_keys/0` in `masque_server`); h2 now also copies `resolver`,
  `allow`, `family`, `connect_timeout` and `socket_opts`.
- `transports` must be a list of `h3`, `h2` and `h1`; anything else
  returns `{error, {invalid_opts, {transports, T}}}` instead of crashing
  the caller or dropping unknown entries. **Breaking**.
- Client sessions answer calls they do not support with
  `{error, not_ready}` (connecting), `{error, not_supported}` (open) or
  `{error, closing}` instead of crashing or leaving the caller waiting.
- `upstream_pool` is ignored for Connect-UDP-Bind (no pooled connection
  is checked out); pooled h3 owners default to 100 streams and report
  full on a transport `stream_limit` error.
- The h2 server now reads `:authority` and `:scheme` from the request
  headers and no longer falls back to the `host` header or a hard-coded
  `https` scheme. Both pseudo-headers are required, matching the h3 server.
- CONNECT-TCP: no `capsule-protocol` header in either direction; a 2xx
  carrying it fails with `{error, {bad_response, capsule_protocol}}` and
  `send_capsule/3` returns `{error, not_supported}`. **Breaking**.
- CONNECT-TCP: `{masque_closed, Sess, peer_fin}` means the peer finished
  sending; the session stays writable until `shutdown_write/1` or
  `close/1`. A half-closed tunnel idles out after 30 s (`eof_timeout`).
  h1 cannot half-close (OTP `ssl` limitation). **Breaking**.
- CONNECT-TCP: upstream errors and handler crashes reset the stream with
  `H3_CONNECT_ERROR` / `CONNECT_ERROR` instead of a FIN.
- CONNECT-TCP: a tunnel write that fails or stays blocked for 30 s resets
  the tunnel instead of dropping data.
- URI templates: adjacent variables, a variable before `{?...}` and a
  non-terminal `{?...}` are rejected at parse time; query-form templates
  require an exact path; IP templates only allow `target` and `ipproto`;
  udp-bind templates without host/port return `{error, bad_template}`.
  **Breaking**.
- `masque:connect/3` and `bind_connect/3` return `{error, Reason}` on
  dial failure instead of exiting, with the raw reason
  (`{connect, econnrefused}`, TLS alerts, `handshake_timeout`,
  `bad_upgrade_response`, `headers_too_large`, `bad_status_line`).
- h1 clients use one overall handshake deadline.
- `recv/2` returns unread data after the peer closes, then
  `{error, closed}`; it returns `{error, closed}` on a dead session. A
  closed queue-mode session lingers at most 30 s.
- Queue-mode datagrams are dropped once `rx_queue_limit` is reached; a
  CONNECT-TCP session ends with `{error, rx_overflow}`.
- Proxy handlers read sockets in `{active, N}` mode (`active_n`, TCP 16,
  UDP and udp-bind 32).
- The h1 server requires `Connection: Upgrade` on upgrade requests.
- Unknown `{reject, _}` reasons from `accept/1` map to 502.
- The router finalizes sessions asynchronously; handler output produced
  before the 2xx is held and sent after it.
- Upstream pool checkout returns `{error, timeout | {dial_failed, R} |
  {dial_crashed, {C, R}}}` instead of exiting, and dials more
  connections per fingerprint when owners hit `max_streams`.
- `release/3` in `masque_ip_session_registry` only frees ranges owned by the
  caller; `release/4` takes the owner pid.
- `masque_capsule:known/1` returns true for every implemented capsule
  type.
- ROUTE_ADVERTISEMENT validation is O(n log n).

### Added

- `rx_queue_limit` connect option (default 1000 items); `masque:info/1`
  reports `rx_dropped` on datagram sessions.
- `checkout_timeout_ms` in `upstream_pool_opts` (default 60 s).
- `active_n` handler option on the TCP, UDP and udp-bind proxy handlers.
- CONNECT-IP forwarding: TTL / hop-limit decrement with ICMP Time
  Exceeded, `mtu` handler option (default 1500) with Packet Too Big /
  Fragmentation Needed, `ttl_zero` and `mtu_exceeded` drop counters.
- CONNECT-IP lifecycle events `peer_address_assigned` and
  `peer_routes_advertised`.
- `masque_chain_handler` forwards ADDRESS_REQUEST upstream and relays
  the prompted ADDRESS_ASSIGN back.
- `via_token` in chain `handler_opts` (one per chain listener by
  default), `masque_chain_handler:new_token/0` and `node_token/0`.
- udp-bind `max_pending_compression_responses` option (default 16).
- udp-bind drop counters: `masque_metrics:setup_bind_counters/0`,
  `bind_drop_inc/1`, `bind_drop_count/1`, `bind_drop_reasons/0`.
- `masque_ip:resolve_target/3`, `masque_ip_packet:scope_check/4`,
  `decrement_ttl/1`, `checksum/1`, `upper_layer/1`,
  `masque_icmp:frag_needed/2`, `is_error/1`,
  `masque_chain_handler:handle_address_request/2`.
- `client_opts/3` in `masque_tls` with an explicit ALPN list.
- `masque_uri:parse_ip_literal/1`, `parse_uint/2`,
  `masque_uri_template:var_names/1`.
- `masque_compression_table:install/3` (reports `close_proxy_id`
  conflicts), `mark_uncompressed_closed/1` and the
  `{error, uncompressed_closed}` result.
- `masque_ip_capsule` decode errors `non_canonical_prefix`,
  `route_range_reversed`, `{unknown_capsule_type, N}`; codec error atoms
  `bad_ip_version` and `unknown_capsule_type`.

### Fixed

- h1 and h2 clients dial an IPv6 literal proxy (`https://[::1]:443`)
  without `ssl_opts => [inet6]`.

- The UDP and TCP proxy handlers accept a resolver returning
  `{ok, [Address]}` (the listener-level shape); a listener `resolver`
  no longer causes 502 or skips the private-address check on TCP.
  `masque_ip:is_public/1` returns `false` for anything that is not an
  address.
- A peer reset of an h3 stream whose session is still starting answers
  the listener at once instead of after 30 s, and no longer leaves a
  running session behind.
- The udp-bind h1 server session applies the h3/h2 rules: cross-side
  conflict handling, the post-close rule, the pending-assign limit, the
  `{compression_assign, {IP, Port}}` action, drop counters and handler
  crash handling.
- `masque.tunnels.active` no longer drifts below zero for IP and h1 TCP
  tunnels, nor above it when an h1 udp-bind session fails in init.
- udp-bind clients bracket IPv6 proxy hosts in `:authority` / `Host`
  and drop `request_headers` that are reserved or contain CR/LF.
- A connecting udp-bind client session answers `info/1` and `close/1`.

- Sessions and upstream sockets end on connection close (h3, h2),
  GOAWAY, peer stream reset and a clean FIN.
- Client streams at or above a GOAWAY id close with `goaway`; lower ids
  keep running.
- Bytes buffered before a stream is claimed are no longer dropped.
- Handler output produced before the h3 2xx (target bytes, datagrams,
  capsules, IP packets) is held until the stream is finalized.
- udp-bind over h2 works end to end; udp-bind sessions survive messages
  before finalize, reset the stream on handler crashes, and clients
  close their connection on stop.
- udp-bind `send_to/3` uses the client's own uncompressed context.
- `[h3, h2]` racing works for `bind_connect/3`.
- h2 tunnel slots are released when a session fails to start.
- Server sessions stop only on their own router `'DOWN'`; other
  `'DOWN'` messages reach the handler.
- CONNECT-IP address allocation skips addresses already in the registry,
  so sessions sharing a pool get distinct addresses.
- CONNECT-IP never answers an ICMP error with an ICMP error.
- Chains relay upstream 508 as 508 and pass CONNECT-TCP half-close
  through; h1 Proxy-Status maps `loop_detected` and `upstream_timeout`.
  An h1-to-h1 self-loop still surfaces as 502 because the h1 client
  exits on the server's close.
- The racer leaves no stray messages, workers or sessions after a race,
  delivers events that arrive right after the 2xx to the owner, and
  reports the real failure reason.
- The upstream pool survives dial crashes and owner deaths during a dial.

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

## [0.6.0]

No release tag or date was recorded for this version; the entries below
were recovered from the former feature matrix (`docs/features.md`).

### Added

- CONNECT-IP drop-reason telemetry: inbound gating attributes drops to
  `bcp38`, `scope_target`, `scope_ipproto`, `malformed`, `forward_drop`
  and others, counted by `masque_metrics:ip_drop_inc/1` and
  `ip_drop_count/1` (OTP `counters`, independent of `instrument`).
- `lifecycle_fun` callback in the default IP proxy handler
  (`address_assigned`, `address_released`, `route_advertised`,
  `packet_dropped`) with matching counters.
- `masque_ip_session_registry`: maps assigned addresses and prefixes to
  the serving session, longest-prefix lookup, cleanup on session exit.
- `masque_ip:inject_packet/2`: push packets from any process to the
  client through the right server session (h1, h2, h3).
- Per-session prefix assignments honouring the requested prefix length,
  clamped by `min_assignable_prefix`.
- `forward_fun` may return `{actions, [forward_action()], State}`.

### Fixed

- URI template hardening, canonical prefix targets, route range
  validation, ADDRESS_ASSIGN/REQUEST canonical prefixes, malformed
  control capsule abort on the IP client, close-on-reject for rejected
  h1 CONNECT, optional `target` / `ipproto` variables, inbound packet
  scoping with IPv6 extension headers.

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
- RFC 9484 §8 MTU check on the H3 client handshake - aborts with
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

