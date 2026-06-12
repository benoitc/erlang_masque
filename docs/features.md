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
| 9484 §3 - CONNECT-IP URI template | `{target}` + `{ipproto}` in Level-1 path and Level-3 query forms | Implemented (`masque_uri_template`, `masque_uri_ip`) |
| 9484 §4 - CONNECT-IP handshake | `:protocol=connect-ip`, `capsule-protocol: ?1` enforcement | Implemented (`masque_ip_client_session`, `masque_ip_server_session`) |
| 9484 §4.7 - Control-plane capsules | `ADDRESS_ASSIGN` (0x01), `ADDRESS_REQUEST` (0x02), `ROUTE_ADVERTISEMENT` (0x03); ordering + disjointness + protocol-0 overlap validation | Implemented (`masque_ip_capsule`) |
| 9484 §6 - Datagram framing | Context-0 = full IP packet; unknown contexts silently dropped | Implemented (`masque_datagram` reused) |
| 9484 §7 - ICMP error synthesis | ICMPv4 (RFC 792) and ICMPv6 (RFC 4443) error builders with correct invoking-packet truncation | Implemented (`masque_icmp`) |
| 9484 §4.7.1 - Mandatory DNS resolution | Resolve hostname targets before 2xx; resolved addresses into initial `ROUTE_ADVERTISEMENT` | Implemented (listener-owned, `resolver` option) |
| 9298 + 9484 over HTTP/1.1 | `Upgrade: connect-udp` / `Upgrade: connect-ip` + capsule-protocol handshake; RFC 9297 capsules on the upgraded TLS socket | Implemented (`masque_h1_client_session`, `masque_ip_h1_client_session`, `masque_h1_server`, session-sup) |
| 9110 §9.3.6 - Classic CONNECT-TCP over HTTP/1.1 | `CONNECT host:port HTTP/1.1` + `200 Connection Established`; IPv6 authority (`[::1]:443`); `Proxy-Authorization` passthrough | Implemented (`masque_tcp_h1_client_session`, `masque_tcp_h1_server_session`) |
| Apple-style transport race | h3 -> h2 -> h1 with staggered head-starts (`prefer_timeout_ms`, `h1_prefer_timeout_ms`) | Implemented (`masque_racer`) |
| Upstream connection pooling | Opt-in `upstream_pool => true`; one pooled h2 / QUIC conn carries many tunnels as streams; fingerprinted by `verify` / `cacerts` / `ssl_opts` / `alpn`; h1 bypasses | Implemented (`masque_upstream_pool`, `masque_upstream_owner`) |
| Client-side request headers | `connect_opts()` `request_headers` for auth schemes that ride on the handshake (Privacy Pass `Authorization: PrivateToken ...`, proxy metadata) | Implemented across all six session modules |
| Server-side rejection challenge | `{reject, Error, ExtraHeaders}` return from `accept/1` attaches `WWW-Authenticate` / `Retry-After` / custom headers to the HTTP response | Implemented (all three server modules) |

## Delivered in v0.7

- **Connect-UDP-Bind** (draft-ietf-masque-connect-udp-listen-11):
  multi-peer UDP proxying as a sibling of CONNECT-UDP. Uses the
  existing `connect-udp` URI template plus a `Connect-UDP-Bind: ?1`
  request and response header to negotiate. Supports both unscoped
  binds (the bind socket on the proxy can talk to any peer the
  operator's policy allows) and scoped binds (proxy enforces the
  peer at the data plane).
- **Per-session UDP bind socket** on the proxy: opens a `gen_udp`
  socket per tunnel, advertises one or more public addresses on
  the response via `Proxy-Public-Address` (RFC 9651 list of String
  IP-port tuples), gates inbound packets via a `peer_filter_fun`
  hook (default rejects RFC 1918 / link-local / multicast,
  loopback allowed for testability), and runs an optional
  `scrub_fun` policy hook for DDoS / per-packet filtering (default
  identity).
- **Compression Contexts** capsules (provisional IANA codes 0x11 /
  0x12 / 0x13): `COMPRESSION_ASSIGN`, `COMPRESSION_ACK`,
  `COMPRESSION_CLOSE` encode/decode, with strict draft-11 wire
  validation (zero context-id rejected, IP Version 0 omits IP/Port,
  `COMPRESSION_CLOSE` with id 0 always malformed).
- **Per-session compression table** with parity (client-even /
  proxy-odd context-IDs), duplicate-id detection, per-tuple
  uniqueness with cross-side conflict resolution (close the
  proxy-opened context) and same-side conflict treated as
  malformed, singleton-uncompressed invariant on both sides,
  ACK accounting (`pending_ack` -> `installed`), close removes
  entries from id and tuple indexes, and bounded size for
  hostile-peer protection.
- **Listener / dispatch** wired across h1, h2, h3: opt-in via
  `accept_bind => true` (default `false`, so existing UDP / TCP /
  IP listeners are unchanged); `bind_handler` opt picks the
  module (default `masque_udp_bind_proxy_handler`). The matcher
  reads `Connect-UDP-Bind` before choosing the URI matcher so the
  percent-encoded `*` wildcard for unscoped bind only flows the
  bind path; legacy CONNECT-UDP requests are bit-for-bit unchanged
  when the header is absent or invalid.
- **Public API** for clients: `masque:bind_connect/3`,
  `masque:send_to/3`, `masque:assign_compression/2`,
  `masque:open_uncompressed_context/1`,
  `masque:close_compression/2`,
  `masque:proxy_public_address/1`.
  Owner messages: `{masque_bind_packet, _, Peer, Bytes}`,
  `{masque_compression_assigned, _, ContextId, Peer}`,
  `{masque_compression_acked, _, ContextId}`,
  `{masque_compression_closed, _, ContextId}`.
- **Documentation**: new `docs/connect_udp_bind.md` (quickstart,
  wire format, coexistence with RFC 9298, compression policy
  seam).

## Delivered in v0.6

- **Drop-reason telemetry**: inbound packet gating split into a
  `accept_inbound/2` helper that attributes drops to a specific axis
  (`bcp38`, `scope_target`, `scope_ipproto`, `malformed`,
  `forward_drop`, ...). New simple counters in `masque_metrics`
  (`ip_drop_inc/1`, `ip_drop_count/1`) backed by the OTP `counters`
  module - independent of `instrument_meter` so tests and embedded
  consumers can read drop counts without booting the meter system.
- **`lifecycle_fun` callback**: the default proxy handler now emits
  `address_assigned`, `address_released`, `route_advertised`, and
  `packet_dropped` events to an optional callback in `handler_opts`,
  with matching simple counters in `masque_metrics`.
- **Cross-session address registry**: new `masque_ip_session_registry`
  (gen_server child of `masque_sup`) maps every assigned address or
  prefix to the session pid that serves it, with longest-prefix
  match by interval inclusion and overlap-rejecting registration.
  Sessions exiting abruptly are gc-ed via process monitors. The
  default proxy handler now releases its allocations on `terminate/2`.
- **Out-of-band packet injection**: `masque_ip:inject_packet/2`
  pushes packets from any process into the right server session
  for delivery to the connected client; handled across h1/h2/h3.
- **Per-session prefix assignments**: the default allocator honours
  the requested prefix length (clamped to `min_assignable_prefix`)
  and walks the pool in stride-aligned blocks. Default
  `min_assignable_prefix` is `#{4 => 32, 6 => 128}` so existing
  configurations keep host-route semantics.
- **Rich `forward_fun` actions**: in addition to the historical
  return shapes, `forward_fun` may return
  `{actions, [forward_action()], State}` to emit multiple effects
  (`{send_ip_packet, _}`, `{icmp_error, {Kind, Spec, Invoking}}`,
  `{drop, atom()}`) in one call; `{drop, _}` is intercepted by the
  handler to bump the drop counter and lifecycle hook without
  putting anything on the wire.
- **RFC 9484 / 9298 / 9931 compliance fixes**: URI-template
  hardening (rejects unsupported RFC 6570 operators, level >3
  modifiers, non-ASCII input), prefix-targets must be canonical
  (host bits zero), per-route start =< end validation,
  ADDRESS_ASSIGN/REQUEST canonical-prefix enforcement, malformed
  control-capsule abort on the IP client, RFC 9931 close-on-
  rejected H1 CONNECT, optional `target` / `ipproto` URI variables,
  inbound packet scoping with IPv6 extension-header walking.

## Delivered in v0.5

- CONNECT-IP (RFC 9484): extended CONNECT with `:protocol=connect-ip`
  over HTTP/3 and HTTP/2. Both endpoints can send every control-plane
  capsule (site-to-site support per §8.2).
- Full bidirectional control plane: typed client API for
  `request_addresses/2`, `assign_addresses/2`, `advertise_routes/2`,
  `send_ip_packet/2`, `ip_info/1`; handler actions for the same on
  the server side.
- Default `masque_ip_proxy_handler` with address-pool allocator
  (round-robin over a configured prefix), listener-owned DNS
  resolution before `accept/1`, BCP-38 source-address filter, and a
  pluggable `forward_fun`.
- ICMP error synthesis (`masque_icmp`): ICMPv4 / ICMPv6 builders for
  `Destination Unreachable`, `Packet Too Big` (v6), and
  `Time Exceeded` with RFC-compliant invoking-packet truncation
  (1232 B on v6, 548 B on v4) and pseudo-header checksums.
- Transport-generic IP sessions: one
  `masque_ip_client_session` and one `masque_ip_server_session`
  serve both H3 and H2 by dispatching on a `transport` field, mirroring
  the TCP session architecture.

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
  tunnels with zero client-side changes. Wire up a chain listener
  on any transport via `masque:start_chain_listener/2` (h3),
  `start_chain_listener_h2/2` (h2), or `start_chain_listener_h1/2`
  (h1); start one per transport and clients race them.

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
- **CONNECT-IP TUN device integration** - phase 2 wires
  `erlang-tun` as an optional dep so a proxy can bridge tunnels to a
  real kernel routing table. The phase-1 default handler exposes a
  `forward_fun` seam; `masque_ip_tun_proxy_handler` takes over from
  there without API change.
- **Private Relay-style relay** - separate application on top of
  `masque` with two-hop wiring, Privacy Pass auth, policy engine.
