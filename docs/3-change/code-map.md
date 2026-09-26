# Code map

This page lists every module in `src/`, grouped by role, with one line on what it does and when you would change it. Use it to find the file you need before you open anything; it is a reference, so scan it rather than read it. It assumes you know the layers from [architecture](../1-understand/architecture.md). Several module names are misleading; they are flagged in [Naming quirks](#naming-quirks).

## Public API

| Module | Role | Change this when... |
|---|---|---|
| `masque` | The facade: `connect/2,3`, `bind_connect/3`, send and receive calls, CONNECT-IP and bind calls, `start_listener*` / `stop_listener*`, `start_chain_listener*`, drain flags, `h3_handlers/1`, `h2_handlers/1`. Picks the session module per protocol and transport and runs single-transport dials. | you add or change a public function or a connect option, or add a protocol (the session-module table lives here and is repeated in `masque_racer`). |

## Extension-facing handlers

| Module | Role | Change this when... |
|---|---|---|
| `masque_handler` | The handler behaviour: callback specs, the `req()` map type, `default_accept/1`. It defines the contract only; the code that calls handlers is in each server session. | you add a callback or a field to the request map. |
| `masque_udp_proxy_handler` | Default CONNECT-UDP handler: opens a `gen_udp` socket to the target, relays both ways, applies `allow`, `resolver`, `family`, `active_n`. | you change how the proxy reaches UDP targets or its policy options. |
| `masque_tcp_proxy_handler` | Default CONNECT-TCP handler: opens a `gen_tcp` connection, relays bytes, maps FIN both ways, `eof_timeout` for half-closed tunnels. | you change TCP dialing, half-close or target policy. |
| `masque_ip_proxy_handler` | Default CONNECT-IP handler: address allocation from `address_pool`, route advertisement, source filtering, TTL and MTU handling, `forward_fun` and `lifecycle_fun` hooks. | you change the CONNECT-IP forwarding plane or address policy. |
| `masque_udp_bind_proxy_handler` | Default Connect-UDP-Bind handler: owns the bind `gen_udp` socket, builds `Proxy-Public-Address`, filters peers. Adds `handle_bind_packet/3`, which is not part of `masque_handler`. | you change bind socket policy or public address reporting. |
| `masque_chain_handler` | Relay handler: opens a MASQUE client tunnel to `upstream_proxy` and relays UDP, TCP and IP; `via` loop detection and the node token. | you change relay behaviour or loop detection. |

## Core architecture

| Module | Role | Change this when... |
|---|---|---|
| `masque_server` | HTTP/3 listener for all protocols: builds the `quic_h3` handler and `connection_handler`, validates requests, resolves targets, calls `accept/1`, asks the router to start sessions, formats rejects. | you change request validation, option lifting into `handler_opts`, or rejects on h3. |
| `masque_h2_server` | HTTP/2 listener for all protocols: same pipeline, starts sessions under the h2 session supervisors, per-connection tunnel counting in ETS. | the same as above for h2, or the h2 tunnel limit. |
| `masque_h1_server` | HTTP/1.1 listener: validates Upgrade (UDP, IP, bind) and classic CONNECT (TCP), starts sessions under the h1 supervisors, closes the connection on reject. | the same as above for h1. |
| `masque_server_connection` | The h3 router: one per h3 connection, owner of the connection, routes datagrams and stream data by stream id, starts and finalizes sessions, enforces `max_tunnels_per_connection` on h3. | you change h3 session start, finalize, or connection teardown. |
| `masque_racer` | Transport race for `connect` with several transports: head starts, winner selection, owner handoff; also `checkout_pool/2`. | you change racing, head-start timing, or pool checkout. |
| `masque_upstream_pool` | Registry of pooled upstream connections keyed by fingerprint; single-flight dial; skips full owners. | you change pool keys, checkout or eviction. |
| `masque_upstream_owner` | One pooled h2 or h3 connection: dials it, opens streams for sessions, forwards connection-level events, idle close. | you change how pooled streams are opened, released or routed. |

## Session implementations

One module per protocol and transport cell. Client sessions are `gen_statem`s, server sessions `gen_server`s. See [client internals](client-internals.md) and [server internals](server-internals.md).

### Client

| Protocol | h3 | h2 | h1 |
|---|---|---|---|
| CONNECT-UDP | `masque_client_session` | `masque_h2_client_session` | `masque_h1_client_session` |
| CONNECT-TCP | `masque_tcp_client_session` | `masque_tcp_client_session` | `masque_tcp_h1_client_session` (classic CONNECT) |
| CONNECT-IP | `masque_ip_client_session` | `masque_ip_client_session` | `masque_ip_h1_client_session` |
| Connect-UDP-Bind | `masque_udp_bind_client_session` | `masque_udp_bind_client_session` | `masque_udp_bind_h1_client_session` |

### Server

| Protocol | h3 | h2 | h1 |
|---|---|---|---|
| CONNECT-UDP | `masque_server_session` | `masque_h2_server_session` | `masque_h1_server_session` |
| CONNECT-TCP | `masque_tcp_server_session` | `masque_tcp_server_session` | `masque_tcp_h1_server_session` (classic CONNECT) |
| CONNECT-IP | `masque_ip_server_session` | `masque_ip_server_session` | `masque_ip_h1_server_session` |
| Connect-UDP-Bind | `masque_udp_bind_server_session` | `masque_udp_bind_server_session` | `masque_udp_bind_h1_server_session` |

Change a session module when you change the wire behaviour of that cell: framing, handshake checks, teardown, owner messages (client) or handler dispatch and actions (server). Behaviour shared across cells is copied in each module, so a fix usually needs to go into every module of the row or column; search for the function name across `src/`.

## Session support

| Module | Role | Change this when... |
|---|---|---|
| `masque_client_failed` | The shared `failed` state: parks a dial error until `handshake_await` collects it. | you change how early dial errors reach the caller. |
| `masque_client_owner` | Holds application-owner messages while `defer_owner` is set, flushes them on `set_owner`. Uses the process dictionary. | you change the racer handoff. |
| `masque_client_rx` | Queue-mode rules shared by client sessions: `rx_queue_limit`, the `closed` state that serves unread data, linger timeout. | you change queue-mode delivery or close semantics. |
| `masque_tls` | TLS client options for h1 and h2 dials: `verify_peer` by default, system CA store, hostname check, ALPN, SNI rules. | you change client TLS defaults. |

## Codecs and URI

| Module | Role | Change this when... |
|---|---|---|
| `masque_datagram` | Context-id prefix on HTTP datagram payloads. | never for new protocols; only on a framing bug. |
| `masque_capsule` | Thin capsule codec over `quic_h3_capsule` plus `known/1`, the set of capsule types the library handles itself. | you add a capsule type the library consumes. |
| `masque_ip_capsule` | CONNECT-IP capsules (ADDRESS_ASSIGN, ADDRESS_REQUEST, ROUTE_ADVERTISEMENT) with RFC 9484 validation. | you change CONNECT-IP capsule rules. |
| `masque_compression_capsule` | Connect-UDP-Bind COMPRESSION_ASSIGN / ACK / CLOSE encode and decode. Pure data. | you change bind capsule wire rules. |
| `masque_compression_table` | Per-session compression table (own and peer), parity, uniqueness and ACK rules. A data structure, not a process. | you change context lifecycle rules. |
| `masque_udp_bind_payload` | Bound UDP payload after the context id, compressed and uncompressed forms. | you change bind datagram payload encoding. |
| `masque_ip_packet` | Read-only IP header parsing for CONNECT-IP scope checks, including IPv6 extension headers. | you change packet scope checks. |
| `masque_icmp` | ICMPv4 and ICMPv6 error packet builders for CONNECT-IP. | you change synthesized ICMP errors. |
| `masque_uri_template` | Generic RFC 6570 subset engine used by all protocols. | you need a new template feature. |
| `masque_uri` | UDP and TCP template facade, host and port validation, authority-form parsing for h1 CONNECT. | you change UDP/TCP target parsing. |
| `masque_uri_ip` | CONNECT-IP template and target / ipproto parsing. | you change CONNECT-IP target parsing. |
| `masque_uri_udp_bind` | Bind matcher (the `*` wildcard) and the `Connect-UDP-Bind` / `Proxy-Public-Address` fields. | you change bind request or response fields. |

## CONNECT-IP plumbing

| Module | Role | Change this when... |
|---|---|---|
| `masque_ip` | Four unrelated helpers: `is_public/1` (SSRF classification), `resolve_target/3` (listener DNS step, used by all three listeners), `reject_requests/1` (reject-all ADDRESS_ASSIGN), `inject_packet/2` (push a packet into an IP server session). | you change SSRF ranges, listener resolution or out-of-band injection. |
| `masque_ip_session_registry` | Address to session registry for CONNECT-IP (ETS `ordered_set`), rejects overlapping ranges, cleans up on session exit. | you change how assigned addresses are tracked or looked up. |

## Support

| Module | Role | Change this when... |
|---|---|---|
| `masque_app` | Application callback: starts `masque_sup`, sets up metrics, creates the node `via` token. | you add application start-up work. |
| `masque_sup` | Top supervisor: the eight session supervisors, the pool, the IP registry, and the `masque_h2_tunnel_counts` ETS table. | you add a supervised process or a global table. |
| `masque_h2_session_sup` | One module, four `simple_one_for_one` instances (UDP, TCP, IP, bind) for h2 server sessions. | you add an h2 protocol. |
| `masque_h1_session_sup` | Same for h1 server sessions. | you add an h1 protocol. |
| `masque_errors` | Handshake error to HTTP status and reason phrase. | you add a reject reason. |
| `masque_metrics` | `instrument_meter` instruments for tunnels and bytes, plus `counters` for CONNECT-IP and bind drops. | you add a metric (see [operations](../2-use/operations.md)). |

## Naming quirks

- `masque_client_session` and `masque_server_session` are h3 CONNECT-UDP only, not generic sessions.
- `masque_h2_client_session` and `masque_h2_server_session` are h2 CONNECT-UDP only. h2 TCP, IP and bind use the `masque_tcp_*`, `masque_ip_*` and `masque_udp_bind_*` modules, which serve both h3 and h2.
- `masque_h1_client_session` and `masque_h1_server_session` are h1 CONNECT-UDP only.
- `masque_server` is the h3 listener for every protocol, although its moduledoc says "CONNECT-UDP proxy listener". The same stale wording is on `masque_h2_server` and `masque_h1_server`.
- `masque_h2_session_sup` and `masque_h1_session_sup` are both a module name and the registered name of their UDP instance; the other instances are registered as `masque_h2_tcp_session_sup`, `masque_h1_ip_session_sup`, and so on.
- `masque_ip` is not "the IP protocol". It is a set of helpers, and `resolve_target/3` runs for every protocol.
- `masque_upstream_owner` is the pool's connection owner; `masque_client_owner` handles the application owner. Neither is the h3 connection owner, which is the router. See [concepts](../1-understand/concepts.md#owner-three-meanings).
- `masque_capsule` is not the only capsule codec. Sessions also call `h2_capsule` and `h1_capsule` from the transport libraries directly, mostly for DATAGRAM capsules and stream decoding on h2 and h1; which codec a given call site uses varies by module.

## Include files

| File | Contents |
|---|---|
| `include/masque.hrl` | `connect-udp` and `connect-tcp` protocol tokens, default UDP and TCP URI templates, context id 0, UDP payload limit, default capsule buffer size, default `rx_queue_limit`, handshake status macros. |
| `include/masque_ip.hrl` | `connect-ip` token, default IP URI pattern, CONNECT-IP capsule types, IP context id, MTU constants, and the `#ip_assignment{}`, `#ip_prefix_request{}`, `#ip_route{}` records used in the public API. |
| `include/masque_udp_bind.hrl` | `Connect-UDP-Bind` and `Proxy-Public-Address` field names, compression capsule types, the uncompressed IP version, and the `#compression_assign{}` record. |

## Tests

`test/` mixes three kinds of files: EUnit modules (`*_tests.erl`, one per codec or unit, plus `prop_masque.erl` for PropEr properties), Common Test suites (`*_SUITE.erl`, which start real listeners on loopback), and helpers shared by both (`masque_test_helpers`, `masque_mock_transport`, `masque_racer_fake_session`, and test handlers such as `masque_echo_handler` and `masque_report_handler`). The suite map, fixtures and known traps are in [testing](testing.md).

Next: [server internals](server-internals.md).
