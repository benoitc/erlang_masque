# Operations

This page is for running `masque` in production: what the metrics mean and which tunnels report them, the CONNECT-IP lifecycle events, the drop counters, what `info/1` tells you, how to drain for a rolling restart, the security defaults in one place, and what gets logged. Read it before you put a proxy behind real traffic. It assumes [server](server.md). When a specific tunnel misbehaves, continue with [debugging](../3-change/debugging.md).

## Metrics

`masque_metrics` creates `instrument_meter` instruments on the `masque` meter when the application starts (the `instrument` application is a dependency and starts with it). Export them with any `instrument` exporter (OTLP, Prometheus).

| Instrument | Kind | Attributes | Meaning |
|---|---|---|---|
| `masque.tunnels.total` | counter | `protocol`, `transport` | Tunnels opened (2xx sent). |
| `masque.tunnels.active` | up/down counter | `protocol`, `transport` | Opened minus closed. |
| `masque.tunnel.duration_ms` | histogram | `protocol`, `transport` | Tunnel lifetime, recorded on close. |
| `masque.tunnels.rejected` | counter | `reason` | Requests the listener refused, whatever the cause: validation, `accept/1`, `init/2` failure, drain, tunnel limit. Tuple reasons such as `{other, 401}` become a binary. |
| `masque.bytes.in` | counter | `protocol`, `transport` | Bytes received from clients. |
| `masque.bytes.out` | counter | `protocol`, `transport` | Bytes sent to clients. |

`protocol` is `udp`, `tcp`, `ip` or `udp_bind`; `transport` is `h3`, `h2` or `h1`. There is no listener-name attribute.

Not every session reports every instrument:

| Session | total | active, duration | bytes |
|---|---|---|---|
| UDP over h3 | yes | yes | in, out |
| UDP over h2, h1 | no | no | no |
| TCP over h3, h2 | no | no | no |
| TCP over h1 | no | closes only | no |
| IP over h3, h1 | no | closes only | no |
| IP over h2 | no | no | no |
| udp-bind over h3, h2 | yes | yes | in, out |
| udp-bind over h1 | yes | yes | out |

Known issue: the sessions marked "closes only" record a close without a matching open, so `masque.tunnels.active` drifts downward (below zero) as those tunnels end, and `masque.tunnels.total` undercounts. Until every session reports both, do not use `masque.tunnels.active` as the number of open tunnels; count them in your handler's `init/2` and `terminate/2` if you need it.

## Counters

Two sets of plain `counters` sit beside the meters. They are node-wide totals, cheap to read, and meant for scrapers and tests.

### Drop counters

```erlang
[{R, masque_metrics:ip_drop_count(R)} || R <- masque_metrics:ip_drop_reasons()].
[{R, masque_metrics:bind_drop_count(R)} || R <- masque_metrics:bind_drop_reasons()].
```

| CONNECT-IP reason | Cause |
|---|---|
| `bcp38` | Source address outside the prefixes assigned to the tunnel. |
| `scope_target`, `scope_ipproto` | Destination or protocol outside the tunnel's target. |
| `malformed` | Not a valid IP packet. |
| `ttl_zero` | TTL or hop limit ran out (ICMP Time Exceeded sent). |
| `mtu_exceeded` | Larger than `mtu` (ICMP Packet Too Big / Fragmentation Needed sent). |
| `forward_drop` | Your `forward_fun` dropped it. |
| `other` | Any other reason passed to `emit_drop` or `{drop, Reason}`. |

The udp-bind reasons are listed in [connect-udp-bind](connect-udp-bind.md#limits-and-drop-counters). They are only counted by the h3 and h2 bind sessions.

### CONNECT-IP lifecycle counters

`masque_metrics:ip_assigned_count/0`, `ip_released_count/0` and `ip_advertised_count/0` count addresses assigned and released and route advertisements sent by the built-in IP handler.

## Lifecycle events

The built-in IP handler calls `lifecycle_fun` from `handler_opts` for `address_assigned`, `address_released`, `route_advertised`, `packet_dropped`, `peer_address_assigned` and `peer_routes_advertised`; see [connect-ip](connect-ip.md#plumbing-for-external-consumers). There is no general tunnel lifecycle hook; for other protocols use your handler's `init/2` and `terminate/2`.

## Inspecting a client session

```erlang
masque:info(Sess).
%% #{state => open, protocol => tcp, transport => h2,
%%   proxy => {<<"proxy.example">>, 4433}, target => {<<"example.com">>, 443}}
```

`state` is `connecting`, `open` or `closed` (the peer ended the tunnel and queue-mode data is still unread). Datagram sessions add `rx_dropped`, the items dropped because the queue was full. CONNECT-IP adds `ipproto`, udp-bind adds `bind`. UDP over h3 reports no `transport`. `masque:ip_info/1` returns the CONNECT-IP addresses, routes and MTU. `info/1` exits if the session is gone.

Server sessions have no public inspection call. `masque_ip_session_registry:all/0` lists the CONNECT-IP address assignments; for the rest see [debugging](../3-change/debugging.md).

## Drain for rolling restarts

1. `masque:drain_listener(Name)` on every listener of the node. New requests get 503 with `proxy-status: masque; error=proxy_internal_error`; open tunnels continue.
2. Wait until your own open-tunnel count reaches zero, or until a deadline. Do not wait on `masque.tunnels.active` (see the known issue above).
3. Stop the listeners (`stop_listener/1`, `stop_listener_h2/1`, `stop_listener_h1/1`) or the node.

Clients that race transports reconnect to whichever instance your DNS or load balancer points at next. `masque:undrain_listener/1` cancels a drain; restarting a listener clears it too.

## Security defaults

| Area | Default | Change with |
|---|---|---|
| Client TLS | Verify the proxy certificate against the system store, check the host name, send SNI (not for IP literals on h2 and h1). | `cacerts`, `verify => verify_none`, `ssl_opts` |
| Chain upstream TLS | Same as the client. | `upstream_opts` |
| UDP and TCP targets | Only public addresses; others refused with 502. | `allow_private` |
| CONNECT-IP | `*` and non-public targets refused with 403; packets limited to the target, the requested protocol and the assigned source prefix. | `allow_private` |
| udp-bind peers | Only public peers. | `allow_loopback`, `allow_private`, `peer_filter_fun` |
| Capsule size | 64 KiB per capsule. | `max_capsule_size` |
| Client queue | 1000 items. | `rx_queue_limit` |
| Tunnels per connection | Unlimited. | `max_tunnels_per_connection` |
| h1 idle tunnel | Ends after 5 minutes without client bytes. | `idle_timeout_ms` |
| Request headers | Library headers cannot be overridden; CR/LF refused on h1 (except udp-bind). | - |
| h1 rejection | Connection closed after every refused request. | - |

`masque_ip:is_public/1` is the single definition of "public" used by all built-in handlers: it excludes loopback, RFC 1918, CGNAT, link-local, documentation, benchmarking, multicast and reserved ranges, and the IPv6 equivalents including ULA, NAT64 and IPv4-mapped addresses.

## Logs

`masque` itself logs one thing: an exception raised by a handler callback in a server session, at error level through `logger`, with the module, function, arity, class, reason and stack. The udp-bind session over h1 does not catch handler exceptions, so there you get the standard OTP crash report instead. Refused requests are not logged; they are counted in `masque.tunnels.rejected`. What the handler crash does to the tunnel is described in [handlers](handlers.md#what-a-crash-does). The transport libraries (`quic`, `h2`, `h1`) log on their own.

Next: [debugging](../3-change/debugging.md), or back to [concepts](../1-understand/concepts.md) for the map of the code.
