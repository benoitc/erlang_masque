# CONNECT-IP (RFC 9484)

`masque` implements RFC 9484 ("Proxying IP in HTTP") on top of the
same H3 + H2 + H1 transports used for CONNECT-UDP. The client and
server APIs follow the shape of the existing UDP/TCP code: one
`masque:connect/3` to dial, one listener per port, owner-message
delivery on the client, handler callbacks on the server.

The remainder of this doc is the usage surface. For the on-the-wire
protocol details see RFC 9484 directly.

## HTTP/1.1 fallback

On networks that block QUIC and also refuse HTTP/2 (or strip ALPN),
`masque` can fall back to HTTP/1.1 over classic HTTPS. The on-the-wire
handshake is an HTTP Upgrade:

```
GET /.well-known/masque/ip/{target}/{ipproto}/ HTTP/1.1
Host: proxy.example:4443
Connection: Upgrade
Upgrade: connect-ip
Capsule-Protocol: ?1
```

On `101 Switching Protocols` the raw TLS socket becomes the tunnel;
RFC 9297 capsules (DATAGRAM for IP packets, `ADDRESS_ASSIGN` /
`ADDRESS_REQUEST` / `ROUTE_ADVERTISEMENT` for the control plane) are
framed directly on that socket. Wire format is identical to the h2
and h3 paths.

Enable via `transports => [h3, h2, h1]` (client) and
`masque:start_listener_h1/2` (server). The racer stages the h1
attempt after `h1_prefer_timeout_ms` (default 500 ms) behind the h2
head-start, so h1 only opens sockets when the preferred transports
have failed or are slow.

## Client

```erlang
{ok, Sess} =
    masque:connect(<<"https://proxy.example:4443">>,
                   {'*', '*'},               %% {ip_target(), ip_ipproto()}
                   #{protocol   => ip,
                     transports => [h3, h2]}).
```

Optional `uri_template` in `connect_opts()` overrides the default
template. When omitted the client synthesises
`https://<proxy-authority>/.well-known/masque/ip/{target}/{ipproto}/`.
An explicit template must be an absolute URI; non-absolute inputs
return `{error, {bad_template, absolute_uri_required}}`. Disabling
the capsule-protocol header for an IP session returns
`{error, {invalid_opts, capsule_protocol_required_for_ip}}` - RFC
9484 §4 makes the header mandatory.

Inbound events arrive as messages to the owner (default `self()`):

```erlang
{masque_ip_packet,           Sess, Packet :: binary()}
{masque_address_assign,      Sess, [ip_assignment()]}
{masque_address_request,     Sess, [ip_prefix_request()]}
{masque_route_advertisement, Sess, [ip_route()]}
{masque_ip_error,            Sess, Reason}
{masque_closed,              Sess, Reason}
```

Outbound control plane is fully typed; both endpoints may send all
three capsules (RFC 9484 §5, site-to-site example §8.2):

```erlang
ok                      = masque:send_ip_packet(Sess, Packet).
{ok, [Id1, Id2]}        = masque:request_addresses(Sess,
                              [{4, {0,0,0,0}, 0},
                               {6, {0,0,0,0,0,0,0,0}, 0}]).
ok                      = masque:assign_addresses(Sess, Assignments).
ok                      = masque:advertise_routes(Sess, Routes).
#{assigned := _, routes := _, mtu := 1500, transport := h3}
                        = masque:ip_info(Sess).
ok                      = masque:close(Sess).
```

Nonzero Request IDs passed to `assign_addresses/2` must match an
outstanding peer `ADDRESS_REQUEST`; otherwise the call returns
`{error, {no_such_pending_request, Id}}`.

The server holds at most 64 unanswered ADDRESS_REQUEST ids per
session; extra requests are answered at once with the RFC 9484 "no
address" entry.

## Server

```erlang
{ok, _} = masque:start_listener(ip_proxy, #{
    port => 4443,
    cert => CertDerOrPemPath,
    key  => KeyDerOrPemPath,

    %% CONNECT-IP specific:
    ip_uri_template => <<"/.well-known/masque/ip/{target}/{ipproto}/">>,
    ip_handler      => masque_ip_proxy_handler,   %% default
    address_pool    => {4, {10,200,0,0}, 16},     %% allocate /32s
    routes          => [{4,{0,0,0,0},{255,255,255,255},0}],
    resolver        => fun inet_res_resolver/1,   %% optional, default
                                                  %% wraps inet_res
    mtu             => 1500,                      %% default
    allow_private   => false                      %% default
}).
```

One listener serves UDP, TCP, and IP simultaneously - each has
distinct `handler` / `uri_template` option pairs (`handler` +
`uri_template` for UDP, `tcp_handler` + `tcp_uri_template` for TCP,
`ip_handler` + `ip_uri_template` for IP). Dispatch is by
`:protocol` on the incoming request.

The default `masque_ip_proxy_handler` allocates addresses
round-robin over `address_pool`, sends an initial
`ROUTE_ADVERTISEMENT` built from `routes` plus the resolver's
output, and filters source addresses (BCP-38). To forward packets,
pass `handler_opts => #{forward_fun => Fun}`. `Fun(Packet, State)`
may return `{reply, Packet, State}`, `{drop, State}`, `{forward,
State}`, or `ok`.

### Target scoping

The default handler only lets a tunnel reach what its target names:

| Target | Accepted | Packets forwarded |
| --- | --- | --- |
| `'*'` | only with `allow_private => true` | any destination |
| prefix (`10.0.0.0/8`, `2001:db8::/32`) | public prefixes; private ones need `allow_private` | destinations inside the prefix; private ones need `allow_private` |
| hostname | when every resolved address is public (the listener resolves it on h3, h2 and h1); otherwise needs `allow_private` | destinations inside the advertised routes |
| address | public addresses; private ones need `allow_private` | that address |

Packets whose source is not inside the prefix assigned to the
session are dropped (`bcp38`). Before any assignment, every source is
dropped unless `allow_private` is set.

To run a private network behind the proxy, opt in on the listener:

```erlang
{ok, _} = masque:start_listener(vpn, #{
    port => 4443, cert => Cert, key => Key,
    address_pool  => {4, {10,200,0,0}, 16},
    allow_private => true
}).
```

### Forwarding

Before a packet leaves the tunnel the default handler:

- decrements the IPv4 TTL or IPv6 hop limit and fixes the IPv4
  header checksum. A packet that reaches zero is dropped
  (`ttl_zero`) and answered with ICMP Time Exceeded.
- compares the packet size with `mtu` (default 1500). A larger
  packet is dropped (`mtu_exceeded`) and answered with ICMPv6 Packet
  Too Big or ICMPv4 Fragmentation Needed carrying the MTU.
- never answers an ICMP error with another ICMP error.

The helpers are public: `masque_ip_packet:decrement_ttl/1`,
`masque_ip_packet:checksum/1`, `masque_ip_packet:upper_layer/1`,
`masque_ip_packet:scope_check/4`, `masque_icmp:frag_needed/2` and
`masque_icmp:is_error/1`.

### Chained CONNECT-IP

`masque_chain_handler` forwards a client's ADDRESS_REQUEST to the
egress and relays the answer back under the client's request ids.
If the upstream cannot take the request, the client gets the RFC 9484
"no address" entry.

## Custom handlers

Implement `masque_handler`. Optional callbacks added by CONNECT-IP:

```erlang
handle_ip_packet(Packet :: binary(), State) ->
    {ok, State} | {ok, State, [action()]} | {stop, Reason, State}.

handle_address_request([ip_prefix_request()], State) -> ...
handle_address_assign([ip_assignment()], State)      -> ...
handle_route_advertisement([ip_route()], State)      -> ...
```

Actions the session interprets:

| Action | Effect |
| --- | --- |
| `{send_ip_packet, Packet}` | Emit `Packet` as a context-0 datagram. |
| `{request_addresses, [ip_prefix()]}` | Emit an ADDRESS_REQUEST (server may ask the client for addresses, RFC 9484 §5.2 site-to-site). |
| `{assign, [ip_assignment()]}` | Emit an ADDRESS_ASSIGN. Nonzero Request IDs must be in the pending-request set. |
| `{advertise, [ip_route()]}` | Emit a ROUTE_ADVERTISEMENT. |
| `{icmp_error, {Kind, Spec, Invoking}}` | Synthesise an ICMP error (see `masque_icmp`). |
| `{send_capsule, Type, Value}` | Emit an extension capsule. |
| `{close, Reason}` | Stop the tunnel. |

## ICMP errors

`masque_icmp` builds full ICMPv4/ICMPv6 packets:

```erlang
Pkt4 = masque_icmp:dest_unreachable(v4, 1, InvokingV4).
Pkt6 = masque_icmp:packet_too_big(1400, InvokingV6).
Pkt6b = masque_icmp:time_exceeded(v6, 0, InvokingV6).
```

The invoking packet is truncated to the IPv4 minimum MTU (548 B
body) or the IPv6 minimum MTU (1232 B body). Checksums include the
IPv6 pseudo-header for ICMPv6. Drop these straight into
`masque:send_ip_packet/2` or return them from a handler:

```erlang
handle_ip_packet(Pkt, State) ->
    case should_drop(Pkt) of
        {yes, Reason} ->
            {ok, State,
             [{icmp_error, {dest_unreachable, {v4, 1}, Pkt}}]};
        no ->
            forward(Pkt, State)
    end.
```

## Plumbing for external consumers

The default proxy handler ships with hooks designed for downstream
applications - typically a TUN/router process - that want to drive
CONNECT-IP without forking the library. There are five seams:

### 1. Address registry

`masque_ip_session_registry` is a `gen_server` child of `masque_sup`
that owns a single ETS table mapping every assigned address or
prefix to the session pid that serves it. The default proxy handler
calls into it on each allocation and on `terminate/2`.

```erlang
%% From a TUN read loop, given the destination address of a packet:
case masque_ip_session_registry:lookup({10,0,0,5}) of
    {ok, SessionPid, _ContextId} ->
        masque_ip:inject_packet(SessionPid, Packet);
    not_found ->
        drop_or_icmp(Packet)
end.
```

Lookup is direct ETS - the registry process is only on the write
path. Storage is a `{Version, StartIntAddr}` ordered set whose
intervals never overlap, so a host route inside an enclosing prefix
resolves to the session that owns the wider prefix. Sessions that
exit abruptly are gc-ed automatically via process monitors.

Public API:

| Call | Purpose |
| --- | --- |
| `lookup(IP)` | Longest-prefix match. Returns `{ok, Pid, CtxId} \| not_found`. |
| `register(V, Addr, Pfx, Pid, CtxId)` | Reject on overlap with `{error, conflict}`. The default allocator skips to the next candidate on conflict, so sessions sharing a pool get distinct addresses. |
| `release(V, Addr, Pfx)` | Free a range owned by the calling process. Default handler calls this from `terminate/2`. |
| `release(V, Addr, Pfx, Pid)` | Free a range only if `Pid` owns it. |
| `release_pid(Pid)` | Drop everything owned by `Pid`. |
| `all/0` | Snapshot for diagnostics. |

### 2. Out-of-band packet injection

`masque_ip:inject_packet(SessionPid, Packet)` is a non-blocking cast
that pushes `Packet` into a server session for delivery to the
connected client, regardless of which transport that session uses
(h1, h2, or h3). It re-uses the same wire path as the
`{send_ip_packet, _}` handler action, so capsule framing, MTU
checks, and metrics fire identically.

### 3. Lifecycle callback

Set `lifecycle_fun => fun((Event, Detail) -> ok)` in `handler_opts`
to receive structured events from the default proxy handler:

| Event | `Detail` |
| --- | --- |
| `address_assigned` | `#{version, address, prefix_len, entry}` |
| `address_released` | `#{version, address, prefix_len}` |
| `route_advertised` | `#{routes => [#ip_route{}]}` |
| `packet_dropped`   | `#{reason, packet_size, ...}` |
| `peer_address_assigned` | `#{entries => [#ip_assignment{}]}` (ADDRESS_ASSIGN from the client) |
| `peer_routes_advertised` | `#{routes => [#ip_route{}]}` (ROUTE_ADVERTISEMENT from the client) |

Typical use: program kernel routes on assign / release, log dropped
packets with their reason. Errors thrown from the callback are
swallowed so a misbehaving consumer cannot break the data plane.

### 4. Per-family prefix policy

`min_assignable_prefix => #{4 => Pfx4, 6 => Pfx6}` (default
`#{4 => 32, 6 => 128}` - host routes only) caps the widest prefix
the allocator will hand out. To delegate `/64`s to clients while
keeping IPv4 host-routed:

```erlang
#{address_pool => {6, {16#2001,16#DB8,0,0,0,0,0,0}, 48},
  min_assignable_prefix => #{4 => 32, 6 => 64}}
```

The allocator walks the pool in stride-aligned blocks of
`2^(MaxPfx - Pfx)` and rejects ranges that overlap any prior
assignment, so prefix and host allocations from the same pool
coexist.

### 5. Rich `forward_fun` actions

In addition to the historical
`{reply, _, _} | {drop, _} | {forward, _} | ok | {error, _}` shapes,
`forward_fun` can return:

```erlang
{actions, [forward_action()], NewState}.

forward_action() :: {send_ip_packet, binary()}
                  | {icmp_error, {atom(), term(), binary()}}
                  | {drop, atom()}.       %% telemetry only
```

`{drop, Reason}` bumps `masque_metrics:ip_drop_inc(Reason)` and
emits a `packet_dropped` lifecycle event without putting anything
on the wire, so a TUN consumer can both reply with an ICMP error
and account for the dropped original in a single call:

```erlang
forward_fun(Pkt, S) ->
    case no_route(Pkt) of
        true ->
            {actions,
             [{icmp_error, {dest_unreachable, {v4, 1}, Pkt}},
              {drop, forward_drop}],
             S};
        false ->
            {forward, S}
    end.
```

TTL and MTU checks already ran before `forward_fun` is called.

### Drop counters

`masque_metrics` exposes simple `counters`-backed read APIs for the
drop axis:

```erlang
masque_metrics:ip_drop_count(bcp38).
masque_metrics:ip_drop_count(scope_target).
masque_metrics:ip_drop_count(forward_drop).
masque_metrics:ip_drop_count(ttl_zero).
masque_metrics:ip_drop_count(mtu_exceeded).
```

Recognised reasons live in `masque_metrics:ip_drop_reasons/0`;
unknown reasons land in the `other` bucket. Public helper
`masque_ip_proxy_handler:emit_drop(Reason, Detail)` lets a TUN
consumer's own data path bump the same counters and lifecycle hook.

## Wire-format notes

Context ID 0 carries raw IP packets (see `masque_datagram`). Unknown
context IDs are silently dropped on receipt (RFC 9484 §6). On H3 the
datagram channel is QUIC DATAGRAM frames; on H2 the datagram channel
is RFC 9297 DATAGRAM-type capsules on the request-stream body; on
H1 the channel is the same DATAGRAM-type capsule riding the upgraded
TLS connection. The library's sessions dispatch internally so handler
code sees the same `handle_ip_packet/2` callback on all transports.

Capsules `ADDRESS_ASSIGN` (0x01), `ADDRESS_REQUEST` (0x02), and
`ROUTE_ADVERTISEMENT` (0x03) are encoded/decoded by
`masque_ip_capsule`. Validation rejects malformed route ordering,
non-disjoint ranges, and protocol-0 ranges that overlap
nonzero-protocol ranges for the same IP version (RFC 9484 §4.7.3).

## RFC 9484 compliance map

| Section | What the RFC requires | Status in `masque` |
| --- | --- | --- |
| §3 URI template | Absolute URI Template (Level-1 path or Level-3 query); client expands, server matches `:path` | Client-side absolute-URI enforcement (`masque_uri_ip:parse_client_template/1`); server-side path+query match (`masque_uri_template`); both template forms supported |
| §4 Request | `:method=CONNECT`, `:protocol=connect-ip`, `capsule-protocol: ?1` on the request | Emitted by the IP client session; `connect/3` forces `capsule_protocol => true` when `protocol => ip` |
| §4 Response | 2xx carries `capsule-protocol: ?1`; no `content-length` / `content-type` | Validated by the `validate_response` check in `masque_ip_client_session`; non-compliant responses tear the session down |
| §4.7.1 `ADDRESS_ASSIGN` | Nonzero Request ID echoes a prior `ADDRESS_REQUEST`; Request ID 0 = unprompted assignment | `masque_ip_capsule` + `masque_ip_server_session` track the pending set; `assign_addresses/2` rejects with `{no_such_pending_request, Id}` when violated |
| §4.7.1 DNS resolution | Hostname targets MUST be resolved server-side before 2xx; resolved addresses advertised | The h3, h2 and h1 listeners run the configurable `resolver` through `masque_ip:resolve_target/3` before `accept/1`; result attached to `req()` under `resolved_addresses` |
| §4.7.2 `ADDRESS_REQUEST` | ≥1 entry, unique nonzero Request IDs per sender | Enforced in `masque_ip_capsule` (encode and decode) |
| §4.7.3 `ROUTE_ADVERTISEMENT` | Ordered by (Version, Protocol, Start); disjoint within (Version, Protocol); protocol-0 ranges MUST NOT overlap nonzero-protocol ranges | All three rules validated by the `validate_routes_result` check in `masque_ip_capsule` |
| §5 Control plane directionality | Both endpoints may send every capsule (site-to-site, §8.2) | Symmetric API: typed `request_addresses/2`, `assign_addresses/2`, `advertise_routes/2` on the client; matching actions (`{request_addresses,_}`, `{assign,_}`, `{advertise,_}`) on the server |
| §6 Datagram framing | `Context ID (varint) | Payload`; context 0 = IP packet; unknown contexts dropped | `masque_datagram` (reused from RFC 9298) - exact shape; unknown contexts silently dropped in both session modules |
| §7 Error handling | Malformed capsule → stream reset per RFC 9297 §3.3; non-2xx carries Proxy-Status | Sessions issue `H3_MESSAGE_ERROR` (H3) / `PROTOCOL_ERROR` (H2); rejects emit RFC 9209 `Proxy-Status` via `masque_errors` |
| §7 ICMP synthesis | SHOULD forward ICMP error back when an IP packet can't be delivered | `masque_icmp` builds ICMPv4 / ICMPv6 errors with correct invoking-packet truncation (548 B / 1232 B) and IPv6 pseudo-header checksum; triggered from handlers via `{icmp_error, {Kind, Spec, Invoking}}` actions |
| §8 MTU | Negotiated H3 datagram size ≥ 1280 B for IPv6 support, else abort | The `check_datagram_mtu` check in `masque_ip_client_session` aborts the H3 handshake with `{mtu_too_low, Got, 1280}`; H2 uses reliable capsules and is exempt |
| §8 BCP-38 | Reject spoofed source addresses | Default handler drops packets whose source is outside the assigned prefix, and every packet before an assignment unless `allow_private` |
| Forwarding | Decrement TTL / hop limit; signal oversize packets | Default handler decrements and emits Time Exceeded; packets above `mtu` get Packet Too Big / Fragmentation Needed |

## Not in scope

- TUN device integration - a follow-up adds `masque_ip_tun_device`
  and `masque_ip_tun_proxy_handler` on top of the current handler API
  (see `docs/features.md`).
- Per-connection tunnel limits, auth hooks beyond `accept/1` - same
  as the UDP/TCP paths; follow-up releases.
