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
`{error, {invalid_opts, capsule_protocol_required_for_ip}}` — RFC
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
    mtu             => 1500
}).
```

One listener serves UDP, TCP, and IP simultaneously — each has
distinct `handler` / `uri_template` option pairs (`handler` +
`uri_template` for UDP, `tcp_handler` + `tcp_uri_template` for TCP,
`ip_handler` + `ip_uri_template` for IP). Dispatch is by
`:protocol` on the incoming request.

The default `masque_ip_proxy_handler` implements the phase-1
handler: round-robin allocation over `address_pool`, an initial
`ROUTE_ADVERTISEMENT` built from `routes` plus the resolver's
output, and BCP-38 source-address filtering. To forward packets,
pass `handler_opts => #{forward_fun => Fun}`. `Fun(Packet, State)`
may return `{reply, Packet, State}`, `{drop, State}`, `{forward,
State}`, or `ok`.

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
| §4 Response | 2xx carries `capsule-protocol: ?1`; no `content-length` / `content-type` | Validated by `masque_ip_client_session:validate_response/1`; non-compliant responses tear the session down |
| §4.7.1 `ADDRESS_ASSIGN` | Nonzero Request ID echoes a prior `ADDRESS_REQUEST`; Request ID 0 = unprompted assignment | `masque_ip_capsule` + `masque_ip_server_session` track the pending set; `assign_addresses/2` rejects with `{no_such_pending_request, Id}` when violated |
| §4.7.1 DNS resolution | Hostname targets MUST be resolved server-side before 2xx; resolved addresses advertised | `masque_server` / `masque_h2_server` run the configurable `resolver` before `accept/1`; result attached to `req()` under `resolved_addresses` |
| §4.7.2 `ADDRESS_REQUEST` | ≥1 entry, unique nonzero Request IDs per sender | Enforced in `masque_ip_capsule` (encode and decode) |
| §4.7.3 `ROUTE_ADVERTISEMENT` | Ordered by (Version, Protocol, Start); disjoint within (Version, Protocol); protocol-0 ranges MUST NOT overlap nonzero-protocol ranges | All three rules validated in `masque_ip_capsule:validate_routes_result/1` |
| §5 Control plane directionality | Both endpoints may send every capsule (site-to-site, §8.2) | Symmetric API: typed `request_addresses/2`, `assign_addresses/2`, `advertise_routes/2` on the client; matching actions (`{request_addresses,_}`, `{assign,_}`, `{advertise,_}`) on the server |
| §6 Datagram framing | `Context ID (varint) | Payload`; context 0 = IP packet; unknown contexts dropped | `masque_datagram` (reused from RFC 9298) — exact shape; unknown contexts silently dropped in both session modules |
| §7 Error handling | Malformed capsule → stream reset per RFC 9297 §3.3; non-2xx carries Proxy-Status | Sessions issue `H3_MESSAGE_ERROR` (H3) / `PROTOCOL_ERROR` (H2); rejects emit RFC 9209 `Proxy-Status` via `masque_errors` |
| §7 ICMP synthesis | SHOULD forward ICMP error back when an IP packet can't be delivered | `masque_icmp` builds ICMPv4 / ICMPv6 errors with correct invoking-packet truncation (548 B / 1232 B) and IPv6 pseudo-header checksum; triggered from handlers via `{icmp_error, {Kind, Spec, Invoking}}` actions |
| §8 MTU | Negotiated H3 datagram size ≥ 1280 B for IPv6 support, else abort | `masque_ip_client_session:check_datagram_mtu/1` aborts H3 handshake with `{mtu_too_low, Got, 1280}`; H2 uses reliable capsules and is exempt |
| §8 BCP-38 | Reject spoofed source addresses | Default handler's `src_filter_passes/2` drops inbound packets whose source is not a locally-assigned address |

## Not in scope

- TUN device integration - a follow-up adds `masque_ip_tun_device`
  and `masque_ip_tun_proxy_handler` on top of the current handler API
  (see plan in `doc/features.md`).
- Per-connection tunnel limits, auth hooks beyond `accept/1` - same
  as the UDP/TCP paths; follow-up releases.
