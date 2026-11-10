# CONNECT-TCP

This page lists what is specific to CONNECT-TCP: the two framings masque speaks, the tokens, FIN per direction, and when HTTP/1.1 can half-close. The rest (connecting, delivery modes, closing) is in [client](client.md), [server](server.md) and [handlers](handlers.md). Read it when you tunnel TCP. Which draft revision the library tracks is recorded in [conformance](../reference/conformance.md).

## Client

```erlang
{ok, Sess} = masque:connect(Proxy, {<<"example.com">>, 443}, #{protocol => tcp}),
ok = masque:send(Sess, Bytes),
receive {masque_data, Sess, Chunk} -> Chunk end.
```

- On h3 and h2 the request is Extended CONNECT with `:protocol = connect-tcp` (or the token in use, see below) on the `/.well-known/masque/tcp/{target_host}/{target_port}/` template. On h1 it is `CONNECT host:port HTTP/1.1` in raw framing, or a `GET` upgrade on the same template in capsule framing; set `proxy_authorization` to send a `Proxy-Authorization` header.
- No datagrams and no context ids. In raw framing the request carries no `capsule-protocol` header, and a 2xx that carries one is refused with `{error, {bad_response, capsule_protocol}}`. `send_capsule/3` returns `{error, not_supported}` in both framings; the `capsule_protocol` option is ignored.
- Bytes are never dropped. In queue mode, a full queue (`rx_queue_limit`) resets the tunnel and `recv/2` ends with `{error, rx_overflow}` after the buffered data.

## Two framings

masque speaks two framings of draft-ietf-httpbis-connect-tcp. Clients use `capsule` unless you set the option `tcp_framing`; a listener answers both. On HTTP/1.1, a proxy that refuses the capsule upgrade (426, 501) is tried again with a classic CONNECT, so you do not need to know which framing it speaks. On HTTP/3 and HTTP/2, set `tcp_framing => raw` only for a proxy of an earlier draft.

| | `raw` | `capsule` (default) |
|---|---|---|
| Draft | earlier revisions | draft-ietf-httpbis-connect-tcp-18 |
| Bytes on the stream | as they are | in `DATA` capsules; `FINAL_DATA` carries the last bytes and the FIN |
| Protocol token | `connect-tcp` | `connect-tcp`, unless `tcp_protocol` says otherwise |
| `capsule-protocol: ?1` | absent | on the request and the response |
| HTTP/1.1 request | classic `CONNECT host:port` | `GET` with `Upgrade: connect-tcp` on the TCP template, answered with 101 |
| Interim `100 Continue` | only if the request expects it | always, before the target is dialed |
| HTTP/1.1 half-close | no | yes |
| A stream that ends without its FIN | a FIN | an abort: the target gets a reset |
| A local timeout | a FIN | an abort |

```erlang
{ok, Sess} = masque:connect(Proxy, {<<"example.com">>, 443}, #{protocol => tcp, tcp_framing => capsule}).
```

## Tokens and capsule codes

The token picks the capsule codes. Set it with `tcp_protocol` when the proxy needs another one:

| `tcp_protocol` | Capsule codes | Peers |
|---|---|---|
| `<<"connect-tcp">>` (default) | `DATA` `0x08`, `FINAL_DATA` `0x09` | draft -18 and the RFC |
| `<<"connect-tcp-12">>` | `0x08`, `0x09` | drafts -12 to -18, by their interop token |
| `<<"connect-tcp-08">>` | `0x2028d7f0`, `0x2028d7f1` | draft -09 |
| `<<"connect-tcp-07">>` | `0x2028d7f0`, `0x2028d7f1` | draft -10 |

```erlang
{ok, Sess} = masque:connect(Proxy, Target, #{
    protocol => tcp, tcp_framing => capsule, tcp_protocol => <<"connect-tcp-08">>
}).
```

Listeners accept every token in the table. The interop tokens always mean capsule framing. A plain `connect-tcp` request is ambiguous on h3 and h2, because raw clients of the earlier revisions send the same token, and the proxy has to choose before any bytes flow, since the target may talk first (SSH, SMTP). The listener option `tcp_framing` decides:

| `tcp_framing` | Framing of a plain `connect-tcp` request on h3 and h2 |
|---|---|
| `auto` (default) | `capsule` when the request carries `capsule-protocol: ?1`, `raw` otherwise. Serves raw clients and capsule clients that send the header. |
| `capsule` | Always capsule, header or not. Raw clients no longer work. |
| `raw` | Always raw. |

On h1 the request form tells them apart, so the option does not apply there.

## Proxies that only speak connect-tcp

In raw framing on h1, a proxy may refuse classic `CONNECT` with 501, or with 426 and `Upgrade: connect-tcp`. The client then retries once in capsule framing on the default template, and remembers that proxy (by host and port) so later tunnels go straight to the upgrade. You get the tunnel either way; the refusal is only returned if the retry fails too.

## What the listener does in capsule framing

- It sends `100 Continue` as soon as it accepts the request, before dialing the target, which can take long when the target does not answer. The client skips it.
- It races the target's IPv6 and IPv4 addresses (Happy Eyeballs) and keeps the first connection.
- A target the policy refuses gets 403, a connection timeout 504, any other failed connection 502. Each carries `Proxy-Status`.
- Payload is forwarded as it arrives, so a capsule of any size is accepted without being held whole in memory.
- Invalid data (a second `FINAL_DATA`, `DATA` after `FINAL_DATA`, a capsule cut short by the end of the stream) and local timeouts abort the tunnel: the stream is reset and the target gets an RST.

## Half-close

On h3 and h2, END_STREAM is TCP FIN, one per direction:

- `masque:shutdown_write(Sess)` sends your FIN; you keep receiving. `send/2` then returns `{error, write_closed}`.
- When the proxy sends its FIN, a message-mode owner gets `{masque_closed, Sess, peer_fin}` and can keep sending. In queue mode `recv/2` returns the buffered bytes, then `{error, closed}`.
- The session ends once both directions are closed.

On h1 in raw framing there is no half-close: OTP `ssl` drops the connection when the peer sends TLS `close_notify`, so a FIN from either side ends the tunnel. In capsule framing the FIN is a `FINAL_DATA` capsule, so h1 half-closes like h3 and h2.

## Server side

Handlers get `handle_data/2` for client bytes and `handle_eof/1` for the client FIN, and answer with `{send_data, Bytes}` or `{send_data, Bytes, true}` (see [handlers](handlers.md#actions)). A tunnel write blocks until the transport takes it; if it fails, or waits more than 30 seconds on h3 and h2, the tunnel ends with `{tunnel_send_failed, _}`.

The built-in `masque_tcp_proxy_handler` opens a `gen_tcp` connection to the target and relays both ways. A FIN from the client shuts down the write side of the target socket; a FIN from the target is passed on to the client. A half-closed tunnel with no traffic for 30 seconds ends with `eof_timeout`. A target reset resets the tunnel; a tunnel the client aborts (stream reset, connection gone) aborts the target connection with an RST, while a clean end closes it with FIN. A target that stops reading ends the tunnel after 30 seconds.

On the client, `close/1` sends the FIN and returns at once; the session then waits up to 2 seconds for the proxy to finish the stream before closing its connection, so the last bytes are not cut off. A pooled stream is handed back to the pool without a reset.

| `handler_opts` key | Default | Meaning |
|---|---|---|
| `allow` | allow all | `fun({Host, Port}) -> boolean()`, checked in `accept/1`. |
| `resolver` | `inet:getaddr/2`, IPv4 first | `fun(Host) -> {ok, Address} \| {ok, [Address]} \| {error, _}`. With a list, the first address is used. |
| `family` | `auto` | `inet`, `inet6` or `auto` (follows the resolved address, so an IPv6-only name works). |
| `allow_private` | `false` | Allow non-public targets. Otherwise refused with 502. |
| `allow_self` | `false` | Allow targets that are the proxy host's own addresses (its non-loopback interfaces and `self_addresses`). Otherwise refused with 502. |
| `self_addresses` | `[]` | Extra addresses that count as the proxy's own, for example a NAT public address. |
| `connect_timeout` | `5000` | Timeout of the connection to the target, in ms. |
| `socket_opts` | `[]` | Extra `gen_tcp` options. |
| `active_n` | `16` | Segments read before the socket pauses until the session wrote them to the tunnel. |

A failed connection to the target refuses the tunnel with 502.

Next: [connect-ip](connect-ip.md).
