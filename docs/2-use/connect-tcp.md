# CONNECT-TCP

This page lists what is specific to CONNECT-TCP: the two framings masque speaks, FIN per direction, and when HTTP/1.1 can half-close. The rest (connecting, delivery modes, closing) is in [client](client.md), [server](server.md) and [handlers](handlers.md). Read it when you tunnel TCP. Which draft revision the library tracks is recorded in [conformance](../reference/conformance.md).

## Client

```erlang
{ok, Sess} = masque:connect(Proxy, {<<"example.com">>, 443}, #{protocol => tcp}),
ok = masque:send(Sess, Bytes),
receive {masque_data, Sess, Chunk} -> Chunk end.
```

- On h3 and h2 the request is Extended CONNECT with `:protocol = connect-tcp` on the `/.well-known/masque/tcp/{target_host}/{target_port}/` template. On h1 it is `CONNECT host:port HTTP/1.1` in raw framing, or a `GET` upgrade on the same template in capsule framing; set `proxy_authorization` to send a `Proxy-Authorization` header.
- No datagrams and no context ids. In raw framing the request carries no `capsule-protocol` header, and a 2xx that carries one is refused with `{error, {bad_response, capsule_protocol}}`. `send_capsule/3` returns `{error, not_supported}` in both framings; the `capsule_protocol` option is ignored.
- Bytes are never dropped. In queue mode, a full queue (`rx_queue_limit`) resets the tunnel and `recv/2` ends with `{error, rx_overflow}` after the buffered data.

## Two framings

masque speaks two revisions of draft-ietf-httpbis-connect-tcp. Pick one with the client option `tcp_framing`; a listener answers both.

| | `raw` (default) | `capsule` |
|---|---|---|
| Draft | earlier revisions | draft-ietf-httpbis-connect-tcp-10 |
| Bytes on the stream | as they are | in `DATA` capsules; `FINAL_DATA` carries the last bytes and the FIN |
| Protocol token | `connect-tcp` | `connect-tcp-07`, as the draft asks of this version |
| `capsule-protocol: ?1` | absent | on the request and the response |
| HTTP/1.1 request | classic `CONNECT host:port` | `GET` with `Upgrade: connect-tcp-07` on the TCP template, answered with 101 |
| HTTP/1.1 half-close | no | yes |
| A stream that ends without its FIN | a FIN | an abort: the target gets a reset |

```erlang
{ok, Sess} = masque:connect(Proxy, {<<"example.com">>, 443}, #{protocol => tcp, tcp_framing => capsule}).
```

On h3 and h2 the request alone cannot always say which framing it uses: the draft makes `capsule-protocol: ?1` a SHOULD, and the proxy has to choose before any bytes flow, since the target may talk first (SSH, SMTP). The listener option `tcp_framing` decides:

| `tcp_framing` | Framing on h3 and h2 |
|---|---|
| `auto` (default) | `capsule` when the request carries `capsule-protocol: ?1`, `raw` otherwise. Serves older clients and -10 clients that send the header. |
| `capsule` | Always capsule: every -10 client, header or not. Older raw clients no longer work. |
| `raw` | Always raw. |

A request with the `connect-tcp-07` token is always capsule framing, whatever the option. On h1 the request form tells them apart, so the option does not apply there. The capsule codes are the provisional ones the draft gives for testing, `0x2028d7f0` and `0x2028d7f1`.

## Proxies that only speak connect-tcp

In raw framing on h1, a proxy may refuse classic `CONNECT` with 501, or with 426 and `Upgrade: connect-tcp`. The client then retries once in capsule framing on the default template, and remembers that proxy (by host and port) so later tunnels go straight to the upgrade. You get the tunnel either way; the refusal is only returned if the retry fails too.

## Slow targets

A target that does not answer can hold the handshake for long. To know the proxy took the request before that, ask for `100 Continue`:

```erlang
{ok, Sess} = masque:connect(Proxy, Target, #{
    protocol => tcp,
    request_headers => [{<<"expect">>, <<"100-continue">>}]
}).
```

Listeners send the 100 before dialing the target, on all three transports. The client skips it and waits for the final response as usual.

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
