# CONNECT-TCP

This page lists what is specific to CONNECT-TCP (draft-ietf-httpbis-connect-tcp on h3 and h2, classic `CONNECT` on h1): the stream is a raw byte pipe, FIN is per direction, and HTTP/1.1 cannot half-close. The rest (connecting, delivery modes, closing) is in [client](client.md), [server](server.md) and [handlers](handlers.md). Read it when you tunnel TCP. Which draft revision the library tracks is recorded in [conformance](../reference/conformance.md).

## Client

```erlang
{ok, Sess} = masque:connect(Proxy, {<<"example.com">>, 443}, #{protocol => tcp}),
ok = masque:send(Sess, Bytes),
receive {masque_data, Sess, Chunk} -> Chunk end.
```

- On h3 and h2 the request is Extended CONNECT with `:protocol = connect-tcp` on the `/.well-known/masque/tcp/{target_host}/{target_port}/` template. On h1 it is `CONNECT host:port HTTP/1.1`; set `proxy_authorization` to send a `Proxy-Authorization` header.
- Raw bytes, no framing: no datagrams, no context ids, no capsules. The request carries no `capsule-protocol` header, and a 2xx that carries one is refused with `{error, {bad_response, capsule_protocol}}`. `send_capsule/3` returns `{error, not_supported}`; the `capsule_protocol` option is ignored.
- Bytes are never dropped. In queue mode, a full queue (`rx_queue_limit`) resets the tunnel and `recv/2` ends with `{error, rx_overflow}` after the buffered data.

## Half-close

On h3 and h2, END_STREAM is TCP FIN, one per direction:

- `masque:shutdown_write(Sess)` sends your FIN; you keep receiving. `send/2` then returns `{error, write_closed}`.
- When the proxy sends its FIN, a message-mode owner gets `{masque_closed, Sess, peer_fin}` and can keep sending. In queue mode `recv/2` returns the buffered bytes, then `{error, closed}`.
- The session ends once both directions are closed.

On h1 there is no half-close: OTP `ssl` drops the connection when the peer sends TLS `close_notify`, so a FIN from either side ends the tunnel.

## Server side

Handlers get `handle_data/2` for client bytes and `handle_eof/1` for the client FIN, and answer with `{send_data, Bytes}` or `{send_data, Bytes, true}` (see [handlers](handlers.md#actions)). A tunnel write blocks until the transport takes it; if it fails, or waits more than 30 seconds on h3 and h2, the tunnel ends with `{tunnel_send_failed, _}`.

The built-in `masque_tcp_proxy_handler` opens a `gen_tcp` connection to the target and relays both ways. A FIN from the client shuts down the write side of the target socket; a FIN from the target is passed on to the client. A half-closed tunnel with no traffic for 30 seconds ends with `eof_timeout`. A target reset resets the tunnel.

| `handler_opts` key | Default | Meaning |
|---|---|---|
| `allow` | allow all | `fun({Host, Port}) -> boolean()`, checked in `accept/1`. |
| `resolver` | `inet:getaddr/2`, IPv4 first | `fun(Host) -> {ok, Address} \| {ok, [Address]} \| {error, _}`. With a list, the first address is used. |
| `family` | `auto` | `inet`, `inet6` or `auto`. |
| `allow_private` | `false` | Allow non-public targets. Otherwise refused with 502. |
| `connect_timeout` | `5000` | Timeout of the connection to the target, in ms. |
| `socket_opts` | `[]` | Extra `gen_tcp` options. |
| `active_n` | `16` | Segments read before the socket pauses until the session wrote them to the tunnel. |

A failed connection to the target refuses the tunnel with 502.

Next: [connect-ip](connect-ip.md).
