# CONNECT-UDP

This page lists what is specific to CONNECT-UDP (RFC 9298): payload limits, context ids, how datagrams travel on each transport, and the options of the built-in `masque_udp_proxy_handler`. Everything shared with other protocols (connecting, delivery modes, closing) is in [client](client.md), [server](server.md) and [handlers](handlers.md). Read it when you tunnel DNS, QUIC or any other UDP flow. Section-by-section RFC mapping is in [conformance](../reference/conformance.md).

## Client

CONNECT-UDP is the default protocol:

```erlang
{ok, Sess} = masque:connect(Proxy, {<<"1.1.1.1">>, 53}),
ok = masque:send(Sess, DnsQuery),
receive {masque_data, Sess, Reply} -> Reply end.
```

- One tunnel reaches one target host and port. Open one tunnel per target.
- Payloads above 65527 bytes are refused with `{error, {payload_too_large, Size, 65527}}`. On h3 a payload that does not fit in a QUIC datagram is refused with `{error, {datagram_too_large, Size, Max}}`.
- `masque:send/3` sends on an explicit context id for extensions; context 0 is the UDP payload. Datagrams on context ids the receiver does not know are dropped silently, on both sides.
- `capsule_protocol => false` omits the `capsule-protocol` header from the request and stops the client from requiring it on the response.

## Datagrams per transport

| Transport | How a datagram travels | Consequence |
|---|---|---|
| h3 | QUIC DATAGRAM frame | Unreliable and unordered, like UDP. |
| h2 | DATAGRAM capsule on the request stream | Reliable and ordered; loss and reordering disappear. |
| h1 | DATAGRAM capsule on the upgraded TLS socket | Same as h2. |

Pin `transports => [h3]` when your protocol depends on UDP loss behaviour.

## Built-in handler

`masque_udp_proxy_handler` resolves the target, opens a connected `gen_udp` socket to it, and relays both ways. The connected socket makes the kernel drop datagrams from any other source; the handler checks the source again.

| `handler_opts` key | Default | Meaning |
|---|---|---|
| `allow` | allow all | `fun({Host, Port}) -> boolean()`, checked in `accept/1`; `false` answers 403. |
| `resolver` | `inet:getaddr/2`, IPv4 first | `fun(Host) -> {ok, Address} \| {ok, [Address]} \| {error, _}`. With a list, the first address is used. |
| `family` | `auto` | `inet`, `inet6` or `auto` (IPv6 when the host is an IPv6 literal). |
| `allow_private` | `false` | Allow targets that resolve to non-public addresses. Otherwise refused with 502. |
| `socket_opts` | `[]` | Extra `gen_udp` options. |
| `active_n` | `32` | Datagrams read from the target before the socket pauses until the session relayed them. |
| `port` | `0` | Local port of the target socket. A fixed port only works for one tunnel at a time. |

On the server side, `{send, Payload}` above 65527 bytes, or above the h3 datagram limit, is dropped silently: HTTP datagrams are unreliable by design.

Next: [connect-tcp](connect-tcp.md) or [connect-ip](connect-ip.md).
