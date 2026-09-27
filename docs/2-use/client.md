# Client

This page covers everything you do on the client side of a tunnel: open it with `masque:connect/2,3`, pick transports and a delivery mode, send and receive, and close it. Read it when you write code that dials a MASQUE proxy. Protocol-specific calls (CONNECT-IP control plane, Connect-UDP-Bind contexts) live on their own pages; this page is about what all tunnels share. It uses the terms "application owner", "delivery mode" and "racer" from [concepts](../1-understand/concepts.md). For exact message shapes and every error reason, see [messages and errors](../reference/messages-and-errors.md).

## Open a tunnel

```erlang
{ok, Sess} = masque:connect(<<"https://proxy.example:4433">>, {<<"1.1.1.1">>, 53}).
{ok, Sess} = masque:connect(ProxyURI, {<<"example.com">>, 443}, #{protocol => tcp}).
{ok, Sess} = masque:connect(ProxyURI, {'*', '*'}, #{protocol => ip}).
```

- The proxy URI must be `https://host[:port]` (port defaults to 443).
- The target is `{Host, Port}` for `udp` and `tcp`, and `{IpTarget, IpProto}` for `ip` (see [connect-ip](connect-ip.md)). Connect-UDP-Bind has its own entry point, `masque:bind_connect/3` (see [connect-udp-bind](connect-udp-bind.md)).
- `connect/2` is `connect/3` with `#{}`.
- `Sess` is the session pid. It returns only after the proxy answered 2xx (101 on HTTP/1.1 Upgrade). On failure you get `{error, Reason}`; `connect` does not exit the caller.

## Options that matter

| Option | Default | What it does |
|---|---|---|
| `protocol` | `udp` | `udp`, `tcp` or `ip`. |
| `transports` | `[h3, h2]` | Transports to try. One entry dials only that transport; two or more are raced. Add `h1` as a last resort: `[h3, h2, h1]`. Anything but a list of `h3`, `h2`, `h1` returns `{error, {invalid_opts, {transports, T}}}`. |
| `prefer_timeout_ms` | `250` | Head start of the first transport before the second one starts. |
| `h1_prefer_timeout_ms` | `500` | Delay before the third transport starts, counted from the start of the second. |
| `timeout` | `5000` | Handshake timeout in ms. When racing, the whole race must finish within it. |
| `verify` | `verify_peer` | `verify_none` turns certificate checks off. All transports. |
| `cacerts` | system store | DER trust anchors. All transports. |
| `ssl_opts` | `[]` | Extra `ssl` client options, merged over the defaults. h2 and h1 only; h3 ignores it. An IPv6 literal proxy (`https://[::1]:443`) gets `inet6` by default. |
| `owner` | caller | Application owner: the process that gets the session's messages. The session monitors it and closes when it exits. |
| `mode` | `message` | Delivery mode, `message` or `queue`. Change later with `masque:set_mode/2`. |
| `rx_queue_limit` | `1000` | Items a queue-mode session buffers. |
| `request_headers` | `[]` | Extra headers on the CONNECT (or h1 Upgrade) request, for example an `authorization` token. |
| `uri_template` | per protocol | Request path template. Must match the proxy's. CONNECT-IP needs an absolute URI. |
| `capsule_protocol` | `true` | UDP: send `capsule-protocol: ?1` and require it back. IP: must stay `true`. TCP: ignored. |
| `proxy_authorization` | none | `Proxy-Authorization` value for CONNECT-TCP over h1. CR or LF in it is refused. |
| `max_capsule_size` | `65536` | Largest buffered capsule before the stream is aborted. |
| `upstream_pool` | `false` | Share one h2 or h3 connection per proxy across tunnels. See below. |
| `upstream_pool_opts` | `#{}` | `idle_timeout_ms` (30000), `max_streams` (integer or `dynamic`), `checkout_timeout_ms` (60000). |

`request_headers` never overrides the headers the library sets itself (the pseudo-headers and `capsule-protocol` on h3 and h2, plus `connect-udp-bind` for a bind; `host`, `upgrade`, `connection` and `capsule-protocol` on h1); such entries are dropped. On h1, a header containing CR or LF never reaches the wire: CONNECT-TCP and Connect-UDP-Bind drop it, and the h1 library refuses it for UDP and IP.

## Transports and racing

With more than one transport, the racer starts the first one, starts the next after `prefer_timeout_ms`, and the next after `h1_prefer_timeout_ms`. The first 2xx wins; the others are stopped. Events the winning session produced before the hand-over are delivered to your owner in order.

```erlang
masque:connect(Proxy, Target, #{transports => [h3]}).              %% QUIC only
masque:connect(Proxy, Target, #{transports => [h2]}).              %% UDP blocked
masque:connect(Proxy, Target, #{transports => [h3, h2, h1],
                                prefer_timeout_ms => 500}).
```

If every attempt fails you get the last attempt's error; if the race runs out of time you get `{error, {race_timeout, LastError}}`.

On h2 and h1 there is no datagram channel, so datagrams travel as capsules on the stream: they arrive in order and are never lost. Force `[h3]` if your application depends on UDP loss semantics.

## TLS

Every transport verifies the proxy certificate by default: system CA store, host name check, and SNI (h2 and h1 omit SNI when you dial an IP literal). For a private CA pass `cacerts`; for a throwaway test proxy pass `verify => verify_none`. See [getting started](getting-started.md#tls-verify_peer-is-the-default).

## Connection pooling

By default each tunnel opens its own connection. With `upstream_pool => true`, h2 and h3 tunnels to the same proxy share a connection, one stream per tunnel:

```erlang
masque:connect(Proxy, Target, #{transports => [h3], upstream_pool => true,
                                upstream_pool_opts => #{idle_timeout_ms => 60000}}).
```

Connections are keyed by proxy host, port, transport and the TLS-relevant options (`verify`, `cacerts`, `ssl_opts`, `alpn`), so different trust settings never share. h1 is never pooled. A checkout that cannot get a connection within `checkout_timeout_ms` returns `{error, timeout}`. How the pool works: [pool](../3-change/pool.md).

## Send and receive

```erlang
ok = masque:send(Sess, Payload),          %% UDP datagram or TCP bytes
ok = masque:send(Sess, ContextId, Payload), %% UDP, explicit context id
```

`send/2,3` blocks until the session accepted the data. On UDP, a payload above 65527 bytes, or above what the h3 connection can carry in a datagram, returns an error instead of being sent. `send/2,3` exits if the session process is gone.

In `message` mode the owner gets `{masque_data, Sess, Data}` for every payload:

```erlang
handle_info({masque_data, Sess, Data}, #{sess := Sess} = State) ->
    {noreply, handle_payload(Data, State)};
handle_info({masque_closed, Sess, Reason}, #{sess := Sess} = State) ->
    {stop, {tunnel_closed, Reason}, State}.
```

In `queue` mode you pull with `recv/2`:

```erlang
{ok, Sess} = masque:connect(Proxy, Target, #{mode => queue, rx_queue_limit => 10000}),
ok = masque:send(Sess, Query),
{ok, Reply} = masque:recv(Sess, 5000).   %% or {error, timeout}
```

The queue holds at most `rx_queue_limit` items. Past it, datagram tunnels (UDP, IP, udp-bind) drop new items and count them in `rx_dropped` from `masque:info/1`. A CONNECT-TCP tunnel cannot lose bytes, so it resets the tunnel instead and `recv/2` ends with `{error, rx_overflow}`.

```erlang
#{state := open, rx_dropped := N} = masque:info(Sess).
```

## Capsules

UDP and IP tunnels can carry extension capsules (RFC 9297) on the request stream:

```erlang
ok = masque:send_capsule(Sess, 16#cafe, <<"body">>),
receive {masque_capsule, Sess, 16#cafe, Value} -> Value end.
```

Capsule types the session itself understands (DATAGRAM, CONNECT-IP control capsules, udp-bind compression capsules) are consumed and never reach you as `masque_capsule`. CONNECT-TCP has no capsule channel: `send_capsule/3` returns `{error, not_supported}`.

## Close

`masque:close(Sess)` ends the tunnel: the session sends FIN on its stream and closes its connection (or gives the stream back to the pool). It always returns `ok`, within 5 seconds even if the session is stuck. You do not get a `masque_closed` message for your own close, except on Connect-UDP-Bind sessions in message mode, which report `{masque_closed, Sess, normal}`.

The session also closes when the owner process exits.

When the other side ends the tunnel, a message-mode owner gets `{masque_closed, Sess, Reason}`. The common reasons:

| Reason | Meaning |
|---|---|
| `peer_fin` | The proxy finished its stream cleanly. On CONNECT-TCP this is a half-close: you can still send (see below). On other protocols the tunnel is over. |
| `peer_reset` | The proxy reset the stream. |
| `peer_closed` | The connection to the proxy closed. |
| `goaway` | The proxy is shutting the connection down and did not process this request. |
| `malformed_capsule`, `truncated_capsule`, `capsule_buffer_overflow` | The proxy sent a bad stream; the session aborted it. |

In queue mode no message is sent. `recv/2` returns what is still buffered, then `{error, closed}` (or `{error, rx_overflow}`). A closed session keeps unread data for at most 30 seconds, then stops. To learn when the session process is gone, monitor it.

### Half-close (CONNECT-TCP)

```erlang
ok = masque:send(Sess, Request),
ok = masque:shutdown_write(Sess),        %% send FIN, keep receiving
receive {masque_closed, Sess, peer_fin} -> done end.
```

After `shutdown_write/1`, `send/2` returns `{error, write_closed}` and a second `shutdown_write/1` returns `{error, already_closed}`. Before the handshake finishes it returns `{error, not_ready}`; on UDP, IP and udp-bind tunnels `{error, not_supported}`. On h1 there is no half-close: OTP `ssl` drops the connection on the peer's TLS `close_notify`, so a FIN in either direction ends the tunnel. See [connect-tcp](connect-tcp.md).

## Errors

`connect/3` returns the underlying cause. The ones you will see most:

| Error | Cause |
|---|---|
| `{invalid_proxy_uri, URI}` | Not an `https://` URI. |
| `{bad_target_for_protocol, P}` | Target shape does not match `protocol`. |
| `{invalid_opts, _}` | For example `capsule_protocol => false` with `protocol => ip`. |
| `{connect, Reason}` | Transport or TLS failure (refused, unreachable, certificate). |
| `{handshake_rejected, Status}` | The proxy answered with a non-2xx status. The h1 sessions add a third element, udp-bind on h2/h3 uses `{bad_status, Status}`. |
| `handshake_timeout` | No answer within `timeout`. |
| `{race_timeout, LastError}` | The race ran out of time. |
| `malformed_response`, `capsule_protocol_not_acknowledged` | The 2xx did not follow the capsule protocol rules. |

The full list, including CONNECT-IP, udp-bind and pool errors, is in [messages and errors](../reference/messages-and-errors.md).

Next: [server](server.md), or the page for your protocol: [connect-udp](connect-udp.md), [connect-tcp](connect-tcp.md), [connect-ip](connect-ip.md), [connect-udp-bind](connect-udp-bind.md).
