# Server

This page is for you when you run a MASQUE proxy: which listener to start per transport, the listener options that matter, how to accept or refuse requests (including an authentication challenge), how to drain a listener, the limits, the security defaults, and the TLS material each transport wants. It does not describe the handler contract; that is [handlers](handlers.md). It uses "listener", "handler" and "router" from [concepts](../1-understand/concepts.md). If you want to see a listener run first, do [getting started](getting-started.md).

## Three listeners

A listener serves one transport. To accept every transport, start three with the same options (only the certificate format differs).

| Transport | Start | Stop | Returns |
|---|---|---|---|
| HTTP/3 (UDP) | `masque:start_listener(Name, Opts)` | `masque:stop_listener(Name)` | `{ok, pid()}` |
| HTTP/2 (TCP+TLS) | `masque:start_listener_h2(Name, Opts)` | `masque:stop_listener_h2(Name \| Ref)` | `{ok, Ref}` |
| HTTP/1.1 (TCP+TLS) | `masque:start_listener_h1(Name, Opts)` | `masque:stop_listener_h1(Name \| Ref)` | `{ok, Ref}` |

Each listener dispatches every tunnel protocol it supports on its own: CONNECT-UDP, CONNECT-TCP and CONNECT-IP, plus Connect-UDP-Bind when `accept_bind => true`. On h3 and h2 the `:protocol` pseudo-header selects the protocol. On h1, UDP and IP arrive as `GET` + `Upgrade`, and TCP as classic `CONNECT host:port`.

The h1 listen socket belongs to the process that calls `start_listener_h1/2`. Start it from a long-lived process (a supervised worker in your application), not from a short-lived one. `examples/two_hop_relay.erl` shows a keeper process for the shell.

To find the port of a listener started with `port => 0`: `quic:get_server_port(Name)` for h3, `h1:server_port(Ref)` for h1.

### Chain listeners

`start_chain_listener/2`, `start_chain_listener_h2/2` and `start_chain_listener_h1/2` take the same options and set `masque_chain_handler` as the UDP, TCP and IP handler, with a fresh `via_token` per listener unless you pass one. Every accepted tunnel is relayed to `handler_opts.upstream_proxy`. See [relay](relay.md).

### Embedding in your own server

If you already run a `quic_h3` or `h2` server, `masque:h3_handlers/1` and `masque:h2_handlers/1` return the handler funs to plug in, with a `fallback` fun for requests that are not MASQUE. On h3 you must use both returned funs (`handler` and `connection_handler`): the connection handler makes the MASQUE router the connection owner, which is how datagrams reach tunnels. Another extension that also needs to own the h3 connection (WebTransport, for example) cannot share that listener.

## Listener options

```erlang
Opts = #{
    port => 4433,
    cert => CertDer, key => Key,            %% h3; PEM paths on h2 and h1
    handler => masque_udp_proxy_handler,    %% CONNECT-UDP (default shown)
    tcp_handler => masque_tcp_proxy_handler,
    ip_handler => masque_ip_proxy_handler,
    bind_handler => masque_udp_bind_proxy_handler,
    handler_opts => #{allow_private => false},
    max_tunnels_per_connection => 256
}.
```

| Option | Transports | Default | Meaning |
|---|---|---|---|
| `port` | all | required | Listen port; `0` picks one. |
| `cert`, `key` | all | required | See [TLS material](#tls-material). |
| `handler`, `tcp_handler`, `ip_handler`, `bind_handler` | all | built-in proxy handlers | Handler module per protocol. |
| `handler_opts` | all | `#{}` | Passed to every handler's `init/2` and visible in `accept/1` as `handler_opts`. |
| `uri_template` | all | `/.well-known/masque/udp/{target_host}/{target_port}/` | CONNECT-UDP and Connect-UDP-Bind path. |
| `tcp_uri_template` | h3, h2 | `/.well-known/masque/tcp/{target_host}/{target_port}/` | CONNECT-TCP path (h1 uses classic CONNECT, no template). |
| `ip_uri_template` | all | `/.well-known/masque/ip/{target}/{ipproto}/` | CONNECT-IP path. |
| `accept_bind` | all | `false` | Accept Connect-UDP-Bind on the UDP template. See [connect-udp-bind](connect-udp-bind.md). |
| `resolver` | all | A + AAAA lookup | Resolves CONNECT-IP host name targets before `accept/1`. Returns `{ok, [Address]}`. |
| `max_tunnels_per_connection` | h3, h2 | `0` (no limit) | Tunnels one client connection may hold. Extra requests get 503. |
| `fallback` | h3, h2 | none | `fun(Conn, StreamId, Method, Path, Headers)` for requests that are not MASQUE. Without it they are rejected. |
| `settings` | h3, h2 | `#{}` | Extra transport settings; the MASQUE ones are always forced on. |
| `acceptors` | h2, h1 | library default | Acceptor processes. |
| `reuseport`, `alpn`, `max_datagram_frame_size` | h3 | `false`, `[<<"h3">>]`, `65535` | QUIC listener tuning. |

### Where handler options go

Handler policy (`allow`, `allow_private`, `family`, `connect_timeout`, `socket_opts`, `active_n`, `mtu`, `address_pool`, and so on) belongs in `handler_opts`. For convenience every listener also copies these top-level keys into `handler_opts`: `address_pool`, `routes`, `mtu`, `resolver`, `allow`, `family`, `allow_private`, `connect_timeout`, `socket_opts` and the udp-bind keys (the list is `handler_opt_keys/0` in `masque_server`). A key in `handler_opts` always wins.

The top-level `resolver` has the listener shape (`{ok, [Address]}`). When it is copied into `handler_opts`, the UDP and TCP proxy handlers use the first address of the list.

## Accept, refuse, authenticate

Before a tunnel starts, the listener validates the request, matches the path, resolves CONNECT-IP host names, and then calls your handler's `accept/1` with the request map (fields in [handlers](handlers.md#the-request-map)). Return `accept` or refuse:

```erlang
accept(#{target_port := 53}) -> accept;
accept(_) -> {reject, forbidden}.                   %% 403
```

The reject reasons and their status codes:

| Reason | Status | Proxy-Status error |
|---|---|---|
| `bad_method` | 405 | `http_protocol_error` |
| `bad_protocol` | 501 | `http_protocol_error` |
| `bad_path` | 404 | `http_protocol_error` |
| `bad_port`, `bad_host` | 400 | `http_protocol_error` |
| `forbidden` | 403 | `destination_ip_prohibited` |
| `resolution_failed` | 502 | `dns_error` |
| `upstream_timeout` | 504 | `connection_timeout` |
| `loop_detected` | 508 | `proxy_loop_detected` |
| `overload` | 503 | `proxy_internal_error` |
| `{other, Status}` | `Status` (400..599) | `proxy_internal_error` |
| anything else | 502 | `proxy_internal_error` |

Every rejection carries a `proxy-status: masque; error=...` header (RFC 9209) and a one-line text body. On h1 the listener also closes the connection after a rejection.

`accept/1` runs in the request handling process, before any session exists, so keep it fast and do not raise: `masque` does not catch exceptions from it. Refusals that need work (opening a socket, dialing an upstream) belong in `init/2`, where `{stop, Reason}` also refuses the tunnel (see [handlers](handlers.md#init-runs-before-the-2xx)).

### Challenge headers (Privacy Pass style)

Return a third element to add response headers to the rejection, for example a `WWW-Authenticate` challenge. Your headers replace the library's on the same name (`content-type`, `content-length`, `proxy-status`).

```erlang
accept(#{headers := H, handler_opts := #{token_key := K}}) ->
    case lists:keyfind(<<"authorization">>, 1, H) of
        {_, <<"PrivateToken token=", T/binary>>} ->
            case my_tokens:verify(T, K) of
                ok -> accept;
                _ -> {reject, forbidden}
            end;
        _ ->
            {reject, {other, 401},
             [{<<"www-authenticate">>, my_tokens:challenge(K)}]}
    end.
```

The client answers the challenge by retrying with `request_headers`:

```erlang
masque:connect(Proxy, Target, #{request_headers =>
    [{<<"authorization">>, <<"PrivateToken token=", Token/binary>>}]}).
```

On h3 the request map also carries `peer` (address and port), and `peer_cert` (DER) when the QUIC connection has a client certificate. `start_listener/2` does not ask clients for a certificate, so `peer_cert` only shows up when you embed `masque` in your own `quic_h3` server configured for mutual TLS. h2 and h1 provide neither field.

## Drain

```erlang
ok = masque:drain_listener(my_h3),   %% new requests get 503 overload
true = masque:is_draining(my_h3),
ok = masque:undrain_listener(my_h3).
```

Draining works by listener name on all three transports. Tunnels already open keep running; only new requests are refused. Starting or stopping a listener clears its drain flag. For rolling restarts see [operations](operations.md#drain-for-rolling-restarts).

## Limits

| Limit | Where | Default | When it trips |
|---|---|---|---|
| `max_tunnels_per_connection` | listener, h3 and h2 | unlimited | 503 `overload`. h1 carries one tunnel per connection anyway. |
| `max_capsule_size` | `handler_opts` | 65536 bytes | A capsule larger than this aborts the tunnel. |
| `idle_timeout_ms` | `handler_opts`, h1 sessions | 300000 | An h1 tunnel with no bytes from the client for this long ends with `idle_timeout`. `infinity` disables it. |
| Session `init/2` time | h3 | 30 s | The request is refused with 502. |

## Security defaults

- The built-in UDP and TCP handlers refuse targets that resolve to non-public addresses (private, loopback, link-local, CGNAT, documentation, multicast; see `masque_ip:is_public/1`). The tunnel is refused with 502 `resolution_failed`. Set `allow_private => true` in `handler_opts` to allow them.
- The built-in IP handler refuses the `*` target and non-public targets with 403 unless `allow_private` is set, and filters packets per tunnel. See [connect-ip](connect-ip.md#target-scoping).
- The built-in udp-bind handler only exchanges packets with public peers; `allow_loopback` and `allow_private` widen that. See [connect-udp-bind](connect-udp-bind.md#peer-filter).
- The chain handler verifies the upstream proxy certificate by default.
- The h1 listener closes the connection after every rejection, so a client cannot smuggle bytes after a refused request.

## TLS material

| Transport | `cert` | `key` |
|---|---|---|
| h3 | DER-encoded certificate (binary) | Decoded private key, as returned by `public_key:der_decode/2` |
| h2 | PEM file path | PEM file path |
| h1 | PEM file path | PEM file path |

Loading the h3 form from PEM files:

```erlang
{ok, CertPem} = file:read_file("cert.pem"),
{ok, KeyPem} = file:read_file("key.pem"),
[{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),
[{KeyType, KeyRaw, not_encrypted}] = public_key:pem_decode(KeyPem),
Key = public_key:der_decode(KeyType, KeyRaw).
```

The listeners take the certificate and key only; they do not forward client-certificate options, so mutual TLS is not configurable on h2 and h1 through `masque`. To rotate certificates, stop and start the listener with the new material.

Next: [handlers](handlers.md), then [operations](operations.md).
