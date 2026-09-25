# API Reference

Complete reference for the `masque` public API. All functions are
exported from the `masque` module unless noted otherwise.

## Types

```erlang
-type session()       :: pid().
-type proxy_uri()     :: binary() | string().
-type target()        :: {binary() | inet:hostname() | inet:ip_address(),
                          inet:port_number()}.
-type transport()     :: h3 | h2 | h1.
```

### connect_opts()

Options for `connect/3`:

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `protocol` | `udp \| tcp \| ip` | `udp` | Tunnel protocol. `udp` opens a CONNECT-UDP tunnel (RFC 9298), `tcp` a CONNECT-TCP tunnel, `ip` a CONNECT-IP tunnel (RFC 9484). |
| `transports` | `[transport()]` | `[h3, h2]` | Transport preference. When both are listed, h3 and h2 race with h3 getting a head start. |
| `prefer_timeout_ms` | `non_neg_integer()` | `250` | Milliseconds h3 gets before h2 starts racing. |
| `timeout` | `pos_integer()` | `5000` | Handshake timeout in milliseconds. |
| `verify` | `verify_peer \| verify_none` | `verify_peer` | TLS certificate verification, on every transport. `verify_peer` also checks the hostname and sends SNI. Use `verify_none` or `cacerts` for self-signed proxies. |
| `cacerts` | `[der_encoded()]` | system CAs | Custom CA certificates for `verify_peer` (honoured on h1, h2 and h3). |
| `ssl_opts` | `[ssl:tls_client_option()]` | `[]` | Extra TLS options passed to the transport. |
| `uri_template` | `binary()` | `/.well-known/masque/udp/{target_host}/{target_port}/` | URI template for the CONNECT request. |
| `capsule_protocol` | `boolean()` | `true` | Whether to validate the `capsule-protocol: ?1` response header. Ignored for `tcp`: CONNECT-TCP never sends the header and rejects a 2xx that carries it. |
| `owner` | `pid()` | `self()` | Process that receives `{masque_data, ...}` messages. |
| `mode` | `message \| queue` | `message` | Initial delivery mode. |
| `rx_queue_limit` | `pos_integer()` | `1000` | Most items buffered in `queue` mode. Datagram sessions drop and count (`rx_dropped` in `info/1`) past it; a TCP session ends with `{error, rx_overflow}`. |
| `upstream_pool` | `boolean()` | `false` | Opt-in connection pooling. When `true`, h2 / h3 attempts share a pooled transport connection keyed by host / port / transport plus a hash of connect-affecting opts (`verify`, `cacerts`, `ssl_opts`, `alpn`). Each tunnel rides a fresh stream on the shared conn. h1 always bypasses the pool (1-tunnel-per-socket). |
| `upstream_pool_opts` | `map()` | `#{}` | Tuning forwarded to pooled owners on cold dials. Recognised keys: `idle_timeout_ms` (non-neg integer, default 30000), `max_streams` (positive integer or `dynamic`), `checkout_timeout_ms` (default 60000; past it `connect/3` returns `{error, timeout}`). |
| `request_headers` | `[{binary(), binary()}]` | `[]` | Extra headers prepended to the CONNECT (or GET+Upgrade on h1) request. Useful for auth schemes that ride on the handshake (e.g. `Authorization: PrivateToken token=...`). Reserved pseudo-headers (`:method`, `:authority`, `:path`, `:protocol`, `capsule-protocol`) are silently dropped. On h1, CR/LF in either key or value is rejected to prevent request-line injection. |

### listener_opts()

Options for `start_listener/2`:

| Key | Type | Required | Description |
| --- | --- | --- | --- |
| `port` | `inet:port_number()` | yes | Listen port. |
| `cert` | `binary()` | yes | DER-encoded server certificate. |
| `key` | `binary()` | yes | DER-encoded private key. |
| `certfile` | `file:filename()` | alt | PEM certificate file (alternative to `cert`). |
| `keyfile` | `file:filename()` | alt | PEM key file (alternative to `key`). |
| `handler` | `module()` | no | Handler module implementing `masque_handler`. Default: `masque_udp_proxy_handler`. |
| `handler_opts` | `term()` | no | Passed to handler `init/2`. Default: `#{}`. |
| `tcp_handler` | `module()` | no | Handler for CONNECT-TCP tunnels. Default: `masque_tcp_proxy_handler`. |
| `uri_template` | `binary()` | no | Custom URI template for UDP. |
| `tcp_uri_template` | `binary()` | no | Custom URI template for TCP. |
| `fallback` | `fun/5` | no | Called for non-MASQUE requests. Signature: `fun(Conn, StreamId, Method, Path, Headers)`. |
| `reuseport` | `boolean()` | no | Enable `SO_REUSEPORT` for kernel-level scaling. Default: `false`. |
| `allow` | `fun(target()) -> boolean()` | no | Policy gate - reject targets that return `false`. |
| `resolver` | `fun(hostname()) -> {ok, ip()} \| {error, _}` | no | Custom DNS resolver. |

---

## Client API

### connect/2,3

```erlang
-spec connect(proxy_uri(), target()) -> {ok, session()} | {error, term()}.
-spec connect(proxy_uri(), target(), connect_opts()) ->
    {ok, session()} | {error, term()}.
```

Open a MASQUE tunnel through a proxy to the given target.

`ProxyURI` is an `https://host:port` URL. `Target` is `{Host, Port}`
naming the endpoint to reach. Returns `{ok, Session}` after the proxy
responds with 2xx.

On failure it returns `{error, Reason}` instead of exiting. `Reason`
is the raw cause, for example `{connect, econnrefused}`, a TLS alert,
`handshake_timeout`, `bad_upgrade_response`, `headers_too_large` or
`bad_status_line`.

```erlang
{ok, Sess} = masque:connect(<<"https://proxy.example:4433">>,
                            {<<"1.1.1.1">>, 53}).
```

For TCP tunnels:

```erlang
{ok, Sess} = masque:connect(ProxyURI, {<<"example.com">>, 80},
                            #{protocol => tcp}).
```

### send/2,3

```erlang
-spec send(session(), iodata()) -> ok | {error, term()}.
-spec send(session(), non_neg_integer(), iodata()) -> ok | {error, term()}.
```

Send data through the tunnel.

- UDP tunnels: sends a UDP packet. Payloads over 65527 bytes are
  silently dropped (HTTP Datagrams are unreliable by design).
- TCP tunnels: sends raw bytes on the stream.

The 3-arity form sends under an explicit context-ID (UDP extension
use only; context 0 is the default).

### recv/2

```erlang
-spec recv(session(), pos_integer()) ->
    {ok, binary()} | {error, timeout | closed | term()}.
```

Block until data arrives or `Timeout` milliseconds elapse. Requires
the session to be in `queue` delivery mode. After the peer closes,
`recv/2` still returns the unread data, then `{error, closed}`; a
closed session keeps its queue for at most 30 s. On a dead session it
returns `{error, closed}`.

```erlang
ok = masque:set_mode(Sess, queue),
ok = masque:send(Sess, <<"ping">>),
{ok, Reply} = masque:recv(Sess, 5000).
```

### set_mode/2

```erlang
-spec set_mode(session(), message | queue) -> ok.
```

Switch the delivery mode of a session:

- `message` (default): the owner process receives
  `{masque_data, Sess, Data}` for each inbound packet.
- `queue`: packets are buffered internally; pull with `recv/2`.

Can be called at any time while the session is open.

### send_capsule/3

```erlang
-spec send_capsule(session(), non_neg_integer(), iodata()) ->
    ok | {error, term()}.
```

Send an RFC 9297 capsule on the tunnel's request stream. The capsule
`Type` is a varint-encoded capsule type; `Value` is the capsule body.

The peer receives it as `{masque_capsule, Sess, Type, Value}` in
message mode. CONNECT-TCP tunnels carry raw bytes only, so
`send_capsule/3` returns `{error, not_supported}` on them.

### shutdown_write/1

```erlang
-spec shutdown_write(session()) -> ok | {error, term()}.
```

Half-close the write side of a TCP tunnel. Sends END_STREAM and
prevents further writes. The session stays open for receiving data.
A half-closed tunnel with no traffic ends after 30 s. On h1 a FIN
ends the whole tunnel: OTP `ssl` drops the connection on the peer's
TLS `close_notify`.

Returns:
- `ok` - FIN sent successfully.
- `{error, not_supported}` - called on a UDP session.
- `{error, not_ready}` - session still connecting.
- `{error, write_closed}` - already shut down.
- `{error, closing}` - session is closing.

### close/1

```erlang
-spec close(session()) -> ok.
```

Close a session. Best-effort: if the session is stuck, `close`
returns `ok` after a 5-second timeout without blocking indefinitely.

### info/1

```erlang
-spec info(session()) -> map().
```

Return a map describing the session's current state and peers.
Datagram sessions (UDP, IP, udp-bind) include `rx_dropped`, the
number of items dropped because the queue was full.

### version/0

```erlang
-spec version() -> binary().
```

Return the library version from the application resource file.

---

## Owner Messages

In `message` delivery mode (the default), the owner process receives
these messages from an active session:

| Message | Meaning |
| --- | --- |
| `{masque_data, Sess, Data}` | Inbound UDP packet or TCP bytes. |
| `{masque_capsule, Sess, Type, Value}` | Inbound RFC 9297 capsule. |
| `{masque_closed, Sess, Reason}` | Session closed (`peer_reset`, `goaway`, `normal`, ...). |
| `{masque_closed, Sess, peer_fin}` | CONNECT-TCP: the peer finished sending. The session stays writable until `shutdown_write/1` or `close/1`. |

Monitor the session pid for definitive shutdown notification:

```erlang
MRef = erlang:monitor(process, Sess),
receive
    {'DOWN', MRef, process, Sess, Reason} -> handle_down(Reason)
end.
```

---

## Server API

### start_listener/2

```erlang
-spec start_listener(atom(), listener_opts()) ->
    {ok, pid()} | {error, term()}.
```

Start an HTTP/3 MASQUE listener. The listener accepts CONNECT-UDP
and CONNECT-TCP requests, dispatching them to the configured handler
module.

```erlang
{ok, _} = masque:start_listener(my_proxy, #{
    port => 4433,
    cert => CertDer,
    key  => KeyDer,
    handler => masque_udp_proxy_handler,
    handler_opts => #{
        allow => fun({_Host, 53}) -> true; ({_, _}) -> false end
    }
}).
```

### stop_listener/1

```erlang
-spec stop_listener(atom()) -> ok | {error, term()}.
```

Stop a running H3 listener by name.

### start_listener_h2/2

```erlang
-spec start_listener_h2(atom(), map()) ->
    {ok, h2:server_ref()} | {error, term()}.
```

Start an HTTP/2 MASQUE listener. Options are similar to the H3
listener but use PEM file paths:

```erlang
{ok, _} = masque:start_listener_h2(my_h2_proxy, #{
    port => 4434,
    cert => "cert.pem",
    key  => "key.pem"
}).
```

### stop_listener_h2/1

```erlang
-spec stop_listener_h2(h2:server_ref()) -> ok | {error, term()}.
```

### start_chain_listener/2

```erlang
-spec start_chain_listener(atom(), map()) ->
    {ok, pid()} | {error, term()}.
```

Start a chaining (two-hop) listener. Convenience wrapper that uses
`masque_chain_handler` as the handler. Every accepted tunnel is
relayed to the upstream proxy specified in
`handler_opts.upstream_proxy`.

```erlang
{ok, _} = masque:start_chain_listener(ingress, #{
    port => 4433,
    cert => CertDer,
    key  => KeyDer,
    handler_opts => #{
        upstream_proxy => <<"https://egress.example:4434">>,
        upstream_opts  => #{verify => verify_none}
    }
}).
```

### start_chain_listener_h2/2

```erlang
-spec start_chain_listener_h2(atom(), map()) ->
    {ok, h2:server_ref()} | {error, term()}.
```

Same as `start_chain_listener/2`, on HTTP/2. Cert/key are PEM file
paths (h2 convention). A full Apple-Private-Relay-shaped ingress
starts one chain listener on each transport so clients can race
them.

### start_chain_listener_h1/2

```erlang
-spec start_chain_listener_h1(atom(), map()) ->
    {ok, h1:server_ref()} | {error, term()}.
```

Same as `start_chain_listener/2`, on HTTP/1.1. Cert/key are PEM
file paths.

### h3_handlers/1

```erlang
-spec h3_handlers(map()) ->
    #{handler := fun(), connection_handler := fun()}.
```

Return the `handler` and `connection_handler` funs for integrating
MASQUE into a user-owned `quic_h3:start_server/3` call. Non-MASQUE
requests fall through to the `fallback` fun if provided.

### h2_handlers/1

```erlang
-spec h2_handlers(map()) -> #{handler := fun()}.
```

Return the `handler` fun for integrating MASQUE into a user-owned
`h2` server.

---

## Handler Behaviour

`masque_handler` defines the server-side callback interface. All
callbacks are optional.

### Callbacks

```erlang
-callback accept(req()) ->
    accept
  | {reject, handshake_error()}
  | {reject, handshake_error(), ExtraHeaders :: [{binary(), binary()}]}.
```

Synchronous accept/reject gate. Runs before the 200 response. A
reject reason the library does not know maps to 502. The
3-tuple form attaches custom response headers to the error (e.g.
`WWW-Authenticate: PrivateToken ...` for a Privacy Pass
challenge); caller-supplied headers override the library's defaults
on key collision.

```erlang
-callback init(req(), Opts :: term()) ->
    {ok, State} | {ok, State, [action()]} | {stop, Reason}.
```

Session start. Opens resources (sockets, upstream connections).
Over h3 the 2xx is sent after `init/2` returns; any output the
handler produces before that (for example from `handle_info/2`) is
held and sent after the 2xx, in order.

```erlang
-callback handle_packet(binary(), State) ->
    {ok, State} | {ok, State, [action()]} | {stop, Reason, State}.
```

Inbound UDP payload (CONNECT-UDP tunnels only).

```erlang
-callback handle_data(binary(), State) ->
    {ok, State} | {ok, State, [action()]} | {stop, Reason, State}.
```

Inbound TCP bytes (CONNECT-TCP tunnels only).

```erlang
-callback handle_capsule(Type :: non_neg_integer(), Value :: binary(), State) ->
    {ok, State} | {ok, State, [action()]} | {stop, Reason, State}.
```

Inbound capsule on the request body stream.

```erlang
-callback handle_eof(State) ->
    {ok, State} | {ok, State, [action()]} | {stop, Reason, State}.
```

Peer half-closed the write side (TCP FIN received). Only relevant
for CONNECT-TCP handlers. If not exported, the session stops
normally.

```erlang
-callback handle_info(Msg :: term(), State) ->
    {ok, State} | {ok, State, [action()]} | {stop, Reason, State}.
```

Any other Erlang message (e.g. `{udp, Socket, ...}`).

```erlang
-callback terminate(Reason :: term(), State) -> term().
```

Session shutdown. Return value ignored.

### Actions

Callbacks may return a list of actions:

| Action | Protocol | Description |
| --- | --- | --- |
| `{send, Data}` | UDP | Send a UDP payload back to the client (context 0). |
| `{send, ContextId, Data}` | UDP | Send under an explicit context-ID. |
| `{send_data, Data}` | TCP | Send raw bytes to the client. |
| `{send_data, Data, Fin}` | TCP | Send bytes, optionally with END_STREAM. |
| `{send_capsule, Type, Value}` | Both | Send an RFC 9297 capsule. |
| `close_session` | Both | Graceful tunnel close. |
| `{close_session, Code, Msg}` | Both | Close with error code and message. |

### Request Map

`accept/1` and `init/2` receive a request map:

```erlang
#{
    method      := binary(),       %% <<"CONNECT">>
    protocol    => udp | tcp,      %% tunnel protocol
    path        := binary(),       %% request path
    authority   := binary(),       %% :authority header
    scheme      := binary(),       %% <<"https">>
    target_host := binary(),       %% extracted from URI template
    target_port := 1..65535,       %% extracted from URI template
    headers     := [{binary(), binary()}],
    handler_opts => term()         %% from listener config
}
```

---

## Built-in Handlers

### masque_udp_proxy_handler

Bridges CONNECT-UDP tunnels to real UDP sockets. Opens a connected
`gen_udp` socket per tunnel for kernel-level spoofing protection.

Handler options:

| Key | Type | Description |
| --- | --- | --- |
| `allow` | `fun(target()) -> boolean()` | Policy gate. Default: allow all. |
| `resolver` | `fun(hostname()) -> {ok, ip()} \| {error, _}` | Custom resolver. |
| `family` | `inet \| inet6 \| auto` | Address family. Default: `auto`. |
| `socket_opts` | `[gen_udp:option()]` | Extra socket options. |
| `allow_private` | `boolean()` | Allow non-public targets. Default: `false`. |
| `active_n` | `pos_integer()` | Datagrams read per `{active, N}` window. Default: `32`. |

### masque_tcp_proxy_handler

Bridges CONNECT-TCP tunnels to real TCP connections via `gen_tcp`.

Handler options: same as UDP proxy, plus:

| Key | Type | Description |
| --- | --- | --- |
| `connect_timeout` | `pos_integer()` | TCP connect timeout in ms. Default: `5000`. |
| `active_n` | `pos_integer()` | Segments read per `{active, N}` window. Default: `16`. The socket is re-armed only after the tunnel write succeeds; a write that fails or stays blocked for 30 s resets the tunnel. |

### masque_chain_handler

Relays tunnels to an upstream MASQUE proxy (two-hop chaining).
Used for Private Relay-style architectures.

Handler options:

| Key | Type | Description |
| --- | --- | --- |
| `upstream_proxy` | `binary()` | URI of the upstream proxy (required). |
| `upstream_opts` | `map()` | Options forwarded to `masque:connect/3` for the upstream leg. Set `upstream_pool => true` here to share one pooled connection to the egress across tunnels. |
| `upstream_timeout` | `pos_integer()` | Upstream connect timeout in ms. Default: `5000`. |
| `allow` | `fun(target()) -> boolean()` | Policy gate. |
| `via_token` | `binary()` | This hop's pseudonym in the `via` header. The chain listeners create one per listener; otherwise `masque_chain_handler:node_token/0`. Create your own with `masque_chain_handler:new_token/0`. |

The upstream leg verifies the egress certificate by default; pass
`verify => verify_none` or `cacerts` in `upstream_opts` for a private
PKI. A request whose `via` header already carries this hop's token is
rejected with 508 and Proxy-Status `proxy_loop_detected`.

---

## Dependencies

| Dependency | Version | Role |
| --- | --- | --- |
| [erlang_quic](https://github.com/benoitc/erlang_quic) | 2.0.1 | QUIC + HTTP/3 transport |
| [erlang_h2](https://github.com/benoitc/erlang_h2) | 0.12.3 | HTTP/2 transport |
| [erlang_h1](https://github.com/benoitc/erlang_h1) | 0.9.1 | HTTP/1.1 transport |
