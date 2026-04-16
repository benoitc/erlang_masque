# Usage guide

This guide covers the patterns the [README](../README.md) only
sketches: the two client delivery modes, running many tunnels in
parallel, integrating MASQUE into an HTTP/3 server you already own,
and the server-side handler module lifecycle.

## Contents

1. [Transport selection (h3/h2 racing)](#1-transport-selection)
2. [Client delivery modes](#2-client-delivery-modes)
3. [Multiple tunnels from one client](#3-multiple-tunnels-from-one-client)
4. [Multiple tunnels on one listener](#4-multiple-tunnels-on-one-listener)
5. [Integrating MASQUE with an existing server](#5-integrating-masque-with-an-existing-server)
6. [Handler behaviour lifecycle](#6-handler-behaviour-lifecycle)
7. [Capsule protocol](#7-capsule-protocol)
8. [Error mapping](#8-error-mapping)
9. [Known limitations](#9-known-limitations)

---

## 1. Transport selection

By default `masque:connect/3` races HTTP/3 and HTTP/2 in parallel,
following the pattern Apple uses in Network.framework and iCloud
Private Relay:

1. Start an h3 (QUIC) connection attempt immediately.
2. After `prefer_timeout_ms` (default 250 ms), start an h2
   (TCP+TLS) attempt in parallel.
3. Whichever handshake produces a 2xx first wins. The loser is
   cancelled.

This gives h3 a head start on networks where QUIC works, while
falling back to h2 in ~250 ms on networks that block UDP.

```erlang
%% Default: race both (recommended for production)
{ok, Sess} = masque:connect(ProxyURI, Target, #{verify => verify_none}).

%% Force h3 only (tests, known-QUIC environments)
{ok, Sess} = masque:connect(ProxyURI, Target,
                            #{transports => [h3],
                              verify => verify_none}).

%% Force h2 only (UDP-blocked networks, firewall policy)
{ok, Sess} = masque:connect(ProxyURI, Target,
                            #{transports => [h2],
                              verify => verify_none}).

%% Tune the head-start window (e.g. 500 ms for high-latency links)
{ok, Sess} = masque:connect(ProxyURI, Target,
                            #{prefer_timeout_ms => 500,
                              verify => verify_none}).
```

### Server-side transport listeners

HTTP/3 and HTTP/2 need separate listeners (QUIC is UDP, h2 is TCP):

```erlang
%% h3 listener (existing API, DER cert/key)
masque:start_listener(my_h3, #{port => 4433, cert => CertDer, key => KeyDer}).

%% h2 listener (PEM file paths, matching erlang_h2 convention)
masque:start_listener_h2(my_h2, #{port => 4434,
                                   cert => "cert.pem",
                                   key => "key.pem"}).
```

Both listeners share the same `masque_handler` behaviour, so the
same handler module works on either transport.

### How it works under the hood

On HTTP/3, UDP payloads travel as native HTTP Datagrams (RFC 9297).
On HTTP/2, there is no datagram channel, so every UDP payload is
wrapped in a DATAGRAM capsule (RFC 9297 S3.2) and sent as stream
body data. The `masque` API hides this difference: `send_packet`,
`recv_packet`, and `{masque_packet, _, _}` messages look the same
regardless of transport.

---

## 2. Client delivery modes

`masque:connect/3` returns a `session()` pid. A session has two
delivery modes for inbound UDP payloads:

| Mode | Delivery | Pick it when… |
| --- | --- | --- |
| `message` (default) | Owner receives `{masque_packet, Sess, Data}` for each incoming UDP packet. | Owner is an OTP process (`gen_server`, `gen_statem`) that already has a mailbox loop and wants to handle packets alongside its other events. |
| `queue` | Packets buffer inside the session; pull with `masque:recv_packet/2`. | Imperative/sync code, scripts, tests, simple request/response patterns. |

Switch at any time with `masque:set_active/2`:

```erlang
{ok, Sess} = masque:connect(ProxyURI, Target, #{verify => verify_none}).
ok = masque:set_active(Sess, queue),
ok = masque:send_packet(Sess, <<"ping">>),
{ok, Reply} = masque:recv_packet(Sess, 5000).
```

Message mode inside a `gen_server`:

```erlang
handle_info({masque_packet, Sess, Data}, State = #{sess := Sess}) ->
    {noreply, State#{last_reply := Data}}.
```

Both modes also surface closure:

- `{masque_closed, Sess, Reason}` - peer reset or abrupt close (message mode).
- The session process terminates (monitor for `{'DOWN', _, process, Sess, _}`).

---

## 3. Multiple tunnels from one client

Every call to `masque:connect/3` returns an independent session with
its own QUIC connection. Open as many as you need concurrently.

```erlang
Targets = [{<<"1.1.1.1">>, 53},
           {<<"8.8.8.8">>, 53},
           {<<"9.9.9.9">>, 53}],
Sessions = [begin
                {ok, S} = masque:connect(ProxyURI, T,
                                         #{verify => verify_none}),
                S
            end || T <- Targets],

[ok = masque:send_packet(S, Query) || S <- Sessions],

Replies = [receive {masque_packet, S, R} -> R after 3000 -> timeout end
           || S <- Sessions],

[masque:close(S) || S <- Sessions].
```

Notes:

- Each session keeps its own QUIC connection open; this costs one
  handshake per tunnel and is the simplest model.
- If you need many tunnels *through the same* QUIC connection to the
  proxy (sharing a single handshake), that's a phase-2 feature - the
  public API does not expose it today.

---

## 4. Multiple tunnels on one listener

The server side already scales: every accepted HTTP/3 connection gets
its own router (`masque_server_connection`) that demultiplexes inbound
HTTP Datagrams by stream-id and dispatches them to the per-tunnel
session process. A single client can open dozens of concurrent
CONNECT-UDP tunnels on one HTTP/3 connection with no extra
configuration.

The built-in `masque_udp_proxy_handler` opens a fresh `gen_udp`
socket per tunnel, so isolation between tunnels is enforced at the
OS level.

If you need to apply per-connection state (e.g. identity,
rate limits), store it in the handler module's state map - `init/2`
runs once per tunnel and sees the full request map, including any
authentication headers you care about.

---

## 5. Integrating MASQUE with an existing server

`masque:start_listener/2` is the one-call path: it spins up a
dedicated `quic_h3` listener that handles nothing but CONNECT-UDP.

If you already run an HTTP/3 service (static routes, a custom API,
another extension), use `masque:h3_handlers/1` instead. It returns
the `handler` and `connection_handler` funs that you splat into your
own `quic_h3:start_server/3` call.

```erlang
%% Your app's existing HTTP/3 routes.
MyHandler = fun
    (Conn, StreamId, <<"GET">>, <<"/health">>, _Hdrs) ->
        ok = quic_h3:send_response(Conn, StreamId, 200, []),
        ok = quic_h3:send_data(Conn, StreamId, <<"ok\n">>, true);
    (Conn, StreamId, _M, _P, _H) ->
        ok = quic_h3:send_response(Conn, StreamId, 404, []),
        ok = quic_h3:send_data(Conn, StreamId, <<>>, true)
end.

%% Ask masque for its piece. Everything that is NOT a CONNECT-UDP
%% request falls through to `fallback'.
#{handler := MasqueHandler,
  connection_handler := MasqueConnHandler} =
    masque:h3_handlers(#{
        handler      => masque_udp_proxy_handler,
        handler_opts => #{
            allow => fun({Host, 53}) ->
                             lists:member(Host, [<<"1.1.1.1">>,
                                                 <<"8.8.8.8">>]);
                        ({_, _}) -> false
                     end
        },
        fallback     => MyHandler
    }).

{ok, _} = quic_h3:start_server(my_app, 4433, #{
    cert     => CertDer,
    key      => KeyDer,
    settings => #{enable_connect_protocol => 1, h3_datagram => 1},
    quic_opts => #{
        alpn                    => [<<"h3">>],
        max_datagram_frame_size => 65535
    },
    handler            => MasqueHandler,
    connection_handler => MasqueConnHandler
}).
```

With this wiring:

- `CONNECT-UDP` requests matching the URI template run through MASQUE.
- Any other request (wrong method, wrong `:protocol`, or a path that
  doesn't match the template) is dispatched to `MyHandler`.

### Why `connection_handler` matters

HTTP Datagrams are delivered to the H3 connection's `owner` pid.
MASQUE spawns one router per connection and sets it as the owner so
datagrams can be fanned out to the right tunnel. That's why
`h3_handlers/1` gives you **both** a `handler` (request dispatch) and
a `connection_handler` (per-connection setup) - you need both for
datagrams to flow.

If you already have your own `connection_handler` (for example to
spawn a per-connection state process), merge its return map with
MASQUE's: keys `owner` and `h3_datagram_enabled` must come from the
MASQUE side for tunnels to work.

### Known limitation — single owner per connection

MASQUE *must* be the connection's `owner` in v0.1. Running MASQUE and
another extension that also needs ownership (e.g. WebTransport)
**on the same port** is not supported. The pragmatic workaround is
two separate listeners on different ports.

---

## 6. Handler behaviour lifecycle

Custom server-side logic is a module implementing the
[`masque_handler`](../src/masque_handler.erl) behaviour. All callbacks
are optional except in the way documented.

```erlang
-module(my_handler).
-behaviour(masque_handler).

-export([accept/1, init/2,
         handle_packet/2, handle_capsule/3,
         handle_info/2, terminate/2]).
```

| Callback | Fires when… | Returns |
| --- | --- | --- |
| `accept/1` | Handshake received, before any 2xx response. | `accept` or `{reject, masque_errors:handshake_error()}`. Optional - default is `accept`. |
| `init/2` | Tunnel is accepted, session process starts. | `{ok, State}` \| `{ok, State, [action()]}` \| `{stop, Reason}`. |
| `handle_packet/2` | Inbound UDP payload arrives (context 0). | `{ok, State}` \| `{ok, State, [action()]}` \| `{stop, Reason, State}`. |
| `handle_capsule/3` | Inbound capsule arrives on the request body stream. | same as `handle_packet`. |
| `handle_info/2` | Any other Erlang message arrives (e.g. `{udp, Socket, …}`). | same as `handle_packet`. |
| `terminate/2` | Session is shutting down. | return value ignored. |

### Actions

Callbacks return a list of actions; the session runs each one in order:

```erlang
-type action() ::
    {send_packet, iodata()}                     %% context 0 - UDP payload
  | {send_packet, ContextId :: non_neg_integer(), iodata()}
  | {send_capsule, Type :: non_neg_integer(), iodata()}
  | close_session
  | {close_session, ErrorCode :: non_neg_integer(), Message :: binary()}.
```

- `{send_packet, Data}` queues an HTTP Datagram back to the client
  (oversize payloads are silently dropped - HTTP Datagrams are
  unreliable by design; see RFC 9298 §5).
- `{send_capsule, Type, Value}` sends a capsule on the request body
  stream. The client delivers it as `{masque_capsule, Sess, Type, Value}`.
- `close_session` (and its 3-ary form) terminates the tunnel
  gracefully.

### `accept/1` policy gate

`accept/1` runs in the handler fun process (a short-lived worker),
*before* the 2xx response is sent. Use it to enforce target
allow-lists, check authentication headers, or refuse overload:

```erlang
accept(#{target_host := H, target_port := P, headers := Hdrs}) ->
    case {allowed(H, P), authenticated(Hdrs)} of
        {true, true}  -> accept;
        {false, _}    -> {reject, forbidden};       %% -> HTTP 403
        {_, false}    -> {reject, {other, 401}}     %% -> HTTP 401
    end.
```

See [`masque_errors`](../src/masque_errors.erl) for the full
`handshake_error()` atom set.

---

## 7. Capsule protocol

RFC 9297 capsules travel reliably on the CONNECT-UDP request stream
body. They're how future extensions will negotiate context IDs,
signal ICMP, etc.

### Client

```erlang
ok = masque:send_capsule(Sess, 16#cafef00d, <<"extension body">>).

receive
    {masque_capsule, Sess, 16#cafef00d, Value} -> Value
end.
```

### Server

```erlang
handle_capsule(Type, Value, State) ->
    %% Echo it back.
    {ok, State, [{send_capsule, Type, Value}]}.
```

Malformed capsule bytes on the wire cause the session to close with
reason `malformed_capsule`. Unknown capsule types are handed to the
handler module as-is; RFC 9297 §3.3 recommends ignoring any type you
don't understand.

---

## 8. Error mapping

RFC 9298 failure modes are rendered as HTTP status codes by
[`masque_errors:handshake_status/1`](../src/masque_errors.erl):

| `handshake_error()` | Status | Meaning |
| --- | --- | --- |
| `bad_method` | 405 | `:method` is not `CONNECT`. |
| `bad_protocol` | 501 | `:protocol` is missing or not `connect-udp`. |
| `bad_path` | 404 | `:path` did not match the URI template. |
| `bad_port` | 400 | target port out of the 1-65535 range. |
| `bad_host` | 400 | target host empty or malformed after percent-decoding. |
| `resolution_failed` | 502 | DNS/resolver hook returned an error. |
| `upstream_timeout` | 504 | target did not respond in time. |
| `forbidden` | 403 | denied by the handler's `accept/1` or the `allow` policy. |
| `loop_detected` | 508 | proxy loop (reserved for phase-2 proxy chaining). |
| `overload` | 503 | proxy-shed load. |
| `{other, N}` | N | escape hatch for any 4xx/5xx status. |

`{reject, Reason}` from `accept/1` uses the same atoms.

---

## 9. Known limitations

- **One owner per QUIC connection.** MASQUE takes the `owner` slot;
  running it alongside another extension that also needs `owner`
  (e.g. WebTransport) on the same port is not supported. Use
  separate listeners on separate ports.
- **One QUIC connection per client session.** Multiple tunnels to the
  same proxy today mean multiple QUIC handshakes. Tunnel multiplexing
  over a single client connection is on the roadmap (phase 2).
- **No proxy chaining / authorization hooks yet.** The design is
  sketched for v0.3; track
  [`docs/features.md`](features.md#deferred-to-follow-up-releases).
- **HTTP/2 datagrams are reliable.** On h2, UDP payloads travel as
  capsules on a TCP stream, so they gain ordering and reliability
  that raw UDP lacks. Applications depending on packet loss or
  reordering semantics should force `transports => [h3]`.
- **HTTP/1.1 Upgrade not supported.** RFC 9298 also defines an
  HTTP/1.1 path; this library covers h3 and h2 only.
- **RFC 9484 (Proxying IP)** lives in a separate library on top of
  `masque`, not here.
