# masque

An Erlang implementation of [RFC 9298 - Proxying UDP in HTTP][rfc9298]
(MASQUE CONNECT-UDP) over **HTTP/3**, built on
[`erlang_quic`][quic]'s `quic_h3` stack. HTTP/1.1 Upgrade and
HTTP/2 transports are not supported.

`masque` lets you tunnel arbitrary UDP flows (DNS, QUIC, WireGuard,
game traffic, …) through an authenticated HTTPS endpoint. Both proxy
**server** and **client** are shipped in this library.

## Features

- RFC 9298 Extended CONNECT handshake (`:protocol = connect-udp`)
- RFC 9297 HTTP Datagrams for UDP payloads (quarter-stream-id handled
  by `quic_h3`)
- Context-ID framing per RFC 9298 §5 (context 0 = UDP)
- Capsule-protocol dispatch for extension capsule types
- Built-in UDP proxy handler (`masque_udp_proxy_handler`) - zero-code
  proxies with optional `allow` / `resolver` policy hooks
- Handler behaviour for custom server-side logic
- Client API in both *message* and *queue* (blocking `recv_packet`)
  delivery modes
- End-to-end compliance CT suite (17 cases) + eunit codecs (29 tests)
  + PropEr properties (3) + skippable external-peer interop suite

- **[Usage guide](docs/usage.md)** - client modes, multiple tunnels,
  integration with an existing `quic_h3` server, handler lifecycle.
- **[Feature matrix](docs/features.md)** - RFC coverage and
  intentional non-goals.

## Installation

Add to your `rebar.config`:

```erlang
{deps, [
    {masque, {git, "https://github.com/benoitc/erlang_masque.git", {branch, "main"}}}
]}.
```

## Quick start

### Running proxy server

```erlang
{ok, CertDer} = file:read_file("cert.der"),
{ok, KeyDer}  = file:read_file("key.der"),

{ok, _} = masque:start_listener(my_proxy, #{
    port    => 4433,
    cert    => CertDer,
    key     => KeyDer
    %% defaults: uri_template = /.well-known/masque/udp/{target_host}/{target_port}/
    %%           handler      = masque_udp_proxy_handler
}).
```

With a policy hook:

```erlang
{ok, _} = masque:start_listener(my_proxy, #{
    port    => 4433,
    cert    => CertDer,
    key     => KeyDer,
    handler_opts => #{
        allow => fun({Host, Port}) ->
            Port =:= 53 andalso lists:member(Host, [<<"1.1.1.1">>, <<"8.8.8.8">>])
        end
    }
}).
```

### Client

```erlang
{ok, Sess} = masque:connect(<<"https://proxy.example:4433">>,
                             {<<"192.0.2.6">>, 443},
                             #{verify => verify_none}),

ok         = masque:send_packet(Sess, <<"hello target">>),

%% Default: owner receives `{masque_packet, Sess, Data}' messages.
receive
    {masque_packet, Sess, Reply} -> Reply
end,

ok         = masque:close(Sess).
```

Blocking receive (no mailbox pattern matching):

```erlang
{ok, Sess} = masque:connect(ProxyURI, Target, #{verify => verify_none}),
ok         = masque:set_active(Sess, queue),
ok         = masque:send_packet(Sess, Payload),
{ok, Bytes} = masque:recv_packet(Sess, 3000).
```

### Custom server handler

```erlang
-module(my_handler).
-behaviour(masque_handler).

-export([accept/1, init/2, handle_packet/2, terminate/2]).

accept(#{target_host := Host}) ->
    case is_allowed(Host) of
        true  -> accept;
        false -> {reject, forbidden}   %% → HTTP 403 to the client
    end.

init(_Req, _Opts) ->
    {ok, #{counter => 0}}.

handle_packet(Data, #{counter := N} = S) ->
    {ok, S#{counter := N + 1}, [{send_packet, Data}]}.

terminate(_Reason, _State) -> ok.
```

## Examples

- [`examples/udp_echo_proxy.erl`](examples/udp_echo_proxy.erl) - a
  zero-code MASQUE proxy on port 4433.
- [`examples/udp_dig_client.erl`](examples/udp_dig_client.erl) -
  resolve a DNS name through a MASQUE proxy.

## Building and testing

```sh
rebar3 compile
rebar3 eunit          # unit tests (codecs)
rebar3 as test proper # PropEr properties
rebar3 ct             # common_test (17 cases)
rebar3 xref
rebar3 dialyzer
```

External-peer interop:

```sh
MASQUE_GO_BIN=/path/to/masque-go rebar3 ct --suite=masque_interop_SUITE
```

## License

Apache License 2.0. See [`LICENSE`](LICENSE).

[rfc9298]: https://www.rfc-editor.org/rfc/rfc9298
[quic]:    https://github.com/benoitc/erlang_quic
