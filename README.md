# masque

[![CI](https://github.com/benoitc/erlang_masque/actions/workflows/ci.yml/badge.svg)](https://github.com/benoitc/erlang_masque/actions/workflows/ci.yml)

An Erlang implementation of the MASQUE family - [RFC 9298 - Proxying
UDP in HTTP][rfc9298], [RFC 9484 - Proxying IP in HTTP][rfc9484], and
the draft-ietf-httpbis-connect-tcp variant - over **HTTP/3** and
**HTTP/2**, built on [`erlang_quic`][quic] (`quic_h3`) and
[`erlang_h2`][h2].

The client races both transports Apple-style (h3 first, h2 after
250 ms, first 2xx wins) so tunnels connect quickly even on networks
that block QUIC.

`masque` lets you tunnel arbitrary UDP flows (DNS, QUIC, WireGuard,
game traffic, …), TCP streams, and full IP packets through an
authenticated HTTPS endpoint. Both proxy **server** and **client**
are shipped in this library.

## Features

- RFC 9298 CONNECT-UDP (`:protocol = connect-udp`): built-in UDP
  proxy handler, `allow` / `resolver` policy hooks, client API in
  both *message* and *queue* (blocking `recv`) delivery modes.
- RFC 9484 CONNECT-IP (`:protocol = connect-ip`): bidirectional
  control plane (`ADDRESS_ASSIGN` / `ADDRESS_REQUEST` /
  `ROUTE_ADVERTISEMENT`), default handler with address-pool
  allocator, listener-owned DNS resolution before `accept/1`,
  BCP-38 source filter, ICMPv4+v6 error synthesis (`masque_icmp`),
  H3 datagram MTU enforcement per §8. See
  [the CONNECT-IP guide](https://hexdocs.pm/masque/connect_ip.html) for
  the §-mapped compliance table.
- draft-ietf-httpbis-connect-tcp (`:protocol = connect-tcp`): TCP
  tunneling with END_STREAM = TCP FIN semantics.
- One listener serves all three protocols; `:protocol` pseudo-header
  selects the handler.
- RFC 9297 HTTP Datagrams (delegated to `quic_h3`) and RFC 9297
  DATAGRAM-type capsules on HTTP/2 (for IP and UDP data planes).
- Capsule-protocol dispatch for extension capsule types.
- Handler behaviour for custom server-side logic; transport-generic
  client sessions for TCP and IP (one module per protocol serves both
  H3 and H2).
- HTTP/2 fallback with Apple-style head-start racing (`transports`
  option; default `[h3, h2]`).
- End-to-end compliance CT suites (UDP + IP) and eunit codecs (URI,
  capsule, datagram, ICMP) + skippable external-peer interop suite.

- **[Usage guide](https://hexdocs.pm/masque/usage.html)** - client modes,
  multiple tunnels, integration with an existing `quic_h3` or `h2` server,
  handler lifecycle, transport selection, connection pooling, metrics.
- **[Design](https://hexdocs.pm/masque/design.html)** - architecture
  overview, supervision tree, client and server request paths, upstream
  pool internals, extension points.
- **[Relay guide](https://hexdocs.pm/masque/relay.html)** - end-to-end
  walkthrough of building an Apple-Private-Relay-shaped ingress + egress
  app on top of the library.
- **[API reference](https://hexdocs.pm/masque/api.html)** - type
  signatures, option maps, handler callbacks, built-in handlers.
- **[CONNECT-IP guide](https://hexdocs.pm/masque/connect_ip.html)** -
  RFC 9484 usage and section-by-section compliance mapping.
- **[Feature matrix](https://hexdocs.pm/masque/features.html)** - RFC
  coverage and intentional non-goals.

[rfc9484]: https://www.rfc-editor.org/rfc/rfc9484

## Installation

Requires Erlang/OTP 29.

Add to your `rebar.config`:

```erlang
{deps, [
    {masque, {git, "https://github.com/benoitc/erlang_masque.git", {branch, "main"}}}
]}.
```

## Quick start

### Proxy server (serves both UDP and TCP tunnels)

```erlang
{ok, _} = masque:start_listener(my_proxy, #{
    port => 4433,
    cert => CertDer,
    key  => KeyDer
    %% One listener dispatches both connect-udp and connect-tcp.
    %% Defaults: udp_handler = masque_udp_proxy_handler,
    %%           tcp_handler = masque_tcp_proxy_handler.
}).
```

### Client

```erlang
%% UDP tunnel (DNS, QUIC, game traffic)
{ok, Sess} = masque:connect(<<"https://proxy:4433">>,
                             {<<"1.1.1.1">>, 53},
                             #{protocol => udp}).

%% TCP tunnel (web, TLS)
{ok, Sess} = masque:connect(<<"https://proxy:4433">>,
                             {<<"example.com">>, 443},
                             #{protocol => tcp}).

%% Unified send/recv - works for both protocols
ok          = masque:send(Sess, Data),
{ok, Reply} = masque:recv(Sess, 5000),
ok          = masque:close(Sess).

%% Message mode (default): owner receives {masque_data, Sess, Data}
receive {masque_data, Sess, Bytes} -> Bytes end.
```

### Custom server handler

```erlang
-module(my_handler).
-behaviour(masque_handler).

-export([accept/1, init/2, handle_packet/2, handle_data/2, terminate/2]).

accept(#{target_host := Host}) ->
    case is_allowed(Host) of
        true  -> accept;
        false -> {reject, forbidden}
    end.

init(_Req, _Opts) -> {ok, #{}}.

%% UDP tunnels
handle_packet(Data, S) -> {ok, S, [{send, Data}]}.

%% TCP tunnels
handle_data(Data, S) -> {ok, S, [{send_data, Data}]}.

terminate(_Reason, _S) -> ok.
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
[h2]:      https://github.com/benoitc/erlang_h2
