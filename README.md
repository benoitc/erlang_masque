# masque

[![CI](https://github.com/benoitc/erlang_masque/actions/workflows/ci.yml/badge.svg)](https://github.com/benoitc/erlang_masque/actions/workflows/ci.yml)

`masque` is an Erlang library for MASQUE: tunnelling UDP, IP and TCP
traffic through an HTTP proxy. You use it to build a proxy server, a
client that connects through one, or both, for example a two-hop relay.

It implements:

| Protocol | Spec | Carries |
|---|---|---|
| CONNECT-UDP | [RFC 9298](https://www.rfc-editor.org/rfc/rfc9298) | UDP datagrams to one target |
| CONNECT-IP | [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484) | IP packets, with address assignment and routes |
| CONNECT-TCP | draft-ietf-httpbis-connect-tcp | a TCP byte stream |
| Connect-UDP-Bind | draft-ietf-masque-connect-udp-listen | UDP to and from many peers |

over three transports: HTTP/3 (QUIC), HTTP/2 and HTTP/1.1. The client
races them so a tunnel still opens on networks that block QUIC. It is
built on [`erlang_quic`](https://github.com/benoitc/erlang_quic),
[`erlang_h2`](https://github.com/benoitc/erlang_h2) and
[`erlang_h1`](https://github.com/benoitc/erlang_h1).

## Install

Requires Erlang/OTP 29 and rebar3.

```erlang
{deps, [
    {masque, {git, "https://github.com/benoitc/erlang_masque.git", {branch, "main"}}}
]}.
```

## A first tunnel

```erlang
%% Proxy: an HTTP/3 listener with the built-in handlers.
{ok, _} = masque:start_listener(my_proxy, #{port => 4433, cert => CertDer, key => Key}),

%% Client: open a CONNECT-UDP tunnel to a DNS server, send, receive, close.
{ok, Sess} = masque:connect(<<"https://proxy.example:4433">>, {<<"1.1.1.1">>, 53}, #{}),
ok = masque:send(Sess, Query),
receive {masque_data, Sess, Reply} -> Reply end,
ok = masque:close(Sess).
```

Clients verify the proxy certificate by default. For a complete,
copy-pasteable walkthrough with a development certificate, read
[Getting started](docs/2-use/getting-started.md).

## Documentation

The docs are organised as a path. Start at the top and stop when you
have what you need.

- **Understand** what masque is and how it fits together:
  [overview](docs/1-understand/overview.md),
  [concepts](docs/1-understand/concepts.md),
  [architecture](docs/1-understand/architecture.md).
- **Use** it in your application:
  [getting started](docs/2-use/getting-started.md),
  [client](docs/2-use/client.md), [server](docs/2-use/server.md),
  [handlers](docs/2-use/handlers.md), the protocol pages
  ([CONNECT-UDP](docs/2-use/connect-udp.md),
  [CONNECT-TCP](docs/2-use/connect-tcp.md),
  [CONNECT-IP](docs/2-use/connect-ip.md),
  [Connect-UDP-Bind](docs/2-use/connect-udp-bind.md)),
  [building a relay](docs/2-use/relay.md),
  [operations](docs/2-use/operations.md).
- **Change** it: [contributing](CONTRIBUTING.md),
  [code map](docs/3-change/code-map.md),
  [how to...](docs/3-change/how-to.md), and the internals pages linked
  from there.
- **Reference**: [messages and errors](docs/reference/messages-and-errors.md),
  [RFC conformance](docs/reference/conformance.md),
  [changelog](CHANGELOG.md).

The same pages are published with the module docs by `rebar3 ex_doc`.

## Examples

`examples/` holds four runnable modules: a UDP echo proxy, a DNS
client, a CONNECT-IP echo proxy, and a two-hop relay. See
[Getting started](docs/2-use/getting-started.md#examples).

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the build, the required
checks and where to start in the code.

## License

Apache License 2.0. See [LICENSE](LICENSE).
