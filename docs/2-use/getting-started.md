# Getting started

This page gets a proxy and a client talking in one Erlang shell. You start an HTTP/3 and an HTTP/2 listener with the built-in handlers, open a CONNECT-UDP tunnel through them, send and receive a datagram, and close. It also covers the one thing that trips everyone up: TLS verification is on by default. Read it first if you have never run `masque`; it assumes you know the words in [concepts](../1-understand/concepts.md). Afterwards go to [client](client.md) or [server](server.md), depending on which side you are building.

## Add the dependency

`masque` needs Erlang/OTP 29 and rebar3.

```erlang
{deps, [
    {masque, {git, "https://github.com/benoitc/erlang_masque.git", {branch, "main"}}}
]}.
```

## Make a development certificate

The h3 listener takes a DER certificate and a decoded private key; the h2 and h1 listeners take PEM file paths. Generate one self-signed pair and use it both ways:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout key.pem -out cert.pem \
    -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
```

```erlang
{ok, _} = application:ensure_all_started(masque),
{ok, CertPem} = file:read_file("cert.pem"),
{ok, KeyPem} = file:read_file("key.pem"),
[{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),
[{KeyType, KeyRaw, not_encrypted}] = public_key:pem_decode(KeyPem),
Key = public_key:der_decode(KeyType, KeyRaw).
```

## Start a proxy

One listener per transport. With no `handler` options each listener uses the built-in proxy handlers: `masque_udp_proxy_handler` for CONNECT-UDP, `masque_tcp_proxy_handler` for CONNECT-TCP, `masque_ip_proxy_handler` for CONNECT-IP.

```erlang
%% HTTP/3 over UDP port 4433: DER cert, decoded key.
{ok, _} = masque:start_listener(my_h3, #{
    port => 4433, cert => CertDer, key => Key,
    handler_opts => #{allow_private => true}   %% dev only: lets you reach 127.0.0.1
}),
%% HTTP/2 over TCP port 4433: PEM file paths.
{ok, _} = masque:start_listener_h2(my_h2, #{
    port => 4433, cert => "cert.pem", key => "key.pem",
    handler_opts => #{allow_private => true}
}).
```

The built-in handlers refuse private and loopback targets unless `allow_private` is set. Leave it off in production.

## Start a target

Any UDP service works. A one-line echo server for the test:

```erlang
Echo = spawn(fun() ->
    {ok, S} = gen_udp:open(9999, [binary, {ip, {127,0,0,1}}]),
    Loop = fun L() -> receive {udp, S, Ip, P, D} -> gen_udp:send(S, Ip, P, D), L() end end,
    Loop()
end).
```

## Connect, send, receive, close

```erlang
{ok, Sess} = masque:connect(<<"https://127.0.0.1:4433">>, {<<"127.0.0.1">>, 9999},
                            #{verify => verify_none}),   %% dev only, see TLS below
ok = masque:send(Sess, <<"hello">>),
receive {masque_data, Sess, Reply} -> Reply after 2000 -> timeout end,
ok = masque:close(Sess).
```

`connect/3` races h3 and h2 (h3 gets a 250 ms head start) and returns once one of them got a 2xx. Received payloads arrive as `{masque_data, Sess, Data}` messages to the calling process.

Dial `127.0.0.1` rather than `localhost` in tests. `localhost` can resolve to both `::1` and `127.0.0.1`, and the test suites avoid it for that reason.

## TLS: verify_peer is the default

Every client transport verifies the proxy certificate against the system CA store and checks the host name. The self-signed certificate above therefore fails the handshake unless you turn verification off, which is what the walkthrough does. You have two choices:

```erlang
%% Turn verification off. Development and tests only.
masque:connect(Proxy, Target, #{verify => verify_none}).

%% Keep verification on with your own CA: sign the proxy certificate with it
%% and pass the CA certificate (DER). The proxy certificate must name the host
%% you dial (DNS SAN for a name, IP SAN for an address).
masque:connect(Proxy, Target, #{cacerts => [CaCertDer]}).
```

Passing the self-signed proxy certificate itself in `cacerts` does not work: OTP `ssl` refuses a self-signed leaf even when it is listed there. `test/masque_client_errors_SUITE.erl` shows how to generate a small test CA.

`cacerts` and `verify` apply to h3, h2 and h1. `ssl_opts` (raw `ssl` options) applies to h2 and h1 only. See [client](client.md#tls).

## Stop

```erlang
masque:stop_listener(my_h3),
masque:stop_listener_h2(my_h2),
exit(Echo, kill).
```

## Examples

The `examples/` directory has four standalone modules. Load them from `rebar3 shell` with `c("examples/NAME").`. Each generates its own throwaway certificate with `openssl`.

| File | What it shows | Try it |
|---|---|---|
| `examples/udp_echo_proxy.erl` | A CONNECT-UDP proxy on h3 with the built-in UDP handler. | `udp_echo_proxy:start(4433).` |
| `examples/udp_dig_client.erl` | A client that resolves a DNS name through a proxy (sends one A query to 1.1.1.1:53). | `udp_dig_client:resolve(<<"https://127.0.0.1:4433">>, <<"example.com">>).` |
| `examples/ip_echo.erl` | A CONNECT-IP proxy with an address pool and an echo `forward_fun`, plus a client that requests an address and pings. | `ip_echo:start(4443), ip_echo:ping().` |
| `examples/two_hop_relay.erl` | An ingress chain listener and an egress proxy on h3, h2 and h1, with UDP and TCP round trips through both hops. | `two_hop_relay:start(), two_hop_relay:run_udp().` |

`udp_dig_client` needs outbound UDP to 1.1.1.1; point it at `udp_echo_proxy` running on the same node.

Next: [client](client.md) or [server](server.md).
