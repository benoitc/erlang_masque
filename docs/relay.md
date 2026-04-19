# Building a standalone relay on `masque`

`masque` is a library, not an application. This guide walks through
the pieces it ships so you can assemble an Apple-Private-Relay-shaped
service (ingress + egress, h3 / h2 / h1, authenticated, pooled,
observable) without library forks.

Scope: what the library provides and how to wire it. Out of scope
and expected to live in your own app: Privacy Pass token issuance,
ACME cert rotation, release packaging, deployment, alerting
rules.

## Contents

1. [Architecture](#1-architecture)
2. [Ingress listener](#2-ingress-listener)
3. [Egress listener](#3-egress-listener)
4. [Authentication on the ingress](#4-authentication-on-the-ingress)
5. [Upstream connection pool](#5-upstream-connection-pool)
6. [Drain and rolling restarts](#6-drain-and-rolling-restarts)
7. [Observability](#7-observability)
8. [Client shape (what an end user runs)](#8-client-shape)
9. [Checklist](#9-checklist)
10. [Non-goals](#10-non-goals)

---

## 1. Architecture

```
+------------+   tunnel (h3 / h2 / h1)   +------------+   tunnel (h3)   +---------+
|  Client    |-------------------------->|  Ingress   |---------------->| Egress  |---> target
| (device)   |                           |  masque    |   pooled        | masque  |
|            |                           |  chain     |   upstream      | proxy   |
+------------+                           +------------+                 +---------+
                                             |                              |
                                    accept/1 gates             forwards UDP / TCP / IP
                                    auth tokens                with policy (allow_private,
                                                                resolver, mtu, ...)
```

The library provides both sides. Apple's Private Relay keeps ingress
and egress in different administrative domains; `masque` does not
require that split - you can run one, both, or many of each.

## 2. Ingress listener

Wire one `start_chain_listener*` per transport you want clients to
race. A relay that supports every rung runs all three:

```erlang
IngressOpts = #{
    port => 4443,
    cert => CertDer, key => KeyDer,
    handler => my_auth_handler,
    handler_opts => #{
        upstream_proxy => <<"https://egress.internal:4434">>,
        upstream_opts  => #{
            verify       => verify_peer,
            cacerts      => relay_pki:ca_certs(),
            transports   => [h3],        %% pool h3 only
            upstream_pool => true        %% share one QUIC conn
        },
        token_key => relay_pki:privacy_pass_key()
    }
},
{ok, _} = masque:start_chain_listener(ingress_h3, IngressOpts),
{ok, _} = masque:start_chain_listener_h2(
            ingress_h2,
            IngressOpts#{cert => CertPem, key => KeyPem}),
{ok, _} = masque:start_chain_listener_h1(
            ingress_h1,
            IngressOpts#{cert => CertPem, key => KeyPem}).
```

The `handler` slot here is `my_auth_handler`, not
`masque_chain_handler`, because we want to run our own
authentication before delegating to the chain. See
[Authentication on the ingress](#4-authentication-on-the-ingress)
for the wrapper shape.

Clients race the three listener ports with a `transports => [h3, h2,
h1]` connect call. The first 2xx wins.

## 3. Egress listener

The egress is a regular MASQUE proxy - built-in handlers do what a
Private Relay egress needs:

```erlang
EgressOpts = #{
    port => 4434,
    cert => EgressCertDer,
    key  => EgressKeyDer,
    handler      => masque_udp_proxy_handler,
    tcp_handler  => masque_tcp_proxy_handler,
    ip_handler   => masque_ip_proxy_handler,
    handler_opts => #{allow_private => false},
    %% Global DNS resolution hook; runs before the ingress's
    %% accept/1 (decision #3 in the handler lifecycle).
    resolver     => fun my_resolver:lookup/1,
    %% Cap concurrent tunnels per connection so one abusive
    %% ingress cannot exhaust the egress.
    max_tunnels_per_connection => 256
},
{ok, _} = masque:start_listener(egress, EgressOpts).
```

`masque_ip_proxy_handler` handles the RFC 9484 bits (address pool
allocation, ROUTE_ADVERTISEMENT, BCP-38 filter) with a
`forward_fun` extension point for your own kernel-side IP
pipeline.

## 4. Authentication on the ingress

The library does not ship Privacy Pass, but it gives you every
hook a token-based scheme needs:

- `accept/1` receives `headers`, `peer`, and (on h3) `peer_cert` in
  the `Req` map.
- `{reject, {other, 401}, ExtraHeaders}` attaches a
  `WWW-Authenticate: PrivateToken ...` challenge to the 401
  response on all three transports.

A wrapper handler that runs Privacy Pass and then delegates to the
chain handler on success:

```erlang
-module(my_auth_handler).
-behaviour(masque_handler).

-export([accept/1, init/2, handle_packet/2, handle_data/2,
         handle_ip_packet/2, handle_info/2, terminate/2]).

accept(#{headers := H, handler_opts := Opts} = Req) ->
    case verify_token(H, Opts) of
        ok ->
            masque_chain_handler:accept(Req);
        {error, no_token} ->
            {reject, {other, 401}, challenge(Opts)};
        {error, bad_token} ->
            {reject, forbidden}
    end.

%% All the data-plane callbacks just delegate.
init(Req, Opts)              -> masque_chain_handler:init(Req, Opts).
handle_packet(P, S)          -> masque_chain_handler:handle_packet(P, S).
handle_data(D, S)            -> masque_chain_handler:handle_data(D, S).
handle_ip_packet(Pkt, S)     -> masque_chain_handler:handle_ip_packet(Pkt, S).
handle_info(M, S)            -> masque_chain_handler:handle_info(M, S).
terminate(R, S)              -> masque_chain_handler:terminate(R, S).

verify_token(H, #{token_key := K}) ->
    case header(<<"authorization">>, H) of
        <<"PrivateToken ", Rest/binary>> -> privacy_pass:verify(Rest, K);
        _                                -> {error, no_token}
    end.

challenge(#{token_key := K}) ->
    [{<<"www-authenticate">>,
      iolist_to_binary(
        [<<"PrivateToken challenge=\"">>, base64:encode(my_challenge:new()),
         <<"\", token-key=\"">>, base64:encode(K),
         <<"\", max-age=3600">>])}].

header(Name, H) ->
    case lists:keyfind(Name, 1, H) of {_, V} -> V; _ -> undefined end.
```

The client retries with the token:

```erlang
masque:connect(ProxyURI, Target, #{
    transports => [h3, h2, h1],
    request_headers =>
        [{<<"authorization">>,
          <<"PrivateToken token=", Token/binary>>}]
}).
```

The library sanitises caller input so a misbehaving client cannot
inject a second CONNECT line via a CR/LF header value on h1, and
cannot override the reserved pseudo-headers on h2/h3.

## 5. Upstream connection pool

For a busy ingress, set `upstream_pool => true` in
`upstream_opts`. Sibling tunnels then share one QUIC (or h2)
connection to the egress:

```erlang
upstream_opts => #{verify => verify_peer,
                    cacerts => relay_pki:ca_certs(),
                    transports => [h3],
                    upstream_pool => true,
                    upstream_pool_opts => #{idle_timeout_ms => 60000}}
```

Pool keys fingerprint `verify` / `cacerts` / `ssl_opts` / `alpn`,
so two ingress modes with different trust configs stay isolated.
h3 pooled conns are always opened datagram-capable, so CONNECT-UDP
/ -TCP / -IP tunnels share one QUIC owner when they point at the
same egress.

Concurrency cap: the pooled owner reads the peer's h2 `SETTINGS`
(`MAX_CONCURRENT_STREAMS`) on cold dial. For h3 it is `dynamic`
(bounded by QUIC `MAX_STREAMS_BIDI`). Operators who want a hard
cap can set `upstream_pool_opts => #{max_streams => N}`.

## 6. Drain and rolling restarts

Graceful drain on each listener:

```erlang
masque:drain_listener(ingress_h3),    %% stop accepting new tunnels
masque:drain_listener(ingress_h2),
masque:drain_listener(ingress_h1).
%% ... wait for in-flight tunnels to terminate ...
masque:stop_listener(ingress_h3).
masque:stop_listener_h2(H2Ref).
masque:stop_listener_h1(ingress_h1).
```

While draining, new CONNECT requests get `503` with
`proxy-status: masque; error=proxy_internal_error`. Existing
tunnels are undisturbed. Undrain with
`masque:undrain_listener/1`.

For a rolling restart under load, drain the ingress, wait for
`masque.tunnels.active` to hit zero (or a drain deadline), then
stop the VM. Newer ingress instances can be started in parallel
on a sibling node; clients will race them once DNS or a load
balancer redirects.

## 7. Observability

`masque_metrics` wires six `instrument_meter` meters - tunnel
counts, active gauge, rejection counter, byte counters, duration
histogram. Every sample carries the tunnel's `protocol`,
`transport`, and `listener` tags. An OTLP or Prometheus exporter
on top of `instrument` fans the meters off the node.

Typical dashboard:

- `masque.tunnels.active{listener=ingress_h3}` - open tunnels per
  listener.
- `rate(masque.tunnels.total{listener=ingress_h3}[1m])` - accept
  rate.
- `rate(masque.tunnels.rejected{reason=forbidden}[1m])` -
  403 / auth failures; sudden spike is an attack signal.
- `histogram_quantile(0.99, masque.tunnel.duration_ms)` - tail
  latency of tunnel lifetime.
- `rate(masque.bytes.in)` / `rate(masque.bytes.out)` - raw
  throughput.

## 8. Client shape

End-user clients see a single URL. A CONNECT-UDP tunnel through
the full relay chain:

```erlang
{ok, Sess} = masque:connect(<<"https://ingress.example:4443">>,
                            {<<"1.1.1.1">>, 53},
                            #{transports => [h3, h2, h1],
                              request_headers =>
                                 [{<<"authorization">>,
                                   <<"PrivateToken token=", T/binary>>}]}),
ok = masque:send(Sess, DnsQuery),
receive {masque_data, Sess, Reply} -> Reply end,
ok = masque:close(Sess).
```

`masque:connect/3` races the three transports; first 2xx wins;
losing attempts are cancelled before they leak traffic. See
[usage.md](usage.md#1-transport-selection) for tuning
`prefer_timeout_ms` and `h1_prefer_timeout_ms`.

## 9. Checklist

What to verify before pointing traffic at your relay:

- [ ] Three ingress listeners up (h3, h2, h1) on the public port.
- [ ] One (or more) egress listeners reachable from the ingress.
- [ ] `accept/1` on the ingress validates auth before delegating
      to the chain handler.
- [ ] `{reject, {other, 401}, [www-authenticate]}` returned for
      missing / expired tokens.
- [ ] `upstream_pool => true` configured on the ingress when you
      expect more than a few concurrent tunnels per egress.
- [ ] `resolver` on the egress short-circuits DNS so `accept/1`
      sees resolved addresses for SSRF checks.
- [ ] `allow_private => false` on the egress to keep RFC 1918
      destinations out (unless you have a legitimate use).
- [ ] `max_tunnels_per_connection` on the egress so a single
      ingress cannot saturate it.
- [ ] Drain wired to SIGTERM / systemd `ExecStop` on both sides.
- [ ] `masque_metrics` exporter configured on both nodes.
- [ ] Cert rotation hook (ACME or internal PKI) stops and restarts
      each listener when new cert material lands.

## 10. Non-goals

These live in your relay app, not in `masque`:

- **Privacy Pass token issuance.** The library gives you the
  handshake hooks (`accept/1` + `request_headers`) but not the
  token protocol itself (see RFC 9578).
- **ACME cert rotation.** Hand fresh DER / PEM paths to
  `stop_listener` + `start_listener` from your own rotation cron.
- **Node discovery.** One ingress knows one `upstream_proxy` URI.
  Fleets of egresses live behind a load balancer or a resolver
  callback outside this library.
- **Rate limits and quota.** `accept/1` can implement both - the
  library provides the hook, not the policy.
- **Release packaging.** Plain rebar3 releases work; this is
  operational, not library-level.
