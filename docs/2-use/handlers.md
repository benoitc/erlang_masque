# Handlers

This page is the contract between the proxy and your code. A handler is a module implementing the `masque_handler` behaviour; the server session calls it for every event of one tunnel and carries out the actions it returns. Read it when the built-in handlers do not do what you need: custom routing, authentication, a TUN device, a relay. After it you will know every callback, which protocol calls which, every action each protocol accepts, the request map, when `init/2` runs relative to the 2xx, and what a crash does. The terms "handler", "action" and "finalize" come from [concepts](../1-understand/concepts.md); listener configuration is in [server](server.md).

## Where handlers plug in

A listener has one handler per protocol:

```erlang
masque:start_listener(my_proxy, #{
    port => 4433, cert => CertDer, key => Key,
    handler => my_udp_handler,          %% CONNECT-UDP
    tcp_handler => my_tcp_handler,      %% CONNECT-TCP
    ip_handler => my_ip_handler,        %% CONNECT-IP
    bind_handler => my_bind_handler,    %% Connect-UDP-Bind (with accept_bind => true)
    handler_opts => #{my_key => 1}
}).
```

`accept/1` runs in the listener's request process. Every other callback runs inside the tunnel's server session process: one process per tunnel, so `self()` in a callback is the session, and anything you send to it (socket messages, timers) comes back through `handle_info/2`.

## Callbacks

All callbacks are optional. An event whose callback is not exported is ignored, with one exception: a CONNECT-TCP FIN from the client without `handle_eof/1` ends the tunnel normally.

| Callback | Called when | Returns |
|---|---|---|
| `accept(Req)` | Request validated, before any session exists. | `accept`, `{reject, Reason}`, `{reject, Reason, ExtraHeaders}`. Default `accept`. |
| `init(Req, HandlerOpts)` | Session starts, before the 2xx. | `{ok, S}`, `{ok, S, Actions}`, `{stop, Reason}`. |
| `handle_packet(Payload, S)` | UDP payload from the client (context id 0). | see below |
| `handle_data(Bytes, S)` | TCP bytes from the client. | see below |
| `handle_eof(S)` | The client sent FIN on a CONNECT-TCP tunnel. | see below |
| `handle_capsule(Type, Value, S)` | A capsule type the session does not handle itself. | see below |
| `handle_info(Msg, S)` | Any other message to the session process. | see below |
| `handle_ip_packet(Packet, S)` | IP packet from the client (context id 0). | see below |
| `handle_address_request(Requests, S)` | Client ADDRESS_REQUEST (`[#ip_prefix_request{}]`). | see below |
| `handle_address_assign(Entries, S)` | Client ADDRESS_ASSIGN (`[#ip_assignment{}]`). | see below |
| `handle_route_advertisement(Routes, S)` | Client ROUTE_ADVERTISEMENT (`[#ip_route{}]`). | see below |
| `handle_bind_packet(Peer, Payload, S)` | udp-bind datagram from the client for `Peer = {IP, Port}`. Not part of the behaviour declaration; the bind sessions call it when exported. | see below, plus `{drop, Reason, S}` |
| `terminate(Reason, S)` | Session is ending. | ignored |

Event callbacks return `{ok, S}`, `{ok, S, Actions}` or `{stop, Reason, S}`. `handle_bind_packet/3` may also return `{drop, Reason, S}` to discard the packet (counted as a udp-bind drop on h3 and h2). Any other return value is ignored and the previous state is kept.

The records (`#ip_prefix_request{}`, `#ip_assignment{}`, `#ip_route{}`) come from `include/masque_ip.hrl`.

### Which protocol calls what

| Callback | UDP | TCP | IP | udp-bind |
|---|:-:|:-:|:-:|:-:|
| `accept/1`, `init/2`, `handle_info/2`, `terminate/2` | yes | yes | yes | yes |
| `handle_packet/2` | yes | | | scoped binds, context id 0 |
| `handle_data/2`, `handle_eof/1` | | yes | | |
| `handle_capsule/3` | yes | | yes | yes |
| `handle_ip_packet/2`, `handle_address_request/2`, `handle_address_assign/2`, `handle_route_advertisement/2` | | | yes | |
| `handle_bind_packet/3` | | | | yes |

`handle_capsule/3` never sees the capsules the session handles itself: DATAGRAM, the CONNECT-IP address and route capsules, and the udp-bind COMPRESSION_ASSIGN / ACK / CLOSE capsules. CONNECT-TCP has no capsules.

`handle_eof/1` differs by transport. On h3 and h2 returning `{ok, S}` keeps the tunnel half-open: you can keep sending to the client until you end your side. On h1 the tunnel ends after `handle_eof/1` whatever you return, because a TLS socket cannot half-close.

## Actions

Actions run in list order. Unknown actions are ignored. A closing action ends the tunnel and the actions after it are not run.

| Action | UDP | TCP | IP | udp-bind | Effect |
|---|:-:|:-:|:-:|:-:|---|
| `{send, Payload}` | yes | | | | Datagram to the client on context 0. Dropped silently above 65527 bytes or above the h3 datagram limit. |
| `{send, ContextId, Payload}` | yes | | | | Datagram on an explicit context id. |
| `{send_data, Bytes}` | | yes | | | Bytes to the client. Blocks until written; a write that fails, or waits more than 30 s on h3 and h2, ends the tunnel with `{tunnel_send_failed, _}`. |
| `{send_data, Bytes, Fin}` | | yes | | | Same, then FIN when `Fin` is `true`. On h3 and h2 this half-closes; on h1 it ends the tunnel. |
| `{send_capsule, Type, Value}` | yes | | yes | yes | Capsule on the request stream. |
| `{send_ip_packet, Packet}` | | | yes | | IP packet to the client on context 0. No MTU check here; the built-in handler checks before it returns this. |
| `{assign, [#ip_assignment{}]}` | | | yes | | ADDRESS_ASSIGN. Every nonzero request id must answer an open client ADDRESS_REQUEST, otherwise the whole action is skipped. Request id 0 is an unprompted assignment. |
| `{advertise, [#ip_route{}]}` | | | yes | | ROUTE_ADVERTISEMENT. |
| `{request_addresses, [{Version, Address, PrefixLen}]}` | | | yes | | ADDRESS_REQUEST from the proxy to the client (request ids are allocated for you). |
| `{icmp_error, {Kind, Spec, Invoking}}` | | | yes | | Builds an ICMP error about `Invoking` with `masque_icmp` and sends it. `Kind`/`Spec`: `dest_unreachable`/`{v4 \| v6, Code}`, `packet_too_big`/`Mtu`, `frag_needed`/`Mtu`, `time_exceeded`/`{v4 \| v6, Code}` or `v4 \| v6`. |
| `{send_bind_packet, {IP, Port}, Payload}` | | | | yes | Datagram from `Peer` to the client, on a proxy context for that peer if one is installed, else on the client's uncompressed context, else dropped. |
| `{compression_assign, {IP, Port}}` | | | | h3, h2 | Opens a proxy compression context for the peer and sends COMPRESSION_ASSIGN. Dropped (and counted) past `max_pending_compression_responses` or after the client closed its uncompressed context. |
| `{compression_assign, #compression_entry{}}` | | | | yes | Sends COMPRESSION_ASSIGN for an entry you built yourself. |
| `{compression_ack, Id}`, `{compression_close, Id}` | | | | yes | Sends COMPRESSION_ACK / COMPRESSION_CLOSE. |
| `{response_headers, [{Name, Value}]}` | | | | yes, `init/2` only | Extra headers on the 2xx or 101. The built-in bind handler uses it for `connect-udp-bind` and `proxy-public-address`. |
| `close_session` | yes | yes | yes | yes | Ends the tunnel cleanly (FIN). |
| `{close_session, Code, Message}` | yes | | | yes | Same as `close_session`; `Code` and `Message` are not sent. |
| `{close, Reason}` | | | yes | | Same as `close_session`; `Reason` is not used. |

## The request map

`accept/1` and `init/2` get the same map (`masque_handler:req()`):

| Key | Present | Value |
|---|---|---|
| `protocol` | always | `udp`, `tcp`, `ip` or `udp_bind`. |
| `method` | always | `<<"CONNECT">>`; `<<"GET">>` for UDP, IP and udp-bind over h1 (Upgrade). |
| `path`, `authority`, `scheme` | always | From the request. On h1 `authority` is the `Host` header and `scheme` is `<<"https">>`. |
| `headers` | always | All request headers, `[{binary(), binary()}]`. |
| `handler_opts` | always | The listener's merged `handler_opts` (also the second argument of `init/2`). |
| `target_host`, `target_port` | UDP, TCP, udp-bind | Decoded from the path. `'*'` for both on an unscoped bind. |
| `bind` | udp-bind | `scoped` or `unscoped`. |
| `ip_target`, `ip_ipproto` | IP | `'*'`, an address, `{Version, Address, PrefixLen}` or a host name binary; `'*'` or `0..255`. |
| `resolved_addresses` | IP | The listener resolver's answer for a host name target, the address itself for an address target, `[]` otherwise. |
| `peer` | h3 | `{Address, Port}` of the client. |
| `peer_cert` | h3, with a client certificate | DER. |

## init runs before the 2xx

On every transport the session calls `init/2` first and sends the 2xx (101 for h1 Upgrade, 200 for h1 CONNECT) only if it returns `{ok, ...}`. A 2xx therefore means your handler is ready: sockets opened, upstream dialed. The actions returned by `init/2` run right after the 2xx.

On h3 the router asks the session to finalize once `init/2` returned. Messages that reach the session in between (for example the first reply from a socket opened in `init/2`) are held, then passed to `handle_info/2` in order after the init actions. On h2 and h1 the session sends the 2xx inside its own start-up, so nothing can arrive earlier.

`{stop, Reason}` from `init/2` refuses the tunnel. `{stop, {reject, E}}` answers with the status of `E` (as in [server](server.md#accept-refuse-authenticate)); any other reason answers 502. On h3, `init/2` must return within 30 seconds or the request is refused with 502.

## Ending a tunnel

The tunnel ends when a callback returns `{stop, Reason, S}`, an action closes it, the client ends or resets the stream, or the connection goes away. `terminate/2` is then called with the reason. Reasons you will see: `normal`, `peer_reset`, `peer_closed` (h2 and h1), `connection_closed` and `router_gone` (h3), `idle_timeout` (h1), `malformed_capsule`, `truncated_capsule`, `capsule_buffer_overflow`, `{tunnel_send_failed, _}` (TCP), and whatever your own callbacks returned.

What the client sees depends on the reason. `normal` (and, for CONNECT-TCP, `target_closed` and `eof_timeout`) ends the stream with FIN. A reason that comes from the client or the connection (`peer_reset`, `peer_closed`, `connection_closed`, `router_gone`) sends nothing. Any other reason resets the stream with an error code, so the client can tell a clean close from a failure; CONNECT-IP sessions are the exception and end the stream with FIN for every reason except a handler crash. On h1 the socket is closed.

## What a crash does

Handler exceptions are caught and logged (see [operations](operations.md#logs)), but the outcome is not the same everywhere:

- In `init/2`: the tunnel is refused with 502 on every transport.
- In an event callback: the tunnel ends with `{handler_crash, Reason}`. On h3 and h2 the stream is reset; on h1 the socket is closed. `terminate/2` still runs.
- In an event callback of a udp-bind session on h1: the exception is not caught and the session process exits.
- In `accept/1`: not caught by `masque`. Return `{reject, _}` instead of raising.
- In `terminate/2`: ignored.

An action the session cannot carry out (a malformed `{icmp_error, _}` spec, an address that does not encode) crashes the session process. Server sessions are never restarted.

A crash is treated as a failure, not a clean close. To end a tunnel on purpose, return `{stop, Reason, S}` or the `close_session` action.

## Example

A handler that echoes UDP payloads and TCP bytes back to the client:

```erlang
-module(echo_handler).
-behaviour(masque_handler).

-export([accept/1, init/2, handle_packet/2, handle_data/2, terminate/2]).

accept(#{headers := H}) ->
    case lists:keyfind(<<"x-echo-key">>, 1, H) of
        {_, <<"secret">>} -> accept;
        _ -> {reject, {other, 401}}
    end.

init(_Req, _HandlerOpts) ->
    {ok, #{count => 0}}.

handle_packet(Payload, #{count := N} = S) ->
    {ok, S#{count := N + 1}, [{send, Payload}]}.

handle_data(Bytes, S) ->
    {ok, S, [{send_data, Bytes}]}.

%% No handle_eof/1: the client's FIN ends the tunnel with our FIN.

terminate(_Reason, _S) ->
    ok.
```

```erlang
{ok, _} = masque:start_listener(echo, #{port => 4433, cert => CertDer, key => Key,
                                        handler => echo_handler,
                                        tcp_handler => echo_handler}),
{ok, S} = masque:connect(<<"https://127.0.0.1:4433">>, {<<"198.51.100.1">>, 7},
                         #{verify => verify_none,
                           request_headers => [{<<"x-echo-key">>, <<"secret">>}]}).
```

The target is never contacted: the handler answers for it. The built-in handlers (`masque_udp_proxy_handler`, `masque_tcp_proxy_handler`, `masque_ip_proxy_handler`, `masque_udp_bind_proxy_handler`, `masque_chain_handler`) are complete examples of real proxying; read them next to this page.

Next: the protocol page you need ([connect-udp](connect-udp.md), [connect-tcp](connect-tcp.md), [connect-ip](connect-ip.md), [connect-udp-bind](connect-udp-bind.md)), or [relay](relay.md).
