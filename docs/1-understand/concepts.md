# Concepts

This page defines the words the rest of the documentation uses. Terms are introduced in order: the protocol basics first, then the pieces of the library, then the advanced subsystems. Read the first two sections before any other page; come back to the last one when a page sends you here. Each entry says what the term means, why it matters, and where it is explained in depth.

If you have not read the [overview](overview.md) yet, start there.

## Protocol basics

### Tunnel

A tunnel is one HTTP request that the proxy accepted with a 2xx (or 101 on HTTP/1.1 Upgrade), and that from then on carries traffic between the client and a target. One tunnel is one request stream: closing the stream ends the tunnel. Everything in `masque` is organised per tunnel: one client session process and one server session process each. See [architecture](architecture.md).

### Target

The target is what the client wants to reach through the proxy: a `{Host, Port}` for UDP and TCP, an `{IpTarget, IpProto}` pair for CONNECT-IP, or `unscoped` / `{Host, Port}` for Connect-UDP-Bind. The client encodes it in the request path through a URI template (for example `/.well-known/masque/udp/{target_host}/{target_port}/`), and the listener matches the path back into a target. See [client](../2-use/client.md) and the `masque_uri*` modules in the [code map](../3-change/code-map.md).

### Extended CONNECT, HTTP/1.1 Upgrade, classic CONNECT

These are the three request shapes that open a tunnel.

- **Extended CONNECT** (h3 and h2): `:method = CONNECT` plus a `:protocol` pseudo-header (`connect-udp`, `connect-ip`, `connect-tcp`). The proxy must advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL`.
- **HTTP/1.1 Upgrade**: `GET` with `Connection: Upgrade`, `Upgrade: connect-udp` or `connect-ip`, and `Capsule-Protocol: ?1`. The proxy answers 101 and the TLS socket becomes the tunnel.
- **Classic CONNECT** (HTTP/1.1, TCP only): `CONNECT host:port HTTP/1.1`, answered with 200, after which the socket is a raw byte pipe.

You need this distinction when you read the listeners or debug a handshake. See [transports](../3-change/transports.md).

### HTTP datagram

An HTTP datagram (RFC 9297) is an unreliable message tied to a request stream. On HTTP/3 it travels as a QUIC DATAGRAM frame. HTTP/2 and HTTP/1.1 have no datagram channel, so the same payload is wrapped in a DATAGRAM capsule on the stream instead. CONNECT-UDP, CONNECT-IP and Connect-UDP-Bind carry their packets as HTTP datagrams; CONNECT-TCP does not use them. See [transports](../3-change/transports.md).

### Capsule and capsule protocol

A capsule is a type-length-value frame sent on the request stream body (RFC 9297). A request or response carrying `Capsule-Protocol: ?1` says the stream body is a sequence of capsules. Capsules carry control messages (CONNECT-IP address and route capsules, udp-bind compression capsules) and, on h2 and h1, the DATAGRAM capsule. Unknown capsule types are ignored, or handed to the handler's `handle_capsule/3`. CONNECT-TCP is the exception: its stream carries raw bytes, not capsules. See [handlers](../2-use/handlers.md) and `masque_capsule` in the [code map](../3-change/code-map.md).

### Context id

Every HTTP datagram payload in MASQUE starts with a variable-length context id. Context 0 carries the plain payload (a UDP payload for CONNECT-UDP, an IP packet for CONNECT-IP). Other ids are reserved for extensions; Connect-UDP-Bind uses them for compression contexts. `masque_datagram` encodes and decodes the prefix, and sessions drop datagrams with unknown ids. You meet it when you call `masque:send/3` or work on udp-bind. See [connect-udp](../2-use/connect-udp.md).

## The pieces of the library

### Owner (three meanings)

"Owner" means three different things in this code base. Always say which one you mean.

- **Application owner**: the process that receives a client tunnel's events, such as `{masque_data, Sess, Data}` and `{masque_closed, Sess, Reason}`. By default it is the caller of `masque:connect/3`; set it with the `owner` connect option. The session monitors it and stops when it exits. See [client](../2-use/client.md).
- **Upstream owner**: a `masque_upstream_owner` process that owns one pooled h2 or h3 connection and lends streams on it to client sessions. See [upstream pool](#upstream-pool-and-fingerprint).
- **h3 connection owner**: `quic_h3` delivers connection-level events (datagrams, close) to one "owner" pid per connection. On the server that pid is the router, `masque_server_connection`. See [router](#router).

### Delivery mode: message vs queue

A client session delivers received data in one of two modes. In `message` mode (the default) every payload is sent to the application owner as a message. In `queue` mode the session buffers payloads until you call `masque:recv/2`; switch with `masque:set_mode/2`. Queue mode is bounded by `rx_queue_limit` (see [backpressure](#backpressure-active_n-rx_queue_limit)). Choose queue mode when you want pull-based reads. See [client](../2-use/client.md).

### Handler

A handler is the module that decides what the proxy does with a tunnel. It implements the `masque_handler` behaviour, all callbacks optional: `accept/1` gates the request, `init/2` sets up the tunnel before the 2xx is sent, and `handle_packet/2`, `handle_data/2`, `handle_capsule/3`, `handle_info/2`, `handle_eof/1` and the CONNECT-IP callbacks react to traffic. Each listener has one handler per protocol (`handler`, `tcp_handler`, `ip_handler`, `bind_handler`); built-in ones proxy to real sockets. This is the main extension point of the library. See [handlers](../2-use/handlers.md).

### Action

Handler callbacks return a list of actions, and the server session carries them out. Examples: `{send, Payload}` (UDP), `{send_data, Bytes}` (TCP), `{send_ip_packet, Packet}` and `{assign, Entries}` (IP), `{send_capsule, Type, Value}`, and `close_session`. Actions keep handlers free of transport details: the same handler works over h3, h2 and h1. Which actions each protocol accepts is listed in [handlers](../2-use/handlers.md).

### Listener

A listener is a server socket that accepts MASQUE requests on one transport: `masque:start_listener/2` (h3), `start_listener_h2/2` or `start_listener_h1/2`. It validates each request, matches the path against its URI templates, resolves the target, calls `accept/1`, and starts a server session. To serve all transports you start one listener per transport. See [server](../2-use/server.md) and [server internals](../3-change/server-internals.md).

### Router

The router, `masque_server_connection`, exists only on HTTP/3. One router runs per accepted h3 connection and is that connection's owner, so it receives every HTTP datagram and routes it by stream id to the right server session. It also starts sessions and limits tunnels per connection. h2 and h1 do not need it because their transport libraries deliver stream events straight to the session. See [architecture](architecture.md) and [server internals](../3-change/server-internals.md).

### Finalize

On HTTP/3 the router starts a session, the session runs the handler's `init/2`, and only then does the router ask the session to "finalize": send the 2xx, claim the stream, run the init actions and replay any messages that arrived meanwhile. This keeps the rule that a 2xx means the tunnel is ready, without blocking the router during `init/2`. On h2 and h1 the session sends the 2xx or 101 at the end of its own `init`, so there is no separate finalize step. See [server internals](../3-change/server-internals.md).

### Racer

The racer, `masque_racer`, runs when you pass more than one transport to `masque:connect/3` (the default is `[h3, h2]`). It starts the first transport, gives it a head start (`prefer_timeout_ms`, default 250 ms), then starts the next one in parallel, and keeps the first handshake that succeeds. Losers are stopped and the winner is handed to your process. See [client](../2-use/client.md) and [client internals](../3-change/client-internals.md).

## Advanced subsystems

### Upstream pool and fingerprint

With `upstream_pool => true`, h2 and h3 client tunnels to the same proxy share one transport connection, each tunnel on its own stream. `masque_upstream_pool` keys connections by a fingerprint: proxy host, port, transport and a hash of the connection-affecting options (`verify`, `cacerts`, `ssl_opts`, `alpn`). Two callers with different trust settings never share a connection. h1 is never pooled. See [pool](../3-change/pool.md).

### Chain and via token

A chain is a proxy whose handler, `masque_chain_handler`, opens a MASQUE client tunnel to an upstream proxy instead of a socket to the target. To stop a request looping between proxies, each chain listener adds a `via` token to the upstream request, and rejects a request that already carries its own token with 508 (`loop_detected`). See [relay](../2-use/relay.md).

### Address assignment and routes

CONNECT-IP adds a control plane on the request stream: ADDRESS_REQUEST (ask for an address), ADDRESS_ASSIGN (give one) and ROUTE_ADVERTISEMENT (say which destinations are reachable). The built-in `masque_ip_proxy_handler` allocates from an `address_pool` and registers assignments in `masque_ip_session_registry`. You need this to build a VPN-like tunnel. See [connect-ip](../2-use/connect-ip.md) and [CONNECT-IP internals](../3-change/connect-ip-internals.md).

### Compression context

In Connect-UDP-Bind one tunnel talks to many peers, so each datagram must say which peer it is for. A compression context maps a context id to a peer `{IP, Port}` so datagrams can omit the address; the uncompressed context carries the address inline. Contexts are opened with COMPRESSION_ASSIGN, confirmed with COMPRESSION_ACK and retired with COMPRESSION_CLOSE; clients use even ids and proxies odd ones. The library never opens contexts by itself. See [connect-udp-bind](../2-use/connect-udp-bind.md) and [udp-bind internals](../3-change/udp-bind-internals.md).

### Backpressure (active_n, rx_queue_limit)

Two knobs keep a fast side from flooding a slow one. On the proxy, the built-in handlers read target sockets in `{active, N}` mode (`active_n` in `handler_opts`): after N messages the socket pauses until the session has relayed them, so a slow client slows reads from the target instead of growing a mailbox. On the client, `rx_queue_limit` (default 1000 items) bounds a queue-mode session's buffer: datagram tunnels drop past it and count the drops, a CONNECT-TCP tunnel ends with `rx_overflow`. See [operations](../2-use/operations.md) and [client](../2-use/client.md).

Next: [architecture](architecture.md).
