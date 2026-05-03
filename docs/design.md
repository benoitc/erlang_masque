# Design

A tour of how `masque` is put together: what the layers are, how a
request flows through them, and where the invariants live. Read this
after `docs/usage.md` when you want to extend the library or debug a
tricky tunnel.

## Contents

1. [Layering at a glance](#1-layering-at-a-glance)
2. [Supervision tree](#2-supervision-tree)
3. [Client connect path](#3-client-connect-path)
4. [Server accept path](#4-server-accept-path)
5. [Per-tunnel session state machines](#5-per-tunnel-session-state-machines)
6. [Datagram vs. capsule framing](#6-datagram-vs-capsule-framing)
7. [Handler behaviour contract](#7-handler-behaviour-contract)
8. [Transport racing](#8-transport-racing)
9. [Two-hop chaining](#9-two-hop-chaining)
10. [Upstream connection pool](#10-upstream-connection-pool)
11. [CONNECT-IP control plane](#11-connect-ip-control-plane)
12. [Metrics](#12-metrics)
13. [Known invariants](#13-known-invariants)
14. [Extension points](#14-extension-points)

---

## 1. Layering at a glance

```
+----------------------------------------------------------+
|  masque.erl                  facade: connect, listen     |
+----------------------------------------------------------+
|  masque_racer                transport race (h3/h2/h1)   |
+----------------------+----------------------+------------+
|  per-tunnel client   |  per-tunnel server   | upstream   |
|  sessions (gen_statem)|  sessions (gen_server)| pool     |
|  one per protocol x   |  one per protocol x  | (h2 / h3) |
|  transport pair       |  transport pair      |           |
+----------------------+----------------------+------------+
|  masque_handler behaviour   (user plug point)             |
+----------------------------------------------------------+
|  masque_capsule / masque_datagram / masque_ip_capsule    |
|  (RFC 9297 capsule + datagram codec, RFC 9484 capsules)  |
+----------------------------------------------------------+
|  erlang_quic (quic_h3) | erlang_h2 | ssl (TLS 1.3 for h1)|
+----------------------------------------------------------+
```

The top facade (`src/masque.erl`) is stateless. It parses URIs,
validates options, picks transports, and delegates to either the
racer or a single-transport dial. Listeners are thin wrappers on the
transport libraries' `start_server` entry points.

One file per `{protocol, role, transport}` combination. Matrix:

| protocol | role   | h3                                | h2                                | h1                                  |
|----------|--------|-----------------------------------|-----------------------------------|-------------------------------------|
| udp      | client | `masque_client_session`           | `masque_h2_client_session`        | `masque_h1_client_session`          |
| udp      | server | `masque_server_session`           | `masque_h2_server_session` (udp)  | `masque_h1_server_session`          |
| tcp      | client | `masque_tcp_client_session` (h3)  | `masque_tcp_client_session` (h2)  | `masque_tcp_h1_client_session`      |
| tcp      | server | `masque_tcp_server_session`       | `masque_h2_server_session` (tcp)  | `masque_tcp_h1_server_session`      |
| ip       | client | `masque_ip_client_session` (h3)   | `masque_ip_client_session` (h2)   | `masque_ip_h1_client_session`       |
| ip       | server | `masque_ip_server_session`        | `masque_h2_server_session` (ip)   | `masque_ip_h1_server_session`       |

The TCP and IP client sessions are transport-generic: one module
dispatches on a `transport :: h3 | h2` field internally. UDP has a
separate h3 and h2 client because the two use different framing
(native QUIC datagrams vs. capsule-wrapped stream bytes) and the
extra indirection was cheaper to avoid.

## 2. Supervision tree

```
masque_sup (one_for_one, 10/10)
|
+-- masque_h2_session_sup          (simple_one_for_one, UDP h2 sessions)
+-- masque_h2_tcp_session_sup      (simple_one_for_one, TCP h2 sessions)
+-- masque_h2_ip_session_sup       (simple_one_for_one, IP h2 sessions)
+-- masque_h1_session_sup          (simple_one_for_one, UDP h1 sessions)
+-- masque_h1_ip_session_sup       (simple_one_for_one, IP h1 sessions)
+-- masque_h1_tcp_session_sup      (simple_one_for_one, TCP h1 sessions)
+-- masque_upstream_pool           (gen_server, pool registry)
```

`masque_sup` also creates the ETS table `masque_h2_tunnel_counts` at
boot. The table holds per-connection tunnel counters that the h2
listener uses to enforce `max_tunnels_per_conn`.

h3 sessions are supervised by the `quic_h3` connection's own
ownership tree; they are not children of `masque_sup`. Client
sessions started via `gen_statem:start_link/3` from `masque:connect/3`
are linked to the caller.

Pooled upstream owners are spawned by `masque_upstream_pool` on
demand and monitored (not linked) so a bad handshake or a DOWN on
the pool owner does not cascade into the pool registry itself.

## 3. Client connect path

```
masque:connect(ProxyURI, Target, Opts)
    |
    | validate_connect_opts (target shape, capsule_protocol,
    |                        proxy_authorization CRLF check)
    |
    | parse_proxy_uri
    |
    +--> connect_via([h3], ...)          -> dial_single_or_pool
    |
    +--> connect_via([h2], ...)          -> dial_single_or_pool
    |
    +--> connect_via([h1], ...)          -> dial_single
    |
    +--> connect_via([h3, h2, h1], ...)  -> masque_racer:race/4
```

### `dial_single`

Starts the correct session module with `Opts#{transport => T}` and
the caller as the owner, monitors the session pid, and calls
`handshake_await` on it. Returns `{ok, Sess}` once the session sees a
2xx; `{error, Reason}` if the handshake fails or the session dies.

Using `start` + monitor (not `start_link`) means the caller does not
receive an `'EXIT'` if the session crashes early; errors come back
cleanly as `{error, _}`.

### `masque_racer`

Runs in the caller's process. Spawns one worker per listed transport,
each of which creates a session owned by the worker. Staggers the
launches: primary starts immediately, secondary after
`prefer_timeout_ms` (default 250 ms), tertiary (only for 3-transport
lists) after `h1_prefer_timeout_ms` more.

The first worker whose session reports a 2xx sends
`{attempt_ready, _, _, Sess}` to the racer. The racer calls
`{set_owner, RealOwner}` on the session to flip ownership, tells
losing workers to kill their sessions, and returns `{ok, Sess}`. The
racer never holds the session in its own mailbox, so losing
attempts' datagrams never reach the winning session's owner.

See `src/masque_racer.erl` for the exact state machine and the test
hooks that inject fake session modules for unit tests.

## 4. Server accept path

```
quic_h3:start_server / h2:start_server / ssl:listen
    |
    | accept a transport connection
    |
    +-- new h3 conn  --> masque_server:connection_handler
    +-- new h2 conn  --> masque_h2_server:connection_handler
    +-- new h1 conn  --> masque_h1_server acceptor proc
    |
    v
masque_server_connection (gen_server, one per conn)
    |
    | route owner-level events (datagrams, SETTINGS, close) to
    | sessions keyed by StreamId; spawn a new session on each
    | incoming CONNECT request; close session when its stream ends.
    |
    | on CONNECT request:
    |   1. parse envelope (method, :protocol, path, capsule-protocol)
    |   2. match :path against the configured URI template
    |   3. run the listener's `resolver` (if set) on the target host
    |   4. call handler:accept/1 with the Req map
    |   5. if accepted: respond 2xx, start per-tunnel session pid,
    |      register it in the router's {StreamId -> SessionPid} map.
    |   6. if rejected: respond with the mapped HTTP status.
    v
per-tunnel server session (gen_server)
    |
    | calls handler:init/2; then one of
    |   handler:handle_packet/2    (UDP)
    |   handler:handle_data/2      (TCP)
    |   handler:handle_ip_packet/2 (IP)
    |   handler:handle_capsule/3   (extension capsules)
    |   handler:handle_info/2      (other Erlang messages)
    | per inbound event; converts actions (e.g. `{send, _}`) into
    | transport calls and returns {noreply, State}.
```

The router is the `owner` of the transport connection. HTTP
Datagrams on h3 and connection-close events on all transports are
delivered to the owner, so the router demultiplexes by StreamId
before handing off to the session. Without this indirection each
session would need its own conn owner - which is exactly what the
upstream pool avoids on the client side (see section 10).

## 5. Per-tunnel session state machines

Client sessions are `gen_statem`s; server sessions are
`gen_server`s. Both hold the single transport-level stream that
carries one tunnel.

States (client): `connecting -> open -> closing`.

- `connecting`: request issued, awaiting 2xx. `handshake_await` is
  a synchronous call that returns `ok` / `{error, _}` when the
  response lands.
- `open`: tunnel live. Data is forwarded bidirectionally.
- `closing`: the owner or peer requested teardown. Sends a FIN /
  closes the stream, releases the pool slot if any, and exits.

Key fields (`#data{}` record):

- `owner`, `owner_ref`: the pid that receives `{masque_data, _, _}`,
  `{masque_closed, _, _}`, `{masque_ip_packet, _, _}`, etc.; the
  monitor reference so we notice if the owner dies.
- `conn`, `stream_id`: underlying transport handles.
- `mode :: message | queue`: delivery mode for inbound payloads.
- `rx_buf`, `rx_waiters`: queue-mode buffering.
- `cap_buf`, `max_cap`: capsule decode buffer for stream body bytes
  (h2 UDP, h1 UDP/IP, anywhere capsules arrive on the stream).
- `pool_owner`: set when the session is riding a pooled connection;
  teardown releases the stream back to the pool instead of closing
  the conn.

Server sessions mirror this shape but own the opposite side of the
tunnel (the target socket, the TCP connection, the IP forwarder).

## 6. Datagram vs. capsule framing

MASQUE over h3 (RFC 9298): UDP payloads travel as QUIC DATAGRAM
frames. Stream body is only used for the capsule protocol
(`capsule-protocol: ?1`) and control-plane capsules.

MASQUE over h2: there is no transport-level datagram channel. Every
UDP payload is wrapped in an RFC 9297 DATAGRAM capsule and sent as
stream body bytes. This gains reliability and ordering - the
trade-off for falling back to h2.

MASQUE over h1: same DATAGRAM-capsule approach, on the upgraded
socket after `HTTP/1.1 101 Switching Protocols`. CONNECT-TCP over
h1 uses classic RFC 9110 §9.3.6: after `200 Connection Established`
the socket becomes a raw byte pipe.

CONNECT-IP encodes similarly: h3 uses QUIC datagrams carrying
`ContextId(0) || IPPayload`, h2 and h1 use DATAGRAM capsules with
the same inner layout. Control-plane capsules
(`ADDRESS_ASSIGN` / `ADDRESS_REQUEST` / `ROUTE_ADVERTISEMENT`) are
sent as stream body on all three transports.

`src/masque_capsule.erl` covers RFC 9297 framing; h2-specific
decoding lives in `h2_capsule` from the `erlang_h2` dep (it knows to
resolve the `datagram` type natively). `src/masque_ip_capsule.erl`
encodes / decodes the RFC 9484 control-plane capsules.

## 7. Handler behaviour contract

`masque_handler` (`src/masque_handler.erl`) is the single extension
point on the server side. Every listener dispatches inbound events
to the configured handler module. Callbacks:

| Callback              | When | Required? |
|-----------------------|------|-----------|
| `accept/1`            | Handshake gate. Return `accept` or `{reject, Error}`. | optional; default accept |
| `init/2`              | First event after 2xx; build handler state. | yes |
| `handle_packet/2`     | Inbound UDP payload (CONNECT-UDP tunnels). | UDP handlers |
| `handle_data/2`       | Inbound TCP byte chunk (CONNECT-TCP tunnels). | TCP handlers |
| `handle_ip_packet/2`  | Inbound IP packet (CONNECT-IP tunnels). | IP handlers |
| `handle_capsule/3`    | Inbound extension capsule on the stream body. | optional |
| `handle_info/2`       | Any other Erlang message (e.g. `{udp, _, _, _, _}` from an owned socket). | optional |
| `terminate/2`         | Session shutdown. | optional |

Callbacks return `{ok, State} | {ok, State, [Action]} | {stop, Reason, State}`.
Actions are transport-agnostic instructions the session translates
to transport calls:

| Action                        | Effect |
|-------------------------------|--------|
| `{send, Payload}`             | Send a UDP payload back to the client. |
| `{send_data, Bytes}`          | Send TCP bytes back to the client. |
| `{send_ip_packet, Packet}`    | Send an IP packet back to the client. |
| `{send_capsule, Type, Value}` | Send an extension capsule on the stream. |
| `{assign, Entries}`           | Send an ADDRESS_ASSIGN capsule (IP). |
| `{advertise, Routes}`         | Send a ROUTE_ADVERTISEMENT capsule (IP). |
| `{request_addresses, Prefs}`  | Send an ADDRESS_REQUEST capsule (IP). |
| `close`                       | Close the tunnel gracefully. |

Built-in handlers:

- `masque_udp_proxy_handler`: opens a `gen_udp` socket, forwards
  packets both ways. Supports `allow`, `resolver`, `family`,
  `allow_private` policies.
- `masque_tcp_proxy_handler`: opens a `gen_tcp` socket, forwards
  bytes both ways. Supports `connect_timeout`, `allow_private`,
  `socket_opts`.
- `masque_ip_proxy_handler`: IP forwarding with an address-pool
  allocator, BCP-38 source filter, `forward_fun` extension point.
- `masque_chain_handler`: opens a MASQUE client session to an
  upstream proxy and relays everything (UDP / TCP / IP) through
  `masque:send/2`, `masque:send_ip_packet/2`, and friends.

## 8. Transport racing

`masque_racer` (`src/masque_racer.erl`) is modelled on Apple's
Network.framework behaviour in iCloud Private Relay. It spawns one
worker per listed transport, each starts its own session, and the
first one to reach a 2xx wins.

Ordering (for `[h3, h2, h1]`):

```
t=0 ms                    : launch h3 attempt
t=prefer_timeout_ms       : launch h2 attempt in parallel
t=prefer_timeout_ms +
  h1_prefer_timeout_ms    : launch h1 attempt in parallel
```

Losers are asked to stop cleanly (`Mod:stop/1`), which runs their
`closing` state and releases any pooled stream before exiting. The
racer does not hold transport events in its mailbox; each session
owns its own mailbox, so a losing attempt's datagrams never leak to
the winning session's owner.

`timeout` caps the whole race - the racer exits with
`{error, {race_timeout, LastError}}` if no attempt reaches 2xx in
time.

## 9. Two-hop chaining

`masque_chain_handler` implements the Apple-Private-Relay shape:

```
Client --tunnel--> Ingress (chain handler) --MASQUE--> Egress --target
```

On the ingress, the chain handler's `init/2` calls `masque:connect/3`
against the configured upstream URI. That returns a session pid the
handler holds in its state. Every inbound `{send, _}` from the
client becomes a `masque:send/2` against the upstream; every
`{masque_data, Upstream, Data}` coming back becomes a
`{send, Data}` action on the downstream tunnel.

Clients don't know they're talking to a chain - the ingress replies
2xx on its own, then proxies. The same handler also supports
CONNECT-TCP (byte pipe) and CONNECT-IP (IP packets +
ADDRESS_ASSIGN / ROUTE_ADVERTISEMENT passthrough).

Convenience wrappers for the three transports:

- `masque:start_chain_listener/2` (h3)
- `masque:start_chain_listener_h2/2`
- `masque:start_chain_listener_h1/2`

All three set the UDP, TCP, and IP handler slots to
`masque_chain_handler`, so any tunnel protocol the client picks is
forwarded upstream.

`examples/two_hop_relay.erl` is a runnable standalone reference.

## 10. Upstream connection pool

Default behaviour: each `masque:connect/3` call opens a fresh
h2 / QUIC handshake to the proxy. For a chain ingress that's one
transport handshake per client tunnel, which is wasteful on warm
traffic.

Opt-in pooling (`upstream_pool => true`) lets siblings share one
underlying h2 / QUIC connection: each new tunnel opens a fresh
stream on the shared connection instead of a fresh socket / QUIC
conn. h1 is always a pool bypass (the protocol is
1-tunnel-per-socket).

### Process shape

```
masque_upstream_pool         (registry gen_server)
    |
    | cache :: #{fingerprint() => [#entry{owner, mon_ref}]}
    | dialing :: #{fingerprint() => [caller_From]}
    |
    | on checkout:
    |   - cache hit  -> return owner pid immediately
    |   - dial already in flight -> join the waiters list
    |   - cold key   -> spawn a masque_upstream_owner via
    |                   start_for_pool/3, record caller as first
    |                   waiter; reply when {dial_result, _, _} arrives
    v
masque_upstream_owner        (per-conn gen_server, one per pooled conn)
    |
    | transport     :: h2 | quic_h3
    | conn          :: pid() (owned by this process via self-dial)
    | refs          :: #{StreamId -> #ref{session_pid, monitor_ref}}
    | max_streams   :: pos_integer() | dynamic
    | idle_ref      :: timer reference for idle eviction
    |
    | exposes acquire_stream/4 and release_stream/2 to sessions;
    | forwards transport-level events ({response, _, _, _},
    | {datagram, _, _}, {stream_reset, _, _}, closed) to the right
    | session by looking up StreamId in refs.
```

### Fingerprint

The pool key is `{Host, Port, Transport, OptsHash}` where

```
OptsHash = sha256(
    #{verify   => verify_peer | verify_none,
      cacerts  => [der()] | default,
      ssl_opts => lists:sort([ssl:tls_client_option()]),
      alpn     => [binary()] | default})
```

`ssl_opts` is sorted so two callers that pass equivalent lists in
different orders still share a pool entry. Per-tunnel knobs
(`protocol`, `timeout`, `owner`, `proxy_authorization`, `mtu`) are
deliberately excluded: they do not affect the connection, only the
tunnel.

### Stream-event routing

h2 and quic_h3 both deliver stream-level events to the connection
owner by default. The owner registers each session as that stream's
handler via `Mod:set_stream_handler(Conn, StreamId, SessionPid)`,
which re-routes `{h2|quic_h3, _, {data, Sid, _, _}}` directly to
the session's mailbox. Pre-registration data is replayed with
`drain_buffer => false` so the session sees it via the same
`handle_info` clause.

Events that stay on the connection owner (not per-stream):

- `{response, StreamId, _, _}` - always.
- `{quic_h3, _, {datagram, StreamId, _}}` - h3 DATAGRAM frames,
  carried to the conn owner and keyed by stream id.
- `{stream_reset, StreamId, _}` - forwarded to the session and the
  ref is dropped.
- `closed` - broadcast to every registered session so each can
  surface `peer_closed` to its own owner; then the owner stops.

The session's `handle_info` clauses for these events are the same
ones used in the non-pooled path, so pooling is transparent at the
session level.

### Idle eviction

When the last stream releases, the owner arms an idle timer
(default 30 s, tune via `upstream_pool_opts => #{idle_timeout_ms =>
N}`). Expiry closes the transport conn and stops the owner
normally; the registry's DOWN handler drops the cache entry so a
subsequent checkout re-dials.

### Stream limits

- h2: the owner reads the peer's SETTINGS
  (`max_concurrent_streams`) at dial time. `unlimited` or absent
  values become `dynamic` / 100 per RFC 9113 §6.5.2.
- h3: always `dynamic`. QUIC `MAX_STREAMS_BIDI` is transport-level;
  when full, `Mod:request/3` returns `{error, stream_limit}` and
  the pool would need to open a sibling conn for the same key
  (not implemented in v0.6 - treated as a follow-up).

### Single-flight dialing

Cold-key checkouts spawn the owner process, which does the
handshake in its own `init_for_pool/3` before entering the normal
gen_server loop. The registry never blocks on a handshake, so a
slow upstream on key A does not stall checkouts on key B.

Multiple concurrent checkouts on the same cold key all join the
`dialing` waiters list and wake up together when the dial
completes - one handshake, N tunnels.

## 11. CONNECT-IP control plane

CONNECT-IP (RFC 9484) adds three capsule types on top of the
CONNECT-UDP base: `ADDRESS_ASSIGN`, `ADDRESS_REQUEST`, and
`ROUTE_ADVERTISEMENT`. All are control-plane capsules carried on the
stream body; IP packets themselves travel via the datagram channel
with context id 0.

Client API (see `src/masque_ip_client_session.erl`):

- `masque:send_ip_packet(Sess, Packet)` - outbound IP packet.
- `masque:request_addresses(Sess, Prefixes)` - ask the server to
  allocate addresses; returns the Request IDs used.
- `masque:assign_addresses(Sess, Entries)` - the client side of
  site-to-site (§8.2) can also push assignments back.
- `masque:advertise_routes(Sess, Routes)` - advertise reachable
  routes.

Owner messages:

- `{masque_ip_packet, Sess, Packet}`
- `{masque_address_assign, Sess, Entries}`
- `{masque_address_request, Sess, Entries}`
- `{masque_route_advertisement, Sess, Routes}`

Server side: `masque_ip_proxy_handler` is the default handler. It
allocates from a configured `address_pool` (prefix-aware, see
"Address allocator" below), sends an unprompted `ADDRESS_ASSIGN` +
initial `ROUTE_ADVERTISEMENT` at init, runs a BCP-38 source filter
plus URI-scope (`target` / `ipproto`) checks on inbound packets, and
delegates the forwarding decision to a configurable `forward_fun`.

Inbound packet gating is consolidated in `accept_inbound/2`, which
returns `ok | {drop, Reason}` so dropped packets carry an
attributable reason. Reasons feed the simple counters in
`masque_metrics` (see §12) and the optional `lifecycle_fun`
callback (see "Lifecycle hook" below).

### Address allocator

The allocator is prefix-aware: `allocate_one/2` honours the
`prefix_len` field of the `ADDRESS_REQUEST` entry, clamping the
response to the configured `min_assignable_prefix`
(`#{4 => 32, 6 => 128}` by default - host routes only, matching the
historical behaviour). `next_free/3` walks the pool in stride-aligned
blocks of `2^(MaxPfx - Pfx)` and rejects ranges that overlap any
existing assignment via `overlaps_assigned/4` (`max(s1,s2) =< min(e1,e2)`
on the integer-address space). Host and prefix allocations from the
same pool are guaranteed not to collide.

### Address registry

`masque_ip_session_registry` (worker child of `masque_sup`) maps
every assigned address or prefix to the session pid that serves it,
across all sessions. Storage is a single ETS `ordered_set` keyed by
`{Version, StartIntAddr}` with values
`{EndIntAddr, Pfx, Pid, ContextId, MRef}`; lookup does longest-prefix
match by interval inclusion (`ets:prev/2` to the candidate, then
endpoint check). Because every registration is rejected on overlap,
at most one interval covers any given address, so the lookup is a
single ETS hit, no scan.

The registry server is only on the write path. The proxy handler
calls `register/5` from `allocate_one/2` and `release/3` from
`terminate/2`. Process monitoring inside the registry releases
orphan ranges if a session exits abruptly. All write APIs tolerate
the registry not being started (no-ops via `whereis/1` checks),
which keeps eunit tests that don't boot the application working.

### Out-of-band injection

`masque_ip:inject_packet(SessionPid, Packet)` casts
`{inject_packet, Packet}` into a server session. Both
`masque_ip_server_session` (h2/h3) and `masque_ip_h1_server_session`
(h1) handle the cast by re-running the existing
`{send_ip_packet, Packet}` action through their own `do_actions/2`
interpreter, so capsule framing, MTU enforcement, and metrics fire
identically to a handler-driven send. This is the seam a TUN device
owner uses to deliver kernel-side packets to a tunnel client; paired
with the registry it gives full read-side fan-out without exposing
the session's internal state machine.

### Lifecycle hook

The default handler's `handler_opts` accepts an optional
`lifecycle_fun :: fun((Event, Detail) -> ok)`. Recognised events:
`address_assigned`, `address_released`, `route_advertised`,
`packet_dropped`. The hook is invoked synchronously from inside the
handler with errors swallowed - a misbehaving consumer cannot break
the data plane. Each event also bumps a simple counter in
`masque_metrics` (see §12) so observers that prefer scraping a
counter to subscribing to a callback are also covered.

### `forward_fun` action list

In addition to the historical
`{reply, _, _} | {drop, _} | {forward, _} | ok | {error, _}` return
shapes, `forward_fun` may return
`{actions, [forward_action()], NewState}` where `forward_action()`
matches the IP server-session interpreter's vocabulary
(`{send_ip_packet, _}`, `{icmp_error, {Kind, Spec, Invoking}}`,
`{drop, Reason}`). `{drop, _}` is intercepted before the action list
reaches the session, so it generates only a drop counter bump and a
`packet_dropped` lifecycle event - it never produces wire output.
This lets a forward_fun reply with ICMP and drop the original in a
single call.

ICMP error synthesis (`src/masque_icmp.erl`) builds
RFC-compliant ICMPv4/v6 replies - Destination Unreachable, Packet
Too Big (v6), Time Exceeded - with truncated invoking packets.

Section-by-section compliance map: `docs/connect_ip.md`.

## 11b. Connect-UDP-Bind

Connect-UDP-Bind (draft-ietf-masque-connect-udp-listen-11) lives
alongside CONNECT-UDP rather than replacing it. It is opt-in via
the listener-level `accept_bind => true` flag. When enabled, the
existing `connect-udp` dispatch additionally inspects a
`Connect-UDP-Bind: ?1` request header (RFC 9651 Boolean): on
match, the request routes to the bind matcher
(`masque_uri_udp_bind`) and the bind handler / session; otherwise
it flows through the legacy CONNECT-UDP path unchanged.

Process model (h3 / h2):

```
masque_server                    masque_h2_session_sup
  validate/7  ─reads Connect-UDP-Bind header
   │
   └─ on ?1 ─> masque_uri_udp_bind:match/2  (accepts %2A wildcard)
                │
                └─> masque_h2_session_sup:start_session(udp_bind)
                                │
                                └─> masque_udp_bind_server_session
                                       │ owns:
                                       │   - 2 compression tables
                                       │     (own + peer)
                                       │   - bind handler state
                                       │     (which holds the
                                       │      gen_udp socket)
                                       │
                                       └─> masque_udp_bind_proxy_handler
                                            opens gen_udp; emits
                                            response_headers action
                                            with Connect-UDP-Bind +
                                            Proxy-Public-Address
```

The h1 path mirrors h2/h3 but the session takes ownership of the
upgraded TLS socket via `h1:accept_upgrade/3` and runs the same
state machine.

### Compression-table state machine

Two tables per session, built in `masque_compression_table`:

- **own**: outbound context-IDs we opened on the peer. Allocations
  follow the parity rule (client even, proxy odd). Entries start
  in `pending_ack` state; a `COMPRESSION_ACK` from the peer flips
  them to `installed`. The session refuses to compress payloads on
  a `pending_ack` entry.
- **peer**: incoming context-IDs the peer opened on us. Entries
  jump straight to `installed` on receipt of a valid
  `COMPRESSION_ASSIGN`. The session emits the matching
  `COMPRESSION_ACK` immediately.

Invariants enforced inside the table:

- Parity check on `install/2` rejects cross-parity ASSIGNs as
  malformed.
- Duplicate context-IDs are malformed.
- Per-tuple uniqueness has two distinct draft-11 cases:
  - Cross-side conflict (peer ASSIGNs a tuple our side opened):
    table returns `{conflict, close_proxy_id, _}` so the session
    can close the proxy-opened context.
  - Same-side conflict (peer ASSIGNs a tuple it already has open):
    `{error, malformed_duplicate_tuple}`.
- Singleton uncompressed: at most one open IP Version 0 mapping.
- Family gating: registrations and encodes for an unadvertised
  address family are rejected.

### Per-session gen_udp lifecycle

The bind handler opens one `gen_udp` socket per session in
`init/2`, computes its public address list (configured override,
hook function, or sockname fallback when bound to a specific
interface), and returns a `{response_headers, _}` action that the
session splices into the 2xx response. On `terminate/2` the
socket is closed.

Inbound packets from the kernel arrive as `{udp, Sock, IP, Port,
Bytes}` messages, are filtered by family (drop unadvertised) and
then emitted as a `{send_bind_packet, {IP, Port}, Bytes}` action.
The session encodes via `masque_udp_bind_payload`, picking the
context-ID from the compression table (or the uncompressed channel
if no compressed mapping exists for the peer).

### Decision: auto-compression lives outside the library

The library never auto-assigns context-IDs. It exposes
`masque:assign_compression/2`,
`masque:open_uncompressed_context/1`,
`masque:close_compression/2` as primitives and surfaces lifecycle
events as owner messages, so a downstream policy module can plug
in LRU / top-N / hot-flow heuristics without touching the lib's
core. The right policy depends on the consumer's traffic shape;
baking a single one in would be wrong for at least half the use
cases.

## 12. Metrics

`src/masque_metrics.erl` exposes two metric surfaces with different
shapes.

The tunnel-lifetime metrics use `instrument_meter` for OpenTelemetry
compatibility:

- `masque.tunnels.total` - counter; incremented on every accepted
  tunnel.
- `masque.tunnels.active` - up/down counter; kept in sync with
  live tunnels.
- `masque.tunnels.rejected` - counter; handshake-level rejections.
- `masque.bytes.in` / `masque.bytes.out` - counters; per-tunnel
  throughput.
- `masque.tunnel.duration_ms` - histogram; tunnel lifetime.

Every sample carries a tags map so OpenTelemetry-style attributes
(e.g. `#{protocol => udp, transport => h3, target_port => 443}`)
flow through. Call `masque_metrics:setup/0` at application start;
the masque application already does this.

The CONNECT-IP plumbing metrics deliberately use the OTP `counters`
module instead - they are intended as a lightweight surface for
downstream consumers (TUN/router, scrapers) and tests, with no
dependency on a meter system being initialised:

- `ip_drop_inc(Reason)` / `ip_drop_count(Reason)` - one bucket per
  reason in `ip_drop_reasons/0` (`bcp38`, `scope_target`,
  `scope_ipproto`, `malformed`, `forward_drop`, `ttl_zero`,
  `mtu_exceeded`, `other`); unknown reasons fold into `other`.
- `ip_assign_inc/0` / `ip_assigned_count/0` - allocator handed out a
  range.
- `ip_release_inc/0` / `ip_released_count/0` - allocator or
  registry freed a range.
- `ip_advertise_inc/0` / `ip_advertised_count/0` - handler emitted a
  ROUTE_ADVERTISEMENT.

`setup_ip_counters/0` is the idempotent allocator; tests call it
directly, the masque application calls it from `setup/0`. All
`*_count` reads return `0` when the counters aren't yet allocated,
all `*_inc` calls become no-ops in the same case.

## 13. Known invariants

- **One owner per transport connection.** Client: the `owner` in
  `Opts` receives all tunnel-level messages. Server: the
  per-connection router (`masque_server_connection`) is the
  transport's owner; sessions receive demultiplexed events from it.
- **The CONNECT stream outlives the tunnel.** The session keeps
  the stream open after the 2xx response; closing the stream
  closes the tunnel.
- **End-stream sent on close.** The session's `closing` state
  sends a FIN on an empty DATA frame and falls back to `cancel`
  only if the stream is already gone. This preserves HTTP
  semantics for middleboxes.
- **Per-tunnel session is process-isolated.** One crashing tunnel
  does not affect siblings on the same transport connection - the
  router drops the entry and moves on.
- **Capsule buffer size is capped.** Stream body bytes get buffered
  until a full capsule decodes; a peer that never sends a length
  will run the buffer to `max_capsule_size` and then the session
  aborts with `capsule_buffer_overflow`.
- **IPv6 authorities are bracketed.** Every outbound
  `:authority` / `Host:` goes through
  `masque_uri:build_authority/2` to bracket IPv6 literals per
  RFC 3986 §3.2.2.
- **`proxy_authorization` is CRLF-sanitised.** Client opt is
  rejected before any socket opens if it contains CR or LF.

## 14. Extension points

Where to plug in without forking the library:

- **Custom tunnel policy.** Implement `masque_handler`; override
  `accept/1` to gate on headers, peer cert, peer IP. The `Req`
  map carries `peer_cert`, `peer`, `headers`, `resolved_addresses`.
  Return `{reject, Error, ExtraHeaders}` to attach response headers
  like `WWW-Authenticate` for a Privacy Pass challenge.
- **Custom tunnel backend.** Implement `masque_handler`; do
  whatever in `init/2`, `handle_packet/2`, `handle_data/2`, and
  emit actions. Examples: record to an audit log, route to
  internal services, dynamically resolve targets.
- **IP packet pipeline.** Use `masque_ip_proxy_handler` and set
  `forward_fun :: fun((Packet, State) -> Return)`. `Return` may use
  the historical `{reply, _, _} | {drop, _} | {forward, _} | ok |
  {error, _}` shapes or the action-list shape
  `{actions, [forward_action()], State}` where each action matches
  the IP server-session interpreter's vocabulary. See
  `docs/connect_ip.md` "Plumbing for external consumers".
- **External TUN/router data plane.** Combine
  `masque_ip_session_registry:lookup/1` with
  `masque_ip:inject_packet/2` to deliver packets read from a TUN
  device to the right server session without going through any
  handler callback. Subscribe to the data plane by setting
  `lifecycle_fun` in `handler_opts` to receive
  `address_assigned` / `address_released` / `route_advertised` /
  `packet_dropped` events.
- **Per-family prefix delegation.** Set
  `min_assignable_prefix => #{4 => N4, 6 => N6}` in `handler_opts`
  to issue prefixes (e.g. `/64` to a CPE) instead of host routes.
- **Upstream connection pooling.** Opt in with
  `upstream_pool => true` on direct clients and on chain handlers.
- **Transport preference.** `transports => [h3]` to force QUIC;
  `[h3, h2, h1]` to enable the full race.
- **Client-side request headers.** Pass
  `request_headers => [{Name, Value}]` in `connect_opts()` to add
  auth headers (`Authorization: PrivateToken ...`) or metadata to
  the CONNECT / Upgrade request. The library sanitises caller
  input (reserved names dropped; CR/LF refused on h1).
- **TLS customisation.** Pass `ssl_opts` for client overrides;
  bring your own cert store via `cacerts`. For server listeners
  use `masque:start_listener/2` / `_h2/2` / `_h1/2`, which
  forward to the respective transport libs' server opts.
- **Shared transport server.** If you already run a QUIC or h2
  server, call `masque_server:h3_handlers/1` /
  `masque_h2_server:h2_handlers/1` to get the handler + connection
  handler functions and wire them into your existing listener
  alongside your own routes (`fallback` fun handles non-MASQUE
  requests).
