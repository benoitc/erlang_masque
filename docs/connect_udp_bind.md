# Connect-UDP-Bind

Implementation of [draft-ietf-masque-connect-udp-listen-11](https://datatracker.ietf.org/doc/html/draft-ietf-masque-connect-udp-listen-11)
("Connect-UDP-Bind"), a sibling of RFC 9298 CONNECT-UDP that adds
multi-peer UDP proxying with optional compression-context
negotiation.

The two protocols coexist: a single listener can accept either or
both. Operators pick per-listener via the `accept_bind` flag.

## Quickstart

### Server

```erlang
{ok, _} = application:ensure_all_started(masque),

%% Opt-in to bind. accept_bind defaults to false; without it the
%% listener treats the Connect-UDP-Bind header as absent.
masque:start_listener(my_relay, #{
    port         => 4433,
    cert         => CertDer,
    key          => KeyDer,
    accept_bind  => true,
    handler_opts => #{
        %% Bind-specific opts go in handler_opts:
        bind_address      => any,                       %% interface
        public_addresses  => [{{198,51,100,1}, 4433}],  %% required
                                                        %% if bind_address
                                                        %% is wildcard
        peer_filter_fun   => fun custom_egress_policy/2, %% optional
        allow_loopback    => false,                     %% default
        allow_private     => false,                     %% default
        max_pending_compression_responses => 16         %% default
    }
}).
```

The same options work on `masque:start_listener_h2/2` and
`masque:start_listener_h1/2`.

### Peer filter

Without `peer_filter_fun`, the proxy only exchanges packets with
public peers (`masque_ip:is_public/1`). Loopback peers need
`allow_loopback => true`; other private, link-local, CGNAT,
multicast or broadcast peers need `allow_private => true`.
IPv4-mapped IPv6 peers (`::ffff:a.b.c.d`) are checked as IPv4.

For a local test setup:

```erlang
handler_opts => #{bind_address => {127,0,0,1}, allow_loopback => true}
```

### Limits and drop counters

The proxy keeps at most `max_pending_compression_responses`
COMPRESSION_ASSIGN capsules waiting for an ACK. Past that, and for
other dropped packets, it bumps a counter you can read:

```erlang
[{R, masque_metrics:bind_drop_count(R)} || R <- masque_metrics:bind_drop_reasons()].
```

Reasons: `context_zero`, `unknown_context`, `malformed`,
`peer_filter`, `pending_limit`, `uncompressed_closed`, `other`.

`bind_handler` defaults to `masque_udp_bind_proxy_handler`. To
plug in your own handler, set
`bind_handler => my_app_bind_handler` in the listener config.

### Client

```erlang
%% Unscoped: bind socket on the proxy can talk to any peer the
%% operator's policy allows. The client sends to any (IP, Port).
%% `transports => [h3, h2]' races both; h1 is also supported.
{ok, Sess} = masque:bind_connect(<<"https://relay.example:4433">>,
                                  unscoped,
                                  #{transports => [h3]}).

%% Scoped: proxy enforces the (Host, Port). Client can still send
%% to (IP, Port) tuples that resolve to that scoped peer.
{ok, Sess} = masque:bind_connect(<<"https://relay.example:4433">>,
                                  {<<"203.0.113.1">>, 53},
                                  #{transports => [h3]}).

%% Read what the proxy advertised (one or more public addresses).
{ok, Addrs} = masque:proxy_public_address(Sess).

%% Open the singleton uncompressed (IP Version 0) context. The
%% client side must do this before the first send_to/3, because the
%% library uses wait-for-ACK semantics.
{ok, _Id} = masque:open_uncompressed_context(Sess).

%% Wait for the ACK message to arrive before sending data on it.
receive {masque_compression_acked, Sess, _} -> ok end.

%% Now send to a peer. send_to/3 uses the client's own
%% uncompressed context.
ok = masque:send_to(Sess, {{203,0,113,1}, 53},
                    <<"hello">>).

%% Inbound packets arrive as owner messages:
receive
    {masque_bind_packet, Sess, {Ip, Port}, Bytes} ->
        io:format("~p:~p sent: ~p~n", [Ip, Port, Bytes])
end.
```

### Owner messages

A bind session emits the following messages to the owner pid
(default: the caller of `bind_connect/3`):

- `{masque_bind_packet, Sess, {IP, Port}, Bytes}` - inbound UDP
  payload from a peer.
- `{masque_compression_assigned, Sess, ContextId, Peer}` - the
  proxy installed an outbound context for `Peer`. Use
  `assign_compression/2` to reciprocate; not all binds need this.
- `{masque_compression_acked, Sess, ContextId}` - one of our
  outbound mappings is now safe to use on send.
- `{masque_compression_closed, Sess, ContextId}` - a mapping was
  retired (by either side).
- `{masque_closed, Sess, Reason}` - tunnel teardown.

`bind_connect/3` verifies the proxy certificate by default (system
CAs, hostname check, SNI) on h1, h2 and h3; pass
`verify => verify_none` or `cacerts` for a self-signed proxy. A dial
failure returns `{error, Reason}`. Closing the session also closes
the connection it opened.

## Wire format

### Handshake

A bind handshake reuses CONNECT-UDP's URI template and pseudo-header
(`:protocol = connect-udp`) and adds a Boolean Structured Field
header:

```
:method:    CONNECT
:protocol:  connect-udp
:scheme:    https
:authority: relay.example:4433
:path:      /.well-known/masque/udp/%2A/%2A/      (unscoped)
            /.well-known/masque/udp/203.0.113.1/53/  (scoped)
capsule-protocol: ?1
connect-udp-bind: ?1
```

Both endpoints indicate bind support by sending
`Connect-UDP-Bind: ?1` (RFC 9651 Boolean) on the request and
response. The bind is only enabled once each side has both sent and
received it.

The proxy's response also carries `Proxy-Public-Address`, an
RFC 9651 list of String items, each shaped as `"ip:port"` (IPv6
literals bracketed):

```
Proxy-Public-Address: "192.0.2.45:54321", "[2001:db8::1234]:54321"
```

A successful 2xx (or 101 on h1) MUST carry both headers. The bind
client aborts the handshake otherwise, with
`{error, missing_bind_response_header}` or
`{error, missing_proxy_public_address}` respectively.

### Datagram payload

Per draft-11 sections 4 and 5, the payload that follows the HTTP
Datagram Context ID has two shapes:

- **Compressed** (registered IP Version 4 or 6): the inner payload
  is the raw UDP bytes only. The peer tuple is implicit in the
  receiver's table entry for the Context ID.
- **Uncompressed** (registered IP Version 0):
  `family || addr || port || udp_payload`. Family is one byte (4 or
  6), address is 4 or 16 bytes (network byte order), port is 2
  bytes, payload is the rest.

Context-ID 0 is reserved on the wire in unscoped binds. In scoped
binds, Context-ID 0 keeps RFC 9298 raw-UDP semantics for the
scoped peer.

### Compression Contexts capsules

Three capsule types (IANA-provisional):

| Type | Code | Body                                                       |
| ---- | ---- | ---------------------------------------------------------- |
| `COMPRESSION_ASSIGN` | `0x11` | `Context ID (varint) || IP Version (8) || [IP Address || UDP Port]` |
| `COMPRESSION_ACK`    | `0x12` | `Context ID (varint)`                                       |
| `COMPRESSION_CLOSE`  | `0x13` | `Context ID (varint)`                                       |

For IP Version 0 (uncompressed registration), `IP Address` and
`UDP Port` are omitted from `COMPRESSION_ASSIGN`. Context ID 0 is
malformed in `COMPRESSION_CLOSE`.

Parity:
- Client allocates **even** Context IDs (2, 4, 6, ...).
- Proxy allocates **odd** Context IDs (1, 3, 5, ...).

The receiver of a `COMPRESSION_ASSIGN` whose ID has the wrong
parity treats it as malformed and aborts the request stream.

## Coexistence with RFC 9298 CONNECT-UDP

Both protocols ship in the library and a single listener can
accept either or both:

| Listener config            | CONNECT-UDP requests | Bind requests |
| -------------------------- | -------------------- | ------------- |
| `accept_bind => false`     | accept (legacy)      | reject (404)  |
| `accept_bind => true`      | accept (legacy)      | accept        |
| (default)                  | accept (legacy)      | reject (404)  |

When `accept_bind => false` (the default), the legacy CONNECT-UDP
path is **bit-for-bit unchanged**. The `Connect-UDP-Bind` header
is ignored even if present. A request that uses the unscoped form
(`%2A/%2A` in the URI variables) flows down the legacy URI matcher
which rejects `*` as a host, so the request fails with the same
4xx the existing code emits today.

When `accept_bind => true`, the dispatcher reads
`Connect-UDP-Bind` before choosing the URI matcher: `?1` selects
the bind matcher (which accepts the wildcard); anything else
(including absent) falls through to the legacy CONNECT-UDP matcher
unchanged.

### When to enable bind

| Scenario                                              | Pick         |
| ----------------------------------------------------- | ------------ |
| Single-peer flows (DNS, NTP, fixed UDP service)       | CONNECT-UDP  |
| Multi-peer (multiple QUIC servers, P2P media, STUN)   | bind         |
| Need a stable public IP-port for inbound (TURN-style) | bind         |
| Privacy relay leg with diverse upstream peers         | bind         |

Compression contexts are an optimisation on top of bind; they
shrink the per-datagram overhead from `(family + addr + port)` to
just a varint Context ID once a peer is known to be hot. They are
not required for correctness - the uncompressed channel works
fine on its own and is the natural fallback.

## Compression policy seam

The library deliberately does **not** auto-assign Context IDs. The
consumer drives the lifecycle through:

- `masque:assign_compression/2` - client opens a compressed
  mapping for a peer.
- `masque:open_uncompressed_context/1` - client opens the
  singleton uncompressed channel (proxy installs it on receipt).
- `masque:close_compression/2` - retire a mapping.

Plus the owner messages listed above. This gives the consumer
freedom to plug in any policy: top-N by traffic, LRU, hot-flow
detection, manual control. A skeleton policy module:

```erlang
-module(my_compression_policy).
-export([start_link/2, on_peer_seen/3]).

start_link(Sess, Opts) ->
    %% State: {Sess, peer_counts, max_contexts, ...}
    gen_server:start_link(?MODULE, {Sess, Opts}, []).

on_peer_seen(Pid, Peer, BytesObserved) ->
    gen_server:cast(Pid, {peer_seen, Peer, BytesObserved}).

%% In handle_cast:
%%  - bump the byte counter for Peer
%%  - if the counter crosses a threshold and this peer has no
%%    compressed mapping, call masque:assign_compression(Sess, Peer)
%%  - if the table is full, pick the LRU mapping and close it
```

The library exposes only the primitives because the right policy
depends on the consumer's traffic shape: a relay that fans out to
thousands of peers wants different heuristics than a STUN backend
where every flow lasts hours.

## Library policy: wait-for-ACK on send

Draft-11 permits sending compressed payloads on a freshly-assigned
Context ID before the matching `COMPRESSION_ACK` arrives, with the
risk that early frames may be dropped by a peer that has not yet
installed the mapping. This library is **conservative**: an
outbound mapping is `pending_ack` until the ACK arrives, and is
only used for compressed payloads after that. Until then, traffic
to that peer either uses an already-installed mapping or the
uncompressed channel, or sits in the encoder waiting.

This is a deliberate choice, not a draft requirement. The trade-off
is a small startup latency for each new mapping in exchange for
zero spec-permitted drops.

## What's not in this PR series

- **Bind-by-default migration** - the two protocols coexist, the
  user picks per-listener.
- **Auto-assignment heuristics** - the library exposes the
  primitives; policy lives in the consumer (see above).
- **Adversarial compression-table fuzzing** - basic bounds and
  malformed-input rejection are unit-tested; targeted fuzz
  coverage is a follow-up.
- **DTLS over MASQUE** drafts - separate work.
