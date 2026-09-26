# Messages and errors

This page is the single reference for the messages masque sends to your processes, the messages its own processes exchange, and every error or close reason with what it means. Use it when you match on a message or a reason and need to know every shape it can take. It is a reference: read the section you need, not the whole page. The concepts behind it (owner, session, router, racer, pool) are in [concepts](../1-understand/concepts.md); how to act on a failure is in [debugging](../3-change/debugging.md).

"Owner" on this page means the application process that receives tunnel events: the caller of `masque:connect/3` or the pid given as `owner`. The pool's `masque_upstream_owner` and the h3 router are named explicitly where they appear.

## Owner messages

A client session sends these to its owner. `Sess` is the session pid returned by `connect/3` or `bind_connect/3`.

### Every protocol

| Message | When |
| --- | --- |
| `{masque_data, Sess, Data}` | Data received, in `message` mode. CONNECT-UDP: one UDP payload (context id 0). CONNECT-TCP: a chunk of the byte stream. |
| `{masque_capsule, Sess, Type, Value}` | A capsule the session does not consume itself (CONNECT-UDP and CONNECT-IP). Sent in both delivery modes. Never sent on CONNECT-TCP, which carries no capsules; udp-bind sessions drop unknown capsules silently. |
| `{masque_closed, Sess, Reason}` | The tunnel ended from the proxy side, in `message` mode. See [close reasons](#close-reasons). |

In `queue` mode, data is not sent as messages: you pull it with `masque:recv/2`, and the end of the tunnel shows up as an error from `recv/2` instead of `masque_closed`.

### CONNECT-IP

| Message | When |
| --- | --- |
| `{masque_ip_packet, Sess, Packet}` | An IP packet (context id 0) arrived, in `message` mode. |
| `{masque_address_assign, Sess, [#ip_assignment{}]}` | The proxy sent ADDRESS_ASSIGN. |
| `{masque_address_request, Sess, [#ip_prefix_request{}]}` | The proxy asked you for addresses (ADDRESS_REQUEST). Answer with `masque:assign_addresses/2`. |
| `{masque_route_advertisement, Sess, [#ip_route{}]}` | The proxy sent ROUTE_ADVERTISEMENT. Each one replaces the previous set. |

The records are defined in `include/masque_ip.hrl`. The moduledoc of `masque_ip_client_session` also lists `{masque_ip_error, Sess, Reason}`; no code sends it.

### Connect-UDP-Bind

| Message | When |
| --- | --- |
| `{masque_bind_packet, Sess, {IP, Port}, Bytes}` | A UDP payload from a peer, in `message` mode. |
| `{masque_compression_assigned, Sess, ContextId, Peer}` | The proxy opened a compression context for `Peer`. |
| `{masque_compression_acked, Sess, ContextId}` | The proxy acknowledged a context you opened; it is now used for sending. |
| `{masque_compression_closed, Sess, ContextId}` | A context was closed by either side. |

### Messages produced during a race

When `transports` lists more than one transport, the session first belongs to a race worker. Anything it would send before the racer hands it to you (for example an ADDRESS_ASSIGN right after the 2xx) is held and delivered to you, in order, when the handoff happens. You never see messages addressed to the worker.

## Close reasons

`{masque_closed, Sess, Reason}` is sent when the proxy side ends the tunnel. You do not get one when you call `masque:close/1` yourself (except on udp-bind, below), and none is sent when the session stops because its owner died.

| Reason | Meaning | Protocols |
| --- | --- | --- |
| `peer_fin` | The proxy ended the stream cleanly. The session sends its own FIN and stops. | UDP and IP on h2/h3 |
| `peer_fin` | Half-close: the target finished sending. The session stays open for writing until `masque:shutdown_write/1` or `masque:close/1`. If you already shut down your side, the session stops. | TCP on h2/h3 |
| `peer_reset` | The proxy reset the stream (handler error, target reset, capsule error on the proxy). | h2/h3 |
| `peer_closed` | The transport connection closed (QUIC or HTTP/2 connection, or the TLS socket on h1). | all |
| `goaway` | The proxy sent GOAWAY and this stream was not going to be processed (h3: stream id at or above the GOAWAY id; h2: above the last stream id). Lower streams keep running. | h2/h3 |
| `{ssl_error, Reason}` | TLS socket error on the upgraded h1 connection. | h1 |
| `malformed_capsule`, `truncated_capsule`, `capsule_buffer_overflow` | The proxy sent a bad capsule, ended the stream mid-capsule, or a capsule larger than `max_capsule_size` (default 65536). The session resets the stream. | UDP and IP on h2/h3 |

udp-bind sessions report differently: they send `{masque_closed, Sess, Reason}` from `terminate/3` whenever they stop in `message` mode, with the process exit reason. A clean end (the proxy's FIN, or your own `masque:close/1`) arrives as `normal`; other values include `peer_reset`, `peer_closed`, `goaway`, `malformed_capsule`, `truncated_capsule`, `capsule_buffer_overflow` and `{ssl_error, _}`. A handshake failure can also be reported this way, with the handshake reason, in addition to the `{error, _}` returned by `bind_connect/3`.

## Results of client calls

### `connect/3` and `bind_connect/3`

Both return `{ok, Sess}` or `{error, Reason}`; a failed dial never exits the caller. Reasons group as follows.

Rejected before any socket opens (`connect/3` only):

| Reason | Cause |
| --- | --- |
| `{invalid_proxy_uri, URI}` | not an `https://host[:port]` URI |
| `{bad_target_for_protocol, Protocol}` | target shape does not match `protocol` (IP needs `{Target, IPProto}`, others `{Host, Port}`) |
| `{invalid_opts, capsule_protocol_required_for_ip}` | `capsule_protocol => false` with `protocol => ip` |
| `{invalid_opts, proxy_authorization_contains_crlf}` / `{invalid_opts, proxy_authorization_must_be_binary}` | bad `proxy_authorization` |

Transport and handshake failures:

| Reason | Cause |
| --- | --- |
| `{connect, R}` | the transport dial failed; `R` is the raw reason (`econnrefused`, a TLS alert, ...) |
| `{request, R}` | the CONNECT request could not be sent |
| `{upgrade, R}` | h1 upgrade failed for another reason than a status or a timeout |
| `handshake_timeout` | no usable response within `timeout` (default 5000 ms) |
| `peer_closed`, `goaway` | the connection closed, or GOAWAY covered the stream, before the response |
| `session_died` | the session process exited before answering |
| `no_extended_connect` | the proxy's SETTINGS do not enable Extended CONNECT |
| `no_h3_datagram` | the proxy's h3 SETTINGS do not enable HTTP datagrams (CONNECT-UDP and CONNECT-IP on h3) |
| `{mtu_too_low, Got, 1280}` | CONNECT-IP on h3: the negotiated datagram size cannot carry a 1280-byte IPv6 packet |

The proxy answered, but not with a usable 2xx:

| Reason | Cause |
| --- | --- |
| `{handshake_rejected, Status}` | non-2xx status on h2/h3 |
| `{handshake_rejected, Status, Detail}` | non-2xx status on h1 (`Detail` is the h1 error or reason phrase) |
| `malformed_response` | 2xx carrying `content-length` or `content-type` |
| `capsule_protocol_not_acknowledged` | CONNECT-UDP: `capsule-protocol: ?1` requested but not echoed |
| `capsule_protocol_missing` | CONNECT-IP: 2xx without `capsule-protocol: ?1` |
| `{bad_response, capsule_protocol}` | CONNECT-TCP: 2xx that switches to capsules |
| `bad_status`, `headers_too_large` | CONNECT-TCP on h1: unreadable status line, response head over the limit |
| `{bad_status, Status}` | udp-bind on h2/h3: non-2xx status |
| `bad_status_line`, `bad_upgrade_response`, `headers_too_large` | udp-bind on h1: unreadable status line, 101 without the right `Upgrade` / `Connection`, response head over the limit |
| `missing_bind_response_header`, `missing_proxy_public_address` | udp-bind: 2xx without `Connect-UDP-Bind: ?1` or `Proxy-Public-Address` |

Racing and pooling (`upstream_pool => true`):

| Reason | Cause |
| --- | --- |
| `{race_timeout, Last}` | no transport won before `timeout`; `Last` is the last attempt's error, or `undefined` |
| `{owner_transfer_failed, Other}` | the winning session did not accept `{set_owner, _}`; the race continues with the others and this surfaces only if it was the last |
| `timeout` | a pooled dial did not finish within `checkout_timeout_ms` (default 60 s) |
| `{dial_failed, R}`, `{dial_crashed, {Class, R}}` | the pooled connection could not be dialed |
| `shutdown` | the pool was closed while you waited |
| `stream_limit` | the pooled connection was at its stream limit when the session asked for a stream |

When several transports race, the reason you get is the last attempt's reason, not necessarily the most useful one. Dial each transport alone to see each failure.

### Data calls

| Call | Result | Meaning |
| --- | --- | --- |
| `send/2,3` | `{error, {payload_too_large, Size, 65527}}` | UDP payload above the RFC 9298 limit |
| `send/2,3` | `{error, {datagram_too_large, Size, Max}}` | h3: payload does not fit the negotiated datagram size |
| `send/2` | `{error, write_closed}` | CONNECT-TCP after `shutdown_write/1` |
| `send_ip_packet/2` | `{error, {packet_too_large, Size, Mtu}}` | packet larger than the session `mtu` |
| `request_addresses/2`, `assign_addresses/2` | `{error, bad_prefix}`, `{error, {bad_prefix_length, P, V}}` | malformed prefix |
| `assign_addresses/2` | `{error, {no_such_pending_request, Id}}` | non-zero request id that the proxy never asked for |
| `send_to/3` | `{error, no_compression_context}` | udp-bind: no installed context for the peer and no uncompressed context |
| `recv/2` | `{ok, Bin}` / `{ok, Peer, Bytes}` (udp-bind) | next queued item |
| `recv/2` | `{error, timeout}` | nothing arrived in time |
| `recv/2` | `{error, closed}` | the tunnel ended and the queue is empty, or the session is gone |
| `recv/2` | `{error, rx_overflow}` | CONNECT-TCP in queue mode: you did not read fast enough and more than `rx_queue_limit` chunks piled up; the tunnel was reset |
| `shutdown_write/1` | `{error, not_supported}` | CONNECT-UDP sessions |
| `shutdown_write/1` | `{error, not_ready}` / `{error, closing}` / `{error, already_closed}` | TCP session still connecting, closing, or already shut down |
| `send_capsule/3` | `{error, not_supported}` | CONNECT-TCP |
| any call | `{error, Reason}` | the session is in `failed`: the dial error is returned and the session stops |
| any call | `{error, closed}` | the session is in `closed` (peer ended, queue not yet drained) |

Queue-mode datagram tunnels do not fail when the queue is full: they drop and count (`rx_dropped` in `masque:info/1`).

Calls a session does not implement are not all handled: CONNECT-IP and udp-bind sessions have no catch-all call clause in `open`, so `masque:send/2` or `masque:shutdown_write/1` on them crashes the session.

`masque:close/1` always returns `ok`.

## Server side: handshake reasons and HTTP status

When a request is refused before the tunnel opens, the listener answers with a status from `masque_errors:handshake_status/1`, a short text body from `masque_errors:status_reason/1`, and a `proxy-status` header (RFC 9209) of the form `masque; error=<type>`. On h1 the response also carries `connection: close` and the connection is closed.

| Reason | Status | Proxy-Status `error` | Produced by |
| --- | --- | --- | --- |
| `bad_method` | 405 | `http_protocol_error` | listener validation: not `CONNECT` (h1: not `GET` or `CONNECT`) |
| `bad_protocol` | 501 | `http_protocol_error` | unknown `:protocol`; h1 upgrade without `Connection: Upgrade` or `Capsule-Protocol: ?1` |
| `bad_path` | 404 | `http_protocol_error` | path does not match the template; missing `:scheme` / `:authority` |
| `bad_port` | 400 | `http_protocol_error` | port out of range; bad `ipproto` for CONNECT-IP |
| `bad_host` | 400 | `http_protocol_error` | empty or malformed host or IP target; h1 `Host` missing or not matching the CONNECT target |
| `resolution_failed` | 502 | `dns_error` | hostname target did not resolve; handler `init/2` failed; session could not start |
| `upstream_timeout` | 504 | `connection_timeout` | a handler's `{reject, upstream_timeout}`; no built-in code produces it |
| `forbidden` | 403 | `destination_ip_prohibited` | built-in handlers' `accept/1`: the `allow` fun said no (UDP, TCP, chain), or a CONNECT-IP target is `'*'` or non-public without `allow_private` |
| `loop_detected` | 508 | `proxy_loop_detected` | `masque_chain_handler`: the `via` header already names this listener, or the upstream answered 508 |
| `overload` | 503 | `proxy_internal_error` | listener draining; `max_tunnels_per_connection` reached |
| `{other, Status}` | `Status` (400..599) | `proxy_internal_error` | handler rejection with an explicit status |
| anything else | 502 | `proxy_internal_error` | unknown `{reject, _}` reason |

`accept/1` can return `{reject, Reason}` or `{reject, Reason, Headers}`; `Headers` are added to the response and win over the library headers of the same name (`content-type`, `content-length`, `proxy-status`).

How a failed session start is mapped: an `init/2` returning `{stop, {reject, R}}` answers with `R`; `{stop, {resolution_failed, _}}` and any other stop reason answer 502 (`resolution_failed`). On h3 the router's `too_many_tunnels` becomes `overload`, and a session that does not start within 30 s becomes `resolution_failed`.

Each rejection increments `masque.tunnels.rejected` with the attribute `reason`.

## Server side: session exit reasons

These are the reasons a server session process stops with. They are passed to the handler's `terminate/2` and decide what the session puts on the wire as it goes.

| Reason | Meaning |
| --- | --- |
| `normal` | the handler returned `{stop, normal, _}` or `close_session`, or the client sent a clean FIN |
| `connection_closed` | the h3 router is shutting down because the connection closed |
| `router_gone` | the h3 router died |
| `peer_reset`, `peer_closed` | the client reset the stream or closed the connection |
| `malformed_capsule`, `truncated_capsule`, `capsule_buffer_overflow` | bad capsule from the client; the stream was reset (`H3_MESSAGE_ERROR` on h3, `PROTOCOL_ERROR` on h2) before stopping |
| `stream_dead` | h3: the 2xx or the stream claim failed during finalize |
| `idle_timeout` | h1: no traffic for `idle_timeout_ms` in `handler_opts` (default 300000) |
| `{tunnel_send_failed, R}` | CONNECT-TCP: a write to the client failed or stayed blocked for 30 s |
| `{handler_crash, R}` | a handler callback raised. In `init/2` this fails the handshake (502). In later callbacks only udp-bind sessions stop; the other sessions log the crash and keep running. |
| `{bad_init, Other}` | `init/2` returned an unexpected shape; the handshake fails (502) |
| handler reasons | whatever the handler returned in `{stop, Reason, _}`; see the built-in list below |

What goes on the wire:

- `normal`: FIN on every protocol.
- `peer_reset`, `peer_closed`, `connection_closed`, `router_gone`: nothing more; the stream or connection is already gone.
- Any other reason depends on the session: CONNECT-UDP resets the stream (`H3_MESSAGE_ERROR` on h3, `PROTOCOL_ERROR` on h2); CONNECT-TCP sends FIN for `target_closed` and `eof_timeout` and resets with `H3_CONNECT_ERROR` / `CONNECT_ERROR` otherwise; CONNECT-IP sends FIN; udp-bind resets with `H3_INTERNAL_ERROR` / `INTERNAL_ERROR`. On h1 the session closes the TLS connection.

Reasons used by the built-in handlers:

| Handler | Reasons |
| --- | --- |
| `masque_udp_proxy_handler` | `{resolution_failed, private_address}`, `{resolution_failed, {resolve, R}}`, `{resolution_failed, {connect, R}}`, `{resolution_failed, {udp_open, R}}` (from `init/2`); `{target_socket_lost, R}`, `{target_socket_error, R}`, `target_socket_closed` |
| `masque_tcp_proxy_handler` | `{resolution_failed, private_address}`, `{resolution_failed, {resolve, R}}`, `{resolution_failed, {tcp_connect, R}}` (from `init/2`); `target_closed`, `{target_error, R}`, `eof_timeout` (a half-closed tunnel idle for 30 s) |
| `masque_udp_bind_proxy_handler` | `{udp_open, R}` (from `init/2`); `{bind_socket_error, R}`, `bind_socket_closed` |
| `masque_chain_handler` | `{resolution_failed, {upstream, R}}` or `{reject, loop_detected}` (from `init/2`); `upstream_closed` |

## Internal messages

These are exchanged between masque's own processes. You do not send or match them in application code, but you will see them in traces and in `sys:get_state/1` output. Open question: they are not documented as stable; treat them as internal and liable to change between versions.

### h3 router and server sessions

The router (`masque_server_connection`) owns the h3 connection and forwards per-stream events to the session registered for the stream, or buffers them (up to 100 per stream) while the session is starting.

| Message | Direction | Meaning |
| --- | --- | --- |
| `{masque_datagram_in, StreamId, Payload}` | router to session | an HTTP datagram for the stream |
| `{masque_stream_data, StreamId, Data, Fin}` | router to session | stream bytes that arrived before the session claimed the stream |
| `{masque_stream_reset, StreamId, Code}` | router to session | the client reset the stream |
| cast `{finalize, Router}` | router to session | send the 2xx, claim the stream, run init actions |
| `{masque_finalized, StreamId, Pid, ok \| {error, stream_dead}}` | session to router | finalize result; on `ok` the router replays the buffer |
| cast `connection_closed` | router to session | the connection is gone; stop |
| `{session_init_done, StreamId, Result}` | init worker to router | result of `gen_server:start/3` for the session |
| calls `{start_session, Args}`, `{cancel_pending, StreamId}`, `{register, ...}`, `{lookup, StreamId}`; cast `{unregister, StreamId}` | listener or session to router | registry operations |

After the claim, the session receives `{quic_h3, Conn, {data, ...}}` and `{quic_h3, Conn, {stream_reset, ...}}` directly from `quic_h3`.

`masque_ip:inject_packet/2` casts `{inject_packet, Packet}` to a CONNECT-IP server session.

### Racer and attempt workers

The racer receives on an alias that it drops before returning, so none of these reach your mailbox afterwards.

| Message | Direction | Meaning |
| --- | --- | --- |
| `{Alias, {attempt_ready, Worker, Transport, Sess}}` | worker to racer | the attempt's handshake succeeded |
| `{Alias, {attempt_failed, Worker, Transport, Reason}}` | worker to racer | the attempt failed |
| `{Alias, start_next_attempt}` | timer to racer | head start elapsed; start the next transport |
| `{Alias, win}` / `{Alias, lose}` | racer to worker | keep the session, or stop it |
| call `handshake_await` | worker to session | wait for the 2xx; replies `ok` or `{error, Reason}` |
| call `{set_owner, Pid}` | racer to session | hand the session to the real owner and flush held messages |

### Pool and upstream owners

| Message | Direction | Meaning |
| --- | --- | --- |
| call `{checkout, Fingerprint, Opts}` | client to `masque_upstream_pool` | get an owner with spare capacity, or wait for a dial |
| `{dial_result, Fingerprint, {ok, Owner} \| {error, R}}` | upstream owner to pool | the owner's own dial finished |
| `{owner_capacity, Owner, Full}` | upstream owner to pool | the owner reached or left its stream limit |
| call `{acquire, Headers, SessionPid, ReqOpts}` | session to upstream owner | open a stream on the pooled connection |
| cast `{release, StreamId}` | session to upstream owner | give the stream back |
| `{timeout, Ref, idle}` | timer to upstream owner | no streams for `idle_timeout_ms` (default 30000); close and stop |

The upstream owner forwards h3 datagrams, responses, resets, connection close and h3 GOAWAY to the sessions on its connection as the original `{quic_h3, ...}` / `{h2, ...}` messages.

### Client session calls

The facade talks to client sessions with `gen_statem` calls: `handshake_await`, `stop`, `info`, `{send, Data}`, `{send, Ctx, Data}`, `{recv, Timeout}`, `{set_mode, Mode}`, `shutdown_write`, `{send_capsule, Type, Value}`, `{set_owner, Pid}`, plus the protocol-specific ones (`ip_info`, `{send_ip_packet, _}`, `{request_addresses, _}`, `{assign_addresses, _}`, `{advertise_routes, _}` for CONNECT-IP; the udp-bind session modules export their own functions).

Next: [conformance](conformance.md) for how these behaviours map to the specs, or [debugging](../3-change/debugging.md) to act on a reason.
