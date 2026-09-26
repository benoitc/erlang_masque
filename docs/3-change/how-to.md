# How to change masque

This page connects common intents to code locations. Each guide names the files you touch, the tests you add, and the contract you must not break. Use it when you know what you want to change but not where. It assumes you have read [architecture](../1-understand/architecture.md); for a module you do not recognise, look it up in [code-map](code-map.md).

A pattern you will meet in almost every guide: session logic is duplicated per protocol and transport. There are nine server session modules and nine client session modules, each with its own copy of handler dispatch, action interpretation and teardown. A change to one behaviour usually means the same edit in several of them. The lists below name every copy so you do not miss one.

Server session modules: `masque_server_session` (UDP, h3), `masque_h2_server_session` (UDP, h2), `masque_h1_server_session` (UDP, h1), `masque_tcp_server_session` (TCP, h2 and h3), `masque_tcp_h1_server_session`, `masque_ip_server_session` (IP, h2 and h3), `masque_ip_h1_server_session`, `masque_udp_bind_server_session` (udp-bind, h2 and h3), `masque_udp_bind_h1_server_session`.

Client session modules: `masque_client_session` (UDP, h3), `masque_h2_client_session` (UDP, h2), `masque_h1_client_session` (UDP, h1), `masque_tcp_client_session` (TCP, h2 and h3), `masque_tcp_h1_client_session`, `masque_ip_client_session` (IP, h2 and h3), `masque_ip_h1_client_session`, `masque_udp_bind_client_session` (udp-bind, h2 and h3), `masque_udp_bind_h1_client_session`.

## If you want to add a handler

What it is: a module implementing the `masque_handler` behaviour, selected per protocol by the listener options `handler`, `tcp_handler`, `ip_handler` and `bind_handler`.

1. Implement the callbacks you need; all are optional. `accept/1` runs in the listener before any session exists; `init/2` runs in the session before the 2xx.
2. Start from the built-in handler closest to your case: `masque_udp_proxy_handler`, `masque_tcp_proxy_handler`, `masque_ip_proxy_handler`, `masque_udp_bind_proxy_handler`, or `masque_chain_handler`.
3. Test it end to end: copy the listener setup from `masque_compliance_SUITE` or `masque_lifecycle_SUITE` and point `handler` at your module.

Contract: return shapes are `{ok, State}`, `{ok, State, Actions}`, `{stop, Reason, State}` (and `{stop, Reason}` from `init/2`). A `{stop, _}` from `init/2` becomes a reject before any 2xx; do not rely on output from a handler that stops in `init/2`. See [handlers](../2-use/handlers.md).

## If you want to add a handler action

What it is: a term a handler returns in its action list, interpreted by the session. There is no shared interpreter: each server session has its own `do_actions/2`.

1. Add a clause to `do_actions/2` in every server session module that should support the action. Existing actions per protocol:
   - UDP (`masque_server_session`, `masque_h2_server_session`, `masque_h1_server_session`): `{send, Data}`, `{send, Ctx, Data}`, `{send_capsule, Type, Value}`, `close_session`, `{close_session, Code, Msg}`.
   - TCP (`masque_tcp_server_session`, `masque_tcp_h1_server_session`): `{send_data, Bytes}`, `{send_data, Bytes, Fin}`, `close_session`.
   - IP (`masque_ip_server_session`, `masque_ip_h1_server_session`): `{send_ip_packet, Pkt}`, `{assign, Entries}`, `{advertise, Routes}`, `{request_addresses, Prefixes}`, `{icmp_error, {Kind, Spec, Invoking}}`, `{send_capsule, Type, Value}`, `{close, Reason}`, `close_session`.
   - udp-bind (`masque_udp_bind_server_session`, `masque_udp_bind_h1_server_session`): `{send_bind_packet, Peer, Bytes}`, `{compression_assign, _}`, `{compression_ack, Id}`, `{compression_close, Id}`, `{send_capsule, Type, Value}`, `close_session`.
2. On h3, actions returned by `init/2` are applied in `finalize` through `run_init_actions/2`, after the 2xx. Make sure your action is safe there.
3. Unknown actions are skipped by the last `do_actions/2` clause. Keep that clause.
4. Document the action in [handlers](../2-use/handlers.md) and add a CHANGELOG entry.

Tests: one end-to-end case per transport you support, with a fixture handler in `test/` that returns the action (see `masque_report_handler` for the style).

Contract: an action never writes to the stream before the 2xx. If you add an action that writes, it must go through the same path as the existing ones so the finalize hold still applies.

## If you want to add a tunnel protocol

What it is: a new `:protocol` value (or header-negotiated variant, as udp-bind is) with its own URI template, sessions and handler. Protocols are additive: add new modules, options and API functions, do not rename or change the UDP, TCP and IP surfaces.

1. Constants: add the `:protocol` token and default template to a header in `include/` (see `masque.hrl`, `masque_ip.hrl`, `masque_udp_bind.hrl`).
2. URI template: reuse `masque_uri` if the variables are `target_host` / `target_port`, or add a `masque_uri_*` module on top of `masque_uri_template` (see `masque_uri_ip`, `masque_uri_udp_bind`).
3. Listener dispatch, in all three listeners:
   - `masque_server`: `defaults/1`, `h3_handlers/1` (template, handler, option lifting into `handler_opts`), `validate/7`, handler selection in `dispatch_request_1/7`.
   - `masque_h2_server`: `defaults/1`, `build_dispatch/1`, `validate/7`, `dispatch_request_1/6`.
   - `masque_h1_server`: `defaults/1`, `build_dispatch/1`, `validate/5,6`, `dispatch_request_1/6`.
   - If targets need resolving before `accept/1`, extend `masque_ip:resolve_target/3`.
4. Server sessions: a module for h2/h3 (dispatch on a `transport` field, like `masque_ip_server_session`) and one for h1.
   - h3: add a clause to `session_module/1` in `masque_server_connection`.
   - h2: add `start_link_<proto>/0`, a `start_session/1` clause and an `init/1` clause to `masque_h2_session_sup`.
   - h1: the same in `masque_h1_session_sup`.
   - Add both supervisors as children in `init/1` in `masque_sup`.
5. Client sessions: the same split. Select them in both `session_mod/2` in `masque` and `transport_mod/2` in `masque_racer` (the table is duplicated).
6. Handler: a default `masque_<proto>_proxy_handler` and any new callbacks as optional callbacks in `masque_handler`.
7. Facade: new functions in `masque.erl` if `connect/3` and `send/2,3` are not enough (udp-bind added `bind_connect/3`, `send_to/3` and friends).

Tests: a codec EUnit module for any new wire format, a `masque_<proto>_compliance_SUITE`, per-transport suites, and lifecycle cases for the new sessions.

Contract: existing listeners must behave the same when the new protocol is not configured. udp-bind shows the pattern: off unless `accept_bind => true`, and the legacy path is unchanged when the negotiation header is absent. Update [conformance](../reference/conformance.md) and [messages-and-errors](../reference/messages-and-errors.md).

## If you want to add or change a transport behaviour

What it is: anything that depends on how `quic_h3`, `h2` or `h1` deliver events or accept calls: framing (datagrams on h3, DATAGRAM capsules on h2 and h1), stream claiming, GOAWAY, resets, half-close.

1. Read [transports](transports.md) first; it lists the messages and calls masque relies on from each dependency.
2. Change the transport-specific clauses in the session modules. Sessions that serve two transports keep them side by side in functions such as `transport_send_data/3`, `transport_cancel/1`, `transport_send_datagram/3`.
3. On h3, check whether the router (`masque_server_connection`) must route a new event; the router is the connection owner and sees everything not claimed by a session.

Tests: `masque_lifecycle_SUITE` for teardown and ordering, `masque_backpressure_SUITE` if you touch send paths, and the per-transport suites.

Contract: h1 cannot half-close (OTP `ssl` drops the connection on `close_notify`); a rejected h1 request closes the connection. Do not make h2 or h3 depend on either.

## If you want to add a capsule type

1. Codec: add encode/decode to the module for its protocol (`masque_ip_capsule`, `masque_compression_capsule`) or a new one, and the type code to the matching header in `include/`. The generic framing is `masque_capsule:encode/2` and `decode/1`, which wrap `quic_h3_capsule`.
2. Registry: add the type to `masque_capsule:known/1` and update `masque_capsule_tests` (its `other_types_are_unknown_test` lists codes that must stay unknown). Sessions do not consult `known/1` today; it documents the set the library implements.
3. Dispatch: add a clause in the sessions that should handle it. Server side: `dispatch_capsule/3` in `masque_ip_server_session`, `masque_ip_h1_server_session`, `masque_udp_bind_server_session`, `masque_udp_bind_h1_server_session` (UDP sessions pass capsules to the handler's `handle_capsule/3` from `drain_capsules/3` or `dispatch_capsule/3`). Client side: `drain_capsules` / `dispatch_capsule` in the matching client session.
4. Everything you do not handle must keep reaching the handler (`handle_capsule/3`) on the server and the owner (`{masque_capsule, Sess, Type, Value}`) on the client. RFC 9297 requires unknown capsules to be ignored, not rejected.

Tests: codec cases in the protocol's `_tests` module, a property in `prop_masque` if the codec is non-trivial, and an end-to-end case in the compliance suite.

## If you want to change connection or tunnel teardown

What it is: how a session ends and what it sends on the way out. Read the teardown section of [server-internals](server-internals.md) first.

Server side, per session module: `terminate/2` (the clauses decide FIN versus reset), `reset_and_stop/2`, and for TCP `end_stream/2`. The router's `terminate/2` in `masque_server_connection` casts `connection_closed` to its sessions. h2 sessions give their slot back with `release_tunnel/1` in `masque_h2_server`.

Client side, per session module: `end_tunnel/3` (queue-mode sessions park in `closed`), `session_teardown/1`, `client_stream_abort/2`, `terminate/3`, and the `closing` state. Pooled sessions release their stream with `release_stream/2` in `masque_upstream_owner` instead of closing the connection.

Tests: a case in `masque_lifecycle_SUITE` per transport, using the template in [testing](testing.md). Run `masque_client_rx_SUITE` if you touch the client path.

Contract:
- A clean end sends FIN; an error resets the stream (`H3_MESSAGE_ERROR` / `protocol_error` for capsule errors, `H3_CONNECT_ERROR` / `connect_error` for CONNECT-TCP).
- The handler's `terminate/2` is always called, and its exceptions are swallowed.
- An h3 session unregisters from its router; an h2 session releases its tunnel slot.
- Owner-visible close reasons are part of the API ([messages-and-errors](../reference/messages-and-errors.md)).

## If you want to change the client connect flow or racing

1. Facade: `masque:connect/3`, `validate_connect_opts/2`, `connect_via/4`, `dial_single_or_pool/5`, `dial_single/4`.
2. Racer: `race/4` in `masque_racer`, `spawn_attempt/5`, `transfer_owner/3`, `checkout_pool/2`.
3. Owner handoff: `masque_client_owner` (holds messages while `defer_owner => true`) and the `{set_owner, Pid}` clause in each client session.
4. Early dial failures: `masque_client_failed`.

Tests: `masque_racer_tests` with `masque_racer_fake_session` for scheduling, `masque_h1_race_SUITE`, `masque_client_errors_SUITE`, and the race cases in `masque_ip_h2_SUITE` and `masque_udp_bind_compliance_SUITE`.

Contract: a session module used by the racer exports `start/3` and `stop/1`, answers the `handshake_await` call with `ok` or `{error, Reason}`, and accepts `{set_owner, Pid}` in `connecting` and `open`. Dial failures return `{error, Reason}` and never exit the caller. No attempt message may reach the caller's mailbox after `race/4` returns (the racer receives through an alias it drops). See [client-internals](client-internals.md).

## If you want to add a metric or lifecycle event

1. New metrics use OTP `counters` with a read API, the way the drop counters do: a `setup_*_counters/0` that stores the reference in `persistent_term`, an `*_inc/1`, a `*_count/1` and a `*_reasons/0` list, all in `masque_metrics`. Call the setup from `masque_metrics:setup/0`. Existing `instrument_meter` instruments stay as they are.
2. Increment from the session or handler that observes the event.
3. Lifecycle events are emitted by `masque_ip_proxy_handler` through its private `invoke_lifecycle/4`; `emit_drop/2,3` is the exported helper for drops. Add the event there and list it in [operations](../2-use/operations.md).

Tests: read the counter before and after in an EUnit or CT case (`masque_ip_proxy_handler_tests` shows the pattern).

Contract: an `*_inc` call must be a no-op when setup has not run, and a `*_count` call must return 0, so tests without the application keep working.

## If you want to bump quic, h2 or h1

1. Change the version in `rebar.config` and run `rebar3 upgrade <dep>` so `rebar.lock` follows.
2. Re-check the contracts listed in [transports](transports.md): the event messages each session matches on (`{quic_h3, Conn, ...}`, `{h2, Conn, ...}`), and the calls it makes (`quic_h3:set_stream_handler/4` with `drain_buffer => false`, `quic_h3:max_datagram_size/2`, `h2:send_data/5` with `block`, `h1:upgrade/4`, `h1:accept_upgrade/3`, `h1:accept_connect/3`).
3. Remove `-dialyzer({nowarn_function, ...})` entries that the new version makes unnecessary (several client sessions carry one for `quic_h3:connect_opts()`).
4. Run every check in [CONTRIBUTING](../../CONTRIBUTING.md), with `rebar3 ct` run twice: `masque_lifecycle_SUITE`, `masque_compliance_SUITE`, `masque_client_errors_SUITE` and `masque_backpressure_SUITE` are the ones that catch behaviour changes in a dependency.
5. Record the bump in the CHANGELOG `Changed` section, as earlier bumps are.

## If you want to debug a tunnel end to end

See [debugging](debugging.md).

## If you want to extend the public API

1. Add the function to `masque.erl` with a `-spec` and a `-doc`. Export new types with `-export_type`.
2. If the call goes to a session, add the matching `handle` clause in every session module that must support it, and a reply in the `failed` and `closed` states (both are shared: `handle/4` in `masque_client_failed`, `closed/5` in `masque_client_rx`).
3. New owner messages or error reasons go in [messages-and-errors](../reference/messages-and-errors.md).
4. Add a CHANGELOG entry under `Added`.

Tests: `masque_facade_tests` for option validation, plus a CT case exercising the call.

Contract: only `masque` and the handler behaviour are meant to be stable; the other modules are described as internal in `masque.erl`. Keep new public entry points in the facade.

## If you want to write a lifecycle regression test

See the template in [testing](testing.md#writing-a-lifecycle-regression-test).

Next: [testing](testing.md) for the tests each guide asks for, or [decisions](decisions.md) for why the code is shaped this way.
