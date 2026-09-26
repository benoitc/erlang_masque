# Decisions

This page records design decisions that are visible in the code, with the reason the code, commit history or earlier docs give for each, and the questions nobody has answered yet. Read it before you change a boundary described here, so you know what the current shape protects. Each entry says what was decided, why, what follows from it, and where it lives. When a reason is not written down anywhere, the entry says so instead of guessing; those cases also appear under [Open questions](#open-questions). Add an entry when you make a decision a later contributor would otherwise have to reverse-engineer.

## Server

### Handler init runs before the 2xx

- **Decision.** The server session runs the handler's `init/2` to completion before any 2xx (or 101/200 on h1) is sent.
- **Why.** RFC 9298 section 3: a 2xx means the proxy is ready to forward, and the built-in handlers open the target socket in `init/2` (comment in `masque_server_session:init/1`). On h1, running `init/2` first also lets a rejection "surface as a clean 502 on the as-yet-unupgraded h1 connection" (comment in `masque_h1_server_session:init/1`).
- **Consequences.** A slow `init/2` delays the response. On h3 it forces the finalize step and the early queue below. A handler cannot write to the tunnel from `init/2` directly; it returns init actions, run after the 2xx.
- **Where.** `init/1` of every server session; [server internals](server-internals.md#the-shared-pipeline).

### One router per h3 connection

- **Decision.** Each accepted h3 connection gets a `masque_server_connection` process that is the `quic_h3` connection owner and routes datagrams to sessions by stream id.
- **Why.** `quic_h3` delivers HTTP datagrams to the connection owner, not to the stream handler (`masque_server:h3_handlers/1` doc, router moduledoc).
- **Consequences.** MASQUE cannot share an h3 connection with another extension that needs the owner slot. All datagrams of a connection pass through one process. The per-connection tunnel limit lives in the router. h2 and h1 have no equivalent process.
- **Where.** `masque_server_connection`, `masque_server:h3_handlers/1`.

### Asynchronous session start and finalize on h3

- **Decision.** The router starts each session from a spawned worker and finalizes it with a cast, buffering the stream's messages meanwhile.
- **Why.** So the router "stays responsive for datagram routing" during handler init, and "a slow `send_response` does not stall datagram routing" (router comments).
- **Consequences.** A two-stage pending state per stream, a 100-message buffer that drops beyond its cap, `cancel_pending/2` for the 30 s timeout.
- **Where.** `masque_server_connection:handle_call({start_session, _}, ...)` and `handle_info({masque_finalized, ...})`.

### Early handler output is held until the 2xx

- **Decision.** Messages a session's handler would act on before finalize are queued and replayed after the 2xx and the init actions.
- **Why.** "Nothing may be written to the stream before the 2xx" (session comments). Added by commits 7c1ee56 and 91e0f43.
- **Consequences.** The queue is bounded only by the target socket's `{active, N}` window.
- **Where.** The `early` field and `replay_early/2` in the h3-capable server sessions.

### A handler crash ends the tunnel

- **Decision.** When a handler callback raises after `init/2`, the session logs it and stops with `{handler_crash, Reason}`. On h3 and h2 the stream is reset, on h1 the socket is closed, and `terminate/2` runs.
- **Why.** Settled by the maintainer (former Q13). Continuing with the handler state from before the crash can leave the handler's sockets and its state out of step, and a reset tells the client the tunnel failed rather than ended.
- **Where.** `dispatch/3` and `safe_apply/3` in every server session.

### h2 and h1 sessions live under per-protocol supervisors

- **Decision.** One `simple_one_for_one` supervisor per protocol and transport under `masque_sup`, children `temporary`.
- **Why.** Introduced with "per-protocol session supervisors" in the scaling commit c27577c; no further reason is recorded.
- **Consequences.** A crashed tunnel is never restarted. h3 sessions are not supervised (Q4).
- **Where.** `masque_h2_session_sup`, `masque_h1_session_sup`, `masque_sup`.

### Rejections carry Proxy-Status

- **Decision.** Every listener reject adds `proxy-status: masque; error=...` and a short text body.
- **Why.** "RFC 9209 structured field - gives clients a machine-readable tag for the failure beyond the numeric status (RFC 9298 section 3 recommendation)" (comment in `reject/4` in `masque_server`).
- **Where.** `reject/4` and `proxy_status_error/1` in the three listeners, `masque_errors`.

### A rejected h1 request closes the connection

- **Decision.** h1 rejects add `connection: close` and close the connection.
- **Why.** RFC 9931: otherwise "the client may treat subsequent bytes on the wire as belonging to the rejected resource" (comment in `reject/4` in `masque_h1_server`).
- **Where.** `reject/4` in `masque_h1_server`.

### CONNECT-TCP over h1 cannot half-close

- **Decision.** A FIN in either direction ends an h1 CONNECT-TCP tunnel.
- **Why.** "OTP `ssl` drops the connection on the peer's close_notify, so a TLS tunnel cannot half-close" (comment in `masque_tcp_h1_server_session`, CHANGELOG).
- **Where.** `masque_tcp_h1_server_session`, `masque_tcp_h1_client_session`.

### Tunnel writes block instead of dropping (CONNECT-TCP)

- **Decision.** A CONNECT-TCP tunnel write waits for the transport (up to 30 s) and a failure stops the session.
- **Why.** Handlers "rely on every earlier write having succeeded", for example the TCP proxy's `{active, N}` re-arm (comment in `do_actions/2` in `masque_tcp_server_session`).
- **Consequences.** A slow client stalls the session process, and through it the target reads.
- **Where.** `tunnel_send/3` in `masque_tcp_server_session`, `proxy_send/2` in `masque_tcp_h1_server_session`.

### Proxy sockets read in `{active, N}`

- **Decision.** Built-in handlers open target and bind sockets with `{active, N}` and re-arm on the passive message.
- **Why.** The passive message arrives after the N data messages, so "every datagram delivered before this message has been relayed" (handler comments). Added in commit 3f68409.
- **Where.** `masque_udp_proxy_handler`, `masque_tcp_proxy_handler`, `masque_udp_bind_proxy_handler`.

### Draining is a listener flag

- **Decision.** `masque:drain_listener/1` sets a persistent term that makes the listener reject new requests with 503. Existing tunnels continue; no GOAWAY is sent.
- **Why.** Not recorded (Q14).
- **Where.** `masque:drain_listener/1`, `is_draining/1`, the `dispatch_request/6,7` of each listener.

## Client

### Client sessions start unlinked and are monitored

- **Decision.** `dial_single/4` uses `Mod:start/3` plus a monitor, not `start_link`.
- **Why.** "So a fast session failure returns `{error, _}` instead of crashing the caller with an EXIT" (comment in `masque.erl`; commit 878e907).
- **Consequences.** A client session is linked to nothing; it monitors its application owner and stops when the owner exits.
- **Where.** `dial_single/4` in `masque`.

### Dial errors are parked in a `failed` state

- **Decision.** A session that fails to dial enters `failed` instead of exiting.
- **Why.** The dial runs before the caller's `handshake_await` is processed; exiting "would turn the caller's `gen_statem:call` into an exit" (`masque_client_failed` moduledoc).
- **Where.** `masque_client_failed`, `connecting/3` in each client session.

### The racer runs in the caller and hands the winner over

- **Decision.** The race loop runs in the caller's process and receives on an alias; workers own the attempts; sessions hold owner messages until `set_owner`.
- **Why.** So "late attempt reports never reach the caller's mailbox" and events produced before `set_owner` reach the real owner in order (racer and `masque_client_owner` moduledocs; commit 5251ab4, "make the transport racer leak-free and lossless").
- **Consequences.** Every client session supports `defer_owner`, `set_owner` and the process-dictionary hold queue.
- **Where.** `masque_racer`, `masque_client_owner`.

### Queue mode is bounded

- **Decision.** `rx_queue_limit` (default 1000) bounds queue mode; datagram tunnels drop past it, CONNECT-TCP ends with `rx_overflow`.
- **Why.** For TCP, "dropping bytes would corrupt the stream, so reset the tunnel" (comment in `rx_overflow/1` in `masque_tcp_client_session`). Commit 8f072f9.
- **Where.** `masque_client_rx`.

### Clients verify proxy certificates by default

- **Decision.** Every client transport uses `verify_peer` with the system CA store, hostname check and SNI unless told otherwise.
- **Why.** Recorded as a security change in the CHANGELOG (commit dd79294).
- **Consequences.** Self-signed setups need `verify => verify_none` or `cacerts`.
- **Where.** `masque_tls`, the dial code of each client session.

## Pool, relay and protocols

### The upstream pool is opt-in, h2/h3 only, keyed by fingerprint

- **Decision.** Pooling needs `upstream_pool => true`; h1 is never pooled; connections are shared only between callers with the same host, port, transport and connection-affecting options.
- **Why.** "Two callers with different trust or ALPN settings get different owners"; h1 is one tunnel per socket (pool and owner moduledocs).
- **Where.** `masque_upstream_pool`, `masque_racer:checkout_pool/2`.

### The pool registry never blocks on a handshake

- **Decision.** Each upstream owner dials in its own process; the registry only records waiters.
- **Why.** "A slow upstream only stalls callers on its own key"; dialing in the owner means the connection is owned by it from the start, which matters because `quic_h3` exposes no `controlling_process/2` equivalent (pool and owner moduledocs).
- **Where.** `masque_upstream_pool:handle_call({checkout, ...})`, `masque_upstream_owner:start_for_pool/3`.

### Relay loops are detected with a per-listener via token

- **Decision.** Chain handlers add a `via` entry with a random per-listener token and reject a request that already carries their token with 508.
- **Why.** "So a chain that points back at itself fails instead of recursing, while two chain listeners on the same node can still be chained together" (`masque_chain_handler` moduledoc; commit ccf8794).
- **Where.** `masque_chain_handler:accept/1`, `chain_all/1` in `masque`.

### Non-public targets are refused by default

- **Decision.** Private and reserved destinations are refused unless `allow_private` (and `allow_loopback` for udp-bind peers) is set.
- **Why.** Recorded as security changes, marked breaking, in the CHANGELOG.
- **Where.** `masque_ip:is_public/1`, `accept/1` and `init/2` of the built-in handlers, the udp-bind peer filter.

### Compression contexts are opened by the application

- **Decision.** The library never opens udp-bind compression contexts by itself; it exposes primitives and owner messages.
- **Why.** "The right policy depends on the consumer's traffic shape; baking a single one in would be wrong for at least half the use cases" (former `docs/design.md`, section "Decision: auto-compression lives outside the library").
- **Where.** `masque:assign_compression/2`, `open_uncompressed_context/1`, `close_compression/2`.

### The address registry is read without its server

- **Decision.** CONNECT-IP lookups read the public ETS table directly; the server handles writes only, and writes are no-ops when the registry is not running.
- **Why.** So "read traffic does not serialise on the server", and so test environments without the application and the proxy handler need no extra setup (registry moduledoc).
- **Where.** `masque_ip_session_registry`.

### Two metric surfaces

- **Decision.** Tunnel metrics use `instrument_meter`; the CONNECT-IP and udp-bind drop, assign and release metrics use OTP `counters`.
- **Why.** `instrument_meter` for OpenTelemetry compatibility; `counters` as "a lightweight surface for downstream consumers ... with no dependency on a meter system being initialised" (former `docs/design.md`, section "Metrics").
- **Where.** `masque_metrics`.

### Unknown capsules and datagram contexts are dropped silently

- **Decision.** Unknown capsule types go to `handle_capsule/3` if exported, else are ignored; unknown context ids and oversize UDP payloads are dropped.
- **Why.** RFC 9297 section 3.3 and RFC 9298 section 5 (comments in `masque_capsule` and the sessions).
- **Where.** `masque_capsule:known/1`, `dispatch_capsule/3` and the datagram paths of every session.

## Open questions

Questions Q1 to Q12 come from the documentation plan; the rest were found while writing the internals pages. None of them has an answer in the repository.

- **Q1.** Should module docs move to `-moduledoc` / `-doc` so internal modules can be hidden from hexdocs? This touches source doc attributes only.
- **Q2.** Is every module except `masque`, the handlers and the codecs meant to be internal? `masque.erl` says so, but the docs publish everything.
- **Q3.** Is the router needed only because `quic_h3` delivers datagrams to the connection owner, or is there another reason h2 and h1 sessions sit under supervisors while h3 has a router?
- **Q4.** Why are h3 server sessions unsupervised (started by the router with `gen_server:start/3`, then linked and monitored)?
- **Q5.** All h2 sessions send the 2xx from their own `init/1`, and the h2 UDP session is the only one in a separate module without a `transport` field or metrics. Is that separation intended?
- **Q6.** Should idle timeouts exist only on h1 sessions?
- **Q7.** Settled: `masque.tunnels.*` covers every protocol and transport; each server session reports one open and one close.
- **Q8.** How stable are internal message shapes (`masque_datagram_in`, `masque_finalized`, `dial_result`, `owner_capacity`)?
- **Q9.** Versioning: the 0.6.0 CHANGELOG entry and the v0.5/v0.6 tags are missing; is hex publishing planned?
- **Q10.** Which connect-tcp draft revision is targeted?
- **Q11.** Should `upstream_pool => true` apply to udp-bind? Today the checkout happens (and may dial) but the session ignores the owner and dials its own connection.
- **Q12.** Is `masque_capsule` meant to become the single capsule codec? Today `quic_h3_capsule` (through `masque_capsule`), `h2_capsule` and `h1_capsule` are all used.
- **Q13.** Settled: [a handler crash ends the tunnel](#a-handler-crash-ends-the-tunnel).
- **Q14.** Should draining send GOAWAY, and should the server react to a client GOAWAY? Today it does neither.
- **Q15.** Settled as a defect: a peer reset of a pending h3 stream now answers the listener with `stream_dead` (see [server internals](server-internals.md)).
- **Q16.** In a scoped udp-bind, context 0 goes to `handle_packet/2`, which the default bind handler does not export, so that traffic is dropped. Intended?
- **Q17.** Settled: the h1 udp-bind server session enforces the same rules as the h3/h2 one (see [udp-bind internals](udp-bind-internals.md#the-h1-session)).
- **Q18.** h3 pooled owners default to `dynamic` capacity and never report full, so the pool never opens a second h3 connection per fingerprint unless `max_streams` is set. Intended?
- **Q19.** The `masque_ip_proxy_handler` moduledoc says the allocator is round-robin; the code is first-fit. Which is intended?
- **Q20.** h1 idle timers are re-armed by inbound bytes only, so a tunnel that only sends toward the client idles out. Should outbound traffic count?
- **Q21.** `dial_single_or_pool/5` waits for the pool checkout up to `checkout_timeout_ms` (60 s), regardless of the connect `timeout`. Intended?
- **Q22.** The chain listeners set `handler`, `tcp_handler` and `ip_handler` to `masque_chain_handler` but not `bind_handler`, so udp-bind is not chained. Intended?
- **Q23.** Are the listener gaps intended: h1 has no `fallback`, no `peer` / `peer_cert` and no tunnel limit; h2 has no `peer` / `peer_cert`? (Option lifting into `handler_opts` is now the same on all three.)
- **Q24.** The udp-bind proxy sends only on its own compressed contexts (or the client's uncompressed one) and reads client datagrams only on client-opened contexts, while the client session treats every installed context as two-way. Which reading of the draft is intended?
- **Q25.** Error stops end the stream differently per protocol: UDP resets with `H3_MESSAGE_ERROR`, TCP with `H3_CONNECT_ERROR`, udp-bind with `H3_INTERNAL_ERROR`, IP with a FIN. Intended?
- **Q26.** The h1 IP session has no limit on pending ADDRESS_REQUEST ids (h3/h2 cap it at 64). Intended?
- **Q27.** Settled: in `connecting` a call answers `{error, not_ready}` except `info` and `stop`; in `open` an unsupported call answers `{error, not_supported}`; in `closing`, `{error, closing}`.

Next: [releasing](releasing.md).
