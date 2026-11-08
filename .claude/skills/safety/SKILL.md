---
name: safety
description: Review a masque change for safety - abuse of the proxy, unbounded resources, failure handling, noisy logs - and prove it under load, packet loss and network changes. Use before every pull request that touches sessions, listeners, handlers, transports or dependencies, before a release, and when someone asks whether something is safe.
---

# Safety

masque is a proxy: anyone who reaches a listener sends it bytes, and every session holds sockets, buffers and processes. Problems here rarely show in functional tests. A log flood of one error report per finished tunnel lived through every test until a load run of 2,000 tunnels showed it; quic migration bugs only showed on simulated networks. This skill is the checklist and the runs.

## Review the change

Read the diff and answer each question with `file:line` evidence, not assumption.

**Who may use it**
- Is the new path off by default (`accept_*` style)? Does anything open a tunnel, a listener or a control channel without authentication or policy (`accept/1`, `authenticate/1`, `allow`, `allow_private`, `allow_self`)?
- Can a client reach targets it should not (private ranges, loopback, the proxy itself, a host name resolving to either)? Policy must apply to resolved addresses, every address when racing.
- Are ids and tokens unpredictable where the spec asks (reverse connect request ids)? Can one client act on another's id, stream or session?

**What a peer can make it hold**
- Every buffer, queue, map and ETS table: what bounds it, and what happens at the bound (`max_capsule_size`, `rx_queue_limit`, router backlog, pending requests, `masque_tcp_upgrade_proxies`)?
- Credit: is it returned only after the bytes went onward (`hold_credit`, `consumed/2`)? A sender must stall, not fill memory.
- Writes: does a blocked write time out (`masque_stream_send`, `masque_tls:bound_sends/2`) instead of blocking forever?
- Timers: idle, handshake, half-close; does every state end?

**How it fails**
- Does every exit path close sockets, release h2 tunnel slots, unregister from the h3 router, remove registry rows, and tell the owner?
- Crashes: handler exceptions caught and reported once; an ordinary end exits quietly (`masque_quiet`), so a peer cannot flood the logs. New session modules must wrap their callbacks the same way.
- Errors to the peer: right status and Proxy-Status, no internal details in bodies; on h1 the connection closes after a rejection.

**Input handling**
- Headers and paths: CR/LF and spaces refused before they reach a request line; h1 parsing stays in `h1_parse` (smuggling).
- Capsules and datagrams: lengths checked before allocation, unknown types skipped, malformed ones abort the stream.

**Dependencies and code**
- No new dependency without the maintainer's approval; never an unreviewed personal fork (declined by the maintainer). Pin releases in `rebar.config`.
- TLS: clients verify certificates by default; nothing turns `verify_none` on outside tests and examples.
- No secrets in code, tests, logs or docs.

## Prove it

Run these and report the numbers, not only pass or fail:

1. The required checks in `AGENTS.md` (fmt, xref, eunit, proper, lint, dialyzer, ct).
2. Load and soak: `MASQUE_LOAD=1 rebar3 ct --suite test/masque_load_SUITE` and `--suite test/masque_soak_SUITE` (leaks across rounds, killed owners, abrupt peers, idle CPU). Every case fails if anything logs an error report; record tunnels per second, datagram loss, router drops, processes and ports before and after. Add a case when the change adds a new kind of session.
3. Networks: `test/netsim/run-docker.sh` (Linux namespaces: Wi-Fi and mobile, NAT expiry, reordering, small MTU, outages). Twice before a pull request.
4. Repetition: five full `rebar3 ct` runs before a pull request; one flaky failure is a bug to find, not to retry away.
5. A case in `masque_lifecycle_SUITE` for any change to session start or teardown, and leak checks in every new suite.

## Report

List what was reviewed, every finding with severity (exploitable, resource exhaustion, failure handling, hygiene) and its fix or reason to accept it, and the run results. If something cannot be tested here (real hardware network changes, interop with absent peers), say so plainly.
