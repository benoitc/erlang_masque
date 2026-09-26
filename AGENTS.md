# Agents

Instructions for AI coding agents working on this project.

## Project Overview

`masque` is an Erlang implementation of the MASQUE family: CONNECT-UDP
(RFC 9298), CONNECT-IP (RFC 9484), and the draft-ietf-httpbis-connect-tcp
variant, carried over HTTP/3, HTTP/2, and HTTP/1.1. It is built on
[`erlang_quic`](https://github.com/benoitc/erlang_quic) (`quic_h3`),
[`erlang_h2`](https://github.com/benoitc/erlang_h2), and
[`erlang_h1`](https://github.com/benoitc/erlang_h1). Requires Erlang/OTP 29
and rebar3.

## Required Checks

Every change must be formatted and pass all checks before committing:

```bash
rebar3 fmt                  # Auto-format (always run first)
rebar3 compile              # Must compile cleanly (warnings are errors)
rebar3 xref                 # Cross-reference analysis must pass
rebar3 eunit                # Unit tests must pass
rebar3 ct                   # Common Test suites must pass
rebar3 lint                 # Elvis linter must pass
rebar3 dialyzer             # Type checking must pass
```

## Build & Development Commands

```bash
rebar3 compile                                       # Build
rebar3 eunit                                         # Run all EUnit tests
rebar3 eunit --module=masque_uri_tests               # Run specific test module
rebar3 ct                                            # Run all Common Test suites
rebar3 ct --suite test/masque_compliance_SUITE       # Run one CT suite
rebar3 lint                                          # Elvis linter
rebar3 fmt --check                                   # Check formatting (erlfmt)
rebar3 fmt                                           # Auto-format code
rebar3 dialyzer                                      # Type checking
rebar3 xref                                          # Cross-reference analysis
rebar3 ex_doc                                        # Generate docs
```

`rebar3 ct` runs every suite. The interop suite (`masque_interop_SUITE`)
self-skips unless `MASQUE_GO_BIN` points at an external MASQUE binary.

## Architecture

### Module Layers

**Public API:** `masque.erl` (the facade: `connect/2,3`, `send/2,3`, `recv/2`,
`close/1`, `info/1`, and the `start_listener*` / `stop_listener*` family for
h3 / h2 / h1).

**Server transports:** `masque_server.erl` (HTTP/3 via `quic_h3`),
`masque_h2_server.erl` (HTTP/2 Extended CONNECT), `masque_h1_server.erl`
(HTTP/1.1 Upgrade and classic CONNECT). Per-stream server state lives in
`masque_server_session.erl`, `masque_h2_server_session.erl`,
`masque_h1_server_session.erl`, and the protocol-specific `*_server_session`
modules; supervised by the `masque_*_session_sup` modules under `masque_sup`.

**Client sessions:** `masque_client_session.erl` and the transport / protocol
variants (`masque_h2_client_session`, `masque_h1_client_session`,
`masque_tcp_client_session`, `masque_ip_client_session`,
`masque_udp_bind_client_session`, and their `*_h1_*` forms).

**Handlers (pluggable):** `masque_handler.erl` is the behaviour (all callbacks
optional: `accept/1`, `init/2`, `handle_packet/2`, `handle_data/2`,
`handle_capsule/3`, `handle_info/2`, `handle_eof/1`, `terminate/2`). Built-in
handlers: `masque_udp_proxy_handler`, `masque_tcp_proxy_handler`,
`masque_ip_proxy_handler`, `masque_udp_bind_proxy_handler`, and
`masque_chain_handler` (relay chaining).

**Codecs:** `masque_datagram` (RFC 9298 context-id framing), `masque_capsule`
(RFC 9297 capsules), `masque_ip_capsule`, `masque_ip_packet`, `masque_icmp`,
`masque_compression_capsule`, `masque_compression_table`,
`masque_udp_bind_payload`.

**URI templates:** `masque_uri`, `masque_uri_template`, `masque_uri_ip`,
`masque_uri_udp_bind`.

**Support:** `masque_racer` (Apple-style h3/h2/h1 transport racing),
`masque_upstream_pool` and `masque_upstream_owner` (upstream connection
pooling), `masque_errors` (status mapping), `masque_metrics`, `masque_tls`,
`masque_ip_session_registry`, `masque_sup`, `masque_app`.

### Supervision Tree

`masque_app` -> `masque_sup` (one_for_one). Listeners and client sessions
attach dynamically; the `masque_h2_session_sup` / `masque_h1_session_sup`
families supervise per-protocol session processes (udp, tcp, ip, udp-bind).

### Key Files

- `include/masque.hrl` - CONNECT-UDP/TCP constants, default URI templates,
  capsule and error-status macros.
- `include/masque_ip.hrl` - CONNECT-IP constants and capsule types (RFC 9484).
- `docs/design.md` - architecture and transport-racing design.
- `docs/features.md` - feature matrix and RFC coverage.
- `docs/api.md` - API reference.

### Session Model

The owner process drives a session through `masque.erl` and receives messages
such as `{masque_data, Sess, Data}` for tunnelled bytes. Server handlers are
invoked per stream; `accept/1` gates the handshake (returning a non-2xx
rejects it) and the `handle_*` callbacks process the tunnel.

## Linting & Formatting Notes

- Formatting is `erlfmt` (`rebar3 fmt`); config is the `{erlfmt, ...}` block in
  `rebar.config`. CI gates on `rebar3 fmt --check`.
- Elvis rules live in `elvis.config` (only `src/**` is linted). Relaxed for the
  initial adoption: `dont_repeat_yourself`, `no_invalid_dynamic_calls` (the
  pluggable handler dispatch is `HandlerMod:Callback(...)`), `no_throw` (the
  capsule and URI parsers use throw for control flow), `no_if_expression`,
  `guard_operators`, `no_deep_nesting`, `no_boolean_in_comparison`, and
  `no_single_clause_case` are disabled. Per-module ignores: `private_data_types`
  (`masque`, `masque_ip_capsule`), `export_used_types`
  (`masque_udp_bind_proxy_handler`), `no_receive_without_timeout`
  (`masque_racer`), `no_god_modules` (`masque`).
- Atom naming regex: `^[a-z](_?[a-zA-Z0-9]+)*(_SUITE)?$`.
