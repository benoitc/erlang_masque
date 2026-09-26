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

Do not rely on a summary here; read the maintained docs before changing code:

- `docs/1-understand/architecture.md` - layers, processes, supervision, global state.
- `docs/3-change/code-map.md` - every module by role, with "change this when".
- `docs/3-change/server-internals.md` and `client-internals.md` - request and
  connect flows, session anatomy, teardown.
- `docs/3-change/transports.md` - h3/h2/h1 differences and the quic_h3, h2, h1
  message contracts the code depends on (re-check them on dependency bumps).
- `docs/3-change/testing.md` - suite map, fixtures, known traps (dial
  `127.0.0.1`, not `localhost`).
- `docs/3-change/decisions.md` - recorded decisions and open questions; do not
  settle an open question in code without the maintainer.

When a change alters behaviour described in `docs/`, update the page in the
same change.

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
