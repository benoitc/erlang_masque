# Agents

Instructions for AI coding agents working on this project.

## Project Overview

`masque` is an Erlang implementation of the MASQUE family: CONNECT-UDP
(RFC 9298), CONNECT-IP (RFC 9484), Connect-UDP-Bind
(draft-ietf-masque-connect-udp-listen), and the
draft-ietf-httpbis-connect-tcp variant, carried over HTTP/3, HTTP/2, and
HTTP/1.1. It is built on
[`erlang_quic`](https://github.com/benoitc/erlang_quic) (`quic_h3`),
[`erlang_h2`](https://github.com/benoitc/erlang_h2), and
[`erlang_h1`](https://github.com/benoitc/erlang_h1). Requires Erlang/OTP 29,
rebar3, CMake (the `instrument` NIF) and `openssl` (test certificates).

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

CI also runs `rebar3 as test proper` and `rebar3 fmt --check`. If you touch
module or function docs, `rebar3 ex_doc` must finish without warnings.

## Working Rules

- New protocols and extensions are additive: new modules, API functions, URI
  templates and opt-in listener options. Existing UDP, TCP and IP surfaces keep
  their names and behaviour. If a spec forces a merge into an existing path,
  keep it to one narrow seam, leave the old path unchanged when the feature is
  off, and say so in the plan. Steps are in `docs/3-change/how-to.md`.
- New metrics use OTP `counters` with a read API or callback hooks, not new
  `instrument_meter` calls.
- On OTP bumps, migrate deprecated constructs instead of adding `nowarn_*`.
- This is a library. Application or product code built on it lives in its own
  repository.
- Work that needs a change in a dependency is split: land and release the
  dependency in its own session first, then pin the release here.
- If you add, remove or rename an owner message, error reason or status mapping,
  update `docs/reference/messages-and-errors.md` and the CHANGELOG. If you change
  what goes on the wire, update `docs/reference/conformance.md`. Session start
  or teardown changes need a case in `test/masque_lifecycle_SUITE.erl`.

## Dependency Bumps

Read the dependency's CHANGELOG before bumping, and look for behaviour the code
relies on: re-check the contracts in `docs/3-change/transports.md` and update the
versions pinned there. Green tests are not enough, since limits and drop rules
often only show under load. `rebar.lock` is gitignored, so `rebar.config` is the
only record of a pin.

## Commits and Pull Requests

Follow `CONTRIBUTING.md`: branch off `main`, one-line lowercase imperative
subjects, no body by default, no `Co-Authored-By` or "generated with" lines, no
test plan in pull requests. User-visible changes get a plain-English line under
`## [Unreleased]` in `CHANGELOG.md`, with `**Breaking**` where it applies. Do not
use em dashes in any text. Do not use step, phase or track labels in commits,
pull requests or plans.

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
self-skips unless `MASQUE_GO_BIN` points at an external MASQUE binary, so a
normal run reports 2 skipped tests and does not cover interop.

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
- Elvis rules live in `elvis.config` (only `src/**` is linted), which is the
  authoritative list. Relaxed for the initial adoption: `dont_repeat_yourself`, `no_invalid_dynamic_calls` (the
  pluggable handler dispatch is `HandlerMod:Callback(...)`), `no_throw` (the
  capsule and URI parsers use throw for control flow), `no_if_expression`,
  `guard_operators`, `no_deep_nesting`, `no_boolean_in_comparison`, and
  `no_single_clause_case` are disabled. Per-module ignores: `private_data_types`
  (`masque`, `masque_ip_capsule`), `export_used_types`
  (`masque_udp_bind_proxy_handler`), `no_receive_without_timeout`
  (`masque_racer`), `no_god_modules` (`masque`).
- Atom naming regex: `^[a-z](_?[a-zA-Z0-9]+)*(_SUITE)?$`.
