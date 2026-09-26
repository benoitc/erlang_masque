# Contributing to masque

This page is your first stop before changing masque. It tells you what to install, which checks must pass, how branches, commits and pull requests are written, and where to read next. Read it once before your first change; after that you will mostly live in [code-map](docs/3-change/code-map.md), [testing](docs/3-change/testing.md) and [how-to](docs/3-change/how-to.md).

## What you need

- Erlang/OTP 29. `rebar.config` sets `{minimum_otp_vsn, "29"}` and CI runs OTP 29 only.
- rebar3 (CI pins 3.25.0).
- CMake. The `instrument` dependency builds a NIF with it, so `rebar3 compile` fails without it.
- `openssl` on your `PATH`. The test suites generate a self-signed certificate with it (see [testing](docs/3-change/testing.md)).

## Build

```bash
rebar3 compile
```

Warnings are errors (`warnings_as_errors` in `rebar.config`).

## Required checks

Every change must pass these before you commit. Run `rebar3 fmt` first so the other checks see formatted code.

```bash
rebar3 fmt                  # erlfmt, rewrites files in place
rebar3 compile              # warnings are errors
rebar3 xref
rebar3 eunit
rebar3 ct
rebar3 lint                 # elvis, src/** only
rebar3 dialyzer
```

CI also runs the property tests and checks formatting without rewriting:

```bash
rebar3 as test proper
rebar3 fmt --check
```

Lint rules and the reasons some are relaxed are listed in `AGENTS.md` and `elvis.config`.

## Branches, commits and pull requests

- Branch off `main`; do not commit to `main` directly.
- Commit subjects are one line, lowercase, imperative, no trailing period. Examples from the history: `dial loopback IP for all compliance suite proxies`, `hold early handler output until the h3 stream is finalized`.
- No body by default, no bullet lists, no `Co-Authored-By` or "generated with" trailers.
- Pull request descriptions are short: what changed and why. No test plan section.
- User-visible changes get a line in `CHANGELOG.md` under `## [Unreleased]`. Mark behaviour changes that can break callers with `**Breaking**`, as the existing entries do.

## Where to start reading

1. [overview](docs/1-understand/overview.md): what MASQUE is and what this library covers.
2. [concepts](docs/1-understand/concepts.md): the vocabulary every other page uses (tunnel, capsule, owner, handler, router, racer, pool).
3. [architecture](docs/1-understand/architecture.md): layers, processes, and why the boundaries sit where they do.
4. The internals page for the area you touch: [server-internals](docs/3-change/server-internals.md), [client-internals](docs/3-change/client-internals.md), [transports](docs/3-change/transports.md), [pool](docs/3-change/pool.md), [connect-ip-internals](docs/3-change/connect-ip-internals.md), [udp-bind-internals](docs/3-change/udp-bind-internals.md).

## Find the right module

Open [code-map](docs/3-change/code-map.md). It lists every module by role and says "change this when...". If your change is one of the common ones (new handler action, new capsule, new protocol, teardown, a dependency bump), [how-to](docs/3-change/how-to.md) names the files to touch and the tests to add.

## Check you did not break a contract

- Owner messages, error reasons and HTTP status mapping are listed in [messages-and-errors](docs/reference/messages-and-errors.md). If your change adds, removes or renames one, update that page and add a CHANGELOG entry.
- Spec behaviour is mapped in [conformance](docs/reference/conformance.md). If you change what goes on the wire, update the matching row.
- Anything that touches session start or teardown needs a case in `test/masque_lifecycle_SUITE.erl`; [testing](docs/3-change/testing.md) has a template.
- New protocols and extensions are additive: new modules, new API functions, new URI templates or listener options. Existing UDP, TCP and IP surfaces keep their names and behaviour.

Next: [overview](docs/1-understand/overview.md), then [code-map](docs/3-change/code-map.md).
