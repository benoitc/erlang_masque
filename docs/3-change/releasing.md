# Releasing

This page lists the steps to ship a version: bump, changelog, tag, publish, docs. You only need it when you cut a release. It also records where the release history has gaps, so you know what not to copy from past releases. Read [CONTRIBUTING](../../CONTRIBUTING.md) first for the checks every release must pass.

## Steps

1. Make sure `main` is green: every check in [CONTRIBUTING](../../CONTRIBUTING.md), including `rebar3 as test proper` and `rebar3 fmt --check`.

2. Bump `vsn` in `src/masque.app.src`. `masque:version/0` reads it at runtime.

   ```erlang
   {vsn, "0.8.0"},
   ```

3. In `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` and open a new empty `## [Unreleased]` above it. The file follows Keep a Changelog: `Added`, `Changed`, `Fixed`, `Security` sections, with `**Breaking**` on entries that change behaviour callers depend on.

4. Commit both files with a subject like the previous release commit (`release 0.7.0`).

5. Tag the commit. Existing tags use a `v` prefix:

   ```bash
   git tag                 # v0.1.0 v0.2.0 v0.3.0 v0.4.0 v0.7.0
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

6. Build the docs and look at them before publishing. `rebar3 ex_doc` writes to `doc/`; the extras and their order come from the `ex_doc` section of `rebar.config`.

   ```bash
   rebar3 ex_doc
   ```

7. Publish to Hex. `rebar.config` already sets `{hex, [{doc, ex_doc}]}`, so the docs are published with the package.

   ```bash
   rebar3 hex publish
   ```

## Notes

- The package metadata (`licenses`, `links`, `description`) lives in `src/masque.app.src`. The description still reads "MASQUE: Proxying UDP in HTTP (RFC 9298) for Erlang", which undersells what the library covers; update it before the next publish.
- Only `masque` and the handler behaviour are described as stable API in `masque.erl`. When a release changes an internal module only, the CHANGELOG entry can say so briefly.

## Open questions

- Open question: there is no `## [0.6.0]` section in `CHANGELOG.md`, although `docs/features.md` lists "Delivered in v0.6" items. Were those released as part of 0.7.0, or is a 0.6.0 entry missing?
- Open question: the tags jump from `v0.4.0` to `v0.7.0`; there is no `v0.5.0` or `v0.6.0` tag, and the `release 0.7.0` commit moved `vsn` straight from `0.4.0` to `0.7.0`. Should the missing tags be created on the commits that match the 0.5.0 changelog entry, or left as they are?
- Open question: is publishing to Hex planned, and under which package name? Nothing in the repository shows a past `rebar3 hex publish`.

Next: [CHANGELOG](../../CHANGELOG.md).
