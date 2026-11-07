---
name: compliance
description: Check masque against a specification requirement by requirement - every MUST, SHOULD and MAY mapped to code, a test and a conformance row - fix the gaps, and add wire-vector end-to-end cases on h3, h2 and h1. Use when implementing or updating a protocol, when a change alters what goes on the wire, after spec-watch finds a new revision, or when someone asks whether masque is compliant.
---

# Compliance

A protocol is not done when the happy path works. This skill walks a spec's requirements one by one and proves each against the code, the way the CONNECT-TCP -18 and reverse connect work was finished. Start with the `spec-watch` skill if you are not sure you have the latest revision.

## Steps

1. **Get the text.** Download the exact revision (`https://www.ietf.org/archive/id/<name>-<rev>.txt`, or the RFC). Work from the text, not from memory or summaries.
2. **List the requirements.** Extract every normative statement: `grep -n "MUST\|SHALL\|SHOULD\|REQUIRED\|RECOMMENDED\|MAY"` and read the paragraph around each. Include figures (examples are test vectors), IANA sections (codes, tokens, default templates) and security considerations. Note the section of each.
3. **Map each one**, in a table you keep while working:
   - where the code does it (`file:line`);
   - which test proves it, on which transports;
   - its row in `docs/reference/conformance.md`.
   Mark each: done, gap, deviation (masque chooses otherwise, with a reason), or not applicable.
4. **Look for what the table misses.** For each role (client, proxy) and each transport (h3, h2, h1), ask:
   - What happens on invalid input: malformed capsule, truncated stream, repeated or out-of-order frames, oversize values, unknown types (must be skipped, RFC 9297 section 3.3)?
   - How does each side close: clean FIN, abort, reset, timeout? Does a local timeout count as an abort where the spec says so?
   - Interim responses (1xx), status codes for refusals (4xx vs 5xx), Proxy-Status, cacheability on h1.
   - Flow control and backpressure: can a slow peer make the other side buffer without bound?
   - Version and token selection: do older peers keep working (additive rule in `AGENTS.md`)?
   - Library limits (OTP `ssl`, `quic_h3`, `h2`, `h1`) that force a deviation: record them, do not hide them.
5. **Fix the gaps.** Follow `AGENTS.md`: additive changes, one narrow seam into existing paths, docs updated in the same change.
6. **Add wire vectors.** For each requirement that puts bytes on the wire, add a case that builds the request and capsules by hand and checks the bytes and the outcome, on h3, h2 and h1, as `masque_e2e_SUITE`'s `vec_*` cases do. Add codec eunit tests with the exact bytes from the spec's figures. Every case keeps the leak check.
7. **Interop.** Check for other implementations (spec-watch notes them). If one exists and is trustworthy, test against it in `masque_interop_SUITE`; if none, say so in `conformance.md`.
8. **Record.** Update the conformance table (requirement, behaviour, module) and its deviations list, `messages-and-errors.md` for new reasons or messages, `decisions.md` for choices, and the CHANGELOG in plain English.
9. **Verify.** Run the checks in `AGENTS.md`, then the `safety` skill's runs (load with the error-report check, netsim) before a PR.

## Report

End with the requirement table summarised: counts of done, deviations (each with its reason), not applicable, and anything still open. Never report "compliant" with an open gap.
