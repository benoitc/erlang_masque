---
name: spec-watch
description: Check whether the specifications masque implements have moved on - a new draft revision, a draft adopted or replaced, an RFC published, errata, new IANA code points - and report what changed and what masque must do. Use before starting work on a protocol, before a release, when an interop peer disagrees, and whenever the user asks whether masque follows the latest specs.
---

# Spec watch

masque implements IETF drafts that keep moving. In November 2026 CONNECT-TCP was implemented against draft -10 while the draft was already at -18 in the RFC Editor queue, with new capsule codes; nobody noticed until an interop check. This skill exists so that does not happen again.

## The specs to check

`docs/reference/conformance.md` is the record: each `## ` heading names a spec and, for drafts, the revision masque implements. Read it first; the list below is a starting point, not the truth.

| Spec | Track at |
|---|---|
| RFC 9298 CONNECT-UDP, RFC 9297 HTTP Datagrams, RFC 9484 CONNECT-IP, RFC 9209 Proxy-Status, RFC 8441 / RFC 9220 Extended CONNECT | errata: `https://www.rfc-editor.org/errata/rfcNNNN` |
| draft-ietf-httpbis-connect-tcp | `https://datatracker.ietf.org/doc/draft-ietf-httpbis-connect-tcp/` (RFC number once published) |
| draft-ietf-masque-connect-udp-listen | `https://datatracker.ietf.org/doc/draft-ietf-masque-connect-udp-listen/` |
| draft-rosomakho-masque-reverse-connect | `https://datatracker.ietf.org/doc/draft-rosomakho-masque-reverse-connect/` (watch for WG adoption under a new name) |

Also check the MASQUE and HTTPBIS working group pages (`https://datatracker.ietf.org/wg/masque/documents/`, `https://datatracker.ietf.org/wg/httpbis/documents/`) for new documents that touch what masque does (new capsules, new upgrade tokens, replacements).

## Steps

1. For each spec, fetch its datatracker page and note: latest revision and date, state (individual, WG, IESG, RFC Ed Queue, RFC NNNN), "replaced by" links, expiry.
2. Compare with the revision in `conformance.md`. If it is the same, say so and move on.
3. If it moved, fetch both texts and diff them (`https://www.ietf.org/archive/id/<name>-<rev>.txt`; strip page headers with `grep -v "^Author\|^Internet-Draft\|^\s*$"` before `diff`). Read every change, not the summary. Look in particular for:
   - capsule type codes, upgrade tokens, interop tokens (sections often called "Interop testing", to be removed at publication);
   - new MUST / SHOULD / MUST NOT, and requirements that became MUST;
   - closing, error and invalid-data rules;
   - template variables and default templates;
   - status codes and headers (Proxy-Status, Capsule-Protocol, Cache-Control).
4. For RFCs, read the verified errata and check whether masque relies on the erroneous text.
5. Report, per spec: implemented revision, latest revision and state, each change that affects masque with the section number, and what masque must change. Keep it short and concrete; quote spec text only where the wording matters.
6. If anything must change, do not edit code from this skill: propose a plan (the maintainer decides scope), then use the `compliance` skill for the work.

## Notes

- Search for implementations at the same time (GitHub, the draft's "Implementation Status" section, the WG wiki): new peers make interop testing possible. Never add an unreviewed personal fork as a dependency; the maintainer declined that once.
- Record the outcome: update the revision and date in `conformance.md` when masque is brought up to date, and the project memory when a spec changes state.
- Dates matter: a draft's interop token (for example `connect-tcp-12`) disappears at publication; check whether masque's defaults should follow.
