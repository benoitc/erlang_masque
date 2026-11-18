# Features

This page lists the protocol features masque could add, with the specification each one comes from. Read it when you plan work beyond the current specs; what masque implements today is in [conformance](reference/conformance.md). Each item would be additive and opt-in, as `AGENTS.md` requires.

## Candidates

| Feature | Specification | Notes |
| --- | --- | --- |
| DNS configuration for CONNECT-IP | draft-ietf-masque-connect-ip-dns-07 | New capsules carrying resolver addresses and search domains from the proxy to the client. Fits the existing CONNECT-IP control plane. |
| Compression of CONNECT-UDP payloads | draft-ietf-masque-http-datagram-compression-02 | Context IDs that stand for repeated payload prefixes. Close to the compression udp-bind already does for peer addresses. |
| QUIC-aware proxying | draft-ietf-masque-quic-proxy-10 | Forwards QUIC packets by connection ID instead of tunnelling them. Needs support from the QUIC stack. |
| Ethernet proxying | draft-ietf-masque-connect-ethernet-18 | CONNECT-ETHERNET, a new tunnel type next to UDP, TCP and IP. |

## Waiting on dependencies

These gaps are recorded as deviations in [conformance](reference/conformance.md) and need a release of the dependency first.

| Gap | Where it must be fixed |
| --- | --- |
| Malformed HTTP/3 datagrams must close the connection with `H3_DATAGRAM_ERROR` (RFC 9297 section 2.1) | erlang_quic |
| `Upgrade` on an HTTP/1.0 request must be ignored (RFC 9110 section 7.8) | erlang_h1 |
| A tunnel stream that receives trailers after the 2xx is reset without telling the session (CONNECT-TCP section 4.3) | erlang_h2 |
