# Features

This page lists the protocol features masque could add, with the specification each one comes from. Read it when you plan work beyond the current specs; what masque implements today is in [conformance](reference/conformance.md). Each item would be additive and opt-in, as `AGENTS.md` requires.

## Candidates

| Feature | Specification | Notes |
| --- | --- | --- |
| DNS configuration for CONNECT-IP | draft-ietf-masque-connect-ip-dns-07 | New capsules carrying resolver addresses and search domains from the proxy to the client. Fits the existing CONNECT-IP control plane. |
| Compression of CONNECT-UDP payloads | draft-ietf-masque-http-datagram-compression-02 | Context IDs that stand for repeated payload prefixes. Close to the compression udp-bind already does for peer addresses. |
| QUIC-aware proxying | draft-ietf-masque-quic-proxy-10 | Forwards QUIC packets by connection ID instead of tunnelling them. Needs support from the QUIC stack. |
| Ethernet proxying | draft-ietf-masque-connect-ethernet-18 | CONNECT-ETHERNET, a new tunnel type next to UDP, TCP and IP. |
