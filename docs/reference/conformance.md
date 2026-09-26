# Conformance

This page maps the specifications masque implements to the behaviour in the code and the module that owns it, and lists the places where masque deviates or adds its own policy. Use it when you review a change that touches the wire, when you check whether a requirement is covered, or when an interop peer disagrees with masque. It is a reference; read the table for the spec you care about. For the messages and reasons mentioned here, see [messages-and-errors](messages-and-errors.md). The compliance suites that pin these rows are listed in [testing](../3-change/testing.md).

Open question: section numbers below come from the code comments and the earlier compliance map. Those sources are not always consistent with each other (for example RFC 9484 capsule rules are cited as both §4.6 and §4.7), so check a number against the RFC text before quoting it elsewhere.

## RFC 9298: Proxying UDP in HTTP

| Section | Requirement | Behaviour in masque | Module |
| --- | --- | --- | --- |
| §2 | URI template with `target_host` and `target_port` | Default `/.well-known/masque/udp/{target_host}/{target_port}/`; client expands, server matches `:path`. Parsing is strict: dotted-quad IPv4 only, no zone ids, digit-only ports, no double decoding. | `masque_uri`, `masque_uri_template`, `include/masque.hrl` |
| §3 | A 2xx means the proxy is ready to forward | The handler's `init/2` (socket open, target checks) runs before the 2xx. On h3 the 2xx is sent from finalize, and handler output produced earlier is held until after it. | `masque_server_session`, `masque_server_connection` |
| §3.2, §3.3 | HTTP/1.1: `GET` with `Upgrade: connect-udp`, `Connection: Upgrade`, `Capsule-Protocol: ?1`; 101 response | Listener requires all three headers and a `Host`; the client validates the 101. | `masque_h1_server`, `masque_h1_client_session` |
| §3.4, §3.5 | HTTP/2 and HTTP/3: Extended CONNECT with `:protocol = connect-udp` | Listeners require `:method = CONNECT`, `:protocol`, `:scheme` and `:authority`. | `masque_server`, `masque_h2_server` |
| §4 | Context ID 0 is UDP payload; other ids are extensions | Context 0 is delivered to `handle_packet/2` / the owner. Unknown context ids are dropped on receipt. `masque:send/3` lets you send on another id. | `masque_datagram`, UDP sessions |
| §5 | UDP payload at most 65527 bytes | Larger payloads are refused on send (`{payload_too_large, _, 65527}` on the client, silent drop in a handler action) and dropped on receipt. On h3 the negotiated datagram size is checked too. | UDP sessions |
| (errors) | Failures are reported as HTTP status codes | See the status mapping in [messages-and-errors](messages-and-errors.md#server-side-handshake-reasons-and-http-status). | `masque_errors` |

Deviations and additions:
- h2 and h3 listeners do not check that a CONNECT-UDP request carries `capsule-protocol: ?1`; the h1 listener does. Clients send it unless `capsule_protocol => false`.
- The client refuses a 2xx that omits `capsule-protocol: ?1` when it asked for it (`capsule_protocol_not_acknowledged`).

## RFC 9297: HTTP Datagrams and the Capsule Protocol

| Section | Requirement | Behaviour in masque | Module |
| --- | --- | --- | --- |
| §2 | HTTP/3 datagrams carry a quarter stream id | Handled by `quic_h3`. | `quic_h3` (dependency) |
| §2.1.1 | `SETTINGS_H3_DATAGRAM = 1` | The h3 listener merges `h3_datagram => 1` into its settings; h3 clients refuse a peer without it (`no_h3_datagram`). | `masque_server`, `masque_client_session`, `masque_ip_client_session` |
| §3.2 | Capsule framing: type, length, value | Encoding and decoding go through `quic_h3_capsule`, wrapped by `masque_capsule`. h2 and h1 sessions use `h2_capsule` and `h1_capsule`. | `masque_capsule` |
| §3.3 | Unknown capsule types are ignored; a malformed or truncated capsule is a stream error | Unknown types reach the handler's `handle_capsule/3` (server) or the owner as `masque_capsule` (client), and udp-bind drops them. Malformed or truncated capsules reset the stream with `H3_MESSAGE_ERROR` (h3) or `PROTOCOL_ERROR` (h2). The receive buffer is capped by `max_capsule_size` (default 65536). | all capsule-carrying sessions |
| §3.4 | A capsule-protocol response carries no `content-length` / `content-type` | Clients refuse such a 2xx (`malformed_response`). Listeners only put these headers on rejections. | client sessions |
| §3.5 | DATAGRAM capsule (type 0) | Used to carry datagrams on h2 and h1. | h2 and h1 sessions |

## RFC 9484: Proxying IP in HTTP

This table replaces the compliance map from the former `docs/connect_ip.md`. Each row was checked against the code.

| Section | Requirement | Behaviour in masque | Module |
| --- | --- | --- | --- |
| §3 | Absolute URI template with `target` and `ipproto` (path or query form) | The client requires an absolute template (`masque_uri_ip:parse_client_template/1`); the server matches path and query forms (`parse_server_template/1`). IP templates only allow `target` and `ipproto`. Prefix targets must be canonical (host bits zero). | `masque_uri_ip`, `masque_uri_template` |
| §4 | Request carries `:protocol = connect-ip` and `capsule-protocol: ?1` | `connect/3` forces `capsule_protocol => true` for `protocol => ip` and refuses `false` (`{invalid_opts, capsule_protocol_required_for_ip}`). | `masque`, `masque_ip_client_session` |
| §4 | 2xx carries `capsule-protocol: ?1`, no `content-length` / `content-type` | The client refuses other responses (`capsule_protocol_missing`, `malformed_response`). | `masque_ip_client_session`, `masque_ip_h1_client_session` |
| HTTP/1.1 | Upgrade with `Upgrade: connect-ip` | Supported on h1, same checks as CONNECT-UDP. | `masque_h1_server`, `masque_ip_h1_*` |
| scope | Proxy limits traffic to the requested `target` / `ipproto` | The default handler drops packets outside the scope (`scope_target`, `scope_ipproto`); a hostname target only reaches its advertised routes; a prefix target drops non-public destinations unless `allow_private`. | `masque_ip_proxy_handler`, `masque_ip_packet` |
| ADDRESS_ASSIGN | Non-zero Request ID answers a prior ADDRESS_REQUEST; ID 0 is unprompted | Both sides track pending ids. The client's `assign_addresses/2` returns `{no_such_pending_request, Id}`; on the server an `{assign, Entries}` action containing an unmatched id is skipped as a whole. | `masque_ip_client_session`, `masque_ip_server_session`, `masque_ip_h1_server_session` |
| ADDRESS_ASSIGN | Hostname targets are resolved before the 2xx and advertised | All three listeners run the `resolver` through `masque_ip:resolve_target/3` before `accept/1`; the result is in `resolved_addresses` and the default handler advertises it. | `masque_ip`, listeners |
| ADDRESS_REQUEST | At least one entry; Request IDs non-zero and unique per sender | Enforced on encode and decode (`empty_address_request`, `duplicate_request_id`). | `masque_ip_capsule` |
| ADDRESS_REQUEST | Proxy answers requests it cannot satisfy | With no pool, or when the pool is exhausted, entries are answered with the all-zero "reject" assignment. | `masque_ip`, `masque_ip_proxy_handler` |
| ROUTE_ADVERTISEMENT | Ordered by (version, protocol, start); disjoint within (version, protocol); protocol-0 ranges do not overlap other protocols; start <= end | All four checks in `validate_routes_result/1`. | `masque_ip_capsule` |
| §5 / §8.2 | Both endpoints may send every capsule | Client API: `request_addresses/2`, `assign_addresses/2`, `advertise_routes/2`. Server actions: `{request_addresses, _}`, `{assign, _}`, `{advertise, _}`. | `masque`, IP sessions |
| §6 | Datagram payload: context id 0 is a full IP packet; unknown contexts dropped | As stated, on every transport. | `masque_datagram`, IP sessions |
| MTU | The tunnel must carry 1280-byte IPv6 packets | On h3 the client aborts the handshake with `{mtu_too_low, Got, 1280}` if the datagram size is too small. h2 and h1 carry datagrams in capsules and are not checked. | `masque_ip_client_session` |
| forwarding | Router duties: decrement TTL / Hop Limit, report errors with ICMP | The default handler decrements, answers Time Exceeded, and Packet Too Big / Fragmentation Needed above `mtu` (default 1500). No ICMP error is sent in reply to an ICMP error. ICMP payloads are truncated to 548 bytes (v4) and 1232 bytes (v6). | `masque_ip_proxy_handler`, `masque_ip_packet`, `masque_icmp` |
| security | Drop packets with spoofed source addresses | The default handler drops packets whose source is outside the assigned prefixes, and every packet before an assignment unless `allow_private` (`bcp38` drop counter). | `masque_ip_proxy_handler` |
| errors | Malformed capsule is a stream error; rejections carry Proxy-Status | Reset with `H3_MESSAGE_ERROR` / `PROTOCOL_ERROR`; see RFC 9209 below. | IP sessions, listeners |

Deviations and additions:
- `'*'` and private targets are refused with 403 unless the listener sets `allow_private` (local policy, not required by the RFC).
- The h2/h3 server session keeps at most 64 unanswered ADDRESS_REQUEST ids per session and rejects the rest at once. The h1 server session has no such bound.
- The default handler forwards accepted packets to a user `forward_fun`; without one, packets are dropped. The RFC leaves the data plane to the implementation.

## RFC 9209: The Proxy-Status HTTP response header

| Requirement | Behaviour in masque | Module |
| --- | --- | --- |
| A proxy names itself and the error type | Every listener rejection carries `proxy-status: masque; error=<type>`, with the type from the reason (`http_protocol_error`, `dns_error`, `connection_timeout`, `destination_ip_prohibited`, `proxy_loop_detected`, `proxy_internal_error`). | `masque_server`, `masque_h2_server`, `masque_h1_server` |

Deviations:
- The proxy identifier is always `masque`; it is not configurable and does not name the listener.
- No other parameters (`details`, `rcode`, `next-hop`) are sent.
- Proxy-Status is only sent on handshake rejections, not on 2xx responses or when a tunnel fails later.
- A handler can replace the header by returning `{reject, Reason, [{<<"proxy-status">>, Value}]}`.

## RFC 9110: HTTP Semantics (CONNECT, Upgrade, Via)

| Section | Requirement | Behaviour in masque | Module |
| --- | --- | --- | --- |
| §9.3.6 | CONNECT to `host:port`; a 2xx turns the connection into a tunnel | Classic CONNECT-TCP on h1: the listener parses the authority-form target (IPv6 in brackets); the client treats any 2xx as success. `proxy_authorization` is sent as `Proxy-Authorization` on this path only, and refused if it contains CR or LF. | `masque_h1_server`, `masque_tcp_h1_client_session`, `masque_tcp_h1_server_session`, `masque_uri` |
| §7.2 with RFC 9112 §3.2.3 | `Host` matches the CONNECT target | The h1 listener refuses a missing or different `Host` with 400 (`bad_host`). | `masque_h1_server` |
| §7.8 | Upgrade needs `Connection: Upgrade`; a 101 names the protocol | The h1 listener requires the token (`bad_protocol` otherwise); the udp-bind h1 client checks both headers on the 101 (`bad_upgrade_response`). | `masque_h1_server`, `masque_udp_bind_h1_client_session` |
| §7.6.3 | `Via` records the hops | Chain handlers add their pseudonym to `via` on the upstream request and refuse a request that already names them (508, `loop_detected`). | `masque_chain_handler` |

A rejected h1 request is answered with `connection: close` and the connection is closed; the code cites RFC 9931 (updates RFC 9298) for this.

## RFC 8441 and RFC 9220: Extended CONNECT

| Requirement | Behaviour in masque | Module |
| --- | --- | --- |
| Server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` | h3 listener merges `enable_connect_protocol => 1` into its settings; h2 listener sets `enable_connect_protocol => true`. | `masque_server`, `masque_h2_server` |
| Client uses `:protocol` only when the peer allows it | h2 and h3 clients read the peer SETTINGS and fail with `no_extended_connect`. | client sessions |
| `:scheme`, `:authority`, `:path` present | Listeners refuse a request without `:scheme` or `:authority` (`bad_path`, 404); the h2 listener no longer falls back to `host` or a fixed scheme. | `masque_server`, `masque_h2_server` |

Stream and connection semantics from RFC 9114 and RFC 9113 that the sessions rely on:
- GOAWAY: on h3 a stream with an id at or above the GOAWAY id ends with `goaway`; on h2 a stream above the last stream id does. Lower streams keep running.
- Errors reset the stream: `H3_MESSAGE_ERROR` / `PROTOCOL_ERROR` for capsule errors, `H3_CONNECT_ERROR` / `CONNECT_ERROR` for CONNECT-TCP.

## draft-ietf-httpbis-connect-tcp

Open question: which revision of the draft is targeted is not recorded anywhere in the repository.

| Requirement | Behaviour in masque | Module |
| --- | --- | --- |
| Extended CONNECT with `:protocol = connect-tcp` and a URI template | Default template `/.well-known/masque/tcp/{target_host}/{target_port}/` (`tcp_uri_template` on the listener, `uri_template` on the client). | `include/masque.hrl`, `masque_tcp_client_session`, listeners |
| The stream carries raw bytes, no capsule protocol | No `capsule-protocol` in either direction; a 2xx that claims it fails with `{bad_response, capsule_protocol}`; `send_capsule/3` returns `{error, not_supported}`. | `masque_tcp_client_session`, `masque_tcp_server_session` |
| END_STREAM is a TCP FIN, one per direction | The peer's FIN is reported as `{masque_closed, Sess, peer_fin}` and the session stays writable; `shutdown_write/1` sends ours. A half-closed tunnel with no traffic for 30 s ends with `eof_timeout`. | TCP sessions, `masque_tcp_proxy_handler` |
| Errors abort the stream | Target reset, target error, failed or blocked (30 s) writes, and handler crashes reset with `H3_CONNECT_ERROR` / `CONNECT_ERROR`. | `masque_tcp_server_session` |

Deviations and open points:
- On HTTP/1.1, masque uses classic `CONNECT host:port` (RFC 9110) instead of the draft's upgrade; the h1 listener has no `tcp_uri_template`.
- h1 cannot half-close: OTP `ssl` drops the connection on the peer's `close_notify`, so a FIN in either direction ends the tunnel.
- Open question: the draft's template variables may not be `target_host` / `target_port` in the targeted revision; check before claiming interop with other implementations.

## draft-ietf-masque-connect-udp-listen-11 (Connect-UDP-Bind)

| Requirement | Behaviour in masque | Module |
| --- | --- | --- |
| `Connect-UDP-Bind: ?1` (RFC 9651 Boolean) on request and response enables the extension | Listeners only look at the header with `accept_bind => true`; an invalid value is treated as absent and the request stays plain CONNECT-UDP. The client refuses a 2xx without it (`missing_bind_response_header`). | `masque_uri_udp_bind`, listeners, udp-bind client sessions |
| Same URI template as CONNECT-UDP; `*` for an unscoped bind | The bind matcher accepts `%2A` for both host and port (both or neither); the plain CONNECT-UDP matcher still refuses it. | `masque_uri_udp_bind` |
| `Proxy-Public-Address` on the response (list of `"ip:port"` strings) | The default handler sets it from `public_addresses`, `public_address_fun` or the bound socket address, and refuses a wildcard bind without one. The client refuses a 2xx without it (`missing_proxy_public_address`). | `masque_udp_bind_proxy_handler`, `masque_uri_udp_bind` |
| Payload formats (sections 4 and 5): compressed = UDP payload only; uncompressed = family, address, port, payload | As stated. | `masque_udp_bind_payload` |
| Context id 0 | Scoped bind: raw UDP to the scoped peer, as in RFC 9298. Unscoped bind: dropped (`context_zero`). | `masque_udp_bind_server_session` |
| COMPRESSION_ASSIGN / ACK / CLOSE capsules | Codes `0x11`, `0x12`, `0x13` (provisional). Context id 0 is malformed; IP version 0 omits address and port. | `masque_compression_capsule` |
| Context id parity, duplicates, tuple conflicts, uncompressed context rules | Client ids even, proxy ids odd; wrong parity or a duplicate id is malformed; a tuple the other side already opened makes the proxy close its own context; a repeated tuple from the same side is malformed; only the client opens the single uncompressed context; after it closes, the proxy opens no new compressed contexts. | `masque_compression_table` |
| Datagram on an unknown context | Dropped (`unknown_context`). | udp-bind sessions |

Library policy, not required by the draft:
- An outbound context is only used after its COMPRESSION_ACK (wait-for-ACK). The draft allows sending earlier at the risk of drops.
- The library never assigns contexts on its own; you drive them with `masque:assign_compression/2`, `open_uncompressed_context/1` and `close_compression/2`.
- The proxy keeps at most `max_pending_compression_responses` (default 16) assigns waiting for an ACK and drops the rest (`pending_limit`).
- The default peer filter only allows public peers (`masque_ip:is_public/1`); loopback needs `allow_loopback`, other non-public peers `allow_private`. IPv4-mapped IPv6 peers are checked as IPv4.
- Bind is also offered over HTTP/1.1, through the CONNECT-UDP upgrade.
- `upstream_pool => true` is ignored for udp-bind; each bind session dials its own connection and closes it with the session.

Next: [messages-and-errors](messages-and-errors.md), or [testing](../3-change/testing.md) for the suites that pin these rows.
