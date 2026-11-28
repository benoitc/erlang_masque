# Conformance

This page maps the specifications masque implements to the behaviour in the code and the module that owns it, and lists the places where masque deviates or adds its own policy. Use it when you review a change that touches the wire, when you check whether a requirement is covered, or when an interop peer disagrees with masque. It is a reference; read the table for the spec you care about. For the messages and reasons mentioned here, see [messages-and-errors](messages-and-errors.md). The compliance suites that pin these rows are listed in [testing](../3-change/testing.md).

Section numbers in the RFC 9484 table were checked against the RFC's table of contents (November 2026). Section numbers in code comments are not always kept in step; quote the ones here.

## RFC 9298: Proxying UDP in HTTP

Interop: tested against quic-go's `masque-go` (with quic-go 0.66) over HTTP/3, its client through masque's proxy and masque's client through its proxy, in `masque_interop_SUITE`.

| Section | Requirement | Behaviour in masque | Module |
| --- | --- | --- | --- |
| §2 | URI template with `target_host` and `target_port` | Default `/.well-known/masque/udp/{target_host}/{target_port}/`; client expands, server matches `:path`. Parsing is strict: dotted-quad IPv4 only, no zone ids, digit-only ports, no double decoding. | `masque_uri`, `masque_uri_template`, `include/masque.hrl` |
| §3 | A 2xx means the proxy is ready to forward | The handler's `init/2` (socket open, target checks) runs before the 2xx. On h3 the 2xx is sent from finalize, and handler output produced earlier is held until after it. | `masque_server_session`, `masque_server_connection` |
| §3.2 | HTTP/1.1: `GET` with a single `Host`, `Upgrade: connect-udp`, `Connection: Upgrade`, `Capsule-Protocol: ?1` | The listener requires all three headers (`Capsule-Protocol` read as a Boolean, parameters allowed) and refuses a missing `Host` or more than one with 400 (`bad_host`, `bad_request`). | `masque_h1_server` |
| §3.3 | The 101 carries `Connection: Upgrade` and a single `Upgrade: connect-udp`; otherwise the client treats the attempt as failed | The UDP, IP, TCP and udp-bind h1 clients check both on the 101 and fail with `bad_upgrade_response`. | `masque_http`, h1 client sessions |
| §3.1 | The proxy must not introduce IP fragmentation and sets IPv4 DF where it can | The proxy's UDP sockets set IPv4 Don't Fragment (Linux `IP_PMTUDISC_DO`, `IP_DONTFRAG` on macOS and FreeBSD) and `IPV6_DONTFRAG`. A packet above the path MTU is dropped. `dont_fragment => false` turns it off; other systems keep the kernel default. | `masque_udp_df`, `masque_udp_proxy_handler`, `masque_udp_bind_proxy_handler` |
| §3.4 | HTTP/2 and HTTP/3: Extended CONNECT with `:protocol = connect-udp` | Listeners require `:method = CONNECT`, `:protocol`, `:scheme` and `:authority`. | `masque_server`, `masque_h2_server` |
| §3.3, §3.5 | A successful response meets RFC 9297 §3.2; otherwise the client treats the attempt as failed | h3 and h2 clients refuse a 2xx that is a 204, 205 or 206 or carries `content-length`, `content-type` or `transfer-encoding` (`malformed_response`), and one without the `capsule-protocol` acknowledgement (`capsule_protocol_not_acknowledged`); h1 clients apply the same to the 101. | UDP client sessions, `masque_http` |
| §4 | Context ID 0 is UDP payload; other ids are extensions | Context 0 is delivered to `handle_packet/2` / the owner. Unknown context ids are dropped on receipt. `masque:send/3` lets you send on another id. | `masque_datagram`, UDP sessions |
| §5 | UDP payload at most 65527 bytes; a receiver aborts the stream on a larger one | Larger payloads are refused on send (`{payload_too_large, _, 65527}` on the client, silent drop in a handler action). A larger context-zero payload received aborts the stream: `H3_DATAGRAM_ERROR` on h3, `PROTOCOL_ERROR` on h2, the connection closed on h1, with reason `udp_payload_too_large`. On h3 a send is also checked against what the path carries now. | UDP sessions, `masque_datagram` |
| (errors) | Failures are reported as HTTP status codes | See the status mapping in [messages-and-errors](messages-and-errors.md#server-side-handshake-reasons-and-http-status). | `masque_errors` |

Deviations and additions:
- h2 and h3 listeners do not check that a CONNECT-UDP request carries `capsule-protocol: ?1`; the h1 listener does. Clients send it unless `capsule_protocol => false`.
- The client refuses a 2xx that omits `capsule-protocol: ?1` when it asked for it (`capsule_protocol_not_acknowledged`).
- §3.1: an ICMP port unreachable from the target does not close the tunnel; datagrams are unreliable and the target may come back. Other socket errors close it.
- §6.1: a packet dropped because it is above the path MTU (Don't Fragment set) is not answered with an ICMP Packet Too Big towards the client.
- §3.2: an h1 request with `Upgrade: connect-udp` but no `Connection: Upgrade` or no `Capsule-Protocol: ?1` is answered 501 (`bad_protocol`), where the RFC suggests 400.
- ECN: the proxy's UDP sockets leave the ECN field at Not-ECT and do not relay the client's marks.

## RFC 9297: HTTP Datagrams and the Capsule Protocol

| Section | Requirement | Behaviour in masque | Module |
| --- | --- | --- | --- |
| §2, §2.1 | HTTP/3 datagrams carry a quarter stream id; a malformed or too large one is an `H3_DATAGRAM_ERROR` connection error | Handled by `quic_h3` (since quic 3.1.3): a datagram without a valid quarter stream id closes the connection with `H3_DATAGRAM_ERROR`; one for a valid but unknown stream is dropped. | `quic_h3` (dependency) |
| §2.1.1 | `SETTINGS_H3_DATAGRAM = 1` | The h3 listener merges `h3_datagram => 1` into its settings; h3 clients refuse a peer without it (`no_h3_datagram`). | `masque_server`, `masque_client_session`, `masque_ip_client_session` |
| §3.2 | Capsule framing: type, length, value | Encoding and decoding go through `quic_h3_capsule`, wrapped by `masque_capsule`. h2 and h1 sessions use `h2_capsule` and `h1_capsule`. | `masque_capsule` |
| §3.2 | The Capsule Protocol is not used with `Content-Length`, `Content-Type` or `Transfer-Encoding`; a 204, 205 or 206 response to a capsule-protocol request is malformed | Listeners refuse a request with `capsule-protocol: ?1` and one of these fields with 400 (`bad_request`). Clients refuse such a 2xx or 101, and a 204, 205 or 206 (`malformed_response`), on UDP, IP and capsule-framed TCP. Listeners only put these fields on rejections. | `masque_http`, listeners, client sessions |
| §3.3 | Unknown capsule types are ignored; a malformed or truncated capsule is a stream error | Unknown types reach the handler's `handle_capsule/3` (server, skipped when it does not export one) or the owner as `masque_capsule` (client), and udp-bind drops them. Malformed or truncated capsules, at the end of the stream included, reset the stream with `H3_MESSAGE_ERROR` (h3) or `PROTOCOL_ERROR` (h2); on h1 the connection ends. The partial capsule a session holds is capped by `max_capsule_size` (default 65536); complete capsules in the same read do not count. | all capsule-carrying sessions |
| §3.4 | `Capsule-Protocol` is a Structured Field Boolean; receivers ignore unknown parameters | Every place that reads a received `capsule-protocol` (clients, the h1 listener, CONNECT-TCP framing, reverse connect) takes `?1` with any parameters as true; `?0`, several field lines and anything malformed are false. masque sends a bare `?1`. | `masque_http` |
| §3.5 | DATAGRAM capsule (type 0) | Used to carry datagrams on h2 and h1. On h3 a DATAGRAM capsule received on the stream is handled as an HTTP datagram too, by server and client sessions. | all datagram-carrying sessions |

Deviations:
- §2: an HTTP/3 datagram for a CONNECT-TCP stream, which does not use datagrams, is dropped instead of closing the connection with `H3_DATAGRAM_ERROR`.
- §3.3: a capsule of an unknown type larger than `max_capsule_size` aborts the stream like any other oversized capsule, instead of being skipped.

## RFC 9484: Proxying IP in HTTP

This table replaces the compliance map from the former `docs/connect_ip.md`. Each row was checked against the code.

Interop: tested against quic-go's `connect-ip-go` 0.8 over HTTP/3, its client through masque's proxy and masque's client through its proxy, in `masque_interop_SUITE`. connect-ip-go also sends the DNS configuration and PREF64 capsules of draft-ietf-masque-connect-ip-dns, which masque does not implement: they are skipped as unknown capsules (RFC 9297 section 3.2) and the tunnel goes on. connect-ip-go does not expand URI templates, so its request carries the URL as configured; the suite uses a bare `*` for the target and protocol, which masque accepts (see the deviations), and connect-ip-go's proxy accepts masque's `%2A`.

| Section | Requirement | Behaviour in masque | Module |
| --- | --- | --- | --- |
| §4.6, erratum 8444 (verified) | A wildcard `target` or `ipproto` MUST be percent-encoded, sent as `%2A` | The client sends `%2A`; the proxy accepts `%2A` and also a bare `*` from older clients. | `masque_uri_template`, `masque_uri_ip` |
| §3 | Absolute URI template with `target` and `ipproto` (path or query form) | The client requires an absolute template (`masque_uri_ip:parse_client_template/1`); the server matches path and query forms (`parse_server_template/1`). IP templates only allow `target` and `ipproto`. Prefix targets must be canonical (host bits zero). | `masque_uri_ip`, `masque_uri_template` |
| §4.2, §4.4 | Request carries `:protocol = connect-ip` and `capsule-protocol: ?1` | `connect/3` forces `capsule_protocol => true` for `protocol => ip` and refuses `false` (`{invalid_opts, capsule_protocol_required_for_ip}`). | `masque`, `masque_ip_client_session` |
| §4.3, §4.5 | 2xx carries `capsule-protocol: ?1`, no `content-length` / `content-type` | The client refuses other responses (`capsule_protocol_missing`, `malformed_response`). | `masque_ip_client_session`, `masque_ip_h1_client_session` |
| §4.2 | Upgrade with `Upgrade: connect-ip` | Supported on h1, same checks as CONNECT-UDP. | `masque_h1_server`, `masque_ip_h1_*` |
| §4.6 | Proxy limits traffic to the requested `target` / `ipproto`; ICMP is always allowed | The default handler drops packets outside the scope (`scope_target`, `scope_ipproto`); a hostname target only reaches its advertised routes; a prefix target drops non-public destinations unless `allow_private`. ICMP (IPv4) and ICMPv6 (IPv6) pass whatever `ipproto` is. | `masque_ip_proxy_handler`, `masque_ip_packet` |
| §4.8 | Walk the IPv6 extension header chain to the first non-extension protocol | Hop-by-Hop (0), Routing (43), Fragment (44), Destination Options (60), AH (51), Mobility (135), HIP (139), Shim6 (140) and the experimental 253 and 254 are walked; ESP (50) ends the walk. | `masque_ip_packet` |
| §4.7.1 | Non-zero Request ID answers a prior ADDRESS_REQUEST; ID 0 is unprompted | Both sides track pending ids. The client's `assign_addresses/2` returns `{no_such_pending_request, Id}`; on the server an `{assign, Entries}` action containing an unmatched id is skipped as a whole. | `masque_ip_client_session`, `masque_ip_server_session`, `masque_ip_h1_server_session` |
| §4.7.1 | Every ADDRESS_ASSIGN carries the full list of assigned addresses; one left out is removed | The default handler answers each ADDRESS_REQUEST with the new entries under their request ids, followed by every address it assigned earlier, with request id 0. An ADDRESS_ASSIGN a session or the client sends on its own (rejections) repeats the addresses the last one left the peer holding. The chain hop relays every upstream ADDRESS_ASSIGN, an empty one too, and sends an entry with an id it never forwarded as id 0. The client replaces its list with each ADDRESS_ASSIGN; `ip_info/1` does not list rejection entries. | `masque_ip_proxy_handler`, IP sessions, `masque_chain_handler` |
| §4.7.1 | Hostname targets are resolved before the 2xx and advertised | All three listeners run the `resolver` through `masque_ip:resolve_target/3` before `accept/1`; the result is in `resolved_addresses` and the default handler advertises it. A failure answers 502. | `masque_ip`, listeners |
| §4.7.2 | At least one entry; Request IDs non-zero and unique per sender; an empty ADDRESS_REQUEST aborts the stream | Enforced on encode and decode (`empty_address_request`, `duplicate_request_id`); a received one that fails aborts the stream on both roles. | `masque_ip_capsule`, IP sessions |
| §4.7.2 | The receiver SHALL respond to every Request ID | With no pool, or when the pool is exhausted, the default handler answers with the all-zero "no address" entry. The server sessions answer with that entry the ids past the 64 pending ones, every id when the handler has no `handle_address_request/2`, and the ids an `{assign, _}` from the handler leaves out (a handler that returns no `{assign, _}` answers later, as the chain hop does). The client answers the proxy's ids past 64 pending ones the same way. | `masque_ip`, `masque_ip_proxy_handler`, IP sessions |
| §4.7.3 | Ordered by (version, protocol, start); disjoint within (version, protocol); protocol-0 ranges do not overlap other protocols; start <= end; a capsule that breaks this aborts the stream | All four checks in `validate_routes_result/1`, on encode and decode; a received one that fails aborts the stream on both roles. The default handler sorts its routes and merges overlapping or adjacent ones (`masque_ip_capsule:normalize_routes/1`). An `{advertise, _}` that still fails to encode is not sent and is logged as a warning. | `masque_ip_capsule`, `masque_ip_proxy_handler`, IP sessions |
| §4.7 (example in §8.2) | Both endpoints may send every capsule | Client API: `request_addresses/2`, `assign_addresses/2`, `advertise_routes/2`. Server actions: `{request_addresses, _}`, `{assign, _}`, `{advertise, _}`. The chain hop relays all three both ways. | `masque`, IP sessions, `masque_chain_handler` |
| §5, §6 | Datagram payload: context id 0 is a full IP packet; unknown contexts dropped | As stated, on every transport. | `masque_datagram`, IP sessions |
| §7.2 | An IPv6 tunnel link MTU is at least 1280; endpoints check it with a 1232-byte ICMPv6 echo unless they know otherwise; MUST abort when QUIC cannot carry 1280 bytes | On h3 the client checks the datagram size after the 2xx and the proxy before the handler runs; either aborts with `{mtu_too_low, Got, 1280}`. masque does not send the echo probe itself, see the deviations. The default handler answers echo requests sent to `ff02::1` or to its `link_local_address` (default `fe80::1`), so a peer's probe succeeds. | IP sessions, `masque_ip_proxy_handler` |
| §7.2 | Decrement TTL / Hop Limit upon encapsulation, not decapsulation | The default handler does not decrement the client's packets. Packets that go into the tunnel are decremented: `forward_fun` replies (by the handler) and injected packets (by the session); one that runs out is dropped (`ttl_zero`) and ICMP Time Exceeded goes back toward its source. ICMP errors masque builds are not decremented. `ttl_decrement => decapsulation` keeps the earlier behaviour (decrement the client's packets, Time Exceeded to the client). | `masque_ip_proxy_handler`, IP server sessions |
| §7.2.1 | SHOULD signal forwarding errors with ICMP | The default handler answers source, scope and destination drops with Destination Unreachable (ICMPv4 code 13; ICMPv6 code 5 for a bad source, code 1 otherwise), Time Exceeded and Packet Too Big / Fragmentation Needed above `mtu` (default 1500). No ICMP error answers an ICMP error, a multicast or broadcast destination or an unspecified source. Errors are rate limited per tunnel (`icmp_rate_limit`, default 10 per second); drops are counted either way. Payloads are truncated to 548 bytes (v4) and 1232 bytes (v6). | `masque_ip_proxy_handler`, `masque_icmp` |
| §10.1 | A packet that does not fit a QUIC DATAGRAM frame is not sent; SHOULD answer ICMP Packet Too Big | On h3 the session drops it (`mtu_exceeded`) and hands ICMP Packet Too Big (Fragmentation Needed for IPv4) for its source to the handler as `{masque_ip_icmp, Icmp}`; the default handler passes it to `forward_fun`, the chain hop sends it upstream. Rate limited like other errors. | `masque_ip_server_session`, `masque_ip_proxy_handler`, `masque_chain_handler` |
| §11 | Drop packets with spoofed source addresses when the allowed prefixes are known | The default handler drops packets whose source is outside the assigned prefixes, and every packet before an assignment unless the source is in `allowed_source_prefixes` (`bcp38` drop counter). The client checks inbound packets against the prefixes it assigned to the proxy when `source_filter => true`. | `masque_ip_proxy_handler`, IP client sessions |
| §4.7 | Malformed capsule is a stream error; rejections carry Proxy-Status | Reset with `H3_MESSAGE_ERROR` / `PROTOCOL_ERROR`, socket closed on h1; see RFC 9209 below. | IP sessions, listeners |

Deviations and additions:
- `'*'` and private targets are refused with 403 unless the listener sets `allow_private` (local policy, not required by the RFC).
- Every server session (h3, h2 and h1) keeps at most 64 unanswered ADDRESS_REQUEST ids per session and rejects the rest at once; the client does the same for the proxy's requests.
- The proxy accepts a bare `*` wildcard as well as `%2A` (erratum 8444 makes the bare form invalid), so clients written before the erratum keep working. The client sends `%2A`.
- The IP URI template rejects variables other than `target` and `ipproto` (section 3 allows a server to add others).
- The default handler forwards accepted packets to a user `forward_fun`; without one, packets are dropped. The RFC leaves the data plane to the implementation.
- Neither endpoint sends the section 7.2 ICMPv6 echo probe. On h3 the QUIC datagram size checked at the start stands in for the probe; h2 and h1 carry packets in capsules and are not checked. A peer that sends the probe gets its answer.
- Only h3 checks the size of packets sent into the tunnel; on h2 and h1 capsules carry any size.
- For IPv4, Fragmentation Needed is sent for a packet too big for the tunnel even when its DF bit is clear: the proxy does not fragment.
- ICMP errors the proxy builds use the invoking packet's destination as their source address, not an address of the proxy.
- Without `source_filter`, the client delivers inbound packets to its owner unchecked; an owner that knows the allowed prefixes applies BCP 38 itself.

## RFC 9209: The Proxy-Status HTTP response header

| Requirement | Behaviour in masque | Module |
| --- | --- | --- |
| §2.1.1: the most specific error type SHOULD be sent | Every listener rejection carries `proxy-status: masque; error=<type>`, the type from the reason (`masque_errors:proxy_status/1`): `http_request_error` for a malformed request (bad method, path, port, host, body fields, duplicate `Host`), `http_request_denied` for an `authenticate` refusal, `dns_error` for a name that did not resolve, `connection_refused`, `connection_timeout`, `destination_ip_unroutable` and `destination_unavailable` for a target that cannot be reached, `destination_ip_prohibited` for a refused address, `proxy_loop_detected`, `http_protocol_error` for an unknown `:protocol`, and `proxy_internal_error` for handler crashes, unknown start failures and overload. | `masque_errors`, listeners |
| §2: an intermediary SHOULD keep the members it received and add its own | A chain listener passes an upstream refusal on with the upstream's status and adds `masque; received-status=<status>`. | `masque_chain_handler`, `masque_errors` |

Deviations:
- The proxy identifier is always `masque`; it is not configurable and does not name the listener.
- No other parameters (`details`, `rcode`, `next-hop`) are sent; `received-status` only on a refusal passed on by a chain listener.
- A chain listener does not forward the upstream's own Proxy-Status members: the client sessions keep the status of a refused response but not its fields.
- Some statuses differ from the RFC's recommendations: a loop is 508 (recommended 502), a refused address is 403 on CONNECT-UDP, CONNECT-IP and capsule-framed CONNECT-TCP (recommended 502; raw CONNECT-TCP keeps 502), and request errors tagged `http_protocol_error` or `http_request_error` are 4xx or 501 rather than 502.
- Proxy-Status is sent on handshake rejections and on the 2xx or 101 of a capsule-framed CONNECT-TCP tunnel (`proxy-status: masque`), not on other success responses or when a tunnel fails later.
- A handler can replace the header by returning `{reject, Reason, [{<<"proxy-status">>, Value}]}`.

## RFC 9110: HTTP Semantics (CONNECT, Upgrade, Via)

| Section | Requirement | Behaviour in masque | Module |
| --- | --- | --- | --- |
| §9.3.6 | CONNECT to `host:port`; a 2xx turns the connection into a tunnel | Classic CONNECT-TCP on h1: the listener parses the authority-form target (IPv6 in brackets); the client treats any 2xx as success. `proxy_authorization` is sent as `Proxy-Authorization` on this path only, and refused if it contains CR or LF. | `masque_h1_server`, `masque_tcp_h1_client_session`, `masque_tcp_h1_server_session`, `masque_uri` |
| §7.2 with RFC 9112 §3.2.3 | `Host` matches the CONNECT target | The h1 listener refuses a missing or different `Host` with 400 (`bad_host`). | `masque_h1_server` |
| §7.2 with RFC 9112 §3.2 | A request with more than one `Host` is a 400 | The h1 listener refuses it before routing (`bad_request`). | `masque_h1_server` |
| §7.8 | Upgrade needs `Connection: Upgrade`; a 101 names the protocol; a server ignores `Upgrade` on an HTTP/1.0 request | The h1 listener requires the token (`bad_protocol` otherwise); every h1 client checks `Connection: Upgrade` and a single `Upgrade` with its token on the 101 (`bad_upgrade_response`). An HTTP/1.0 request that carried `Upgrade` is answered 400 (`bad_request`): h1 0.11.1 ignores the field on HTTP/1.0, and the listener reads the request version with `h1:request_version/2`. | `masque_h1_server`, `masque_http`, h1 client sessions |
| §7.6.3 | `Via` records the hops | Chain handlers add their pseudonym to `via` on the upstream request, with the received-protocol of the request they got (`3`, `2` or `1.1`), and refuse a request that already names them (508, `loop_detected`). | `masque_chain_handler` |

A rejected h1 request is answered with `connection: close` and the connection is closed (RFC 9931, which updates RFC 9298): h1 closes it after the response, draining what the client sent past the request first, so the client reads the whole response.

## RFC 8441 and RFC 9220: Extended CONNECT

| Requirement | Behaviour in masque | Module |
| --- | --- | --- |
| Server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` | h3 listener merges `enable_connect_protocol => 1` into its settings; h2 listener sets `enable_connect_protocol => true`. | `masque_server`, `masque_h2_server` |
| Client uses `:protocol` only when the peer allows it | h2 and h3 clients read the peer SETTINGS and fail with `no_extended_connect` (and `no_h3_datagram` on h3 without HTTP Datagrams). | client sessions |
| A `:protocol` the server does not support is refused | Listeners answer 501 (`bad_protocol`, `http_protocol_error`). | `masque_server`, `masque_h2_server` |
| `:scheme`, `:authority`, `:path` present | Listeners refuse a request without `:scheme` or `:authority` (`bad_path`, 404); the h2 listener no longer falls back to `host` or a fixed scheme. | `masque_server`, `masque_h2_server` |

Stream and connection semantics from RFC 9114 and RFC 9113 that the sessions rely on:
- GOAWAY: on h3 a stream with an id at or above the GOAWAY id ends with `goaway`; on h2 a stream above the last stream id does. Lower streams keep running.
- Errors reset the stream: `H3_MESSAGE_ERROR` / `PROTOCOL_ERROR` for capsule errors, `H3_CONNECT_ERROR` / `CONNECT_ERROR` for CONNECT-TCP.

## draft-ietf-httpbis-connect-tcp

masque implements draft-ietf-httpbis-connect-tcp-18 (in the RFC Editor queue) in capsule framing. Capsule framing is the client default. It also keeps the raw framing of the earlier revisions (`tcp_framing => raw`), and the provisional capsule codes of drafts -09 and -10 for peers that still use them. See [connect-tcp](../2-use/connect-tcp.md#two-framings).

| Requirement | Behaviour in masque | Module |
| --- | --- | --- |
| §3: Extended CONNECT with `:protocol = connect-tcp` and a URI template | Default template `/.well-known/masque/tcp/{target_host}/{target_port}/` (`tcp_uri_template` on the listener, `uri_template` on the client). | `include/masque.hrl`, `masque_tcp_client_session`, listeners |
| §3: the proxy attempts the TCP connection before its final response | The handler dials in `init/2`; the 2xx or 101 goes out only once it has connected. | TCP server sessions |
| §3.1, §8.3: bytes in `DATA` (`0x08`) and `FINAL_DATA` (`0x09`) | Capsule framing. Empty capsules are valid. Other capsule types are skipped, including after `FINAL_DATA`. | `masque_tcp_capsule`, TCP sessions |
| §3.1: payload is forwarded before its capsule ends | The decoder passes payload on as it arrives and only buffers capsule headers, so a capsule of any size is accepted and never held whole in memory. `max_capsule_size` does not apply to CONNECT-TCP. | `masque_tcp_capsule` |
| §3.2: h1 `GET` with `Upgrade: connect-tcp`, answered with 101 | On the h1 listener's `tcp_uri_template`, with or without `Capsule-Protocol`; the 101 repeats the request's token. Classic `CONNECT` keeps working beside it. | `masque_h1_server`, `masque_tcp_h1_*_session` |
| §3.2, §3.3: `Capsule-Protocol: ?1` SHOULD be on requests and successful responses | The client always sends it in capsule framing; listeners always answer with it. On h3 and h2 a plain `connect-tcp` request without it is raw framing, unless the listener sets `tcp_framing => capsule`. | TCP sessions |
| §3.4.2: authentication uses `Authorization` and 401, not 407 and `Proxy-Authorization` | On the h1 upgrade the client sends `proxy_authorization` as `Authorization` (replacing one in `request_headers`). Classic CONNECT keeps `Proxy-Authorization`. Listeners leave the credential to the `authenticate` fun. | `masque_tcp_h1_client_session` |
| §3.4.3: h1 responses that could be cached carry `Cache-Control: no-store` | Every h1 listener rejection carries it. No other caching headers are sent. | `masque_h1_server` |
| §3.5: `FINAL_DATA` is a FIN; a stream ending without it is an abort | An abort resets the target (`SO_LINGER` 0) and the stream (`H3_CONNECT_ERROR`, `CONNECT_ERROR`); the client reports `peer_reset`. A clean end sends `FINAL_DATA` before the stream's FIN. | TCP sessions |
| §3.5: a graceful close closes the send stream gracefully | `masque:close/1`, and an owner that exits with `normal` or a shutdown, send `FINAL_DATA` (capsule framing) and the stream FIN on h3 and h2. On h1 in capsule framing the session writes `FINAL_DATA` behind any send in progress, waits up to 2 s for it, then closes the connection. | TCP client sessions |
| §3.5: otherwise the send stream SHOULD close abruptly: `H3_CONNECT_ERROR` on h3, `CONNECT_ERROR` on h2, TCP RST on h1 without TLS | `masque:abort/1`, an owner crash, `rx_overflow`, a failed close, invalid data and trailers from the proxy reset the client stream with `H3_CONNECT_ERROR` (`0x10f`) or `CONNECT_ERROR`, a pooled stream included; on h1 the connection closes without `FINAL_DATA`. The relay handler aborts its upstream when its downstream ends any other way than normally. A listener mounted on a cleartext h1 server closes an aborted capsule tunnel with an RST (`SO_LINGER` 0). | TCP sessions, `masque_upstream_owner`, `masque_chain_handler` |
| §3.5: a local timeout is an abrupt close | In capsule framing the session idle timeout and the handler's `eof_timeout` reset the stream and the target instead of closing them. | TCP server sessions, `masque_tcp_proxy_handler` |
| §3.5.1: invalid data is an abrupt close | A second `FINAL_DATA`, `DATA` after `FINAL_DATA`, or a capsule cut by the end of the stream aborts the tunnel with `{bad_capsule, Reason}`, on the listener and on the client (including bytes that arrive with the h1 101). | `masque_tcp_capsule`, TCP sessions |
| §4.1: optimistic data before the 2xx on h2 and h3 | Bytes that arrive before the target is connected are held by the transport and written once it is; they are dropped with the request if the connection fails. The client does not send early. | `masque_tcp_server_session` |
| §4.1: race address families (Happy Eyeballs) | In capsule framing the default handler resolves both families and races them (RFC 8305 order, 250 ms apart); losing connections are closed before any payload. Raw framing dials the first address, as before. | `masque_tcp_dial`, `masque_tcp_proxy_handler` |
| §4.2: 4xx for refused requests, 5xx for failed connections | Malformed requests get 400, 404 or 405. In capsule framing a target the policy refuses gets 403, a connection timeout 504, and any other failed connection 502. Raw framing keeps 502 for all three. | `masque_tcp_proxy_handler`, `masque_errors` |
| §4.3: 100 (Continue) when the proxy accepts a request | Every capsule-framed request gets 100 before the target is dialed, on all three transports. Raw requests get it only when they carry `Expect: 100-continue`. The client skips interim responses. | TCP server sessions, TCP client sessions |
| §4.3: `Proxy-Status` on success and failure; no trailers | `proxy-status: masque` on the 2xx or 101 of a capsule tunnel; rejections carry it as described under RFC 9209. No trailers are sent. Received trailers are malformed: quic_h3 closes the connection (`H3_FRAME_UNEXPECTED`) on HEADERS after a CONNECT request; h2 resets a tunnel stream that gets them after the 2xx and, since h2 0.18.1, tells the session, which resets the target (`peer_reset`); it passes on ones sent before the 2xx, which abort the tunnel (`trailers_received`). | TCP sessions, transports |
| §5.2: a client falls back from classic CONNECT | An h1 client in raw framing that gets 501, or 426 with `Upgrade: connect-tcp`, retries once in capsule framing on the default template and remembers the proxy (by host and port, until the node restarts) so later tunnels skip the refused CONNECT. | `masque_tcp_h1_client_session` |
| §8.1.1: the interop token is `connect-tcp-12` | Listeners accept `connect-tcp-12` and always frame it in capsules with the permanent codes. The client sends it with `tcp_protocol => <<"connect-tcp-12">>`. | listeners, TCP client sessions |
| Drafts -09 and -10: tokens `connect-tcp-08` and `connect-tcp-07`, codes `0x2028d7f0` and `0x2028d7f1` | Listeners accept both tokens and use the provisional codes for them; the client uses them with `tcp_protocol => <<"connect-tcp-08">>` or `<<"connect-tcp-07">>`. | `masque_tcp_capsule`, listeners, TCP client sessions |
| Earlier revisions: raw bytes, no capsule protocol | With `tcp_framing => raw` on h3 and h2; on h1 the client's first try is a classic CONNECT, which is raw. No `capsule-protocol` in either direction; a 2xx that claims it fails with `{bad_response, capsule_protocol}`; `send_capsule/3` returns `{error, not_supported}`. | `masque_tcp_client_session`, `masque_tcp_server_session` |
| END_STREAM is a TCP FIN, one per direction (raw) | The peer's FIN is reported as `{masque_closed, Sess, peer_fin}` and the session stays writable; `shutdown_write/1` sends ours. A half-closed tunnel with no traffic for 30 s ends with `eof_timeout`. | TCP sessions, `masque_tcp_proxy_handler` |
| Errors abort the stream | Target reset, target error, failed or blocked (30 s) writes, and handler crashes reset with `H3_CONNECT_ERROR` / `CONNECT_ERROR`. | `masque_tcp_server_session` |

Deviations and open points:
- On h3 and h2 a plain `connect-tcp` request is capsule framing only with `capsule-protocol: ?1` by default, since raw clients of the earlier revisions send the same token. A listener with `tcp_framing => capsule` serves -18 clients that leave the header out, at the cost of those raw clients. Interop tokens are never ambiguous.
- Section 8.1.1 asks implementations of this draft version to use `connect-tcp-12`. masque's client sends `connect-tcp`, the name the RFC registers, with `capsule-protocol: ?1`; a peer that only knows the interop token is reached with `tcp_protocol => <<"connect-tcp-12">>`.
- The only other capsule implementation found is the draft author's masque-go fork, which speaks draft -09 (`connect-tcp-08`). It is not yet part of the interop suite.
- On HTTP/2, the listener only accepts Extended CONNECT, so a client sending classic `CONNECT host:port`, such as `curl --proxy-http2`, gets 501. A -18 client takes that as the cue to retry on the default template (§5.2).
- h1 in raw framing cannot half-close: OTP `ssl` drops the connection on the peer's `close_notify`, so a FIN in either direction ends the tunnel. Capsule framing can.
- An h1 abort over TLS is sent as a TLS close with `close_notify`, because OTP `ssl` has no way to close a connection without it. A capsule peer still sees the abort, since the stream ends without `FINAL_DATA`; masque's client reports it as `peer_reset`. A peer that relies only on the missing `close_notify` sees a clean close, and so does any peer when the abort follows a `FINAL_DATA` already sent (`shutdown_write/1`) or when the tunnel is a classic CONNECT.
- After a peer's QUIC RESET_STREAM on an h3 tunnel, quic_h3 resets the listener's half of the stream with `H3_REQUEST_INCOMPLETE`, not `H3_CONNECT_ERROR`; the target still gets an RST.
- Only h1 clients fall back from classic CONNECT: on h3 and h2 masque's client always uses Extended CONNECT.
- The TLS early data options of §4.1 are all optional, and masque does nothing specific for them: whether early data is used is left to the transport options. `RESET_STREAM_AT` (§3.5) is not used.
- Happy Eyeballs applies to the default resolver and to a `resolver` that returns a list; with `family` set, only that family is dialed.

## draft-ietf-masque-connect-udp-listen-16 (Connect-UDP-Bind)

masque implements draft -16 (August 2026, submitted for publication). Codes, headers and payload formats are the same as in -11; -16 tightens the rules below.

| Requirement | Behaviour in masque | Module |
| --- | --- | --- |
| §6: `Connect-UDP-Bind: ?1` (RFC 9651 Boolean) on request and response enables the extension | Listeners only look at the header with `accept_bind => true`; an invalid value is treated as absent and the request stays plain CONNECT-UDP. Unknown parameters are ignored (`?1;x` enables it); a field sent more than once, or a list, is ignored. The proxy always sends `Connect-UDP-Bind: ?1` on an accepted bind, whatever its handler returns. The client refuses a 2xx without it (`missing_bind_response_header`). | `masque_uri_udp_bind`, listeners, udp-bind client sessions |
| §2: same URI template as CONNECT-UDP; `*` for an unscoped bind, percent-encoded as `%2A`; only one `*` is malformed (4xx, SHOULD be 400) | The client sends `%2A` for both; the bind matcher accepts `%2A` (and a bare `*`) for both host and port; one alone gets 400. The plain CONNECT-UDP matcher still refuses `*`. | `masque_uri_udp_bind`, `masque_uri_template` |
| §7: `Proxy-Public-Address` on the response (RFC 9651 List of `"ip:port"` strings); the proxy MUST send it | The default handler sets it from `public_addresses`, `public_address_fun` or the bound socket address, and refuses a wildcard bind without one. When a handler gives no valid list, the session refuses the bind with 500 and runs the handler's `terminate/2`. Field lines sent more than once are combined into one list. The client refuses a 2xx without a valid list (`missing_proxy_public_address`). | udp-bind server sessions, `masque_udp_bind_proxy_handler`, `masque_uri_udp_bind` |
| Payload formats (sections 4 and 5): compressed = UDP payload only; uncompressed = family, address, port, payload | As stated. | `masque_udp_bind_payload` |
| §3: context id 0 | Scoped bind: raw UDP to the scoped peer, as in RFC 9298. Unscoped bind: the request stream is aborted (`context_zero_datagram`), on the proxy and on the client. | udp-bind sessions |
| COMPRESSION_ASSIGN / ACK / CLOSE capsules | Codes `0x11`, `0x12`, `0x13` (provisional). Context id 0 is malformed; IP version 0 omits address and port. | `masque_compression_capsule` |
| §3.1, §4: context id parity, duplicates, tuple conflicts, uncompressed context rules | Client ids even, proxy ids odd; wrong parity or a duplicate id is malformed; neither side registers a tuple the peer already opened (the client's `assign_compression/2` returns `{error, tuple_open_by_peer}`, the proxy sends on the client's context); when both sides opened a tuple at once, the proxy-opened context is closed (by either side); a repeated tuple from the same side is malformed; only the client opens the single uncompressed context, and may close it and open another; while it is closed, whichever side closed it, the proxy opens no new compressed contexts, and the ones opened before stay. A malformed capsule aborts the stream. | `masque_compression_table`, udp-bind sessions |
| §3.1, §9: accept or reject each COMPRESSION_ASSIGN | Accepted: COMPRESSION_ACK. Rejected with COMPRESSION_CLOSE, the stream staying open: beyond the context limit (`max_compression_contexts_in`, else `max_compression_contexts`, default 1024; `max_compression_contexts_out` bounds the proxy's own), a family the proxy did not advertise, or a peer the handler refuses (`allow_peer/2`; the default handler applies its scope, peer filter and `allow`). | udp-bind sessions, `masque_udp_bind_proxy_handler` |
| §3.3: a closed id is never reused; datagrams on a closed context are discarded | A COMPRESSION_ASSIGN for a closed or rejected id is malformed; late datagrams are dropped. | `masque_compression_table`, udp-bind sessions |
| §9: bound buffering of compression responses; abort at the limit | Compression capsules wait for the transport (h3 retry on `send_ready`, h2 flow control, h1 send timeout) instead of being dropped; one that does not drain in 30 s ends the session (`control_send_failed`). | udp-bind sessions, `masque_stream_send` |
| Datagram on an unknown context | Dropped (`unknown_context`). | udp-bind sessions |

Deviations and policy:
- Reuse of a closed id is detected for the last 64 closed or rejected ids of each table, so memory stays bounded; an older id reused is accepted as new.
- The wire vectors (`masque_udp_bind_vectors_SUITE`) drive the proxy on h3, h2 and h1; their `client_` cases drive the client from a fake proxy (context 0 abort, version-0 ASSIGN from the proxy, missing bind header or address list), since masque's own proxy never sends that input.
- §2 lets a scoped request (a real `target_host` and `target_port`) fall back to plain CONNECT-UDP when the proxy does not enable bind. The client does not: `masque:bind_connect/3` refuses a 2xx without the bind header on a scoped request too (`missing_bind_response_header`). Use `masque:connect/3` for plain CONNECT-UDP.
- A scoped bind exchanges packets only with the template target (the default handler's scope): datagrams, registrations and inbound packets for other peers are dropped or rejected.
- A static `public_addresses` list is advertised as given, so a proxy behind NAT can announce its public address; its families are not checked against the bound socket.

Library policy, not required by the draft:
- An outbound context is only used after its COMPRESSION_ACK (wait-for-ACK). The draft allows sending earlier at the risk of drops.
- The library never assigns contexts on its own; you drive them with `masque:assign_compression/2`, `open_uncompressed_context/1` and `close_compression/2`.
- The proxy keeps at most `max_pending_compression_responses` (default 16) assigns waiting for an ACK and drops the rest (`pending_limit`).
- The default peer filter only allows public peers (`masque_ip:is_public/1`); loopback needs `allow_loopback`, other non-public peers `allow_private`. IPv4-mapped IPv6 peers are checked as IPv4.
- Bind is also offered over HTTP/1.1, through the CONNECT-UDP upgrade.
- `upstream_pool => true` is ignored for udp-bind; each bind session dials its own connection and closes it with the session.

Next: [messages-and-errors](messages-and-errors.md), or [testing](../3-change/testing.md) for the suites that pin these rows.

## draft-rosomakho-masque-reverse-connect-01

Reverse connect is off unless a listener sets `accept_listen => true`. The draft is an individual draft (21 June 2026, expires 23 December 2026). See [reverse connect](../2-use/reverse-connect.md).

| Section | Requirement | Behaviour in masque | Module |
| --- | --- | --- | --- |
| §4.1 | Listener template with optional `target` and `ipproto` | `target`: host name, address, prefix, `*`, `*.domain`, `.`; `ipproto`: 6, 17, `*`. A missing variable means `*`. Default `/.well-known/masque/listen/{target}/{ipproto}/`. Other variables are refused. | `masque_uri_reverse` |
| §4.2, §4.3 | `connect-listen` over `Upgrade` (h1) or Extended CONNECT (h2, h3), capsule protocol | Listener answers 101 or 200 with `capsule-protocol: ?1`; the client requires it. | listeners, `masque_listen_*_session` |
| §4.4 | AVAILABLE_SERVICES, a full list that replaces the previous one | Decoded and handed to `handle_services/2`; a malformed record aborts the channel. | `masque_reverse_capsule`, `masque_listen_server_session` |
| §5.1 | CONNECTION_REQUEST with a request id unique on the channel | Ids are random 62-bit values, registered before the capsule is sent. The client aborts the channel on a reused id or a malformed request, and declines requests past `max_pending_requests` (64) unanswered ones. An unanswered request expires on the client after `pending_request_timeout_ms` (default 30 s), without a capsule. | `masque_reverse_registry`, `masque_listen_client_session`, `masque_reverse_ids` |
| §5.1 | CONNECTION_REQUEST_DECLINED; one for no outstanding request is an error | The requester gets `{error, declined}`; an unknown id or a malformed capsule aborts the channel (`H3_MESSAGE_ERROR`, `PROTOCOL_ERROR`, on h1 the connection closes). A DECLINED for a request that timed out on the proxy is ignored: it crossed the timeout. | `masque_listen_server_session` |
| §5.2 | Accept template with `request_id`, MAY contain other variables | Default `/.well-known/masque/accept/{request_id}/`; a template without `request_id` is refused, by the listener at start and by `masque:reverse_listen/3` before it connects (`bad_template`). Other variables are allowed; the agent fills them from `uri_vars`. | `masque_uri_reverse` |
| §5.2.1, §5.2.2 | Malformed accept: 400; unknown id: 404 | `bad_request` (400) and `unknown_request` (404). An accept on another connection (h2, h3) or with another identity (h1) also gets 404. | `masque_reverse_listener` |
| §5.2.1, §5.2.2 | A non-conforming accept response is a failed accept | A UDP accept that is not answered with the capsule protocol fails (`capsule_protocol_not_acknowledged`) on h3, h2 and h1. See the deviations for TCP accepts. | UDP client sessions |
| §5.2.2 | h2/h3 accepts run on the control channel's connection | The client opens the channel on a connection of its own and every accept stream on it; the proxy checks the connection. | `masque_upstream_owner`, `masque_reverse_listener` |
| §5.3 | TCP in connect-tcp DATA and FINAL_DATA capsules | Accept streams run as CONNECT-TCP in capsule framing with the draft -18 codes (`0x08`, `0x09`), with its half-close, abort and flow control. No `100 Continue` is sent. | `masque_tcp_*_session`, `masque_reverse_accept_handler` |
| §5.3 | UDP like CONNECT-UDP | Accept streams for UDP services run as CONNECT-UDP sessions: QUIC datagrams on h3, DATAGRAM capsules on h2 and h1. Datagrams too large for the path are dropped. | `masque_*_server_session`, `masque_reverse_accept_udp_handler`, UDP client sessions |
| §6 | Authenticated users only; on h1 authenticate the channel and each accept; random ids | `listen_handler`'s `authenticate/1` runs for every `connect-listen` and every h1 `connect-accept`; without a handler, channels get 403. | `masque_reverse_listener` |
| §7.3 | Capsule types TBD | Provisional private values: AVAILABLE_SERVICES `0x5243a0`, CONNECTION_REQUEST `0x5243a1`, CONNECTION_REQUEST_DECLINED `0x5243a2`. None is a GREASE value. | `include/masque_reverse.hrl` |

Deviations and open points:
- The capsule codes are masque's own until the draft assigns them, so only masque peers interoperate. No other implementation of the draft is known.
- The control channel has no idle timeout by default (`listen_idle_timeout_ms`); the draft does not set one.
- The client checks the last 4,096 request ids of a channel for reuse, so its memory stays bounded; a reuse of an older id is accepted as new. The draft gives no limit, and the ids are random, so there is no high-water mark to keep instead.
- Past `max_pending_requests` unanswered requests the client declines new ones itself (CONNECTION_REQUEST_DECLINED), so a proxy cannot grow the agent's memory or its owner's mailbox. The draft does not require a limit.
- A request the owner leaves unanswered expires on the client after `pending_request_timeout_ms` with no capsule sent: the proxy has given up on it by then, and a late DECLINED would be an error for a strict proxy.
- The proxy remembers the last 4,096 requests that timed out on a channel and ignores a DECLINED for them; a DECLINED for an older one aborts the channel.
- On a TCP accept (h3, h2, h1) the client does not require `Capsule-Protocol: ?1` on the response: draft-ietf-httpbis-connect-tcp-18 sections 3.2 and 3.3 make it a SHOULD for the proxy, so a response without it is still accepted. On h1 every accept checks `Connection: Upgrade` and the `connect-accept` token of the 101.

## Related drafts masque does not implement

These MASQUE drafts touch what masque does but are not implemented. Each would be a new, opt-in feature; they are listed as candidates in [features](../features.md).

| Draft | State (November 2026) | What it adds |
| --- | --- | --- |
| draft-ietf-masque-connect-ip-dns-07 | MASQUE working group | DNS configuration capsules for CONNECT-IP (resolver addresses and search domains for the client) |
| draft-ietf-masque-http-datagram-compression-02 | MASQUE working group | Context-ID based compression of CONNECT-UDP payloads (the idea udp-bind uses for its peers) |
| draft-ietf-masque-quic-proxy-10 | MASQUE working group | QUIC-aware proxying: forwarding QUIC packets by connection ID without re-encapsulation |
| draft-ietf-masque-connect-ethernet-18 | MASQUE working group | Proxying Ethernet frames over HTTP |
