%%% -*- erlang -*-
%%%
%%% MASQUE protocol constants (RFC 9298 - Proxying UDP in HTTP).
%%%
%%% Layered on top of HTTP Datagrams (RFC 9297) and HTTP/3 (RFC 9114),
%%% exposed through `erlang_quic's `quic_h3' API.

-ifndef(MASQUE_HRL).
-define(MASQUE_HRL, true).

%%====================================================================
%% Extended CONNECT (RFC 9220 / RFC 8441)
%%====================================================================

%% The value of the `:protocol' pseudo-header for RFC 9298 requests.
-define(MASQUE_CONNECT_UDP_PROTOCOL, <<"connect-udp">>).

%% The value of the `:protocol' pseudo-header for draft-ietf-httpbis-connect-tcp.
-define(MASQUE_CONNECT_TCP_PROTOCOL, <<"connect-tcp">>).

%% Interop tokens of the CONNECT-TCP drafts. Each always means capsule
%% framing. `connect-tcp-12' (drafts -12 to -18) uses the permanent
%% capsule codes; `connect-tcp-08' (draft -09) and `connect-tcp-07'
%% (draft -10) use the provisional ones.
-define(MASQUE_CONNECT_TCP_12_PROTOCOL, <<"connect-tcp-12">>).
-define(MASQUE_CONNECT_TCP_08_PROTOCOL, <<"connect-tcp-08">>).
-define(MASQUE_CONNECT_TCP_07_PROTOCOL, <<"connect-tcp-07">>).

%% Proxies that refused classic CONNECT but took connect-tcp
%% (draft-ietf-httpbis-connect-tcp-10 section 5.2), keyed by host and port.
-define(MASQUE_TCP_UPGRADE_PROXIES, masque_tcp_upgrade_proxies).

%% Default request URI templates.
%% Variables: `target_host' (IP literal, reg-name, or percent-encoded)
%%            `target_port' (1..65535)
-define(MASQUE_DEFAULT_URI_TEMPLATE,
    <<"/.well-known/masque/udp/{target_host}/{target_port}/">>
).
-define(MASQUE_DEFAULT_TCP_URI_TEMPLATE,
    <<"/.well-known/masque/tcp/{target_host}/{target_port}/">>
).

%%====================================================================
%% Inner datagram framing (RFC 9298 §5)
%%====================================================================

%% Context ID 0 carries raw UDP payloads. Non-zero contexts are reserved
%% for extensions (e.g. compression, ICMP, QUIC-aware proxying).
-define(MASQUE_CONTEXT_ID_UDP, 0).

%% RFC 9298 §5: maximum UDP payload carried in an HTTP Datagram.
%% Anything larger is refused outbound and dropped inbound.
-define(MASQUE_MAX_UDP_PAYLOAD, 65527).

%% Default capsule-buffer ceiling in bytes. Capsules exceeding this
%% trigger a stream reset with H3_MESSAGE_ERROR (RFC 9297 §3.3).
%% 64 KiB covers an IPv6 MTU datagram plus generous capsule overhead;
%% operators expecting larger extension capsules can raise this via
%% `max_capsule_size' in `connect_opts' / listener `handler_opts'.
-define(MASQUE_DEFAULT_MAX_CAPSULE_SIZE, 65536).

%% CONNECT-TCP capsules, draft-ietf-httpbis-connect-tcp-18 section 8.3.
-define(MASQUE_CAPSULE_DATA, 16#08).
-define(MASQUE_CAPSULE_FINAL_DATA, 16#09).
%% The provisional codes of drafts -09 and -10.
-define(MASQUE_CAPSULE_DATA_PROVISIONAL, 16#2028d7f0).
-define(MASQUE_CAPSULE_FINAL_DATA_PROVISIONAL, 16#2028d7f1).

%% Tunnels one client connection may hold (h3, h2); 0 means no limit.
-define(MASQUE_DEFAULT_MAX_TUNNELS, 100).

%% Default bound on a queue-mode client session's receive queue, in
%% received items (datagrams, IP packets or TCP chunks). Override per
%% session with `rx_queue_limit' in `masque:connect/3' opts. Datagram
%% tunnels drop and count past it; CONNECT-TCP ends the tunnel with
%% `rx_overflow'.
-define(MASQUE_DEFAULT_RX_QUEUE_LIMIT, 1000).

%% RFC 9114 §8.1: stream-level error codes we emit.
-define(MASQUE_H3_MESSAGE_ERROR, 16#10E).

%%====================================================================
%% Capsule types (RFC 9298 §7)
%%====================================================================

%% No capsule types are mandatory at the base spec. Unknown capsules
%% MUST be silently ignored per RFC 9297 §3.3. Extension capsules are
%% registered here as they are added to the IANA registry.

%%====================================================================
%% Error mapping (RFC 9298 §3)
%%====================================================================

%% malformed request or path
-define(MASQUE_STATUS_BAD_REQUEST, 400).
%% template did not match
-define(MASQUE_STATUS_NOT_FOUND, 404).
%% :method != CONNECT
-define(MASQUE_STATUS_METHOD_NOT_ALLOWED, 405).
%% resolution / upstream failure
-define(MASQUE_STATUS_BAD_GATEWAY, 502).
%% upstream did not respond
-define(MASQUE_STATUS_GATEWAY_TIMEOUT, 504).
%% policy: self-loop
-define(MASQUE_STATUS_LOOP_DETECTED, 508).
%% :protocol not recognized
-define(MASQUE_STATUS_NOT_IMPLEMENTED, 501).

-endif.
