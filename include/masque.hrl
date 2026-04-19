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

%% Default request URI templates.
%% Variables: `target_host' (IP literal, reg-name, or percent-encoded)
%%            `target_port' (1..65535)
-define(MASQUE_DEFAULT_URI_TEMPLATE,
        <<"/.well-known/masque/udp/{target_host}/{target_port}/">>).
-define(MASQUE_DEFAULT_TCP_URI_TEMPLATE,
        <<"/.well-known/masque/tcp/{target_host}/{target_port}/">>).

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

-define(MASQUE_STATUS_BAD_REQUEST,       400). %% malformed request or path
-define(MASQUE_STATUS_NOT_FOUND,         404). %% template did not match
-define(MASQUE_STATUS_METHOD_NOT_ALLOWED,405). %% :method != CONNECT
-define(MASQUE_STATUS_BAD_GATEWAY,       502). %% resolution / upstream failure
-define(MASQUE_STATUS_GATEWAY_TIMEOUT,   504). %% upstream did not respond
-define(MASQUE_STATUS_LOOP_DETECTED,     508). %% policy: self-loop
-define(MASQUE_STATUS_NOT_IMPLEMENTED,   501). %% :protocol not recognized

-endif.
