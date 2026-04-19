%%% -*- erlang -*-
%%%
%%% CONNECT-IP (RFC 9484) protocol constants — IANA "HTTP Capsule Types"
%%% registrations, context-ID assignments, and IP-layer wire constants.

-ifndef(MASQUE_IP_HRL).
-define(MASQUE_IP_HRL, true).

%%====================================================================
%% Extended CONNECT
%%====================================================================

-define(MASQUE_CONNECT_IP_PROTOCOL, <<"connect-ip">>).

-define(MASQUE_DEFAULT_IP_URI_PATH_PATTERN,
        <<"/.well-known/masque/ip/{target}/{ipproto}/">>).

%%====================================================================
%% Capsule types (RFC 9484 §5)
%%====================================================================

-define(MASQUE_CAPSULE_ADDRESS_ASSIGN,       16#01).
-define(MASQUE_CAPSULE_ADDRESS_REQUEST,      16#02).
-define(MASQUE_CAPSULE_ROUTE_ADVERTISEMENT,  16#03).

%%====================================================================
%% Datagram context IDs (RFC 9484 §6)
%%====================================================================

%% Context ID 0 carries full IP packets. Non-zero context IDs are
%% reserved for extensions; the receiver must buffer briefly then
%% drop unregistered context IDs.
-define(MASQUE_CONTEXT_ID_IP, 0).

%%====================================================================
%% IP layer
%%====================================================================

-define(MASQUE_IP_VERSION_V4, 4).
-define(MASQUE_IP_VERSION_V6, 6).

%% "Any protocol" wildcard for ROUTE_ADVERTISEMENT ranges.
-define(MASQUE_IP_PROTO_ALL, 0).

%% IPv6 minimum MTU (RFC 8200 §5). The mandatory abort in RFC 9484 §8
%% for H3+QUIC-DATAGRAM tunnels uses this value.
-define(MASQUE_IPV6_MIN_MTU, 1280).

%% IPv4 minimum reassembly buffer size from RFC 791.
-define(MASQUE_IPV4_MIN_MTU, 576).

%%====================================================================
%% Records
%%====================================================================

-record(ip_assignment, {
    request_id  :: non_neg_integer(),    %% 0 = unprompted
    version     :: 4 | 6,
    address     :: inet:ip_address(),
    prefix_len  :: 0..128
}).

-record(ip_prefix_request, {
    request_id  :: pos_integer(),        %% nonzero per §4.7.2
    version     :: 4 | 6,
    address     :: inet:ip_address(),
    prefix_len  :: 0..128
}).

-record(ip_route, {
    version     :: 4 | 6,
    start_addr  :: inet:ip_address(),
    end_addr    :: inet:ip_address(),
    ip_protocol :: 0..255
}).

-endif.
