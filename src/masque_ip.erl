%%% @doc IP address classification for SSRF protection.
%%%
%%% `is_public/1' returns `false' for loopback, RFC 1918 private,
%%% link-local, multicast, and reserved address ranges in both
%%% IPv4 and IPv6. The built-in proxy handlers call this after DNS
%%% resolution to reject tunnels targeting internal networks.
-module(masque_ip).

-export([is_public/1, reject_requests/1, inject_packet/2]).

-include("masque_ip.hrl").

%% @doc Build the RFC 9484 §5.2 "reject all" answer to a batch of
%% inbound ADDRESS_REQUEST entries: each reply carries the same
%% Request ID and IP Version, an all-zero address, and the maximum
%% prefix length for that version (32 for v4, 128 for v6).
-spec reject_requests([#ip_prefix_request{}]) -> [#ip_assignment{}].
reject_requests(Requests) ->
    [reject_one(R) || R <- Requests].

reject_one(#ip_prefix_request{request_id = Id, version = 4}) ->
    #ip_assignment{
        request_id = Id,
        version = 4,
        address = {0, 0, 0, 0},
        prefix_len = 32
    };
reject_one(#ip_prefix_request{request_id = Id, version = 6}) ->
    #ip_assignment{
        request_id = Id,
        version = 6,
        address = {0, 0, 0, 0, 0, 0, 0, 0},
        prefix_len = 128
    }.

%% @doc Push an IP packet into a server session for delivery to its
%% connected client. Non-blocking. Intended for out-of-band injectors
%% (e.g. a TUN device owner that holds the session pid via the
%% address registry); accepted by both `masque_ip_server_session'
%% (h2/h3) and `masque_ip_h1_server_session' (h1).
-spec inject_packet(pid(), binary()) -> ok.
inject_packet(SessionPid, Packet) when
    is_pid(SessionPid),
    is_binary(Packet)
->
    gen_server:cast(SessionPid, {inject_packet, Packet}).

-spec is_public(inet:ip_address()) -> boolean().

%% IPv4

%% 0.0.0.0/8
is_public({0, _, _, _}) ->
    false;
%% RFC 1918
is_public({10, _, _, _}) ->
    false;
%% RFC 6598 CGN
is_public({100, B, _, _}) when B >= 64, B =< 127 -> false;
%% loopback
is_public({127, _, _, _}) ->
    false;
%% link-local
is_public({169, 254, _, _}) ->
    false;
%% RFC 1918
is_public({172, B, _, _}) when B >= 16, B =< 31 -> false;
%% RFC 6890
is_public({192, 0, 0, _}) ->
    false;
%% TEST-NET-1
is_public({192, 0, 2, _}) ->
    false;
%% 6to4 relay
is_public({192, 88, 99, _}) ->
    false;
%% RFC 1918
is_public({192, 168, _, _}) ->
    false;
%% benchmarking
is_public({198, 18, _, _}) ->
    false;
%% benchmarking
is_public({198, 19, _, _}) ->
    false;
%% TEST-NET-2
is_public({198, 51, 100, _}) ->
    false;
%% TEST-NET-3
is_public({203, 0, 113, _}) ->
    false;
%% multicast + reserved
is_public({A, _, _, _}) when A >= 224 -> false;
%% IPv6

%% ::  unspecified
is_public({0, 0, 0, 0, 0, 0, 0, 0}) ->
    false;
%% ::1 loopback
is_public({0, 0, 0, 0, 0, 0, 0, 1}) ->
    false;
%% ::ffff:0:0/96 mapped v4
is_public({0, 0, 0, 0, 0, 16#FFFF, _, _}) ->
    false;
%% 64:ff9b::/96 NAT64
is_public({16#64, 16#FF9B, _, _, _, _, _, _}) ->
    false;
%% discard 100::/64
is_public({16#100, _, _, _, _, _, _, _}) ->
    false;
%% teredo
is_public({16#2001, 0, _, _, _, _, _, _}) ->
    false;
%% documentation
is_public({16#2001, 16#DB8, _, _, _, _, _, _}) ->
    false;
is_public({A, _, _, _, _, _, _, _}) when
    A >= 16#FC00,
    %% ULA fc00::/7
    A =< 16#FDFF
->
    false;
is_public({A, _, _, _, _, _, _, _}) when
    A >= 16#FE80,
    %% link-local fe80::/10
    A =< 16#FEBF
->
    false;
%% multicast ff00::/8
is_public({A, _, _, _, _, _, _, _}) when A >= 16#FF00 -> false;
is_public(_) ->
    true.
