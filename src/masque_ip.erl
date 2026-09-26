-module(masque_ip).
-moduledoc """
IP address classification for SSRF protection.

`is_public/1` returns `false` for loopback, RFC 1918 private,
link-local, multicast, and reserved address ranges in both
IPv4 and IPv6. The built-in proxy handlers call this after DNS
resolution to reject tunnels targeting internal networks.
""".

-export([is_public/1, reject_requests/1, inject_packet/2, resolve_target/3]).

-include("masque_ip.hrl").

-doc """
Build the RFC 9484 §5.2 "reject all" answer to a batch of
inbound ADDRESS_REQUEST entries: each reply carries the same
Request ID and IP Version, an all-zero address, and the maximum
prefix length for that version (32 for v4, 128 for v6).
""".
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

-doc """
Push an IP packet into a server session for delivery to its
connected client. Non-blocking. Intended for out-of-band injectors
(e.g. a TUN device owner that holds the session pid via the
address registry); accepted by both `masque_ip_server_session`
(h2/h3) and `masque_ip_h1_server_session` (h1).
""".
-spec inject_packet(pid(), binary()) -> ok.
inject_packet(SessionPid, Packet) when
    is_pid(SessionPid),
    is_binary(Packet)
->
    gen_server:cast(SessionPid, {inject_packet, Packet}).

-doc """
Attach `resolved_addresses` to a CONNECT-IP request.

RFC 9484 sec 4.7.1: hostname targets MUST be resolved before the
2xx response. The resolved address list is attached to the request
so the handler's `accept/1` can apply SSRF policy on the real
addresses and `init/2` can advertise them as routes. Literal IP
targets resolve to themselves; prefix and `*` targets get an empty
list. Other protocols pass through unchanged. Shared by the h3, h2
and h1 listeners.
""".
-spec resolve_target(atom(), map(), fun((binary()) -> {ok, [inet:ip_address()]} | {error, term()})) ->
    {ok, map()} | {error, resolution_failed}.
resolve_target(ip, #{ip_target := Target} = Req, Resolver) when
    is_binary(Target)
->
    %% Binary ip_target is a hostname (IPs parse into tuples).
    case Resolver(Target) of
        {ok, Addrs} -> {ok, Req#{resolved_addresses => Addrs}};
        {error, _} -> {error, resolution_failed}
    end;
resolve_target(ip, #{ip_target := {_, _, _, _} = A} = Req, _Resolver) ->
    {ok, Req#{resolved_addresses => [A]}};
resolve_target(ip, #{ip_target := {_, _, _, _, _, _, _, _} = A} = Req, _Resolver) ->
    {ok, Req#{resolved_addresses => [A]}};
resolve_target(ip, Req, _Resolver) ->
    {ok, Req#{resolved_addresses => []}};
resolve_target(_, Req, _Resolver) ->
    {ok, Req}.

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
%% ::/96 IPv4-compatible (deprecated)
is_public({0, 0, 0, 0, 0, 0, _, _}) ->
    false;
%% ::ffff:0:0/96 mapped v4
is_public({0, 0, 0, 0, 0, 16#FFFF, _, _}) ->
    false;
%% 64:ff9b::/96 NAT64 and 64:ff9b:1::/48 local-use NAT64
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
%% 6to4 2002::/16
is_public({16#2002, _, _, _, _, _, _, _}) ->
    false;
%% documentation 3fff::/20
is_public({16#3FFF, B, _, _, _, _, _, _}) when B =< 16#0FFF -> false;
%% SRv6 SIDs 5f00::/16
is_public({16#5F00, _, _, _, _, _, _, _}) ->
    false;
is_public({A, _, _, _, _, _, _, _}) when
    A >= 16#FC00,
    %% ULA fc00::/7
    A =< 16#FDFF
->
    false;
is_public({A, _, _, _, _, _, _, _}) when
    A >= 16#FE80,
    %% link-local fe80::/10 and site-local fec0::/10
    A =< 16#FEFF
->
    false;
%% multicast ff00::/8
is_public({A, _, _, _, _, _, _, _}) when A >= 16#FF00 -> false;
is_public({_, _, _, _}) ->
    true;
is_public({_, _, _, _, _, _, _, _}) ->
    true;
%% Anything that is not an address is never public.
is_public(_) ->
    false.
