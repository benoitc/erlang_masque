-module(masque_ip).
-moduledoc """
IP address classification for SSRF protection.

`is_public/1` returns `false` for loopback, RFC 1918 private,
link-local, multicast, and reserved address ranges in both
IPv4 and IPv6. The built-in proxy handlers call this after DNS
resolution to reject tunnels targeting internal networks.

`is_self/2` returns `true` for the proxy host's own non-loopback
addresses (its interfaces, plus the `self_addresses` and
`public_addresses` handler options), so a client cannot reach
services on the proxy host through its public address. The handlers
refuse those targets unless `allow_self` is set.
""".

-export([is_public/1, reject_requests/1, inject_packet/2, resolve_target/3]).
-export([is_self/2]).
-export([is_rejection/1, held_set/1]).
%% Shared by the CONNECT-IP sessions and handlers.
-export([
    ttl_mode/1,
    icmp_rate_limit/1,
    request_entries/1,
    answers/1,
    report_advertise/1,
    too_big/2,
    time_exceeded/1,
    source_in/2
]).

%% ICMP errors one tunnel may generate per second (and its burst).
-define(DEFAULT_ICMP_RATE, 10).

%% Interface addresses are read at most this often.
-define(SELF_TTL_MS, 5000).

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
True for the RFC 9484 section 4.7.2 "no address" entry: an all-zero
address with the maximum prefix length (`0.0.0.0/32`, `::/128`).
""".
-spec is_rejection(#ip_assignment{}) -> boolean().
is_rejection(#ip_assignment{version = 4, address = {0, 0, 0, 0}, prefix_len = 32}) ->
    true;
is_rejection(#ip_assignment{version = 6, address = {0, 0, 0, 0, 0, 0, 0, 0}, prefix_len = 128}) ->
    true;
is_rejection(#ip_assignment{}) ->
    false.

-doc """
The addresses an ADDRESS_ASSIGN leaves its receiver holding, ready to
be repeated in a later one (RFC 9484 section 4.7.1: each ADDRESS_ASSIGN
is the full set): rejection entries dropped, duplicates removed, and
every request id set to 0 since a repeated entry answers no request.
""".
-spec held_set([#ip_assignment{}]) -> [#ip_assignment{}].
held_set(Entries) ->
    held_set(Entries, []).

held_set([], Acc) ->
    lists:reverse(Acc);
held_set([E | Rest], Acc) ->
    E0 = E#ip_assignment{request_id = 0},
    case is_rejection(E) orelse lists:member(E0, Acc) of
        true -> held_set(Rest, Acc);
        false -> held_set(Rest, [E0 | Acc])
    end.

-doc false.
%% Where the TTL / Hop Limit is decremented (`ttl_decrement' handler
%% option): `encapsulation' (RFC 9484 section 7.2, the default) or
%% `decapsulation'.
-spec ttl_mode(map()) -> encapsulation | decapsulation.
ttl_mode(#{ttl_decrement := decapsulation}) -> decapsulation;
ttl_mode(_Opts) -> encapsulation.

-doc false.
%% `icmp_rate_limit' handler option: ICMP errors per second and tunnel.
-spec icmp_rate_limit(map()) -> non_neg_integer().
icmp_rate_limit(#{icmp_rate_limit := N}) when is_integer(N), N >= 0 -> N;
icmp_rate_limit(_Opts) -> ?DEFAULT_ICMP_RATE.

-doc false.
%% Entries of a proxy-initiated ADDRESS_REQUEST: `{V, Addr, Pfx}'
%% tuples get a fresh request id, `#ip_prefix_request{}' records keep
%% theirs.
-spec request_entries([{4 | 6, inet:ip_address(), 0..128} | #ip_prefix_request{}]) ->
    [#ip_prefix_request{}].
request_entries(Prefixes) ->
    [request_entry(P) || P <- Prefixes].

request_entry(#ip_prefix_request{} = R) ->
    R;
request_entry({V, A, P}) ->
    #ip_prefix_request{
        request_id = erlang:unique_integer([positive, monotonic]),
        version = V,
        address = A,
        prefix_len = P
    }.

-doc false.
%% True when a handler's result carries an `{assign, _}' action.
-spec answers(term()) -> boolean().
answers({ok, _HS, Actions}) when is_list(Actions) ->
    lists:any(fun(A) -> is_tuple(A) andalso element(1, A) =:= assign end, Actions);
answers(_) ->
    false.

-doc false.
%% A ROUTE_ADVERTISEMENT a handler asked for could not be encoded (the
%% routes are not ordered or overlap, RFC 9484 section 4.7.3): say so
%% instead of dropping it silently.
-spec report_advertise(ok | {error, term()}) -> ok.
report_advertise({error, {bad_routes, Reason}}) ->
    logger:warning("masque: ROUTE_ADVERTISEMENT not sent, invalid routes: ~0p", [Reason]),
    ok;
report_advertise(_) ->
    ok.

-doc false.
%% True when the source address of `Packet' lies in one of `Entries'.
-spec source_in(binary(), [#ip_assignment{}]) -> boolean().
source_in(<<4:4, _:92, Src:32, _/binary>>, Entries) ->
    in_entries(4, Src, 32, Entries);
source_in(<<6:4, _:60, Src:128, _/binary>>, Entries) ->
    in_entries(6, Src, 128, Entries);
source_in(_Packet, _Entries) ->
    false.

in_entries(V, Src, Bits, Entries) ->
    lists:any(
        fun
            (#ip_assignment{version = EV, address = A, prefix_len = P}) when EV =:= V ->
                Shift = Bits - P,
                (Src bsr Shift) =:= (addr_int(A) bsr Shift);
            (_) ->
                false
        end,
        Entries
    ).

addr_int({A, B, C, D}) ->
    (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D;
addr_int({A, B, C, D, E, F, G, H}) ->
    (A bsl 112) bor (B bsl 96) bor (C bsl 80) bor (D bsl 64) bor
        (E bsl 48) bor (F bsl 32) bor (G bsl 16) bor H.

-doc false.
-spec too_big(binary(), non_neg_integer()) -> binary().
too_big(<<4:4, _/bitstring>> = Packet, Mtu) ->
    masque_icmp:frag_needed(min(Mtu, 16#FFFF), Packet);
too_big(Packet, Mtu) ->
    masque_icmp:packet_too_big(Mtu, Packet).

-doc false.
-spec time_exceeded(binary()) -> binary().
time_exceeded(<<4:4, _/bitstring>> = Packet) ->
    masque_icmp:time_exceeded(v4, Packet);
time_exceeded(Packet) ->
    masque_icmp:time_exceeded(v6, Packet).

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

-doc """
Return `true` when `IP` is one of the proxy host's own non-loopback
addresses: an interface address, or an address listed in the
`self_addresses` or `public_addresses` (`{IP, Port}`) handler
options. Loopback is left to `is_public/1` and `allow_private`.
""".
-spec is_self(inet:ip_address(), map()) -> boolean().
is_self(IP, Opts) ->
    Extra =
        maps:get(self_addresses, Opts, []) ++
            [A || {A, _Port} <- maps:get(public_addresses, Opts, [])],
    lists:member(IP, Extra) orelse lists:member(IP, interface_addresses()).

%% Cached in the `masque_self_addrs' table (owned by `masque_sup')
%% when the application runs; read directly otherwise.
interface_addresses() ->
    Now = erlang:monotonic_time(millisecond),
    try ets:lookup(masque_self_addrs, addrs) of
        [{addrs, Stamp, Addrs}] when Now - Stamp < ?SELF_TTL_MS ->
            Addrs;
        _ ->
            Addrs = read_interface_addresses(),
            ets:insert(masque_self_addrs, {addrs, Now, Addrs}),
            Addrs
    catch
        error:badarg -> read_interface_addresses()
    end.

read_interface_addresses() ->
    case inet:getifaddrs() of
        {ok, Ifs} ->
            lists:usort([
                A
             || {_Name, Props} <- Ifs,
                {addr, A} <- Props,
                not is_loopback(A)
            ]);
        {error, _} ->
            []
    end.

is_loopback({127, _, _, _}) -> true;
is_loopback({0, 0, 0, 0, 0, 0, 0, 1}) -> true;
is_loopback(_) -> false.

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
%% ::ffff:0:0:0/96 IPv4-translated (SIIT, RFC 6052 / RFC 7915)
is_public({0, 0, 0, 0, 16#FFFF, 0, _, _}) ->
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
%% benchmarking 2001:2::/48
is_public({16#2001, 2, 0, _, _, _, _, _}) ->
    false;
%% ORCHID (deprecated) 2001:10::/28
is_public({16#2001, B, _, _, _, _, _, _}) when B >= 16#10, B =< 16#1F -> false;
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
