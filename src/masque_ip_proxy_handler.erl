%%% @doc Default CONNECT-IP proxy handler (RFC 9484).
%%%
%%% Responsibilities:
%%% <ul>
%%%   <li>Allocate addresses from the configured `address_pool' in
%%%       response to `ADDRESS_REQUEST' capsules (round-robin).</li>
%%%   <li>Emit the initial `ROUTE_ADVERTISEMENT' combining the
%%%       configured static `routes' with any `resolved_addresses'
%%%       populated by the listener's DNS step.</li>
%%%   <li>BCP-38 source-address filtering on inbound packets (via
%%%       `masque_ip:is_public/1').</li>
%%%   <li>Hand each accepted IP packet to the user-supplied
%%%       `forward_fun' (default: drop).</li>
%%% </ul>
%%%
%%% Phase 2 replaces this handler with `masque_ip_tun_proxy_handler'
%%% which owns a TUN device instead of a forwarder-fun.
-module(masque_ip_proxy_handler).
-behaviour(masque_handler).

-export([accept/1, init/2,
         handle_ip_packet/2,
         handle_address_request/2,
         handle_address_assign/2,
         handle_route_advertisement/2,
         terminate/2]).

-include("masque_ip.hrl").

-record(state, {
    opts          :: map(),
    resolved = [] :: [inet:ip_address()],
    %% Address pool: either a single prefix or a list of prefixes.
    pools = []    :: [#ip_route{}],
    %% Already-assigned addresses (tagged with the IP version).
    assigned = [] :: [ip_assignment_tuple()]
}).

-type ip_assignment_tuple() ::
      {4, inet:ip4_address(), 0..32}
    | {6, inet:ip6_address(), 0..128}.

%%====================================================================
%% accept — SSRF gate using the resolved-addresses list
%%====================================================================

accept(Req) ->
    Opts = maps:get(handler_opts, Req, #{}),
    Allow = maps:get(allow_private, Opts, false),
    Addrs = maps:get(resolved_addresses, Req, []),
    case Allow orelse Addrs =:= [] orelse
         lists:all(fun masque_ip:is_public/1, Addrs) of
        true  -> accept;
        false -> {reject, forbidden}
    end.

%%====================================================================
%% init — publish the initial ROUTE_ADVERTISEMENT
%%====================================================================

init(Req, Opts) ->
    Resolved = maps:get(resolved_addresses, Req, []),
    Pools = normalize_pools(maps:get(address_pool, Opts, [])),
    StaticRoutes = maps:get(routes, Opts, []),
    ResolvedRoutes = [route_for(A) || A <- Resolved],
    Routes = lists:usort(StaticRoutes ++ ResolvedRoutes),
    S = #state{opts = Opts, resolved = Resolved, pools = Pools},
    case Routes of
        [] -> {ok, S};
        _  -> {ok, S, [{advertise, Routes}]}
    end.

%%====================================================================
%% ADDRESS_REQUEST — round-robin allocator from the pool
%%====================================================================

handle_address_request(Requests, #state{} = S) ->
    {Entries, S1} = allocate_or_reject(Requests, S),
    {ok, S1, [{assign, Entries}]}.

allocate_or_reject(Requests, #state{pools = []} = S) ->
    %% No pool configured — reject everything per RFC 9484 §5.2.
    {masque_ip:reject_requests(Requests), S};
allocate_or_reject(Requests, #state{} = S) ->
    lists:mapfoldl(fun allocate_one/2, S, Requests).

allocate_one(#ip_prefix_request{request_id = Id, version = V}, S) ->
    case next_free(V, S) of
        {ok, Addr, Pfx, S1} ->
            {#ip_assignment{request_id = Id, version = V,
                            address = Addr, prefix_len = Pfx},
             S1};
        none ->
            %% Pool exhausted — single-entry rejection.
            Req = #ip_prefix_request{request_id = Id, version = V,
                                     address = zero_addr(V),
                                     prefix_len = max_prefix(V)},
            [Reject] = masque_ip:reject_requests([Req]),
            {Reject, S}
    end.

next_free(V, #state{pools = Pools, assigned = Assigned} = S) ->
    case pick_pool(V, Pools) of
        undefined -> none;
        Pool ->
            case iter_pool(Pool, Assigned) of
                {ok, Addr} ->
                    {ok, Addr, max_prefix(V),
                     S#state{assigned =
                                 [{V, Addr, max_prefix(V)} | Assigned]}};
                exhausted -> none
            end
    end.

pick_pool(_V, []) -> undefined;
pick_pool(V, [#ip_route{version = V} = P | _]) -> P;
pick_pool(V, [_ | Rest]) -> pick_pool(V, Rest).

iter_pool(#ip_route{start_addr = S, end_addr = E}, Assigned) ->
    iter_range(S, E, Assigned).

iter_range(Addr, End, _Assigned) when Addr > End -> exhausted;
iter_range(Addr, End, Assigned) ->
    Taken = lists:any(fun({_, A, _}) -> A =:= Addr end, Assigned),
    case Taken of
        true  -> iter_range(inc_addr(Addr), End, Assigned);
        false -> {ok, Addr}
    end.

inc_addr({A,B,C,D}) ->
    N = ((A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D) + 1,
    {(N bsr 24) band 16#FF, (N bsr 16) band 16#FF,
     (N bsr 8) band 16#FF, N band 16#FF};
inc_addr({A,B,C,D,E,F,G,H}) ->
    N = (A bsl 112) bor (B bsl 96) bor (C bsl 80) bor (D bsl 64)
        bor (E bsl 48) bor (F bsl 32) bor (G bsl 16) bor H,
    N1 = N + 1,
    {(N1 bsr 112) band 16#FFFF, (N1 bsr 96) band 16#FFFF,
     (N1 bsr 80) band 16#FFFF, (N1 bsr 64) band 16#FFFF,
     (N1 bsr 48) band 16#FFFF, (N1 bsr 32) band 16#FFFF,
     (N1 bsr 16) band 16#FFFF, N1 band 16#FFFF}.

%% Turn an `address_pool' option (a prefix, a route, or a list of
%% these) into a list of `#ip_route{}` ranges we can allocate from.
normalize_pools(Pool) when is_list(Pool) ->
    [normalize_pool(P) || P <- Pool];
normalize_pools(Pool) ->
    [normalize_pool(Pool)].

normalize_pool(#ip_route{} = R) -> R;
normalize_pool({4, {A,B,C,D}, Pfx}) when Pfx >= 0, Pfx =< 32 ->
    {Start, End} = prefix_range_v4({A,B,C,D}, Pfx),
    #ip_route{version = 4, start_addr = Start, end_addr = End,
              ip_protocol = 0};
normalize_pool({6, Addr, Pfx}) when Pfx >= 0, Pfx =< 128,
                                     tuple_size(Addr) =:= 8 ->
    {Start, End} = prefix_range_v6(Addr, Pfx),
    #ip_route{version = 6, start_addr = Start, end_addr = End,
              ip_protocol = 0}.

prefix_range_v4(Addr, Pfx) ->
    N = ip_int(Addr, 32),
    Mask = (1 bsl 32) - (1 bsl (32 - Pfx)),
    Start = int_ip(N band Mask, 32, 4),
    End = int_ip((N band Mask) bor ((1 bsl (32 - Pfx)) - 1), 32, 4),
    {Start, End}.

prefix_range_v6(Addr, Pfx) ->
    N = ip_int(Addr, 128),
    Mask = (1 bsl 128) - (1 bsl (128 - Pfx)),
    Start = int_ip(N band Mask, 128, 6),
    End = int_ip((N band Mask) bor ((1 bsl (128 - Pfx)) - 1), 128, 6),
    {Start, End}.

ip_int({A,B,C,D}, 32) ->
    (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D;
ip_int({A,B,C,D,E,F,G,H}, 128) ->
    (A bsl 112) bor (B bsl 96) bor (C bsl 80) bor (D bsl 64)
    bor (E bsl 48) bor (F bsl 32) bor (G bsl 16) bor H.

int_ip(N, 32, 4) ->
    {(N bsr 24) band 16#FF, (N bsr 16) band 16#FF,
     (N bsr 8) band 16#FF, N band 16#FF};
int_ip(N, 128, 6) ->
    {(N bsr 112) band 16#FFFF, (N bsr 96) band 16#FFFF,
     (N bsr 80) band 16#FFFF, (N bsr 64) band 16#FFFF,
     (N bsr 48) band 16#FFFF, (N bsr 32) band 16#FFFF,
     (N bsr 16) band 16#FFFF, N band 16#FFFF}.

zero_addr(4) -> {0,0,0,0};
zero_addr(6) -> {0,0,0,0,0,0,0,0}.

max_prefix(4) -> 32;
max_prefix(6) -> 128.

%%====================================================================
%% Data-plane: forward_fun
%%====================================================================

handle_ip_packet(Packet, #state{opts = Opts} = S) ->
    case src_filter_passes(Packet, S) of
        true  -> forward(Packet, S, Opts);
        false -> {ok, S}
    end.

forward(Packet, S, Opts) ->
    case maps:find(forward_fun, Opts) of
        {ok, Fun} when is_function(Fun, 2) ->
            case Fun(Packet, S) of
                {reply, RepPkt, S2}  -> {ok, S2, [{send_ip_packet, RepPkt}]};
                {drop, S2}           -> {ok, S2};
                {forward, S2}        -> {ok, S2};
                ok                   -> {ok, S};
                {error, _}           -> {ok, S}
            end;
        error ->
            {ok, S}
    end.

%% BCP-38-style source check: reject packets whose source address
%% doesn't match one the proxy actually assigned to this client.
%% (`allow_private' skips the check, matching the accept/1 gate.)
src_filter_passes(_Packet, #state{opts = Opts, assigned = []}) ->
    maps:get(allow_private, Opts, true);
src_filter_passes(<<4:4, _/bitstring>> = Packet, #state{assigned = Assigned}) ->
    case Packet of
        <<_:12/binary, SA:8, SB:8, SC:8, SD:8, _/binary>> ->
            lists:any(fun({4, {A,B,C,D}, _}) ->
                              {A,B,C,D} =:= {SA,SB,SC,SD};
                         (_) -> false
                      end, Assigned);
        _ -> false
    end;
src_filter_passes(<<6:4, _/bitstring>> = Packet, #state{assigned = Assigned}) ->
    case Packet of
        <<_:8/binary, SA:16, SB:16, SC:16, SD:16,
          SE:16, SF:16, SG:16, SH:16, _/binary>> ->
            lists:any(fun({6, {A,B,C,D,E,F,G,H}, _}) ->
                              {A,B,C,D,E,F,G,H} =:=
                                  {SA,SB,SC,SD,SE,SF,SG,SH};
                         (_) -> false
                      end, Assigned);
        _ -> false
    end;
src_filter_passes(_, _) ->
    false.

%%====================================================================
%% Peer-initiated control-plane (bidirectional per §8.2)
%%====================================================================

handle_address_assign(_Entries, S) -> {ok, S}.

handle_route_advertisement(_Entries, S) -> {ok, S}.

terminate(_Reason, _S) -> ok.

%%====================================================================
%% Helpers
%%====================================================================

route_for({_,_,_,_} = A) ->
    #ip_route{version = 4, start_addr = A, end_addr = A, ip_protocol = 0};
route_for({_,_,_,_,_,_,_,_} = A) ->
    #ip_route{version = 6, start_addr = A, end_addr = A, ip_protocol = 0}.
