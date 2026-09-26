%%% @doc Default CONNECT-IP proxy handler (RFC 9484).
%%%
%%% Responsibilities:
%%% <ul>
%%%   <li>Allocate addresses from the configured `address_pool' in
%%%       response to `ADDRESS_REQUEST' capsules (round-robin).</li>
%%%   <li>Emit the initial `ROUTE_ADVERTISEMENT' combining the
%%%       configured static `routes' with any `resolved_addresses'
%%%       populated by the listener's DNS step.</li>
%%%   <li>BCP-38 source-address filtering on inbound packets: the
%%%       source must fall inside a prefix assigned to this client.</li>
%%%   <li>Act as a router for accepted packets: decrement the TTL /
%%%       Hop Limit (ICMP Time Exceeded when it runs out) and enforce
%%%       the `mtu' option (default 1500; ICMPv6 Packet Too Big or
%%%       ICMPv4 Fragmentation Needed when exceeded).</li>
%%%   <li>Hand each accepted IP packet to the user-supplied
%%%       `forward_fun' (default: drop).</li>
%%%   <li>Record the addresses and routes the client assigns or
%%%       advertises to the proxy (reported through `lifecycle_fun'
%%%       as `peer_address_assigned' / `peer_routes_advertised').</li>
%%% </ul>
%%%
%%% Assigned prefixes are registered in `masque_ip_session_registry',
%%% which also keeps sessions sharing one pool from getting the same
%%% addresses. A consumer that owns a TUN device can look up the
%%% serving session there and push packets back with
%%% `masque_ip:inject_packet/2'.
-module(masque_ip_proxy_handler).
-behaviour(masque_handler).

-export([
    accept/1,
    init/2,
    handle_ip_packet/2,
    handle_address_request/2,
    handle_address_assign/2,
    handle_route_advertisement/2,
    terminate/2
]).

%% Public helpers reused by downstream consumers (TUN/router) so they
%% emit the same drop counter and lifecycle events as the default
%% handler.
-export([emit_drop/2, emit_drop/3]).

-include("masque_ip.hrl").

-define(DEFAULT_MTU, 1500).

-record(state, {
    opts :: map(),
    resolved = [] :: [inet:ip_address()],
    %% Address pool: either a single prefix or a list of prefixes.
    pools = [] :: [#ip_route{}],
    %% Already-assigned addresses (tagged with the IP version).
    assigned = [] :: [ip_assignment_tuple()],
    %% Routes advertised at init. A hostname target is scoped to them.
    routes = [] :: [#ip_route{}],
    %% Addresses and routes the client assigned / advertised to us
    %% (RFC 9484 sec 4.7: both directions are allowed).
    peer_assigned = [] :: [#ip_assignment{}],
    peer_routes = [] :: [#ip_route{}],
    %% Negotiated URI scope: target / ipproto from the request line.
    %% `'*'' on either axis means "any" and skips the per-packet check.
    target = '*' :: masque_uri_ip:ip_target(),
    ipproto = '*' :: masque_uri_ip:ip_ipproto()
}).

-type ip_assignment_tuple() ::
    {4, inet:ip4_address(), 0..32}
    | {6, inet:ip6_address(), 0..128}.

%%====================================================================
%% accept — SSRF gate using the resolved-addresses list
%%====================================================================

accept(Req) ->
    Opts = maps:get(handler_opts, Req, #{}),
    case maps:get(allow_private, Opts, false) orelse target_is_public(Req) of
        true -> accept;
        false -> {reject, forbidden}
    end.

%% `*' can reach anything, so it needs `allow_private'. A prefix must
%% start and end on public addresses (the data plane also drops
%% non-public destinations inside it). Hostnames and literals are
%% checked on their resolved addresses.
target_is_public(Req) ->
    case maps:get(ip_target, Req, '*') of
        '*' ->
            false;
        {V, Net, Pfx} when V =:= 4; V =:= 6 ->
            {First, Last} = prefix_bounds(V, Net, Pfx),
            masque_ip:is_public(First) andalso masque_ip:is_public(Last);
        {_, _, _, _} = A ->
            masque_ip:is_public(A);
        {_, _, _, _, _, _, _, _} = A ->
            masque_ip:is_public(A);
        _Host ->
            lists:all(
                fun masque_ip:is_public/1,
                maps:get(resolved_addresses, Req, [])
            )
    end.

prefix_bounds(4, Net, Pfx) -> prefix_range_v4(Net, Pfx);
prefix_bounds(6, Net, Pfx) -> prefix_range_v6(Net, Pfx).

%%====================================================================
%% init — publish the initial ROUTE_ADVERTISEMENT
%%====================================================================

init(Req, Opts) ->
    Resolved = maps:get(resolved_addresses, Req, []),
    Pools = normalize_pools(maps:get(address_pool, Opts, [])),
    StaticRoutes = maps:get(routes, Opts, []),
    ResolvedRoutes = [route_for(A) || A <- Resolved],
    Routes = lists:usort(StaticRoutes ++ ResolvedRoutes),
    Target = maps:get(ip_target, Req, '*'),
    IPProto = maps:get(ip_ipproto, Req, '*'),
    S = #state{
        opts = Opts,
        resolved = Resolved,
        pools = Pools,
        routes = Routes,
        target = Target,
        ipproto = IPProto
    },
    case Routes of
        [] ->
            {ok, S};
        _ ->
            masque_metrics:ip_advertise_inc(),
            invoke_lifecycle(Opts, route_advertised, #{routes => Routes}, Opts),
            {ok, S, [{advertise, Routes}]}
    end.

%%====================================================================
%% ADDRESS_REQUEST — round-robin allocator from the pool
%%====================================================================

handle_address_request(Requests, #state{} = S) ->
    {Entries, S1} = allocate_or_reject(Requests, S),
    {ok, S1, [{assign, Entries}]}.

emit_assigned(
    #ip_assignment{
        version = V,
        address = A,
        prefix_len = Pfx
    } = E,
    #state{opts = Opts}
) ->
    masque_metrics:ip_assign_inc(),
    invoke_lifecycle(
        Opts,
        address_assigned,
        #{
            version => V,
            address => A,
            prefix_len => Pfx,
            entry => E
        },
        Opts
    ).

allocate_or_reject(Requests, #state{pools = []} = S) ->
    %% No pool configured — reject everything per RFC 9484 §5.2.
    {masque_ip:reject_requests(Requests), S};
allocate_or_reject(Requests, #state{} = S) ->
    lists:mapfoldl(fun allocate_one/2, S, Requests).

allocate_one(
    #ip_prefix_request{
        request_id = Id,
        version = V,
        prefix_len = ReqPfx
    },
    #state{opts = Opts} = S
) ->
    %% RFC 9484 §4.6: the proxy MAY answer with the same prefix
    %% length the client asked for, or with a more specific (longer)
    %% one. The `min_assignable_prefix' opt sets the widest prefix
    %% the proxy is willing to give out per IP family.
    Pfx = effective_prefix(V, ReqPfx, Opts),
    case next_free(V, Pfx, S) of
        {ok, Addr, S1} ->
            Entry = #ip_assignment{
                request_id = Id,
                version = V,
                address = Addr,
                prefix_len = Pfx
            },
            emit_assigned(Entry, S1),
            {Entry, S1};
        none ->
            %% Pool exhausted — single-entry rejection.
            Req = #ip_prefix_request{
                request_id = Id,
                version = V,
                address = zero_addr(V),
                prefix_len = max_prefix(V)
            },
            [Reject] = masque_ip:reject_requests([Req]),
            {Reject, S}
    end.

effective_prefix(V, ReqPfx, Opts) ->
    Min = min_assignable(V, Opts),
    Max = max_prefix(V),
    %% Clamp into [Min, Max]. RFC 9484 says we may return a longer
    %% (= numerically larger) prefix, never a wider one than Min.
    Cand =
        case
            is_integer(ReqPfx) andalso ReqPfx >= 0 andalso
                ReqPfx =< Max
        of
            true -> ReqPfx;
            false -> Max
        end,
    erlang:max(Cand, Min).

min_assignable(V, Opts) ->
    Default = max_prefix(V),
    case maps:get(min_assignable_prefix, Opts, undefined) of
        undefined -> Default;
        Map when is_map(Map) -> maps:get(V, Map, Default);
        N when is_integer(N) -> N
    end.

%% Claim a candidate range in the cross-session registry. Another
%% session sharing the pool may already hold it (`{error, conflict}'),
%% in which case the allocator moves on to the next candidate.
register_with_registry(V, Addr, Pfx, Opts) ->
    %% The handler runs inside the session's process, so `self()' is
    %% the session pid. Context id 0 is the IP datagram context per
    %% RFC 9484 §6 (matches `MASQUE_CONTEXT_ID_IP'). Both can be
    %% overridden via opts for embedded uses.
    Pid = session_pid(Opts),
    Ctx = maps:get(ip_context_id, Opts, ?MASQUE_CONTEXT_ID_IP),
    masque_ip_session_registry:register(V, Addr, Pfx, Pid, Ctx) =:= ok.

session_pid(Opts) ->
    maps:get(session_pid, Opts, self()).

next_free(V, Pfx, #state{pools = Pools, assigned = Assigned, opts = Opts} = S) ->
    case pick_pool(V, Pools) of
        undefined ->
            none;
        Pool ->
            Claim = fun(Addr) -> register_with_registry(V, Addr, Pfx, Opts) end,
            case iter_pool(V, Pfx, Pool, Assigned, Claim) of
                {ok, Addr} ->
                    {ok, Addr, S#state{assigned = [{V, Addr, Pfx} | Assigned]}};
                exhausted ->
                    none
            end
    end.

pick_pool(_V, []) -> undefined;
pick_pool(V, [#ip_route{version = V} = P | _]) -> P;
pick_pool(V, [_ | Rest]) -> pick_pool(V, Rest).

iter_pool(
    V,
    Pfx,
    #ip_route{start_addr = StartAddr, end_addr = EndAddr},
    Assigned,
    Claim
) ->
    Max = max_prefix(V),
    Stride = 1 bsl (Max - Pfx),
    StartInt = align_up(addr_to_int(V, StartAddr), Stride),
    EndInt = addr_to_int(V, EndAddr),
    iter_range_strided(V, StartInt, EndInt, Stride, Assigned, Claim).

iter_range_strided(_V, Cur, End, _Stride, _Assigned, _Claim) when
    Cur > End
->
    exhausted;
iter_range_strided(V, Cur, End, Stride, Assigned, Claim) ->
    %% A candidate range covers [Cur, Cur + Stride - 1] in int space.
    Last = Cur + Stride - 1,
    Next = fun() -> iter_range_strided(V, Cur + Stride, End, Stride, Assigned, Claim) end,
    case Last > End of
        true ->
            exhausted;
        false ->
            case overlaps_assigned(V, Cur, Last, Assigned) of
                true ->
                    Next();
                false ->
                    Addr = int_to_addr(V, Cur),
                    case Claim(Addr) of
                        true -> {ok, Addr};
                        false -> Next()
                    end
            end
    end.

overlaps_assigned(V, S, E, Assigned) ->
    Max = max_prefix(V),
    lists:any(
        fun
            ({V0, A, P0}) when V0 =:= V ->
                AStart = addr_to_int(V, A),
                AEnd = AStart + (1 bsl (Max - P0)) - 1,
                max(S, AStart) =< min(E, AEnd);
            (_) ->
                false
        end,
        Assigned
    ).

align_up(N, Stride) when Stride > 0 ->
    Mask = Stride - 1,
    (N + Mask) band (bnot Mask).

addr_to_int(4, {A, B, C, D}) ->
    (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D;
addr_to_int(6, {A, B, C, D, E, F, G, H}) ->
    (A bsl 112) bor (B bsl 96) bor (C bsl 80) bor (D bsl 64) bor
        (E bsl 48) bor (F bsl 32) bor (G bsl 16) bor H.

int_to_addr(4, N) ->
    {(N bsr 24) band 16#FF, (N bsr 16) band 16#FF, (N bsr 8) band 16#FF, N band 16#FF};
int_to_addr(6, N) ->
    {
        (N bsr 112) band 16#FFFF,
        (N bsr 96) band 16#FFFF,
        (N bsr 80) band 16#FFFF,
        (N bsr 64) band 16#FFFF,
        (N bsr 48) band 16#FFFF,
        (N bsr 32) band 16#FFFF,
        (N bsr 16) band 16#FFFF,
        N band 16#FFFF
    }.

%% Turn an `address_pool' option (a prefix, a route, or a list of
%% these) into a list of `#ip_route{}` ranges we can allocate from.
normalize_pools(Pool) when is_list(Pool) ->
    [normalize_pool(P) || P <- Pool];
normalize_pools(Pool) ->
    [normalize_pool(Pool)].

normalize_pool(#ip_route{} = R) ->
    R;
normalize_pool({4, {A, B, C, D}, Pfx}) when Pfx >= 0, Pfx =< 32 ->
    {Start, End} = prefix_range_v4({A, B, C, D}, Pfx),
    #ip_route{
        version = 4,
        start_addr = Start,
        end_addr = End,
        ip_protocol = 0
    };
normalize_pool({6, Addr, Pfx}) when
    Pfx >= 0,
    Pfx =< 128,
    tuple_size(Addr) =:= 8
->
    {Start, End} = prefix_range_v6(Addr, Pfx),
    #ip_route{
        version = 6,
        start_addr = Start,
        end_addr = End,
        ip_protocol = 0
    }.

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

ip_int({A, B, C, D}, 32) ->
    (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D;
ip_int({A, B, C, D, E, F, G, H}, 128) ->
    (A bsl 112) bor (B bsl 96) bor (C bsl 80) bor (D bsl 64) bor
        (E bsl 48) bor (F bsl 32) bor (G bsl 16) bor H.

int_ip(N, 32, 4) ->
    {(N bsr 24) band 16#FF, (N bsr 16) band 16#FF, (N bsr 8) band 16#FF, N band 16#FF};
int_ip(N, 128, 6) ->
    {
        (N bsr 112) band 16#FFFF,
        (N bsr 96) band 16#FFFF,
        (N bsr 80) band 16#FFFF,
        (N bsr 64) band 16#FFFF,
        (N bsr 48) band 16#FFFF,
        (N bsr 32) band 16#FFFF,
        (N bsr 16) band 16#FFFF,
        N band 16#FFFF
    }.

zero_addr(4) -> {0, 0, 0, 0};
zero_addr(6) -> {0, 0, 0, 0, 0, 0, 0, 0}.

max_prefix(4) -> 32;
max_prefix(6) -> 128.

%%====================================================================
%% Data-plane: forward_fun
%%====================================================================

handle_ip_packet(Packet, #state{opts = Opts} = S) ->
    case accept_inbound(Packet, S) of
        ok ->
            route(Packet, S);
        {drop, Reason} ->
            emit_drop(Reason, drop_detail(Packet), Opts),
            {ok, S}
    end.

%% Router duties before handing the packet on: decrement the TTL /
%% Hop Limit and check the egress MTU. Failures drop the packet and
%% answer the client with the matching ICMP error, unless the packet
%% is itself an ICMP error (RFC 1122 §3.2.2, RFC 4443 §2.4 (e)).
route(Packet, #state{opts = Opts} = S) ->
    case masque_ip_packet:decrement_ttl(Packet) of
        {ok, Fwd} ->
            Mtu = maps:get(mtu, Opts, ?DEFAULT_MTU),
            case byte_size(Fwd) > Mtu of
                true ->
                    emit_drop(mtu_exceeded, drop_detail(Packet), Opts),
                    icmp_reply(Packet, fun() -> too_big(Packet, Mtu) end, S);
                false ->
                    forward(Fwd, S)
            end;
        {error, ttl_zero} ->
            emit_drop(ttl_zero, drop_detail(Packet), Opts),
            icmp_reply(Packet, fun() -> time_exceeded(Packet) end, S);
        {error, malformed} ->
            emit_drop(malformed, drop_detail(Packet), Opts),
            {ok, S}
    end.

%% The drop itself is already counted (`ttl_zero' / `mtu_exceeded').
icmp_reply(Packet, Build, S) ->
    case masque_icmp:is_error(Packet) of
        true ->
            {ok, S};
        false ->
            {ok, S, [{send_ip_packet, Build()}]}
    end.

too_big(<<4:4, _/bitstring>> = Packet, Mtu) ->
    masque_icmp:frag_needed(Mtu, Packet);
too_big(Packet, Mtu) ->
    masque_icmp:packet_too_big(Mtu, Packet).

time_exceeded(<<4:4, _/bitstring>> = Packet) ->
    masque_icmp:time_exceeded(v4, Packet);
time_exceeded(Packet) ->
    masque_icmp:time_exceeded(v6, Packet).

%% RFC 9484 §5: the proxy MUST drop packets that fail BCP-38 source
%% filtering or fall outside the negotiated `target' / `ipproto'
%% scope. Returns the first failing axis so the drop counter and the
%% lifecycle hook can attribute the cause.
accept_inbound(
    Packet,
    #state{target = Target, ipproto = IPProto, routes = Routes} = S
) ->
    case src_filter_passes(Packet, S) of
        false ->
            {drop, bcp38};
        true ->
            case masque_ip_packet:scope_check(Packet, Target, IPProto, Routes) of
                ok -> dst_filter(Packet, S);
                {error, Reason} -> {drop, Reason}
            end
    end.

%% A prefix target may cover private space the accept/1 bounds check
%% cannot see; drop non-public destinations unless `allow_private'.
dst_filter(Packet, #state{target = {V, _, _}, opts = Opts}) when V =:= 4; V =:= 6 ->
    case maps:get(allow_private, Opts, false) of
        true ->
            ok;
        false ->
            {ok, _, Dst} = masque_ip_packet:destination(Packet),
            case masque_ip:is_public(Dst) of
                true -> ok;
                false -> {drop, scope_target}
            end
    end;
dst_filter(_Packet, _S) ->
    ok.

forward(Packet, #state{opts = Opts} = S) ->
    case maps:find(forward_fun, Opts) of
        {ok, Fun} when is_function(Fun, 2) ->
            case Fun(Packet, S) of
                %% Backward-compat shapes -----------------------------
                {reply, RepPkt, S2} ->
                    {ok, S2, [{send_ip_packet, RepPkt}]};
                {drop, S2} ->
                    emit_drop(forward_drop, drop_detail(Packet), Opts),
                    {ok, S2};
                {forward, S2} ->
                    {ok, S2};
                ok ->
                    {ok, S};
                {error, _} ->
                    {ok, S};
                %% New action-list shape ------------------------------
                %% Lets a forward_fun emit multiple effects in one call
                %% (e.g. ICMP error + drop). Recognised actions match
                %% the existing IP-server-session interpreter:
                %%   {send_ip_packet, binary()}
                %%   {icmp_error, {Kind, Spec, Invoking}}
                %%   {drop, atom()}                 % telemetry only
                {actions, Actions, S2} when is_list(Actions) ->
                    {Wire, _} = process_forward_actions(Actions, Packet, Opts),
                    {ok, S2, Wire}
            end;
        error ->
            {ok, S}
    end.

process_forward_actions(Actions, Packet, Opts) ->
    lists:foldl(
        fun
            ({drop, Reason}, {Wire, Drops}) ->
                emit_drop(Reason, drop_detail(Packet), Opts),
                {Wire, [Reason | Drops]};
            (Action, {Wire, Drops}) ->
                {Wire ++ [Action], Drops}
        end,
        {[], []},
        Actions
    ).

%%====================================================================
%% Drop emit / lifecycle hook
%%====================================================================

%% @doc Bump the drop counter and invoke `lifecycle_fun' if configured
%% in handler opts. Public so a TUN/router consumer that runs its own
%% data path can drive the same telemetry without re-implementing it.
-spec emit_drop(atom(), map()) -> ok.
emit_drop(Reason, Detail) ->
    masque_metrics:ip_drop_inc(Reason),
    invoke_lifecycle(Detail, packet_dropped, Detail#{reason => Reason}, #{}).

-spec emit_drop(atom(), map(), map()) -> ok.
emit_drop(Reason, Detail, Opts) ->
    masque_metrics:ip_drop_inc(Reason),
    invoke_lifecycle(Opts, packet_dropped, Detail#{reason => Reason}, Opts).

drop_detail(Packet) when is_binary(Packet) ->
    #{packet_size => byte_size(Packet)}.

invoke_lifecycle(_Carrier, Event, Detail, Opts) ->
    case maps:find(lifecycle_fun, Opts) of
        {ok, Fun} when is_function(Fun, 2) ->
            try Fun(Event, Detail) of
                _ -> ok
            catch
                _:_ -> ok
            end;
        _ ->
            ok
    end.

%% BCP-38-style source check: reject packets whose source address
%% is not inside a prefix the proxy assigned to this client. With
%% nothing assigned, only `allow_private' lets packets through.
src_filter_passes(_Packet, #state{opts = Opts, assigned = []}) ->
    maps:get(allow_private, Opts, false);
src_filter_passes(<<4:4, _:92, Src:32, _/bitstring>>, #state{assigned = Assigned}) ->
    in_assigned(4, Src, Assigned);
src_filter_passes(<<6:4, _:60, Src:128, _/bitstring>>, #state{assigned = Assigned}) ->
    in_assigned(6, Src, Assigned);
src_filter_passes(_, _) ->
    false.

in_assigned(V, Src, Assigned) ->
    Max = max_prefix(V),
    lists:any(
        fun
            ({V0, A, Pfx}) when V0 =:= V ->
                Shift = Max - Pfx,
                (Src bsr Shift) =:= (addr_to_int(V, A) bsr Shift);
            (_) ->
                false
        end,
        Assigned
    ).

%%====================================================================
%% Peer-initiated control-plane (bidirectional per §8.2)
%%====================================================================

%% The client assigned addresses to the proxy. Keep the latest entry
%% per request id and report it.
handle_address_assign(Entries, #state{peer_assigned = Prev, opts = Opts} = S) ->
    Ids = [Id || #ip_assignment{request_id = Id} <- Entries],
    Kept = [E || #ip_assignment{request_id = Id} = E <- Prev, not lists:member(Id, Ids)],
    invoke_lifecycle(Opts, peer_address_assigned, #{entries => Entries}, Opts),
    {ok, S#state{peer_assigned = Kept ++ Entries}}.

%% Each ROUTE_ADVERTISEMENT carries the peer's full route set
%% (RFC 9484 sec 4.7.3), so it replaces the previous one.
handle_route_advertisement(Routes, #state{opts = Opts} = S) ->
    invoke_lifecycle(Opts, peer_routes_advertised, #{routes => Routes}, Opts),
    {ok, S#state{peer_routes = Routes}}.

terminate(_Reason, #state{assigned = Assigned, opts = Opts}) ->
    [release_one(Entry, Opts) || Entry <- Assigned],
    ok.

release_one({V, Addr, Pfx}, Opts) ->
    _ = masque_ip_session_registry:release(V, Addr, Pfx, session_pid(Opts)),
    invoke_lifecycle(
        Opts,
        address_released,
        #{version => V, address => Addr, prefix_len => Pfx},
        Opts
    ),
    ok.

%%====================================================================
%% Helpers
%%====================================================================

route_for({_, _, _, _} = A) ->
    #ip_route{version = 4, start_addr = A, end_addr = A, ip_protocol = 0};
route_for({_, _, _, _, _, _, _, _} = A) ->
    #ip_route{version = 6, start_addr = A, end_addr = A, ip_protocol = 0}.
