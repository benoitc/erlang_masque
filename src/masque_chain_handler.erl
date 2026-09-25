%%% @doc MASQUE handler that chains to an upstream proxy.
%%%
%%% Instead of opening a `gen_udp' / `gen_tcp' socket to the resolved
%%% target (what the built-in UDP / TCP / IP proxy handlers do), this
%%% handler opens a MASQUE client session to an upstream proxy and
%%% relays traffic both ways. The result is a two-hop tunnel:
%%%
%%% ```
%%% Client -> Ingress (this handler) -> Egress (upstream) -> Target
%%% '''
%%%
%%% This is the server-side chaining pattern used by Apple Private
%%% Relay: the client connects to the Ingress; the Ingress chains to
%%% the Egress transparently.
%%%
%%% Covers all three tunnel protocols:
%%%
%%% <ul>
%%%   <li>CONNECT-UDP (`protocol = udp'): packets forwarded via
%%%       `masque:send/2' both ways.</li>
%%%   <li>CONNECT-TCP (`protocol = tcp'): bytes forwarded via
%%%       `masque:send/2' both ways.</li>
%%%   <li>CONNECT-IP (`protocol = ip'): IP packets forwarded via
%%%       `masque:send_ip_packet/2'; ROUTE_ADVERTISEMENT and
%%%       unprompted ADDRESS_ASSIGN (request_id 0) from the upstream
%%%       are forwarded to the client. A client ADDRESS_REQUEST is
%%%       forwarded upstream with fresh request ids and the upstream
%%%       ADDRESS_ASSIGN answer is relayed back under the client's
%%%       ids.</li>
%%% </ul>
%%%
%%% Configure via `handler_opts':
%%% <ul>
%%%   <li>`upstream_proxy := binary()' - URI of the upstream proxy
%%%       (e.g. `<<"https://egress:4434">>'). Required.</li>
%%%   <li>`upstream_opts => map()' - options forwarded to
%%%       `masque:connect/3' for the upstream leg (verify, transports,
%%%       timeout, etc.). Default `#{verify => verify_none}'.</li>
%%%   <li>`allow => fun(target()) -> boolean()' - optional policy
%%%       gate, same as `masque_udp_proxy_handler'.</li>
%%% </ul>
-module(masque_chain_handler).
-behaviour(masque_handler).

-export([
    accept/1,
    init/2,
    handle_packet/2,
    handle_data/2,
    handle_capsule/3,
    handle_eof/1,
    handle_info/2,
    terminate/2
]).
-export([handle_ip_packet/2, handle_address_request/2]).

-ifdef(TEST).
%% Test-only: construct a state record without running init/2 / opening
%% a real MASQUE session. The unit tests drive callbacks against this.
-export([test_state/2]).
-endif.

-include("masque_ip.hrl").

-record(state, {
    upstream :: pid(),
    protocol :: udp | tcp | ip,
    %% Upstream request id -> client request id for forwarded
    %% ADDRESS_REQUESTs still waiting for their ADDRESS_ASSIGN.
    id_map = #{} :: #{pos_integer() => pos_integer()}
}).

-ifdef(TEST).
test_state(Upstream, Protocol) when
    is_pid(Upstream),
    Protocol =:= udp orelse Protocol =:= tcp orelse Protocol =:= ip
->
    #state{upstream = Upstream, protocol = Protocol}.
-endif.

%%====================================================================
%% Behaviour callbacks
%%====================================================================

-spec accept(masque_handler:req()) -> masque_handler:accept_result().
accept(#{protocol := ip, ip_target := Target, ip_ipproto := IPProto} = Req) ->
    Opts = maps:get(handler_opts, Req, #{}),
    AllowFun = maps:get(allow, Opts, fun(_) -> true end),
    case AllowFun({Target, IPProto}) of
        true -> accept;
        false -> {reject, forbidden}
    end;
accept(#{target_host := Host, target_port := Port} = Req) ->
    Opts = maps:get(handler_opts, Req, #{}),
    AllowFun = maps:get(allow, Opts, fun(_) -> true end),
    case AllowFun({Host, Port}) of
        true -> accept;
        false -> {reject, forbidden}
    end.

-spec init(masque_handler:req(), map()) -> {ok, #state{}} | {stop, term()}.
init(
    #{
        protocol := ip,
        ip_target := Target,
        ip_ipproto := IPProto
    } = _Req,
    Opts
) ->
    UpstreamURI = maps:get(upstream_proxy, Opts),
    UpstreamOpts = maps:get(upstream_opts, Opts, #{verify => verify_none}),
    Timeout = maps:get(upstream_timeout, Opts, 5000),
    ConnOpts = UpstreamOpts#{
        timeout => Timeout,
        owner => self(),
        protocol => ip
    },
    case masque:connect(UpstreamURI, {Target, IPProto}, ConnOpts) of
        {ok, Sess} ->
            {ok, #state{upstream = Sess, protocol = ip}};
        {error, Reason} ->
            {stop, {resolution_failed, {upstream, Reason}}}
    end;
init(
    #{
        target_host := Host,
        target_port := Port,
        protocol := Proto
    } = _Req,
    Opts
) ->
    UpstreamURI = maps:get(upstream_proxy, Opts),
    UpstreamOpts = maps:get(upstream_opts, Opts, #{verify => verify_none}),
    Timeout = maps:get(upstream_timeout, Opts, 5000),
    ConnOpts = UpstreamOpts#{
        timeout => Timeout,
        owner => self(),
        protocol => Proto
    },
    case masque:connect(UpstreamURI, {Host, Port}, ConnOpts) of
        {ok, Sess} ->
            {ok, #state{upstream = Sess, protocol = Proto}};
        {error, Reason} ->
            {stop, {resolution_failed, {upstream, Reason}}}
    end.

-spec handle_packet(binary(), #state{}) -> {ok, #state{}}.
handle_packet(Data, #state{upstream = Sess} = State) ->
    _ = masque:send(Sess, Data),
    {ok, State}.

-spec handle_data(binary(), #state{}) -> {ok, #state{}}.
handle_data(Data, #state{upstream = Sess} = State) ->
    _ = masque:send(Sess, Data),
    {ok, State}.

-spec handle_ip_packet(binary(), #state{}) -> {ok, #state{}}.
handle_ip_packet(Packet, #state{upstream = Sess} = State) ->
    _ = masque:send_ip_packet(Sess, Packet),
    {ok, State}.

%% Forward the client's ADDRESS_REQUEST upstream. The upstream
%% session allocates its own request ids; remember the mapping so the
%% answer can be relayed under the client's ids. If the upstream leg
%% cannot take the request, answer with the RFC 9484 "no address"
%% entry right away.
-spec handle_address_request([#ip_prefix_request{}], #state{}) ->
    {ok, #state{}} | {ok, #state{}, [term()]}.
handle_address_request(Requests, #state{upstream = Sess, id_map = Map} = State) ->
    Prefixes = [
        {V, Addr, Pfx}
     || #ip_prefix_request{version = V, address = Addr, prefix_len = Pfx} <- Requests
    ],
    DownIds = [Id || #ip_prefix_request{request_id = Id} <- Requests],
    try masque:request_addresses(Sess, Prefixes) of
        {ok, UpIds} when length(UpIds) =:= length(DownIds) ->
            Map1 = maps:merge(Map, maps:from_list(lists:zip(UpIds, DownIds))),
            {ok, State#state{id_map = Map1}};
        _ ->
            {ok, State, [{assign, masque_ip:reject_requests(Requests)}]}
    catch
        exit:_ ->
            {ok, State, [{assign, masque_ip:reject_requests(Requests)}]}
    end.

-spec handle_capsule(non_neg_integer(), binary(), #state{}) -> {ok, #state{}}.
handle_capsule(Type, Value, #state{upstream = Sess} = State) ->
    _ = masque:send_capsule(Sess, Type, Value),
    {ok, State}.

-spec handle_eof(#state{}) -> {ok, #state{}} | {stop, term(), #state{}}.
handle_eof(#state{upstream = Sess} = State) ->
    _ =
        (try
            masque:shutdown_write(Sess)
        catch
            _:_ -> ok
        end),
    {ok, State}.

-spec handle_info(term(), #state{}) ->
    {ok, #state{}} | {ok, #state{}, [term()]} | {stop, term(), #state{}}.
handle_info(
    {masque_data, Sess, Data},
    #state{
        upstream = Sess,
        protocol = udp
    } = State
) ->
    {ok, State, [{send, Data}]};
handle_info(
    {masque_data, Sess, Data},
    #state{
        upstream = Sess,
        protocol = tcp
    } = State
) ->
    {ok, State, [{send_data, Data}]};
handle_info(
    {masque_ip_packet, Sess, Packet},
    #state{upstream = Sess, protocol = ip} = State
) ->
    {ok, State, [{send_ip_packet, Packet}]};
handle_info(
    {masque_address_assign, Sess, Entries},
    #state{upstream = Sess, protocol = ip, id_map = Map} = State
) ->
    %% Unprompted entries (request_id 0) pass through. Prompted ones
    %% answer a request we forwarded: relay them under the client's
    %% request id. Entries for ids we never forwarded are dropped, the
    %% ingress session would reject them on the client leg.
    {Relay, Map1} = lists:foldr(fun map_assign/2, {[], Map}, Entries),
    State1 = State#state{id_map = Map1},
    case Relay of
        [] -> {ok, State1};
        _ -> {ok, State1, [{assign, Relay}]}
    end;
handle_info(
    {masque_route_advertisement, Sess, Routes},
    #state{upstream = Sess, protocol = ip} = State
) ->
    {ok, State, [{advertise, Routes}]};
handle_info({masque_capsule, Sess, Type, Value}, #state{upstream = Sess} = State) ->
    {ok, State, [{send_capsule, Type, Value}]};
handle_info({masque_closed, Sess, _Reason}, #state{upstream = Sess} = State) ->
    {stop, upstream_closed, State};
handle_info(_Other, State) ->
    {ok, State}.

map_assign(#ip_assignment{request_id = 0} = E, {Acc, Map}) ->
    {[E | Acc], Map};
map_assign(#ip_assignment{request_id = UpId} = E, {Acc, Map}) ->
    case maps:take(UpId, Map) of
        {DownId, Map1} -> {[E#ip_assignment{request_id = DownId} | Acc], Map1};
        error -> {Acc, Map}
    end.

-spec terminate(term(), #state{}) -> ok.
terminate(_Reason, #state{upstream = Sess}) ->
    _ = masque:close(Sess),
    ok.
