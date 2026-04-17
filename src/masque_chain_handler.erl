%%% @doc MASQUE handler that chains to an upstream proxy.
%%%
%%% Instead of opening a `gen_udp' socket to the resolved target
%%% (what `masque_udp_proxy_handler' does), this handler opens a
%%% MASQUE client session to an upstream proxy and relays datagrams
%%% both ways. The result is a two-hop tunnel:
%%%
%%% ```
%%% Client -> Ingress (this handler) -> Egress (upstream) -> Target
%%% '''
%%%
%%% This is the server-side chaining pattern used by Apple Private
%%% Relay: the client connects to the Ingress; the Ingress chains to
%%% the Egress transparently.
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

-export([accept/1, init/2, handle_packet/2, handle_data/2,
         handle_capsule/3, handle_info/2, terminate/2]).

-record(state, {
    upstream :: pid(),
    protocol :: udp | tcp
}).

%%====================================================================
%% Behaviour callbacks
%%====================================================================

accept(#{target_host := Host, target_port := Port} = Req) ->
    Opts = maps:get(handler_opts, Req, #{}),
    AllowFun = maps:get(allow, Opts, fun(_) -> true end),
    case AllowFun({Host, Port}) of
        true  -> accept;
        false -> {reject, forbidden}
    end.

-spec init(masque_handler:req(), map()) -> {ok, #state{}} | {stop, term()}.
init(#{target_host := Host, target_port := Port,
       protocol := Proto} = _Req, Opts) ->
    UpstreamURI = maps:get(upstream_proxy, Opts),
    UpstreamOpts = maps:get(upstream_opts, Opts, #{verify => verify_none}),
    Timeout = maps:get(upstream_timeout, Opts, 5000),
    ConnOpts = UpstreamOpts#{timeout => Timeout, owner => self(),
                              protocol => Proto},
    case masque:connect(UpstreamURI, {Host, Port}, ConnOpts) of
        {ok, Sess} ->
            {ok, #state{upstream = Sess, protocol = Proto}};
        {error, Reason} ->
            {stop, {resolution_failed, {upstream, Reason}}}
    end.

handle_packet(Data, #state{upstream = Sess} = State) ->
    _ = masque:send(Sess, Data),
    {ok, State}.

handle_data(Data, #state{upstream = Sess} = State) ->
    _ = masque:send(Sess, Data),
    {ok, State}.

handle_capsule(Type, Value, #state{upstream = Sess} = State) ->
    _ = masque:send_capsule(Sess, Type, Value),
    {ok, State}.

handle_info({masque_data, Sess, Data}, #state{upstream = Sess,
                                              protocol = udp} = State) ->
    {ok, State, [{send, Data}]};
handle_info({masque_data, Sess, Data}, #state{upstream = Sess,
                                              protocol = tcp} = State) ->
    {ok, State, [{send_data, Data}]};
handle_info({masque_capsule, Sess, Type, Value}, #state{upstream = Sess} = State) ->
    {ok, State, [{send_capsule, Type, Value}]};
handle_info({masque_closed, Sess, _Reason}, #state{upstream = Sess} = State) ->
    {stop, upstream_closed, State};
handle_info(_Other, State) ->
    {ok, State}.

terminate(_Reason, #state{upstream = Sess}) ->
    _ = masque:close(Sess),
    ok.
