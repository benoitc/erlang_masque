%%% @doc Built-in MASQUE handler that bridges a CONNECT-UDP tunnel to
%%% a real UDP flow on the server.
%%%
%%% For every accepted tunnel the handler opens a `gen_udp' socket
%%% bound to ephemeral port and a specific family, resolves the
%%% target hostname, and relays bytes in both directions:
%%%
%%% <ul>
%%%   <li>Client-to-target: `handle_packet/2' sends the payload to the
%%%       resolved target on the UDP socket.</li>
%%%   <li>Target-to-client: `{udp, Socket, _, _, Bytes}' messages arrive
%%%       on the session process and are emitted as `send_packet' actions
%%%       back through the tunnel.</li>
%%% </ul>
%%%
%%% Configure policy via `handler_opts':
%%% <ul>
%%%   <li>`allow => fun(target()) -> boolean()' - gate on host+port.</li>
%%%   <li>`resolver => fun(binary()) -> {ok, inet:ip_address()}
%%%                                   | {error, term()}' - override the
%%%       default `inet:getaddr/2' resolver.</li>
%%%   <li>`family => inet | inet6 | auto' (default `auto').</li>
%%%   <li>`socket_opts => [gen_udp:option()]' - extra options merged on
%%%       top of `[binary, {active, true}]'.</li>
%%% </ul>
-module(masque_udp_proxy_handler).
-behaviour(masque_handler).

-export([accept/1, init/2, handle_packet/2, handle_info/2, terminate/2]).

-record(state, {
    socket       :: gen_udp:socket(),
    target_ip    :: inet:ip_address(),
    target_port  :: 1..65535
}).

%%====================================================================
%% Behaviour callbacks
%%====================================================================

accept(#{target_host := Host, target_port := Port} = Req) ->
    Opts = maps:get(handler_opts, Req, #{}),
    AllowFun = maps:get(allow, Opts, fun default_allow/1),
    case AllowFun({Host, Port}) of
        true  -> accept;
        false -> {reject, forbidden}
    end.

init(#{target_host := Host, target_port := Port} = Req, Opts) ->
    ResolverFun = maps:get(resolver, Opts, fun default_resolver/1),
    Family = pick_family(maps:get(family, Opts, auto), Host),
    SocketOpts = [binary, {active, true}
                  | maps:get(socket_opts, Opts, [])],
    case resolve(ResolverFun, Host, Family) of
        {ok, IP, BindFamily} ->
            case gen_udp:open(0, [BindFamily | SocketOpts]) of
                {ok, Socket} ->
                    {ok, #state{socket = Socket,
                                target_ip = IP,
                                target_port = Port}};
                {error, Reason} ->
                    {stop, {udp_open, Reason}}
            end;
        {error, Reason} ->
            _ = Req,  %% silence unused warning when tracing disabled
            {stop, {resolve, Reason}}
    end.

handle_packet(Data, #state{socket = S, target_ip = IP,
                            target_port = P} = State) ->
    case gen_udp:send(S, IP, P, Data) of
        ok -> {ok, State};
        {error, _Reason} ->
            %% Dropping outbound is fine - UDP is lossy.
            {ok, State}
    end.

handle_info({udp, Socket, _FromIP, _FromPort, Bytes},
            #state{socket = Socket} = State) ->
    {ok, State, [{send_packet, Bytes}]};
handle_info({udp_passive, Socket}, #state{socket = Socket} = State) ->
    %% Only hit if the user passed `{active, N}` in socket_opts.
    _ = inet:setopts(Socket, [{active, true}]),
    {ok, State};
handle_info(_Other, State) ->
    {ok, State}.

terminate(_Reason, #state{socket = S}) ->
    _ = gen_udp:close(S),
    ok.

%%====================================================================
%% Policy defaults
%%====================================================================

default_allow({_Host, _Port}) ->
    true.

default_resolver(Host) when is_binary(Host) ->
    default_resolver(binary_to_list(Host));
default_resolver(Host) when is_list(Host) ->
    case inet_parse:address(Host) of
        {ok, IP} ->
            {ok, IP};
        _ ->
            case inet:getaddr(Host, inet) of
                {ok, IP}    -> {ok, IP};
                {error, _}  -> inet:getaddr(Host, inet6)
            end
    end.

%%====================================================================
%% Helpers
%%====================================================================

pick_family(inet, _Host)   -> inet;
pick_family(inet6, _Host)  -> inet6;
pick_family(auto, Host)    ->
    %% Auto-pick based on whether the host string looks like an IPv6 literal.
    HostStr = if is_binary(Host) -> binary_to_list(Host); true -> Host end,
    case inet:parse_address(HostStr) of
        {ok, {_, _, _, _, _, _, _, _}} -> inet6;
        _ -> inet
    end.

resolve(ResolverFun, Host, Family) ->
    case ResolverFun(Host) of
        {ok, IP} ->
            ActualFamily = if tuple_size(IP) =:= 8 -> inet6;
                              true                 -> Family
                           end,
            {ok, IP, ActualFamily};
        Err ->
            Err
    end.
