%%% @doc Built-in MASQUE handler that bridges a CONNECT-TCP tunnel to
%%% a real TCP connection on the server.
%%%
%%% For every accepted tunnel the handler resolves the target host,
%%% opens a `gen_tcp' connection, and relays bytes both ways:
%%%
%%% <ul>
%%%   <li>Client-to-target: `handle_data/2' writes bytes to the TCP socket.</li>
%%%   <li>Target-to-client: `{tcp, Socket, Bytes}' messages arrive on the
%%%       session and are emitted as `{send_data, Bytes}' actions.</li>
%%%   <li>Target FIN: `{tcp_closed, Socket}' closes the tunnel.</li>
%%% </ul>
%%%
%%% Accepts the same policy hooks as the UDP proxy (`allow', `resolver',
%%% `family'), plus `connect_timeout' (default 5000 ms).
-module(masque_tcp_proxy_handler).
-behaviour(masque_handler).

-export([accept/1, init/2, handle_data/2, handle_info/2, terminate/2]).

-record(state, {
    socket :: gen_tcp:socket()
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

init(#{target_host := Host, target_port := Port}, Opts) ->
    ResolverFun = maps:get(resolver, Opts, fun default_resolver/1),
    Family = pick_family(maps:get(family, Opts, auto), Host),
    ConnTimeout = maps:get(connect_timeout, Opts, 5000),
    case resolve(ResolverFun, Host) of
        {ok, IP} ->
            TcpOpts = [binary, {active, true}, Family
                       | maps:get(socket_opts, Opts, [])],
            case gen_tcp:connect(IP, Port, TcpOpts, ConnTimeout) of
                {ok, Socket} ->
                    {ok, #state{socket = Socket}};
                {error, Reason} ->
                    {stop, {resolution_failed, {tcp_connect, Reason}}}
            end;
        {error, Reason} ->
            {stop, {resolution_failed, {resolve, Reason}}}
    end.

handle_data(Data, #state{socket = S} = State) ->
    case gen_tcp:send(S, Data) of
        ok ->
            {ok, State};
        {error, closed} ->
            {stop, target_closed, State};
        {error, Reason} ->
            {stop, {target_error, Reason}, State}
    end.

handle_info({tcp, Socket, Bytes}, #state{socket = Socket} = State) ->
    {ok, State, [{send_data, Bytes}]};
handle_info({tcp_closed, Socket}, #state{socket = Socket} = State) ->
    {stop, target_closed, State};
handle_info({tcp_error, Socket, Reason}, #state{socket = Socket} = State) ->
    {stop, {target_error, Reason}, State};
handle_info(_Other, State) ->
    {ok, State}.

terminate(_Reason, #state{socket = S}) ->
    _ = gen_tcp:close(S),
    ok.

%%====================================================================
%% Helpers
%%====================================================================

default_resolver(Host) when is_binary(Host) ->
    default_resolver(binary_to_list(Host));
default_resolver(Host) when is_list(Host) ->
    case inet_parse:address(Host) of
        {ok, IP} -> {ok, IP};
        _        ->
            case inet:getaddr(Host, inet) of
                {ok, IP}   -> {ok, IP};
                {error, _} -> inet:getaddr(Host, inet6)
            end
    end.

pick_family(inet, _Host)  -> inet;
pick_family(inet6, _Host) -> inet6;
pick_family(auto, Host) ->
    HostStr = if is_binary(Host) -> binary_to_list(Host); true -> Host end,
    case inet:parse_address(HostStr) of
        {ok, {_, _, _, _, _, _, _, _}} -> inet6;
        _ -> inet
    end.

resolve(ResolverFun, Host) ->
    ResolverFun(Host).
