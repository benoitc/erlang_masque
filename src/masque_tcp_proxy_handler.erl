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
%%%   <li>Client FIN: `handle_eof/1' shuts down the write side of the
%%%       socket; target bytes keep flowing to the client.</li>
%%%   <li>Target FIN: `{tcp_closed, Socket}' ends the stream toward the
%%%       client with FIN; client bytes keep flowing to the target.</li>
%%% </ul>
%%%
%%% The tunnel ends once both directions have seen FIN. A half-closed
%%% tunnel with no traffic for 30 seconds ends with `eof_timeout'.
%%%
%%% The socket runs in `{active, N}' mode (`active_n', default 16).
%%% After N messages it pauses; the `tcp_passive' notice is handled
%%% only once the session has written every earlier chunk to the
%%% tunnel, so a slow client stalls reads from the target instead of
%%% growing the session mailbox.
%%%
%%% Accepts the same policy hooks as the UDP proxy (`allow', `resolver',
%%% `family'), plus `connect_timeout' (default 5000 ms).
-module(masque_tcp_proxy_handler).
-behaviour(masque_handler).

-export([
    accept/1,
    init/2,
    handle_data/2,
    handle_eof/1,
    handle_info/2,
    terminate/2
]).

-define(DEFAULT_ACTIVE_N, 16).
%% Idle time allowed on a half-closed tunnel.
-define(EOF_IDLE_MS, 30000).

-record(state, {
    socket :: gen_tcp:socket(),
    active_n = ?DEFAULT_ACTIVE_N :: pos_integer(),
    eof_timer :: reference() | undefined,
    %% The client sent FIN (we shut down our write side).
    write_closed = false :: boolean(),
    %% The target sent FIN.
    read_closed = false :: boolean()
}).

%%====================================================================
%% Behaviour callbacks
%%====================================================================

-spec accept(masque_handler:req()) -> masque_handler:accept_result().
accept(#{target_host := Host, target_port := Port} = Req) ->
    Opts = maps:get(handler_opts, Req, #{}),
    AllowFun = maps:get(allow, Opts, fun(_) -> true end),
    case AllowFun({Host, Port}) of
        true -> accept;
        false -> {reject, forbidden}
    end.

-spec init(masque_handler:req(), term()) -> {ok, #state{}} | {stop, term()}.
init(#{target_host := Host, target_port := Port}, Opts) ->
    ResolverFun = maps:get(resolver, Opts, fun default_resolver/1),
    Family = pick_family(maps:get(family, Opts, auto), Host),
    ConnTimeout = maps:get(connect_timeout, Opts, 5000),
    AllowPrivate = maps:get(allow_private, Opts, false),
    ActiveN = maps:get(active_n, Opts, ?DEFAULT_ACTIVE_N),
    case resolve(ResolverFun, Host) of
        {ok, IP} ->
            case AllowPrivate orelse masque_ip:is_public(IP) of
                false ->
                    {stop, {resolution_failed, private_address}};
                true ->
                    TcpOpts = [
                        binary,
                        {active, ActiveN},
                        %% Report a target RST as `{tcp_error, _,
                        %% econnreset}' so the tunnel is reset rather
                        %% than closed cleanly.
                        {show_econnreset, true},
                        %% Keep the socket writable after the target's
                        %% FIN so the tunnel can half-close.
                        {exit_on_close, false},
                        Family
                        | maps:get(socket_opts, Opts, [])
                    ],
                    case gen_tcp:connect(IP, Port, TcpOpts, ConnTimeout) of
                        {ok, Socket} ->
                            {ok, #state{socket = Socket, active_n = ActiveN}};
                        {error, Reason} ->
                            {stop, {resolution_failed, {tcp_connect, Reason}}}
                    end
            end;
        {error, Reason} ->
            {stop, {resolution_failed, {resolve, Reason}}}
    end.

-spec handle_data(binary(), #state{}) -> {ok, #state{}} | {stop, term(), #state{}}.
handle_data(Data, #state{socket = S} = State) ->
    case gen_tcp:send(S, Data) of
        ok ->
            {ok, rearm_eof_timer(State)};
        {error, closed} ->
            {stop, target_closed, State};
        {error, Reason} ->
            {stop, {target_error, Reason}, State}
    end.

-spec handle_eof(#state{}) -> {ok, #state{}} | {stop, term(), #state{}}.
handle_eof(#state{socket = S, read_closed = true} = State) ->
    _ = gen_tcp:shutdown(S, write),
    {stop, normal, cancel_eof_timer(State#state{write_closed = true})};
handle_eof(#state{socket = S} = State) ->
    _ = gen_tcp:shutdown(S, write),
    {ok, arm_eof_timer(State#state{write_closed = true})}.

-spec handle_info(term(), #state{}) ->
    {ok, #state{}} | {ok, #state{}, [term()]} | {stop, term(), #state{}}.
handle_info({tcp, Socket, Bytes}, #state{socket = Socket} = State) ->
    {ok, rearm_eof_timer(State), [{send_data, Bytes}]};
handle_info({tcp_passive, Socket}, #state{socket = Socket, active_n = N} = State) ->
    %% The session stops on a failed tunnel write, so reaching this
    %% clause means every earlier chunk was handed to the tunnel.
    _ = inet:setopts(Socket, [{active, N}]),
    {ok, State};
handle_info({tcp_closed, Socket}, #state{socket = Socket, write_closed = true} = State) ->
    {stop, target_closed, cancel_eof_timer(State)};
handle_info({tcp_closed, Socket}, #state{socket = Socket} = State) ->
    %% Half-close: FIN toward the client, keep forwarding its bytes.
    {ok, arm_eof_timer(State#state{read_closed = true}), [{send_data, <<>>, true}]};
handle_info({timeout, TRef, eof_timeout}, #state{eof_timer = TRef} = State) ->
    {stop, eof_timeout, State#state{eof_timer = undefined}};
handle_info({tcp_error, Socket, Reason}, #state{socket = Socket} = State) ->
    {stop, {target_error, Reason}, State};
handle_info(_Other, State) ->
    {ok, State}.

-spec terminate(term(), #state{}) -> ok.
terminate(_Reason, #state{socket = S}) ->
    _ = gen_tcp:close(S),
    ok.

%%====================================================================
%% Helpers
%%====================================================================

arm_eof_timer(State) ->
    State1 = cancel_eof_timer(State),
    State1#state{eof_timer = erlang:start_timer(?EOF_IDLE_MS, self(), eof_timeout)}.

%% Traffic on a half-closed tunnel restarts its idle timer.
rearm_eof_timer(#state{eof_timer = undefined} = State) -> State;
rearm_eof_timer(State) -> arm_eof_timer(State).

cancel_eof_timer(#state{eof_timer = undefined} = State) ->
    State;
cancel_eof_timer(#state{eof_timer = TRef} = State) ->
    _ = erlang:cancel_timer(TRef),
    State#state{eof_timer = undefined}.

default_resolver(Host) when is_binary(Host) ->
    default_resolver(binary_to_list(Host));
default_resolver(Host) when is_list(Host) ->
    case inet_parse:address(Host) of
        {ok, IP} ->
            {ok, IP};
        _ ->
            case inet:getaddr(Host, inet) of
                {ok, IP} -> {ok, IP};
                {error, _} -> inet:getaddr(Host, inet6)
            end
    end.

pick_family(inet, _Host) ->
    inet;
pick_family(inet6, _Host) ->
    inet6;
pick_family(auto, Host) ->
    HostStr =
        if
            is_binary(Host) -> binary_to_list(Host);
            true -> Host
        end,
    case inet:parse_address(HostStr) of
        {ok, {_, _, _, _, _, _, _, _}} -> inet6;
        _ -> inet
    end.

%% A listener-level `resolver' returns an address list (it is shared
%% with CONNECT-IP); a handler-level one may return a single address.
resolve(ResolverFun, Host) ->
    case ResolverFun(Host) of
        {ok, [IP | _]} -> {ok, IP};
        {ok, []} -> {error, nxdomain};
        {ok, IP} when is_tuple(IP) -> {ok, IP};
        {error, _} = Err -> Err;
        Other -> {error, {bad_resolver_result, Other}}
    end.
