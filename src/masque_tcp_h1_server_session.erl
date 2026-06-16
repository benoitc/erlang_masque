%%% @doc Per-tunnel server session for classic CONNECT-TCP over
%%% HTTP/1.1 (RFC 9110 §9.3.6).
%%%
%%% Spawned by `masque_h1_server' after a `CONNECT' method + valid
%%% authority-form request-target passes validation. This session
%%% takes the raw TLS socket over from the h1 state machine via
%%% `h1:accept_connect/3' (writes the 200 Connection Established
%%% response atomically, no response-body framing), then bridges
%%% bytes through the configured `tcp_handler' (default
%%% `masque_tcp_proxy_handler'), which owns the outbound target
%%% socket.
%%%
%%% Handler contract identical to `masque_tcp_server_session':
%%% `init/2' opens the target, `handle_data/2' forwards
%%% client-to-target, `handle_info/2' returns `{send_data, Bytes}'
%%% actions for target-to-client. The only difference on this path
%%% is the proxy-side wire (raw `ssl:send/2', no capsules, no
%%% Extended CONNECT).
-module(masque_tcp_h1_server_session).
-behaviour(gen_server).

-export([start_link/1]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-record(state, {
    transport :: gen_tcp | ssl,
    socket :: ssl:sslsocket() | gen_tcp:socket(),
    handler :: module(),
    h_state :: term(),
    req :: map(),
    start_time :: integer() | undefined,
    idle_ms :: non_neg_integer() | infinity,
    idle_ref :: reference() | undefined
}).

%%====================================================================
%% API
%%====================================================================

-spec start_link(map()) -> {ok, pid()} | ignore | {error, term()}.
start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

%%====================================================================
%% gen_server
%%====================================================================

init(#{
    conn := Conn,
    stream_id := StreamId,
    handler := Handler,
    handler_opts := HOpts,
    req := Req
}) ->
    process_flag(trap_exit, true),
    IdleMs = maps:get(idle_timeout_ms, HOpts, 300000),
    case init_handler(Handler, Req, HOpts) of
        {ok, HState, InitActions} ->
            case h1:accept_connect(Conn, StreamId, []) of
                {ok, Transport, Socket, Buffer} ->
                    State0 = arm_idle(#state{
                        transport = Transport,
                        socket = Socket,
                        handler = Handler,
                        h_state = HState,
                        req = Req,
                        start_time = erlang:monotonic_time(millisecond),
                        idle_ms = IdleMs
                    }),
                    case apply_init_actions(InitActions, State0) of
                        {ok, State1} ->
                            %% Any bytes read past the CRLF blank line
                            %% belong to the tunnel - feed them to the
                            %% handler before arming active-once. If
                            %% the handler crashes on that first chunk,
                            %% close the socket before stopping so the
                            %% raw TLS session does not leak.
                            case seed_handler(Buffer, State1) of
                                {stop, Reason} ->
                                    _ = safe_close_socket(State1),
                                    {stop, Reason};
                                State2 ->
                                    _ = arm_once(State2),
                                    {ok, State2}
                            end;
                        {stop, Reason, _S} ->
                            _ = safe_close_socket(State0),
                            {stop, Reason}
                    end;
                {error, Reason} ->
                    try_callback(
                        Handler,
                        terminate,
                        [{accept_connect, Reason}, HState]
                    ),
                    {stop, {accept_connect, Reason}}
            end;
        {stop, Reason} ->
            %% Target resolution / policy denied this request. The
            %% listener already checked `accept/1' before spawning us;
            %% reject here surfaces via `{stop, _}' and the listener
            %% treats it as a 502.
            {stop, Reason}
    end.

handle_call(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

handle_cast(_Msg, S) ->
    {noreply, S}.

handle_info({ssl, Sock, Bytes}, #state{socket = Sock} = S) ->
    handle_proxy_bytes(Bytes, arm_idle(S));
handle_info({tcp, Sock, Bytes}, #state{socket = Sock} = S) ->
    handle_proxy_bytes(Bytes, arm_idle(S));
handle_info(
    {timeout, Ref, idle},
    #state{idle_ref = Ref} = S
) ->
    {stop, idle_timeout, S};
handle_info({ssl_closed, Sock}, #state{socket = Sock} = S) ->
    handle_proxy_eof(S);
handle_info({tcp_closed, Sock}, #state{socket = Sock} = S) ->
    handle_proxy_eof(S);
handle_info({ssl_error, Sock, Reason}, #state{socket = Sock} = S) ->
    {stop, {ssl_error, Reason}, S};
handle_info({tcp_error, Sock, Reason}, #state{socket = Sock} = S) ->
    {stop, {tcp_error, Reason}, S};
handle_info({'EXIT', _Pid, _Reason}, S) ->
    {noreply, S};
handle_info(Msg, S) ->
    dispatch(handle_info, [Msg], S).

terminate(
    Reason,
    #state{
        handler = Handler,
        h_state = HState,
        start_time = Start
    } = S
) ->
    _ = cancel_idle(S),
    _ = safe_close_socket(S),
    try_callback(Handler, terminate, [Reason, HState]),
    _ = emit_tunnel_closed(Start),
    ok.

code_change(_OldVsn, S, _Extra) ->
    {ok, S}.

emit_tunnel_closed(undefined) ->
    ok;
emit_tunnel_closed(T) ->
    Duration = erlang:monotonic_time(millisecond) - T,
    masque_metrics:tunnel_closed(
        Duration,
        #{protocol => tcp, transport => h1}
    ).

%%====================================================================
%% Proxy-side data path
%%====================================================================

handle_proxy_bytes(Bytes, S) ->
    case dispatch(handle_data, [Bytes], S) of
        {noreply, S2} ->
            _ = arm_once(S2),
            {noreply, S2};
        Other ->
            Other
    end.

handle_proxy_eof(#state{handler = Handler} = S) ->
    case exported(Handler, handle_eof, 1) of
        true ->
            case dispatch(handle_eof, [], S) of
                {noreply, S2} -> {stop, normal, S2};
                {stop, _, _} = Stop -> Stop
            end;
        false ->
            {stop, normal, S}
    end.

seed_handler(<<>>, S) ->
    S;
seed_handler(Bytes, S) ->
    case dispatch(handle_data, [Bytes], S) of
        {noreply, S2} -> S2;
        {stop, Reason, _S2} -> {stop, Reason}
    end.

%%====================================================================
%% Handler dispatch (mirrors masque_tcp_server_session)
%%====================================================================

init_handler(Handler, Req, HOpts) ->
    case exported(Handler, init, 2) of
        true ->
            case safe_apply(Handler, init, [Req, HOpts]) of
                {ok, HState} -> {ok, HState, []};
                {ok, HState, Actions} -> {ok, HState, Actions};
                {stop, Reason} -> {stop, Reason};
                Other -> {stop, {bad_init, Other}}
            end;
        false ->
            {ok, undefined, []}
    end.

dispatch(CB, Extra, #state{handler = Handler, h_state = HS} = S) ->
    case exported(Handler, CB, length(Extra) + 1) of
        true ->
            case safe_apply(Handler, CB, Extra ++ [HS]) of
                {ok, HS2} ->
                    {noreply, S#state{h_state = HS2}};
                {ok, HS2, Actions} ->
                    apply_actions_noreply(
                        Actions, S#state{h_state = HS2}
                    );
                {stop, Reason, HS2} ->
                    {stop, Reason, S#state{h_state = HS2}};
                _ ->
                    {noreply, S}
            end;
        false ->
            {noreply, S}
    end.

exported(Mod, Fun, Arity) ->
    _ = code:ensure_loaded(Mod),
    erlang:function_exported(Mod, Fun, Arity).

apply_init_actions(Actions, State) ->
    case do_actions(Actions, State) of
        {ok, S2} -> {ok, S2};
        {stop, Reason, S2} -> {stop, Reason, S2}
    end.

apply_actions_noreply(Actions, State) ->
    case do_actions(Actions, State) of
        {ok, S2} -> {noreply, S2};
        {stop, Reason, S2} -> {stop, Reason, S2}
    end.

do_actions([], S) ->
    {ok, S};
do_actions([{send_data, Bytes} | Rest], S) ->
    _ = proxy_send(S, Bytes),
    do_actions(Rest, S);
do_actions([{send_data, Bytes, _Fin} | Rest], S) ->
    _ = proxy_send(S, Bytes),
    do_actions(Rest, S);
do_actions([close_session | _Rest], S) ->
    {stop, normal, S};
do_actions([_Unknown | Rest], S) ->
    do_actions(Rest, S).

proxy_send(#state{transport = ssl, socket = Sock}, Bytes) ->
    ssl:send(Sock, Bytes);
proxy_send(#state{transport = gen_tcp, socket = Sock}, Bytes) ->
    gen_tcp:send(Sock, Bytes).

%%====================================================================
%% Socket helpers
%%====================================================================

arm_once(#state{transport = ssl, socket = Sock}) ->
    ssl:setopts(Sock, [{active, once}, {mode, binary}]);
arm_once(#state{transport = gen_tcp, socket = Sock}) ->
    inet:setopts(Sock, [{active, once}, {mode, binary}]).

safe_close_socket(State) ->
    try
        close_socket(State)
    catch
        _:_ -> ok
    end.

close_socket(#state{transport = ssl, socket = S}) -> ssl:close(S);
close_socket(#state{transport = gen_tcp, socket = S}) -> gen_tcp:close(S).

%%====================================================================
%% Misc
%%====================================================================

safe_apply(M, F, A) ->
    try
        apply(M, F, A)
    catch
        Class:Reason:Stack ->
            error_logger:error_msg(
                "masque tcp-h1 handler ~p:~p/~p failed: ~p:~p~n~p~n",
                [M, F, length(A), Class, Reason, Stack]
            ),
            {stop, {handler_crash, Reason}}
    end.

try_callback(Mod, Fun, Args) ->
    Arity = length(Args),
    case erlang:function_exported(Mod, Fun, Arity) of
        true ->
            (try
                apply(Mod, Fun, Args)
            catch
                _:_ -> ok
            end);
        false ->
            ok
    end.

%%====================================================================
%% Idle timer
%%====================================================================

arm_idle(#state{idle_ms = infinity} = S) ->
    S;
arm_idle(#state{idle_ms = 0} = S) ->
    S;
arm_idle(#state{idle_ref = OldRef, idle_ms = Ms} = S) ->
    case OldRef of
        undefined ->
            ok;
        _ ->
            _ = erlang:cancel_timer(OldRef),
            ok
    end,
    Ref = erlang:start_timer(Ms, self(), idle),
    S#state{idle_ref = Ref}.

cancel_idle(#state{idle_ref = undefined}) ->
    ok;
cancel_idle(#state{idle_ref = Ref}) ->
    _ = erlang:cancel_timer(Ref),
    ok.
