%%% Per-tunnel server session for HTTP/1.1 MASQUE (CONNECT-UDP).
%%%
%%% Spawned by the h1 request-handler after a `GET` with
%%% `Upgrade: connect-udp` passes validation. The session itself calls
%%% `h1:accept_upgrade/3` so that socket ownership lands on this
%%% process (the h1 connection transfers controlling_process to the
%%% caller of accept_upgrade).
%%%
%%% After the 101 response the raw TLS socket becomes the tunnel.
%%% Datagrams flow as RFC 9297 DATAGRAM capsules; the capsule wire
%%% format is identical to the h2 / h3 paths so `masque_datagram` and
%%% `masque_capsule` are reused unchanged.
-module(masque_h1_server_session).
-moduledoc false.
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

-include("masque.hrl").

-record(state, {
    transport :: gen_tcp | ssl,
    socket :: ssl:sslsocket() | gen_tcp:socket(),
    handler :: module(),
    h_state :: term(),
    req :: map(),
    cap_buf = <<>> :: binary(),
    max_cap :: pos_integer(),
    idle_ms :: non_neg_integer() | infinity,
    idle_ref :: reference() | undefined,
    start_time :: integer() | undefined
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

%% A tunnel counts as open once `init_session/1' succeeded: the 2xx is
%% sent and the stream (or socket) is ours. `terminate/2' closes it.
init(Args) ->
    case init_session(Args) of
        {ok, S} ->
            masque_metrics:tunnel_opened(#{protocol => udp, transport => h1}),
            {ok, S#state{start_time = erlang:monotonic_time(millisecond)}};
        Other ->
            Other
    end.

init_session(#{
    conn := Conn,
    stream_id := StreamId,
    handler := Handler,
    handler_opts := HOpts,
    req := Req
}) ->
    process_flag(trap_exit, true),
    MaxCap = maps:get(
        max_capsule_size,
        HOpts,
        ?MASQUE_DEFAULT_MAX_CAPSULE_SIZE
    ),
    IdleMs = maps:get(idle_timeout_ms, HOpts, 300000),
    %% Run the handler's init/2 first so a rejection surfaces as a
    %% clean 502 on the as-yet-unupgraded h1 connection. Only then
    %% call accept_upgrade, which writes 101 and transfers socket
    %% ownership to this process.
    case init_handler(Handler, Req, HOpts) of
        {ok, HState, Actions} ->
            case
                h1:accept_upgrade(
                    Conn,
                    StreamId,
                    [{<<"capsule-protocol">>, <<"?1">>}]
                )
            of
                {ok, Socket, Buffer} ->
                    Transport = socket_transport(Socket),
                    State0 = arm_idle(#state{
                        transport = Transport,
                        socket = Socket,
                        handler = Handler,
                        h_state = HState,
                        req = Req,
                        cap_buf = Buffer,
                        max_cap = MaxCap,
                        idle_ms = IdleMs
                    }),
                    %% Drain anything already past the 101 CRLF before
                    %% arming the socket.
                    case drain_and_arm(State0) of
                        {ok, State1} ->
                            apply_actions(Actions, State1);
                        {stop, Reason, _State} ->
                            _ = close_socket(State0),
                            {stop, Reason}
                    end;
                {error, Reason} ->
                    try_callback(
                        Handler,
                        terminate,
                        [{accept_upgrade, Reason}, HState]
                    ),
                    {stop, {accept_upgrade, Reason}}
            end;
        {stop, Reason} ->
            {stop, Reason}
    end.

handle_call(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

handle_cast(_Msg, S) ->
    {noreply, S}.

handle_info(
    {ssl, Sock, Bytes},
    #state{
        socket = Sock,
        cap_buf = Buf,
        max_cap = Max
    } = S
) ->
    S1 = arm_idle(S),
    New = <<Buf/binary, Bytes/binary>>,
    case byte_size(New) > Max of
        true -> {stop, capsule_buffer_overflow, S1};
        false -> step(S1#state{cap_buf = New})
    end;
handle_info(
    {tcp, Sock, Bytes},
    #state{
        socket = Sock,
        cap_buf = Buf,
        max_cap = Max
    } = S
) ->
    S1 = arm_idle(S),
    New = <<Buf/binary, Bytes/binary>>,
    case byte_size(New) > Max of
        true -> {stop, capsule_buffer_overflow, S1};
        false -> step(S1#state{cap_buf = New})
    end;
handle_info(
    {timeout, Ref, idle},
    #state{idle_ref = Ref} = S
) ->
    {stop, idle_timeout, S};
handle_info({ssl_closed, Sock}, #state{socket = Sock} = S) ->
    {stop, peer_closed, S};
handle_info({tcp_closed, Sock}, #state{socket = Sock} = S) ->
    {stop, peer_closed, S};
handle_info({ssl_error, Sock, Reason}, #state{socket = Sock} = S) ->
    {stop, {ssl_error, Reason}, S};
handle_info({tcp_error, Sock, Reason}, #state{socket = Sock} = S) ->
    {stop, {tcp_error, Reason}, S};
handle_info({'EXIT', _Pid, _Reason}, S) ->
    {noreply, S};
handle_info(Msg, S) ->
    dispatch(handle_info, [Msg], S).

terminate(Reason, S) ->
    emit_tunnel_closed(S),
    terminate_session(Reason, S).

emit_tunnel_closed(#state{start_time = undefined}) ->
    ok;
emit_tunnel_closed(#state{start_time = T}) ->
    masque_metrics:tunnel_closed(
        erlang:monotonic_time(millisecond) - T,
        #{protocol => udp, transport => h1}
    ).

terminate_session(_Reason, #state{handler = Handler, h_state = HState} = S) ->
    _ = cancel_idle(S),
    _ = close_socket(S),
    try_callback(Handler, terminate, [_Reason, HState]),
    ok.

code_change(_OldVsn, S, _Extra) ->
    {ok, S}.

%%====================================================================
%% Capsule decode loop
%%====================================================================

%% Drain everything buffered, then re-arm active-once. Used once at
%% startup (to consume bytes that arrived past the 101 CRLF) and after
%% every inbound {tcp|ssl, _, _} message.
step(#state{cap_buf = Buf} = S) ->
    case h1_capsule:decode(Buf) of
        {ok, {Type, Inner}, Rest} ->
            case dispatch_capsule(Type, Inner, S#state{cap_buf = Rest}) of
                {noreply, S2} -> step(S2);
                Stop -> Stop
            end;
        {more, _} ->
            _ = arm_once(S),
            {noreply, S}
    end.

drain_and_arm(S) ->
    case step(S) of
        {noreply, S2} -> {ok, S2};
        {stop, Reason, S2} -> {stop, Reason, S2}
    end.

dispatch_capsule(datagram, Inner, S) ->
    case masque_datagram:decode(Inner) of
        {ok, {?MASQUE_CONTEXT_ID_UDP, UdpBytes}} when
            byte_size(UdpBytes) =< ?MASQUE_MAX_UDP_PAYLOAD
        ->
            dispatch(handle_packet, [UdpBytes], S);
        _ ->
            %% RFC 9298 §5: unknown context-id or oversize -> drop.
            {noreply, S}
    end;
dispatch_capsule(Type, Inner, S) when is_integer(Type) ->
    %% RFC 9297 §3.3 mandates silent-drop for unknown capsule types.
    %% `dispatch/3' preserves that: if the handler does not export
    %% `handle_capsule/3' it returns `{noreply, S}' unchanged. Handlers
    %% that do export it are treated as an extension hook.
    dispatch(handle_capsule, [Type, Inner], S).

%%====================================================================
%% Handler dispatch (mirrors masque_h2_server_session)
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
                {stop, Reason} ->
                    {stop, Reason, S};
                _ ->
                    {noreply, S}
            end;
        false ->
            {noreply, S}
    end.

exported(Mod, Fun, Arity) ->
    _ = code:ensure_loaded(Mod),
    erlang:function_exported(Mod, Fun, Arity).

apply_actions(Actions, State) ->
    case do_actions(Actions, State) of
        {ok, S2} -> {ok, S2};
        {stop, Reason, _} -> {stop, Reason}
    end.

apply_actions_noreply(Actions, State) ->
    case do_actions(Actions, State) of
        {ok, S2} -> {noreply, S2};
        {stop, Reason, S2} -> {stop, Reason, S2}
    end.

do_actions([], S) ->
    {ok, S};
do_actions([{send, Data} | Rest], S) ->
    do_actions([{send, ?MASQUE_CONTEXT_ID_UDP, Data} | Rest], S);
do_actions([{send, Ctx, Data} | Rest], S) ->
    PayloadSize = iolist_size(Data),
    case
        Ctx =:= ?MASQUE_CONTEXT_ID_UDP andalso
            PayloadSize > ?MASQUE_MAX_UDP_PAYLOAD
    of
        true ->
            do_actions(Rest, S);
        false ->
            Inner = iolist_to_binary(masque_datagram:encode(Ctx, Data)),
            _ = h1_upgrade:send_capsule(
                S#state.transport,
                S#state.socket,
                datagram,
                Inner
            ),
            do_actions(Rest, S)
    end;
do_actions([{send_capsule, Type, Value} | Rest], S) ->
    _ = h1_upgrade:send_capsule(
        S#state.transport,
        S#state.socket,
        Type,
        Value
    ),
    do_actions(Rest, S);
do_actions([close_session | _Rest], S) ->
    {stop, normal, S};
do_actions([{close_session, _Code, _Msg} | _Rest], S) ->
    {stop, normal, S};
do_actions([_Unknown | Rest], S) ->
    do_actions(Rest, S).

safe_apply(M, F, A) ->
    try
        apply(M, F, A)
    catch
        Class:Reason:Stack ->
            logger:error(
                "masque h1 handler ~p:~p/~p failed: ~p:~p~n~p",
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
%% Socket helpers
%%====================================================================

arm_once(#state{transport = ssl, socket = Sock}) ->
    ssl:setopts(Sock, [{active, once}, {mode, binary}]);
arm_once(#state{transport = gen_tcp, socket = Sock}) ->
    inet:setopts(Sock, [{active, once}, {mode, binary}]).

close_socket(#state{transport = T, socket = S}) ->
    close_transport(T, S).

close_transport(ssl, S) ->
    try
        ssl:close(S)
    catch
        _:_ -> ok
    end;
close_transport(gen_tcp, S) ->
    try
        gen_tcp:close(S)
    catch
        _:_ -> ok
    end.

%% `h1:accept_upgrade/3' returns the raw socket without identifying the
%% transport. Infer it from the shape: ssl sockets are `#sslsocket{}'
%% records; gen_tcp sockets are ports (or nif socket records).
socket_transport(Socket) when
    is_tuple(Socket),
    element(1, Socket) =:= sslsocket
->
    ssl;
socket_transport(_) ->
    gen_tcp.

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
