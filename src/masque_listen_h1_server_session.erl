%%% Server side of a reverse connect control channel over HTTP/1.1
%%% (draft-rosomakho-masque-reverse-connect-01 section 4.2).
%%%
%%% After the 101 the TLS socket carries capsules only, as in
%%% `masque_listen_server_session'. Writes go straight to the socket,
%%% bounded by its send timeout (`masque_tls:bound_sends/2'): a client
%%% that stops reading ends the channel instead of losing a capsule.
%%% Accept streams come on new connections and are matched to this
%%% channel by the identity `authenticate/1' returned.
-module(masque_listen_h1_server_session).
-moduledoc false.
-behaviour(gen_server).

-export([start_link/1]).

-export([
    init/1,
    handle_continue/2,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-include("masque.hrl").

-record(state, {
    transport :: ssl | gen_tcp,
    socket :: term(),
    handler :: module(),
    h_state :: term(),
    identity :: term(),
    buf = <<>> :: binary(),
    max_cap = ?MASQUE_DEFAULT_MAX_CAPSULE_SIZE :: pos_integer(),
    requests = #{} :: #{non_neg_integer() => {gen_server:from(), reference()}},
    idle_ms = infinity :: non_neg_integer() | infinity,
    idle_ref :: reference() | undefined,
    start_time :: integer() | undefined
}).

-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

init(Args) ->
    masque_quiet:stop(init_inner(Args)).

init_inner(Args) ->
    case masque_session_start:deferred(Args) of
        true ->
            {ok, {starting, Args}, {continue, start}};
        false ->
            case start(Args) of
                {ok, S} -> {ok, S};
                {stop, Reason} -> {stop, Reason};
                {stop, Reason, _S} -> {stop, Reason}
            end
    end.

handle_continue(Continue, State) ->
    masque_quiet:stop(handle_continue_inner(Continue, State)).

handle_continue_inner(start, {starting, Args}) ->
    case start(Args) of
        {ok, S} ->
            masque_session_start:report(Args, ok),
            {noreply, S};
        {stop, Reason} ->
            masque_session_start:report(Args, {error, Reason}),
            {stop, normal, {starting, Args}};
        {stop, Reason, S} ->
            masque_session_start:report(Args, {error, {responded, Reason}}),
            {stop, {shutdown, Reason}, S}
    end.

start(#{
    conn := Conn,
    stream_id := StreamId,
    handler := Handler,
    handler_opts := HOpts,
    req := #{reverse_identity := Identity} = Req
}) ->
    process_flag(trap_exit, true),
    case init_handler(Handler, Identity, Req) of
        {ok, HState} ->
            case h1:accept_upgrade(Conn, StreamId, [{<<"capsule-protocol">>, <<"?1">>}]) of
                {ok, Socket, Buffer} ->
                    Transport = socket_transport(Socket),
                    _ = masque_tls:bound_sends(Transport, Socket),
                    masque_metrics:tunnel_opened(#{protocol => listen, transport => h1}),
                    S0 = #state{
                        transport = Transport,
                        socket = Socket,
                        handler = Handler,
                        h_state = HState,
                        identity = Identity,
                        max_cap = maps:get(
                            max_capsule_size, HOpts, ?MASQUE_DEFAULT_MAX_CAPSULE_SIZE
                        ),
                        idle_ms = maps:get(idle_timeout_ms, HOpts, infinity),
                        start_time = erlang:monotonic_time(millisecond)
                    },
                    case bytes_in(Buffer, arm_idle(S0)) of
                        {noreply, S1} ->
                            _ = arm_once(S1),
                            {ok, S1};
                        {stop, Reason, S1} ->
                            {stop, Reason, S1}
                    end;
                {error, Reason} ->
                    try_callback(Handler, terminate, [{accept_upgrade, Reason}, HState]),
                    {stop, {accept_upgrade, Reason}}
            end;
        {stop, Reason} ->
            {stop, Reason}
    end.

init_handler(Handler, Identity, Req) ->
    case exported(Handler, init, 2) of
        true ->
            case safe_apply(Handler, init, [Identity, Req]) of
                {ok, HState} -> {ok, HState};
                {stop, Reason} -> {stop, Reason};
                Other -> {stop, {bad_init, Other}}
            end;
        false ->
            {ok, Identity}
    end.

socket_transport(Socket) when is_tuple(Socket), element(1, Socket) =:= sslsocket -> ssl;
socket_transport(_Socket) -> gen_tcp.

handle_call(Request, From, State) ->
    masque_quiet:stop(handle_call_inner(Request, From, State)).

handle_call_inner({request_connection, Service, Timeout}, {Pid, _} = From, #state{} = S) ->
    #state{identity = I, requests = R} = S,
    Entry = #{
        control => self(), conn => undefined, identity => I, requester => Pid, service => Service
    },
    Id = masque_reverse_registry:register(Entry),
    Capsule = masque_reverse_capsule:encode({connection_request, Id, Service}),
    case send(S, Capsule) of
        ok ->
            TRef = erlang:start_timer(Timeout, self(), {request_timeout, Id}),
            {noreply, S#state{requests = R#{Id => {From, TRef}}}};
        {error, Reason} ->
            ok = masque_reverse_registry:delete(Id),
            {stop, {control_send_failed, Reason}, {error, closed}, S}
    end;
handle_call_inner(info, _From, #state{identity = I, requests = R} = S) ->
    {reply, #{protocol => listen, transport => h1, identity => I, pending => map_size(R)}, S};
handle_call_inner(_Request, _From, S) ->
    {reply, {error, unknown_call}, S}.

handle_cast(Msg, State) ->
    masque_quiet:stop(handle_cast_inner(Msg, State)).

handle_cast_inner(_Msg, S) ->
    {noreply, S}.

handle_info(Msg, State) ->
    masque_quiet:stop(handle_info_inner(Msg, State)).

handle_info_inner({ssl, Sock, Bytes}, #state{socket = Sock} = S) ->
    rearm(bytes_in(Bytes, arm_idle(S)));
handle_info_inner({tcp, Sock, Bytes}, #state{socket = Sock} = S) ->
    rearm(bytes_in(Bytes, arm_idle(S)));
handle_info_inner({Closed, Sock}, #state{socket = Sock, buf = <<>>} = S) when
    Closed =:= ssl_closed; Closed =:= tcp_closed
->
    {stop, normal, S};
handle_info_inner({Closed, Sock}, #state{socket = Sock} = S) when
    Closed =:= ssl_closed; Closed =:= tcp_closed
->
    {stop, truncated_capsule, S};
handle_info_inner({Error, Sock, Reason}, #state{socket = Sock} = S) when
    Error =:= ssl_error; Error =:= tcp_error
->
    {stop, {Error, Reason}, S};
handle_info_inner({timeout, Ref, idle}, #state{idle_ref = Ref} = S) ->
    {stop, idle_timeout, S};
handle_info_inner({timeout, _TRef, {request_timeout, Id}}, #state{requests = R} = S) ->
    case maps:take(Id, R) of
        {{From, _}, R2} ->
            ok = masque_reverse_registry:delete(Id),
            gen_server:reply(From, {error, timeout}),
            {noreply, S#state{requests = R2}};
        error ->
            {noreply, S}
    end;
handle_info_inner({masque_reverse_accepted, Id, Stream}, #state{requests = R} = S) ->
    case maps:take(Id, R) of
        {{From, TRef}, R2} ->
            _ = erlang:cancel_timer(TRef),
            gen_server:reply(From, {ok, Stream}),
            {noreply, arm_idle(S#state{requests = R2})};
        error ->
            %% Stopped, not killed, so its `terminate' resets the stream
            %% and frees the h2 tunnel slot and the gauge.
            gen_server:cast(Stream, abandon),
            {noreply, S}
    end;
handle_info_inner({'EXIT', _Pid, _Reason}, S) ->
    {noreply, S};
handle_info_inner(Msg, S) ->
    dispatch(handle_info, [Msg], S).

rearm({noreply, S}) ->
    _ = arm_once(S),
    {noreply, S};
rearm(Stop) ->
    Stop.

bytes_in(<<>>, S) ->
    {noreply, S};
bytes_in(Bytes, #state{buf = Buf} = S) ->
    case capsules(<<Buf/binary, Bytes/binary>>, S) of
        {ok, Rest, S2} -> {noreply, S2#state{buf = Rest}};
        Stop -> Stop
    end.

capsules(Buf, #state{max_cap = Max} = S) ->
    case masque_capsule:decode(Buf) of
        {ok, {Type, Value, Rest}} ->
            case capsule(masque_reverse_capsule:type(Type), Value, S) of
                {noreply, S2} -> capsules(Rest, S2);
                Stop -> Stop
            end;
        {more, _} ->
            case masque_capsule:pending_size(Buf) > Max of
                true -> {stop, capsule_buffer_overflow, S};
                false -> {ok, Buf, S}
            end;
        {error, _} ->
            {stop, malformed_capsule, S}
    end.

capsule(available_services, Value, S) ->
    case masque_reverse_capsule:decode(available_services, Value) of
        {ok, {available_services, Services}} -> dispatch(handle_services, [Services], S);
        {error, _} -> {stop, malformed_capsule, S}
    end;
capsule(connection_request_declined, Value, #state{requests = R} = S) ->
    case masque_reverse_capsule:decode(connection_request_declined, Value) of
        {ok, {connection_request_declined, Id}} ->
            case maps:take(Id, R) of
                {{From, TRef}, R2} ->
                    _ = erlang:cancel_timer(TRef),
                    _ = masque_reverse_registry:take(Id),
                    gen_server:reply(From, {error, declined}),
                    {noreply, S#state{requests = R2}};
                error ->
                    {stop, malformed_capsule, S}
            end;
        {error, _} ->
            {stop, malformed_capsule, S}
    end;
capsule(_Other, _Value, S) ->
    {noreply, S}.

dispatch(CB, Extra, #state{handler = Handler, h_state = HS} = S) ->
    case exported(Handler, CB, length(Extra) + 1) of
        true ->
            case safe_apply(Handler, CB, Extra ++ [HS]) of
                {ok, HS2} -> {noreply, S#state{h_state = HS2}};
                {stop, Reason, HS2} -> {stop, Reason, S#state{h_state = HS2}};
                {stop, Reason} -> {stop, Reason, S};
                _ -> {noreply, S}
            end;
        false ->
            {noreply, S}
    end.

send(#state{transport = T, socket = Sock}, Bin) ->
    masque_tls:send_failed(T:send(Sock, Bin), T, Sock).

terminate(Reason, State) ->
    terminate_inner(masque_quiet:reason(Reason), State).

terminate_inner(_Reason, {starting, Args}) ->
    masque_session_start:abandon(Args);
terminate_inner(Reason, #state{handler = Handler, h_state = HS, requests = R} = S) ->
    maps:foreach(
        fun(_Id, {From, TRef}) ->
            _ = erlang:cancel_timer(TRef),
            gen_server:reply(From, {error, closed})
        end,
        R
    ),
    ok = masque_reverse_registry:delete_control(self()),
    _ = cancel_idle(S),
    _ =
        (try
            close_socket(S)
        catch
            _:_ -> ok
        end),
    try_callback(Handler, terminate, [Reason, HS]),
    masque_metrics:tunnel_closed(
        erlang:monotonic_time(millisecond) - S#state.start_time, #{
            protocol => listen, transport => h1
        }
    ),
    ok.

code_change(_OldVsn, S, _Extra) ->
    {ok, S}.

arm_once(#state{transport = ssl, socket = Sock}) -> ssl:setopts(Sock, [{active, once}]);
arm_once(#state{transport = gen_tcp, socket = Sock}) -> inet:setopts(Sock, [{active, once}]).

close_socket(#state{transport = ssl, socket = Sock}) -> ssl:close(Sock);
close_socket(#state{transport = gen_tcp, socket = Sock}) -> gen_tcp:close(Sock).

arm_idle(#state{idle_ms = infinity} = S) ->
    S;
arm_idle(#state{idle_ms = 0} = S) ->
    S;
arm_idle(#state{idle_ms = Ms} = S) ->
    _ = cancel_idle(S),
    S#state{idle_ref = erlang:start_timer(Ms, self(), idle)}.

cancel_idle(#state{idle_ref = undefined}) -> ok;
cancel_idle(#state{idle_ref = Ref}) -> erlang:cancel_timer(Ref).

exported(Mod, Fun, Arity) ->
    _ = code:ensure_loaded(Mod),
    erlang:function_exported(Mod, Fun, Arity).

safe_apply(M, F, A) ->
    try
        apply(M, F, A)
    catch
        Class:Reason:Stack ->
            masque_crash_log:handler("listen", M, F, length(A), Class, Reason, Stack),
            {stop, {handler_crash, Reason}}
    end.

try_callback(Mod, Fun, Args) ->
    case exported(Mod, Fun, length(Args)) of
        true ->
            _ = safe_apply(Mod, Fun, Args),
            ok;
        false ->
            ok
    end.
