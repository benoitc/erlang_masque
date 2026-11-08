%%% Server side of a reverse connect control channel over HTTP/3 or
%%% HTTP/2 (draft-rosomakho-masque-reverse-connect-01 sections 4 and 5).
%%%
%%% The stream carries capsules only. The client sends AVAILABLE_SERVICES
%%% and CONNECTION_REQUEST_DECLINED; this session sends CONNECTION_REQUEST
%%% for each `masque:request_connection/3' call and answers the caller
%%% when the matching accept stream starts, the client declines, or the
%%% request times out. Every capsule write blocks until the transport
%%% takes it (`masque_stream_send'), so none is dropped on a busy
%%% connection.
%%%
%%% The `listen_handler' module follows the channel: `init/2' runs in this
%%% process (so `self()' is the handle to pass to
%%% `masque:request_connection/3'), then `handle_services/2',
%%% `handle_info/2' and `terminate/2'.
-module(masque_listen_server_session).
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
-include("masque_reverse.hrl").

%% RFC 9114 section 8.1: a malformed capsule is a message error
%% (RFC 9297 section 3.3).
-define(H3_MESSAGE_ERROR, 16#10e).

-record(state, {
    conn :: pid(),
    stream_id :: non_neg_integer(),
    transport :: h3 | h2,
    handler :: module(),
    h_state :: term(),
    identity :: term(),
    router_ref :: reference() | undefined,
    %% H3 path: waiting for the router's finalize. Messages and calls
    %% that arrive meanwhile wait for the 2xx.
    pending = false :: boolean(),
    early = [] :: [term()],
    early_calls = [] :: [{term(), gen_server:from()}],
    buf = <<>> :: binary(),
    max_cap = ?MASQUE_DEFAULT_MAX_CAPSULE_SIZE :: pos_integer(),
    %% Outstanding requests: id -> {caller, timer}.
    requests = #{} :: #{non_neg_integer() => {gen_server:from(), reference()}},
    idle_ms = infinity :: non_neg_integer() | infinity,
    idle :: masque_idle:idle() | undefined,
    start_time :: integer() | undefined,
    fin_sent = false :: boolean()
}).

%%====================================================================
%% API
%%====================================================================

-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

%%====================================================================
%% gen_server
%%====================================================================

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

start(
    #{
        conn := Conn,
        stream_id := StreamId,
        transport := Transport,
        handler := Handler,
        handler_opts := HOpts,
        req := #{reverse_identity := Identity} = Req
    } = Args
) ->
    process_flag(trap_exit, true),
    RouterRef =
        case maps:find(router, Args) of
            {ok, Router} -> erlang:monitor(process, Router);
            error -> undefined
        end,
    case init_handler(Handler, Identity, Req) of
        {ok, HState} ->
            S = #state{
                conn = Conn,
                stream_id = StreamId,
                transport = Transport,
                handler = Handler,
                h_state = HState,
                identity = Identity,
                router_ref = RouterRef,
                max_cap = maps:get(max_capsule_size, HOpts, ?MASQUE_DEFAULT_MAX_CAPSULE_SIZE),
                idle_ms = maps:get(idle_timeout_ms, HOpts, infinity)
            },
            case RouterRef of
                undefined ->
                    case open(S) of
                        {ok, S2} -> {ok, S2};
                        {error, S2} -> {stop, stream_dead, S2}
                    end;
                _ ->
                    {ok, S#state{pending = true}}
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

%% Send the 2xx and take the stream.
open(#state{transport = T, conn = C, stream_id = Sid} = S) ->
    case send_response(T, C, Sid) of
        ok ->
            case claim(T, C, Sid) of
                {error, _} ->
                    {error, S};
                _ ->
                    masque_metrics:tunnel_opened(#{protocol => listen, transport => T}),
                    {ok, S#state{
                        pending = false,
                        start_time = erlang:monotonic_time(millisecond),
                        idle = masque_idle:new(S#state.idle_ms)
                    }}
            end;
        {error, _} ->
            {error, S}
    end.

send_response(h3, C, Sid) -> quic_h3:send_response(C, Sid, 200, response_headers());
send_response(h2, C, Sid) -> h2:send_response(C, Sid, 200, response_headers()).

response_headers() -> [{<<"capsule-protocol">>, <<"?1">>}].

claim(h3, C, Sid) -> quic_h3:set_stream_handler(C, Sid, self(), #{drain_buffer => false});
claim(h2, C, Sid) -> h2:set_stream_handler(C, Sid, self()).

%% H3: the router's finalize, after which the stream is ours.
finalize(#state{early = Early, early_calls = Calls} = S) ->
    case open(S) of
        {ok, S1} ->
            S2 = S1#state{early = [], early_calls = []},
            case replay(lists:reverse(Early), S2) of
                {noreply, S3} -> replay_calls(lists:reverse(Calls), S3);
                Stop -> Stop
            end;
        {error, S1} ->
            {error, S1}
    end.

replay([], S) ->
    {noreply, S};
replay([Msg | Rest], S) ->
    case handle_info(Msg, S) of
        {noreply, S2} -> replay(Rest, S2);
        Stop -> Stop
    end.

replay_calls([], S) ->
    {noreply, S};
replay_calls([{Request, From} | Rest], S) ->
    case handle_call(Request, From, S) of
        {noreply, S2} ->
            replay_calls(Rest, S2);
        {reply, Reply, S2} ->
            gen_server:reply(From, Reply),
            replay_calls(Rest, S2);
        {stop, Reason, Reply, S2} ->
            gen_server:reply(From, Reply),
            {stop, Reason, S2}
    end.

handle_call(Request, From, State) ->
    masque_quiet:stop(handle_call_inner(Request, From, State)).

handle_call_inner(finalize, _From, #state{pending = true} = S) ->
    case finalize(S) of
        {noreply, S2} -> {reply, ok, S2};
        {stop, Reason, S2} -> {stop, Reason, ok, S2};
        {error, S2} -> {reply, {error, stream_dead}, S2}
    end;
handle_call_inner(Request, From, #state{pending = true, early_calls = Calls} = S) ->
    {noreply, S#state{early_calls = [{Request, From} | Calls]}};
handle_call_inner({request_connection, Service, Timeout}, {Pid, _} = From, S) ->
    request_connection(Service, Timeout, Pid, From, S);
handle_call_inner(info, _From, #state{transport = T, identity = I, requests = R} = S) ->
    {reply, #{protocol => listen, transport => T, identity => I, pending => map_size(R)}, S};
handle_call_inner(_Request, _From, S) ->
    {reply, {error, unknown_call}, S}.

%% Section 5.1: a random id, registered before the capsule goes out, so
%% the accept that follows always finds it.
request_connection(Service, Timeout, Requester, From, S) ->
    #state{transport = T, conn = C, stream_id = Sid, identity = I, requests = R} = S,
    Entry = #{
        control => self(),
        conn => C,
        identity => I,
        requester => Requester,
        service => Service
    },
    Id = masque_reverse_registry:register(Entry),
    Capsule = masque_reverse_capsule:encode({connection_request, Id, Service}),
    case masque_stream_send:send(T, C, Sid, Capsule, false) of
        ok ->
            TRef = erlang:start_timer(Timeout, self(), {request_timeout, Id}),
            {noreply, touch(S#state{requests = R#{Id => {From, TRef}}})};
        {error, Reason} ->
            ok = masque_reverse_registry:delete(Id),
            {stop, {control_send_failed, Reason}, {error, closed}, S}
    end.

handle_cast(Msg, State) ->
    masque_quiet:stop(handle_cast_inner(Msg, State)).

handle_cast_inner({finalize, Router}, #state{pending = true} = S) ->
    Result = finalize(S),
    Reply =
        case Result of
            {error, _} -> {error, stream_dead};
            _ -> ok
        end,
    Router ! {masque_finalized, S#state.stream_id, self(), Reply},
    case Result of
        {noreply, S2} -> {noreply, S2};
        {stop, Reason, S2} -> {stop, Reason, S2};
        {error, S2} -> {stop, stream_dead, S2}
    end;
handle_cast_inner(connection_closed, S) ->
    {stop, connection_closed, S};
handle_cast_inner(_Msg, S) ->
    {noreply, S}.

handle_info(Msg, State) ->
    masque_quiet:stop(handle_info_inner(Msg, State)).

%% This stream carries no HTTP datagrams; the h3 router passes on
%% whatever the peer sends for it. Drop them before they count as
%% traffic, so they cannot keep the stream from idling out or pile up.
handle_info_inner({masque_datagram_in, _, _}, S) ->
    {noreply, S};
handle_info_inner({timeout, Ref, masque_idle}, #state{idle = Idle} = S) when Idle =/= undefined ->
    case masque_idle:check(Ref, Idle) of
        expired -> {stop, idle_timeout, S};
        {ok, Idle2} -> {noreply, S#state{idle = Idle2}}
    end;
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
            {noreply, touch(S#state{requests = R2})};
        error ->
            %% The caller gave up first: nobody owns the stream.
            %% Stopped, not killed, so its `terminate' resets the stream
            %% and frees the h2 tunnel slot and the gauge.
            gen_server:cast(Stream, abandon),
            {noreply, S}
    end;
handle_info_inner({'DOWN', MRef, process, _, _}, #state{router_ref = MRef} = S) ->
    {stop, router_gone, S};
handle_info_inner(Msg, #state{pending = true, early = Early} = S) ->
    {noreply, S#state{early = [Msg | Early]}};
handle_info_inner({Tag, _Conn, {data, Sid, Bytes, Fin}}, #state{stream_id = Sid} = S) when
    Tag =:= quic_h3; Tag =:= h2
->
    stream_in(Bytes, Fin, touch(S));
handle_info_inner({masque_stream_data, Sid, Bytes, Fin}, #state{stream_id = Sid} = S) ->
    stream_in(Bytes, Fin, touch(S));
handle_info_inner({Tag, _Conn, {stream_reset, Sid, _}}, #state{stream_id = Sid} = S) when
    Tag =:= quic_h3; Tag =:= h2
->
    {stop, peer_reset, S};
handle_info_inner({masque_stream_reset, Sid, _}, #state{stream_id = Sid} = S) ->
    {stop, peer_reset, S};
handle_info_inner({quic_h3, _Conn, {send_ready, _}}, S) ->
    {noreply, S};
handle_info_inner({h2, _Conn, {closed, _}}, S) ->
    {stop, peer_closed, S};
handle_info_inner({'EXIT', _Pid, _Reason}, S) ->
    {noreply, S};
handle_info_inner(Msg, S) ->
    dispatch(handle_info, [Msg], S).

%% Capsules from the client. Unknown types are skipped (RFC 9297
%% section 3.3); a malformed one aborts the channel.
stream_in(Bytes, Fin, #state{buf = Buf} = S) ->
    case capsules(<<Buf/binary, Bytes/binary>>, S) of
        {ok, Rest, S2} when Fin, Rest =:= <<>> ->
            {stop, normal, S2#state{buf = <<>>}};
        {ok, _Rest, S2} when Fin ->
            {stop, truncated_capsule, S2};
        {ok, Rest, S2} ->
            {noreply, S2#state{buf = Rest}};
        {stop, _, _} = Stop ->
            Stop
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
                    %% Section 5.1: a DECLINED for no outstanding request
                    %% is a stream error.
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

touch(#state{idle = undefined} = S) -> S;
touch(#state{idle = Idle} = S) -> S#state{idle = masque_idle:touch(Idle)}.

terminate(Reason, State) ->
    terminate_inner(masque_quiet:reason(Reason), State).

terminate_inner(_Reason, {starting, Args}) ->
    masque_session_start:abandon(Args);
terminate_inner(Reason, #state{handler = Handler, h_state = HS, requests = R} = S) ->
    %% Requests still waiting for an accept fail now.
    maps:foreach(
        fun(_Id, {From, TRef}) ->
            _ = erlang:cancel_timer(TRef),
            gen_server:reply(From, {error, closed})
        end,
        R
    ),
    ok = masque_reverse_registry:delete_control(self()),
    _ =
        (try
            end_stream(Reason, S)
        catch
            _:_ -> ok
        end),
    maybe_release_h2_tunnel(S),
    try_callback(Handler, terminate, [Reason, HS]),
    emit_closed(S),
    ok.

%% The client's reset or connection loss needs no answer; a bad capsule
%% resets the stream; any other end closes it with FIN.
end_stream(Reason, _S) when
    Reason =:= peer_reset;
    Reason =:= peer_closed;
    Reason =:= connection_closed;
    Reason =:= router_gone
->
    ok;
end_stream(Reason, #state{transport = h3, conn = C, stream_id = Sid}) when
    Reason =:= malformed_capsule;
    Reason =:= truncated_capsule;
    Reason =:= capsule_buffer_overflow
->
    quic_h3:cancel(C, Sid, ?H3_MESSAGE_ERROR);
end_stream(Reason, #state{transport = h2, conn = C, stream_id = Sid}) when
    Reason =:= malformed_capsule;
    Reason =:= truncated_capsule;
    Reason =:= capsule_buffer_overflow
->
    h2:cancel(C, Sid, protocol_error);
end_stream(_Reason, #state{pending = true}) ->
    ok;
end_stream(_Reason, #state{transport = h3, conn = C, stream_id = Sid}) ->
    quic_h3:send_data(C, Sid, <<>>, true);
end_stream(_Reason, #state{transport = h2, conn = C, stream_id = Sid}) ->
    h2:send_data(C, Sid, <<>>, true).

maybe_release_h2_tunnel(#state{transport = h2, conn = Conn}) ->
    masque_h2_server:release_tunnel(Conn);
maybe_release_h2_tunnel(_) ->
    ok.

emit_closed(#state{start_time = undefined}) ->
    ok;
emit_closed(#state{start_time = T, transport = Transport}) ->
    masque_metrics:tunnel_closed(
        erlang:monotonic_time(millisecond) - T, #{protocol => listen, transport => Transport}
    ).

code_change(_OldVsn, S, _Extra) ->
    {ok, S}.

exported(Mod, Fun, Arity) ->
    _ = code:ensure_loaded(Mod),
    erlang:function_exported(Mod, Fun, Arity).

safe_apply(M, F, A) ->
    try
        apply(M, F, A)
    catch
        Class:Reason:Stack ->
            logger:error(
                "masque listen handler ~p:~p/~p failed: ~p:~p~n~p",
                [M, F, length(A), Class, Reason, Stack]
            ),
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
