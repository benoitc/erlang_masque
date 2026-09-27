%%% Per-tunnel server session for HTTP/2 MASQUE.
%%%
%%% One of these is spawned by the h2 request-handler fun after an
%%% Extended CONNECT (`:protocol = connect-udp`) passes validation.
%%%
%%% HTTP/2 has no native datagram channel; UDP payloads arrive as
%%% DATAGRAM capsules on the request-body stream, interleaved with
%%% any extension capsules. This module owns the capsule decode loop,
%%% dispatches to the user handler (same behaviour as the h3 server),
%%% and sends responses back as capsules on the same stream.
-module(masque_h2_server_session).
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

-define(DEFAULT_IDLE_MS, 300000).

-record(state, {
    conn :: pid(),
    stream_id :: non_neg_integer(),
    handler :: module(),
    h_state :: term(),
    req :: map(),
    cap_buf = <<>> :: binary(),
    max_cap :: pos_integer(),
    start_time :: integer() | undefined,
    %% Idle timeout (`idle_timeout_ms'), armed once the tunnel is open.
    idle_ms = ?DEFAULT_IDLE_MS :: non_neg_integer() | infinity,
    idle :: masque_idle:idle() | undefined
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

%% With a `starter' the real start runs in `handle_continue/2' so the
%% session supervisor is not held up (see `masque_session_start').
init(Args) ->
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

handle_continue(start, {starting, Args}) ->
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

%% A tunnel counts as open once `init_session/1' succeeded: the 2xx is
%% sent and the stream is ours. `terminate/2' closes it. `{stop, R}'
%% means nothing was sent; `{stop, R, S}' means the handler started
%% (and the 2xx may be out), so `terminate/2' must clean up.
start(Args) ->
    case init_session(Args) of
        {ok, S} ->
            masque_metrics:tunnel_opened(#{protocol => udp, transport => h2}),
            {ok, S#state{
                start_time = erlang:monotonic_time(millisecond),
                idle = masque_idle:new(S#state.idle_ms)
            }};
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
    case init_handler(Handler, Req, HOpts) of
        {ok, HState, Actions} ->
            State0 = #state{
                conn = Conn,
                stream_id = StreamId,
                handler = Handler,
                idle_ms = maps:get(idle_timeout_ms, HOpts, ?DEFAULT_IDLE_MS),
                h_state = HState,
                req = Req,
                max_cap = MaxCap
            },
            case h2:send_response(Conn, StreamId, 200, response_headers()) of
                ok ->
                    case claim_stream(State0) of
                        {ok, State1} ->
                            %% If `claim_stream' drained buffered data
                            %% into `cap_buf', schedule an immediate
                            %% drain so capsules don't wait until the
                            %% next inbound DATA frame.
                            State = maybe_flush_buf(State1),
                            case do_actions(Actions, State) of
                                {ok, S2} -> {ok, S2};
                                {stop, Reason, S2} -> {stop, Reason, S2}
                            end;
                        {error, _} ->
                            {stop, stream_dead, State0}
                    end;
                {error, _} ->
                    {stop, stream_dead, State0}
            end;
        {stop, Reason} ->
            {stop, Reason}
    end.

claim_stream(
    #state{
        conn = Conn,
        stream_id = StreamId,
        cap_buf = Buf
    } = S
) ->
    case h2:set_stream_handler(Conn, StreamId, self()) of
        ok ->
            {ok, S};
        {ok, Chunks} ->
            More = iolist_to_binary([D || {D, _Fin} <- Chunks]),
            {ok, S#state{cap_buf = <<Buf/binary, More/binary>>}};
        {error, _} = Err ->
            Err
    end.

response_headers() ->
    [{<<"capsule-protocol">>, <<"?1">>}].

maybe_flush_buf(#state{cap_buf = <<>>} = S) ->
    S;
maybe_flush_buf(#state{} = S) ->
    self() ! flush_cap_buf,
    S.

handle_call(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

handle_cast(_Msg, S) ->
    {noreply, S}.

%% Every message counts as traffic for the idle timer; the timer's
%% own message checks whether the tunnel has been idle long enough.
handle_info({timeout, Ref, masque_idle}, #state{idle = Idle} = S) when Idle =/= undefined ->
    case masque_idle:check(Ref, Idle) of
        expired -> {stop, idle_timeout, S};
        {ok, Idle2} -> {noreply, S#state{idle = Idle2}}
    end;
handle_info(Msg, #state{idle = Idle} = S) when Idle =/= undefined ->
    handle_traffic(Msg, S#state{idle = masque_idle:touch(Idle)});
handle_info(Msg, S) ->
    handle_traffic(Msg, S).

handle_traffic(
    {h2, _Conn, {data, StreamId, Bytes, Fin}},
    #state{
        stream_id = StreamId,
        cap_buf = Buf,
        max_cap = Max
    } = S
) ->
    New = <<Buf/binary, Bytes/binary>>,
    case byte_size(New) > Max of
        true -> reset_and_stop(capsule_buffer_overflow, S);
        false -> drain_capsules(New, Fin, S)
    end;
handle_traffic(flush_cap_buf, #state{cap_buf = Buf} = S) when Buf =/= <<>> ->
    drain_capsules(Buf, false, S#state{cap_buf = <<>>});
handle_traffic(flush_cap_buf, S) ->
    {noreply, S};
handle_traffic({'EXIT', _Pid, _Reason}, S) ->
    {noreply, S};
handle_traffic(
    {h2, _Conn, {stream_reset, StreamId, _}},
    #state{stream_id = StreamId} = S
) ->
    {stop, peer_reset, S};
handle_traffic({h2, _Conn, {closed, _Reason}}, S) ->
    {stop, peer_closed, S};
handle_traffic(Msg, S) ->
    dispatch(handle_info, [Msg], S).

terminate(_Reason, {starting, Args}) ->
    masque_session_start:abandon(Args);
terminate(Reason, S) ->
    emit_tunnel_closed(S),
    terminate_session(Reason, S).

emit_tunnel_closed(#state{start_time = undefined}) ->
    ok;
emit_tunnel_closed(#state{start_time = T}) ->
    masque_metrics:tunnel_closed(
        erlang:monotonic_time(millisecond) - T,
        #{protocol => udp, transport => h2}
    ).

terminate_session(normal, #state{
    conn = Conn,
    stream_id = StreamId,
    handler = Handler,
    h_state = HState
}) ->
    masque_h2_server:release_tunnel(Conn),
    _ =
        (try
            h2:send_data(Conn, StreamId, <<>>, true)
        catch
            _:_ -> ok
        end),
    try_callback(Handler, terminate, [normal, HState]),
    ok;
terminate_session(Reason, #state{
    conn = Conn,
    handler = Handler,
    h_state = HState
}) when
    Reason =:= peer_reset;
    Reason =:= peer_closed
->
    masque_h2_server:release_tunnel(Conn),
    try_callback(Handler, terminate, [Reason, HState]),
    ok;
terminate_session(Reason, #state{
    conn = Conn,
    stream_id = StreamId,
    handler = Handler,
    h_state = HState
}) ->
    masque_h2_server:release_tunnel(Conn),
    _ =
        (try
            h2:cancel(Conn, StreamId, protocol_error)
        catch
            _:_ -> ok
        end),
    try_callback(Handler, terminate, [Reason, HState]),
    ok.

code_change(_OldVsn, S, _Extra) ->
    {ok, S}.

%%====================================================================
%% Capsule decode loop
%%====================================================================

drain_capsules(Buf, Fin, S) ->
    case h2_capsule:decode(Buf) of
        {ok, {Type, Inner}, Rest} ->
            case dispatch_capsule(Type, Inner, S) of
                {noreply, S2} ->
                    drain_capsules(Rest, Fin, S2#state{cap_buf = <<>>});
                {stop, _, _} = Stop ->
                    Stop
            end;
        {more, _} when Fin, Buf =/= <<>> ->
            reset_and_stop(truncated_capsule, S);
        {more, _} when Fin ->
            %% Clean END_STREAM: terminate/2 sends our END_STREAM back.
            {stop, normal, S#state{cap_buf = <<>>}};
        {more, _} ->
            {noreply, S#state{cap_buf = Buf}}
    end.

dispatch_capsule(datagram, Inner, S) ->
    case masque_datagram:decode(Inner) of
        {ok, {?MASQUE_CONTEXT_ID_UDP, UdpBytes}} when
            byte_size(UdpBytes) =< ?MASQUE_MAX_UDP_PAYLOAD
        ->
            dispatch(handle_packet, [UdpBytes], S);
        _ ->
            %% Unknown context-id or oversize: RFC 9298 §5 says drop.
            {noreply, S}
    end;
dispatch_capsule(Type, Inner, S) when is_integer(Type) ->
    dispatch(handle_capsule, [Type, Inner], S).

reset_and_stop(Reason, #state{conn = Conn, stream_id = StreamId} = S) ->
    _ =
        (try
            h2:cancel(Conn, StreamId, protocol_error)
        catch
            _:_ -> ok
        end),
    {stop, Reason, S}.

%%====================================================================
%% Handler dispatch (mirrors masque_server_session)
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
            Capsule = iolist_to_binary(h2_capsule:encode(datagram, Inner)),
            _ = h2:send_data(
                S#state.conn,
                S#state.stream_id,
                Capsule,
                false
            ),
            do_actions(Rest, S)
    end;
do_actions([{send_capsule, Type, Value} | Rest], S) ->
    Enc = iolist_to_binary(masque_capsule:encode(Type, Value)),
    _ = h2:send_data(S#state.conn, S#state.stream_id, Enc, false),
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
                "masque h2 handler ~p:~p/~p failed: ~p:~p~n~p",
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
