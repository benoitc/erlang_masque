%%% @doc Per-tunnel server-side session.
%%%
%%% One of these is spawned by the listener's handler fun after a
%%% CONNECT-UDP request passes validation. It receives routed
%%% datagrams from the connection router (`masque_server_connection')
%%% and invokes the configured user handler module to produce reply
%%% datagrams or close the session.
-module(masque_server_session).
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
    conn :: pid(),
    stream_id :: non_neg_integer(),
    router :: pid(),
    handler :: module(),
    h_state :: term(),
    req :: map(),
    cap_buf = <<>> :: binary(),
    max_cap :: pos_integer(),
    cap_fin_seen = false :: boolean(),
    %% Actions from handler init, applied after finalize
    pending_actions :: [term()] | undefined,
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

init(#{
    conn := Conn,
    stream_id := StreamId,
    router := Router,
    handler := Handler,
    handler_opts := HOpts,
    req := Req
}) ->
    process_flag(trap_exit, true),
    %% Monitor router so we stop if it dies during or after init.
    erlang:monitor(process, Router),
    %% RFC 9298 §3: a 2xx response means the tunnel is set up and the
    %% proxy is ready to forward UDP. So the user's `init/2' (which
    %% for the built-in proxy opens the gen_udp socket and validates
    %% the target) MUST run to completion before we commit to 200.
    %%
    %% The 200 response and stream claiming are deferred to finalize/0,
    %% called by the router after registration, so the router stays
    %% responsive during handler init.
    MaxCap = maps:get(
        max_capsule_size,
        HOpts,
        ?MASQUE_DEFAULT_MAX_CAPSULE_SIZE
    ),
    case init_handler(Handler, Req, HOpts) of
        {ok, HState, Actions} ->
            State = #state{
                conn = Conn,
                stream_id = StreamId,
                router = Router,
                handler = Handler,
                h_state = HState,
                req = Req,
                max_cap = MaxCap,
                pending_actions = Actions
            },
            {ok, State};
        {stop, Reason} ->
            {stop, Reason}
    end.

response_headers() ->
    [{<<"capsule-protocol">>, <<"?1">>}].

%% `drain_buffer => false' makes quic_h3 replay bytes that arrived
%% before the claim as ordinary `{data, _, _, Fin}' messages, ahead of
%% any later data, so they go through the normal decode path.
claim_stream(#state{conn = Conn, stream_id = StreamId} = S) ->
    case
        quic_h3:set_stream_handler(Conn, StreamId, self(), #{
            drain_buffer => false
        })
    of
        {error, _} = Err -> Err;
        _ -> {ok, S}
    end.

handle_call(
    finalize,
    _From,
    #state{
        pending_actions = Actions,
        conn = Conn,
        stream_id = StreamId
    } = S
) when
    Actions =/= undefined
->
    case
        quic_h3:send_response(
            Conn,
            StreamId,
            200,
            response_headers()
        )
    of
        ok ->
            case claim_stream(S#state{pending_actions = undefined}) of
                {ok, State} ->
                    masque_metrics:tunnel_opened(
                        #{protocol => udp, transport => h3}
                    ),
                    {reply, ok,
                        run_init_actions(
                            Actions,
                            State#state{
                                start_time =
                                    erlang:monotonic_time(millisecond)
                            }
                        )};
                {error, _} ->
                    {reply, {error, stream_dead}, S}
            end;
        {error, _} ->
            {reply, {error, stream_dead}, S}
    end;
handle_call(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

handle_cast(connection_closed, S) ->
    {stop, connection_closed, S};
handle_cast(_Msg, S) ->
    {noreply, S}.

handle_info(
    {masque_datagram_in, StreamId, Payload},
    #state{stream_id = StreamId} = S
) ->
    masque_metrics:bytes_in(
        byte_size(Payload),
        #{protocol => udp, transport => h3}
    ),
    case masque_datagram:decode(Payload) of
        {ok, {?MASQUE_CONTEXT_ID_UDP, UdpBytes}} when
            byte_size(UdpBytes) =< ?MASQUE_MAX_UDP_PAYLOAD
        ->
            dispatch(handle_packet, [UdpBytes], S);
        {ok, {?MASQUE_CONTEXT_ID_UDP, _}} ->
            %% Oversized UDP payload — RFC 9298 §5 says drop.
            {noreply, S};
        {ok, {_Ctx, _Bytes}} ->
            %% Unknown context-id: RFC 9298 §5 says silently drop.
            {noreply, S};
        {error, _} ->
            {noreply, S}
    end;
handle_info(
    {masque_stream_data, StreamId, Data, Fin},
    #state{stream_id = StreamId} = S
) ->
    handle_stream_bytes(Data, Fin, S);
handle_info(
    {quic_h3, _Conn, {data, StreamId, Data, Fin}},
    #state{stream_id = StreamId} = S
) ->
    handle_stream_bytes(Data, Fin, S);
handle_info(
    {masque_stream_reset, StreamId, _ErrorCode},
    #state{stream_id = StreamId} = S
) ->
    {stop, peer_reset, S};
%% Once the stream is claimed, quic_h3 reports resets to us directly.
handle_info(
    {quic_h3, _Conn, {stream_reset, StreamId, _ErrorCode}},
    #state{stream_id = StreamId} = S
) ->
    {stop, peer_reset, S};
handle_info({'DOWN', _MRef, process, _Pid, _Reason}, S) ->
    %% Router died - clean up
    {stop, router_gone, S};
handle_info(Msg, S) ->
    dispatch(handle_info, [Msg], S).

terminate(
    normal,
    #state{
        conn = Conn,
        stream_id = StreamId,
        router = Router,
        handler = Handler,
        h_state = HState
    } = S
) ->
    emit_tunnel_closed(S),
    _ =
        (try
            quic_h3:send_data(Conn, StreamId, <<>>, true)
        catch
            _:_ -> ok
        end),
    _ =
        (try
            masque_server_connection:unregister_session(Router, StreamId)
        catch
            _:_ -> ok
        end),
    try_callback(Handler, terminate, [normal, HState]),
    ok;
terminate(
    Reason,
    #state{
        router = Router,
        stream_id = StreamId,
        handler = Handler,
        h_state = HState
    } = S
) when
    Reason =:= connection_closed;
    Reason =:= router_gone;
    Reason =:= peer_reset
->
    emit_tunnel_closed(S),
    _ =
        (try
            masque_server_connection:unregister_session(Router, StreamId)
        catch
            _:_ -> ok
        end),
    try_callback(Handler, terminate, [Reason, HState]),
    ok;
terminate(
    Reason,
    #state{
        router = Router,
        stream_id = StreamId,
        handler = Handler,
        h_state = HState
    } = S
) when
    Reason =:= truncated_capsule;
    Reason =:= capsule_buffer_overflow
->
    emit_tunnel_closed(S),
    _ =
        (try
            masque_server_connection:unregister_session(Router, StreamId)
        catch
            _:_ -> ok
        end),
    try_callback(Handler, terminate, [Reason, HState]),
    ok;
terminate(
    Reason,
    #state{
        conn = Conn,
        stream_id = StreamId,
        router = Router,
        handler = Handler,
        h_state = HState
    } = S
) ->
    emit_tunnel_closed(S),
    _ =
        (try
            quic_h3:cancel(Conn, StreamId, ?MASQUE_H3_MESSAGE_ERROR)
        catch
            _:_ -> ok
        end),
    _ =
        (try
            masque_server_connection:unregister_session(Router, StreamId)
        catch
            _:_ -> ok
        end),
    try_callback(Handler, terminate, [Reason, HState]),
    ok.

code_change(_OldVsn, S, _Extra) ->
    {ok, S}.

emit_tunnel_closed(#state{start_time = undefined}) ->
    ok;
emit_tunnel_closed(#state{start_time = T}) ->
    Duration = erlang:monotonic_time(millisecond) - T,
    masque_metrics:tunnel_closed(
        Duration,
        #{protocol => udp, transport => h3}
    ).

%%====================================================================
%% Handler dispatch
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

%% `erlang:function_exported/3` returns `false' for modules that have
%% not yet been loaded in this VM - which is the common case for a
%% user-supplied handler module encountered for the first time. Force
%% a load attempt before asking.
exported(Mod, Fun, Arity) ->
    _ = code:ensure_loaded(Mod),
    erlang:function_exported(Mod, Fun, Arity).

apply_actions_noreply(Actions, State) ->
    case do_actions(Actions, State) of
        {ok, S2} -> {noreply, S2};
        {stop, Reason, S2} -> {stop, Reason, S2}
    end.

run_init_actions([], S) ->
    S;
run_init_actions(Actions, S) ->
    case do_actions(Actions, S) of
        {ok, S2} -> S2;
        {stop, Reason, _} -> exit(Reason)
    end.

do_actions([], S) ->
    {ok, S};
do_actions([{send, Data} | Rest], S) ->
    do_actions([{send, ?MASQUE_CONTEXT_ID_UDP, Data} | Rest], S);
do_actions([{send, Ctx, Data} | Rest], S) ->
    %% Silent drop on oversize - RFC 9298 §5 (HTTP Datagrams are
    %% unreliable; application can resend if it cares).
    PayloadSize = iolist_size(Data),
    Max = quic_h3:max_datagram_size(S#state.conn, S#state.stream_id),
    Overhead = ctx_overhead(Ctx),
    TooBigForUDP =
        Ctx =:= ?MASQUE_CONTEXT_ID_UDP andalso
            PayloadSize > ?MASQUE_MAX_UDP_PAYLOAD,
    TooBigForQUIC = Max > 0 andalso (PayloadSize + Overhead) > Max,
    case TooBigForUDP orelse TooBigForQUIC of
        true ->
            do_actions(Rest, S);
        false ->
            Enc = masque_datagram:encode(Ctx, Data),
            _ = quic_h3:send_datagram(S#state.conn, S#state.stream_id, Enc),
            masque_metrics:bytes_out(
                PayloadSize,
                #{protocol => udp, transport => h3}
            ),
            do_actions(Rest, S)
    end;
do_actions([{send_capsule, Type, Value} | Rest], S) ->
    Enc = masque_capsule:encode(Type, Value),
    EncBin = iolist_to_binary(Enc),
    _ = quic_h3:send_data(S#state.conn, S#state.stream_id, EncBin, false),
    masque_metrics:bytes_out(
        byte_size(EncBin),
        #{protocol => udp, transport => h3}
    ),
    do_actions(Rest, S);
do_actions([close_session | _Rest], S) ->
    {stop, normal, S};
do_actions([{close_session, _Code, _Msg} | _Rest], S) ->
    {stop, normal, S};
do_actions([_Unknown | Rest], S) ->
    do_actions(Rest, S).

handle_stream_bytes(
    Data,
    Fin,
    #state{
        cap_buf = Buf,
        max_cap = Max
    } = S
) ->
    New = <<Buf/binary, Data/binary>>,
    case byte_size(New) > Max of
        true ->
            reset_and_stop(capsule_buffer_overflow, S);
        false ->
            drain_capsules(New, Fin, S#state{cap_fin_seen = Fin})
    end.

%% Pull every complete capsule out of `Buf` and dispatch it to the
%% handler module. Malformed capsules and a FIN arriving mid-capsule
%% abort the HTTP/3 stream with H3_MESSAGE_ERROR per RFC 9297 §3.3 /
%% RFC 9114 §4.1.2.
drain_capsules(Buf, Fin, S) ->
    case masque_capsule:decode(Buf) of
        {ok, {Type, Value, Rest}} ->
            case dispatch(handle_capsule, [Type, Value], S) of
                {noreply, S2} ->
                    drain_capsules(Rest, Fin, S2#state{cap_buf = <<>>});
                {stop, _, _} = Stop ->
                    Stop
            end;
        {more, _} when Fin, Buf =/= <<>> ->
            %% Stream closed mid-capsule — truncated.
            reset_and_stop(truncated_capsule, S);
        {more, _} when Fin ->
            %% Clean FIN on a capsule boundary: the client ended the
            %% tunnel. terminate/2 sends our FIN back.
            {stop, normal, S#state{cap_buf = <<>>}};
        {more, _} ->
            {noreply, S#state{cap_buf = Buf}};
        {error, _Reason} ->
            reset_and_stop(malformed_capsule, S)
    end.

reset_and_stop(Reason, #state{conn = Conn, stream_id = StreamId} = S) ->
    _ =
        (try
            quic_h3:cancel(Conn, StreamId, ?MASQUE_H3_MESSAGE_ERROR)
        catch
            _:_ -> ok
        end),
    {stop, Reason, S}.

safe_apply(M, F, A) ->
    try
        apply(M, F, A)
    catch
        Class:Reason:Stack ->
            error_logger:error_msg(
                "masque handler ~p:~p/~p failed: ~p:~p~n~p~n",
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

ctx_overhead(V) when V < 64 -> 1;
ctx_overhead(V) when V < 16384 -> 2;
ctx_overhead(V) when V < 1073741824 -> 4;
ctx_overhead(_) -> 8.
