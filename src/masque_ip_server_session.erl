%%% @doc Per-tunnel server session for CONNECT-IP (RFC 9484).
%%%
%%% Transport-generic (H3 + H2) in the shape of
%%% `masque_tcp_server_session': a single `gen_server' with a
%%% `transport :: h3 | h2' field that dispatches at the transport
%%% boundary. Over H3 the datagram channel is QUIC DATAGRAM frames
%%% (delivered via the connection router as
%%% `{masque_datagram_in, StreamId, Payload}'); over H2 it is the
%%% RFC 9297 DATAGRAM-type capsule on the stream body.
-module(masque_ip_server_session).
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
-include("masque_ip.hrl").

-record(state, {
    conn :: pid(),
    stream_id :: non_neg_integer(),
    router :: pid() | undefined,
    transport :: h3 | h2,
    handler :: module(),
    h_state :: term(),
    req :: map(),
    cap_buf = <<>> :: binary(),
    max_cap :: pos_integer(),
    pending_actions :: [term()] | undefined,
    %% Handler actions produced before the 200 is sent and the stream
    %% is claimed (e.g. an upstream ROUTE_ADVERTISEMENT forwarded by a
    %% chain handler whose init/2 raced ahead of finalize). Held in
    %% order and flushed once the stream is open.
    pending_out = [] :: [term()],
    %% Request IDs received from the client (from ADDRESS_REQUEST) but
    %% not yet answered by this server session.
    peer_pending = #{} :: #{pos_integer() => true},
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

init(
    #{
        conn := Conn,
        stream_id := StreamId,
        transport := Transport,
        handler := Handler,
        handler_opts := HOpts,
        req := Req
    } = Args
) ->
    process_flag(trap_exit, true),
    Router = maps:get(router, Args, undefined),
    _ =
        case Router of
            undefined -> ok;
            _ -> erlang:monitor(process, Router)
        end,
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
                transport = Transport,
                handler = Handler,
                h_state = HState,
                req = Req,
                max_cap = MaxCap
            },
            case Router of
                undefined ->
                    %% H2 path: send 200 + claim immediately.
                    finalize_h2(State, Actions);
                _ ->
                    {ok, State#state{pending_actions = Actions}}
            end;
        {stop, Reason} ->
            {stop, Reason}
    end.

finalize_h2(State0, Actions) ->
    case send_response(State0, 200, response_headers()) of
        ok ->
            State1 = claim_stream_and_buffer(State0),
            State = maybe_flush_buf(State1),
            apply_init_actions(Actions, State);
        {error, _} ->
            {stop, stream_dead}
    end.

%% Bytes that landed on the stream before the handler was claimed
%% are surfaced via `{ok, Chunks}'. Merge them into `cap_buf' so the
%% drain loop sees them.
claim_stream_and_buffer(
    #state{
        transport = h2,
        conn = C,
        stream_id = Sid,
        cap_buf = Buf
    } = S
) ->
    case h2:set_stream_handler(C, Sid, self()) of
        ok ->
            S;
        {ok, Chunks} ->
            More = iolist_to_binary([D || {D, _Fin} <- Chunks]),
            S#state{cap_buf = <<Buf/binary, More/binary>>};
        _ ->
            S
    end;
claim_stream_and_buffer(#state{transport = h3} = S) ->
    _ = claim_stream(S),
    S.

maybe_flush_buf(#state{cap_buf = <<>>} = S) ->
    S;
maybe_flush_buf(S) ->
    self() ! flush_cap_buf,
    S.

apply_init_actions(Actions, State) ->
    case do_actions(Actions, State) of
        {ok, S2} -> {ok, S2};
        {stop, Reason, _} -> {stop, Reason}
    end.

response_headers() ->
    [{<<"capsule-protocol">>, <<"?1">>}].

send_response(#state{transport = h3, conn = C, stream_id = S}, Status, Hdrs) ->
    quic_h3:send_response(C, S, Status, Hdrs);
send_response(#state{transport = h2, conn = C, stream_id = S}, Status, Hdrs) ->
    h2:send_response(C, S, Status, Hdrs).

claim_stream(#state{transport = h3, conn = C, stream_id = S}) ->
    quic_h3:set_stream_handler(C, S, self());
claim_stream(#state{transport = h2, conn = C, stream_id = S}) ->
    h2:set_stream_handler(C, S, self()).

%%====================================================================
%% Calls / casts
%%====================================================================

handle_call(
    finalize,
    _From,
    #state{pending_actions = Actions, pending_out = Out} = S
) when
    Actions =/= undefined
->
    case send_response(S, 200, response_headers()) of
        ok ->
            case claim_stream(S) of
                Ok when Ok =:= ok; is_tuple(Ok) ->
                    %% Stream is now open: run the handler's init actions,
                    %% then flush any actions buffered before finalize.
                    {reply, ok,
                        run_init_actions(
                            Actions ++ Out,
                            S#state{
                                pending_actions = undefined,
                                pending_out = [],
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
handle_cast({inject_packet, Pkt}, S) when is_binary(Pkt) ->
    %% Out-of-band packet injection from a process other than the
    %% session itself (e.g. a TUN device owner). Re-uses the same
    %% transport-send path the `{send_ip_packet, _}' action uses.
    case do_actions([{send_ip_packet, Pkt}], S) of
        {ok, S2} -> {noreply, S2};
        {stop, Reason, S2} -> {stop, Reason, S2}
    end;
handle_cast(_Msg, S) ->
    {noreply, S}.

%%====================================================================
%% Info — datagrams + stream bytes
%%====================================================================

%% H3 datagram path (via connection router).
handle_info(
    {masque_datagram_in, StreamId, Payload},
    #state{stream_id = StreamId} = S
) ->
    dispatch_datagram(Payload, S);
handle_info(
    {masque_stream_data, StreamId, Data, Fin},
    #state{stream_id = StreamId} = S
) ->
    handle_stream_bytes(Data, Fin, S);
handle_info(
    {masque_stream_reset, StreamId, _},
    #state{stream_id = StreamId} = S
) ->
    {stop, peer_reset, S};
handle_info(
    {Tag, _Conn, {data, StreamId, Bytes, Fin}},
    #state{stream_id = StreamId} = S
) when
    Tag =:= quic_h3; Tag =:= h2
->
    handle_stream_bytes(Bytes, Fin, S);
handle_info(
    {Tag, _Conn, {stream_reset, StreamId, _}},
    #state{stream_id = StreamId} = S
) when
    Tag =:= quic_h3; Tag =:= h2
->
    {stop, peer_reset, S};
handle_info({h2, _Conn, {closed, _Reason}}, S) ->
    {stop, peer_closed, S};
handle_info(flush_cap_buf, #state{cap_buf = Buf} = S) when Buf =/= <<>> ->
    drain_capsules(Buf, false, S#state{cap_buf = <<>>});
handle_info(flush_cap_buf, S) ->
    {noreply, S};
handle_info({'EXIT', _Pid, _Reason}, S) ->
    {noreply, S};
handle_info({'DOWN', _MRef, process, _Pid, _Reason}, S) ->
    {stop, router_gone, S};
handle_info(Msg, S) ->
    dispatch(handle_info, [Msg], S).

terminate(
    Reason,
    #state{
        conn = Conn,
        transport = Transport,
        router = Router,
        stream_id = StreamId,
        handler = Handler,
        h_state = HState
    } = S
) when
    Reason =:= connection_closed;
    Reason =:= router_gone;
    Reason =:= peer_reset;
    Reason =:= peer_closed
->
    maybe_release_h2_tunnel(Transport, Conn),
    _ = unregister_from_router(Router, StreamId),
    try_callback(Handler, terminate, [Reason, HState]),
    emit_tunnel_closed(S),
    ok;
terminate(
    Reason,
    #state{
        conn = Conn,
        transport = Transport,
        router = Router,
        stream_id = StreamId,
        handler = Handler,
        h_state = HState
    } = S
) ->
    maybe_release_h2_tunnel(Transport, Conn),
    _ = unregister_from_router(Router, StreamId),
    _ =
        (try
            transport_send_data(S, <<>>, true)
        catch
            _:_ -> ok
        end),
    try_callback(Handler, terminate, [Reason, HState]),
    emit_tunnel_closed(S),
    ok.

maybe_release_h2_tunnel(h2, Conn) -> masque_h2_server:release_tunnel(Conn);
maybe_release_h2_tunnel(_, _) -> ok.

unregister_from_router(undefined, _) ->
    ok;
unregister_from_router(Router, StreamId) ->
    try
        masque_server_connection:unregister_session(Router, StreamId)
    catch
        _:_ -> ok
    end.

emit_tunnel_closed(#state{start_time = undefined}) ->
    ok;
emit_tunnel_closed(#state{start_time = T, transport = Transport}) ->
    Duration = erlang:monotonic_time(millisecond) - T,
    masque_metrics:tunnel_closed(
        Duration,
        #{protocol => ip, transport => Transport}
    ).

code_change(_OldVsn, S, _Extra) ->
    {ok, S}.

%%====================================================================
%% Datagram dispatch
%%====================================================================

dispatch_datagram(Payload, S) ->
    case masque_datagram:decode(Payload) of
        {ok, {?MASQUE_CONTEXT_ID_IP, IPPkt}} ->
            dispatch(handle_ip_packet, [IPPkt], S);
        {ok, {_OtherCtx, _}} ->
            %% unknown context-id — silently drop
            {noreply, S};
        {error, _} ->
            {noreply, S}
    end.

%%====================================================================
%% Stream-body (capsule) handling
%%====================================================================

handle_stream_bytes(Data, Fin, #state{cap_buf = Buf, max_cap = Max} = S) ->
    New = <<Buf/binary, Data/binary>>,
    case byte_size(New) > Max of
        true -> reset_and_stop(capsule_buffer_overflow, S);
        false -> drain_capsules(New, Fin, S)
    end.

drain_capsules(Buf, Fin, S) ->
    case decode_one_capsule(S, Buf) of
        {ok, {Type, Inner}, Rest} ->
            case dispatch_capsule(Type, Inner, S) of
                {noreply, S2} ->
                    drain_capsules(Rest, Fin, S2#state{cap_buf = <<>>});
                Stop ->
                    Stop
            end;
        {more, _} when Fin, Buf =/= <<>> ->
            reset_and_stop(truncated_capsule, S);
        {more, _} ->
            {noreply, S#state{cap_buf = Buf}};
        {error, _} ->
            reset_and_stop(malformed_capsule, S)
    end.

%% h2_capsule decodes the `datagram` type natively; masque_capsule
%% (H3 path) returns the raw integer type.
decode_one_capsule(#state{transport = h2}, Buf) ->
    case h2_capsule:decode(Buf) of
        {ok, {datagram, Inner}, Rest} ->
            {ok, {datagram, Inner}, Rest};
        {ok, {Type, Inner}, Rest} when is_integer(Type) ->
            {ok, {Type, Inner}, Rest};
        Other ->
            Other
    end;
decode_one_capsule(#state{transport = h3}, Buf) ->
    case masque_capsule:decode(Buf) of
        {ok, {Type, Inner, Rest}} -> {ok, {Type, Inner}, Rest};
        Other -> Other
    end.

dispatch_capsule(datagram, Inner, S) ->
    %% H2-only: datagram is a capsule carrying a Context-ID+Payload.
    dispatch_datagram(Inner, S);
dispatch_capsule(
    ?MASQUE_CAPSULE_ADDRESS_REQUEST,
    Body,
    #state{peer_pending = Pend} = S
) ->
    case masque_ip_capsule:decode_address_request(Body) of
        {ok, Entries} ->
            Pend1 = lists:foldl(
                fun(#ip_prefix_request{request_id = Id}, Acc) ->
                    Acc#{Id => true}
                end,
                Pend,
                Entries
            ),
            dispatch(
                handle_address_request,
                [Entries],
                S#state{peer_pending = Pend1}
            );
        {error, _} ->
            reset_and_stop(malformed_capsule, S)
    end;
dispatch_capsule(?MASQUE_CAPSULE_ADDRESS_ASSIGN, Body, S) ->
    case masque_ip_capsule:decode_address_assign(Body) of
        {ok, Entries} ->
            dispatch(handle_address_assign, [Entries], S);
        {error, _} ->
            reset_and_stop(malformed_capsule, S)
    end;
dispatch_capsule(?MASQUE_CAPSULE_ROUTE_ADVERTISEMENT, Body, S) ->
    case masque_ip_capsule:decode_route_advertisement(Body) of
        {ok, Entries} ->
            dispatch(handle_route_advertisement, [Entries], S);
        {error, _} ->
            reset_and_stop(malformed_capsule, S)
    end;
dispatch_capsule(Type, Inner, S) when is_integer(Type) ->
    %% Unknown capsule — hand to generic handle_capsule if defined,
    %% otherwise ignore per RFC 9297 §3.3.
    dispatch(handle_capsule, [Type, Inner], S).

reset_and_stop(
    Reason,
    #state{
        transport = h3,
        conn = Conn,
        stream_id = StreamId
    } = S
) ->
    _ =
        (try
            quic_h3:cancel(Conn, StreamId, ?MASQUE_H3_MESSAGE_ERROR)
        catch
            _:_ -> ok
        end),
    {stop, Reason, S};
reset_and_stop(
    Reason,
    #state{
        transport = h2,
        conn = Conn,
        stream_id = StreamId
    } = S
) ->
    _ =
        (try
            h2:cancel(Conn, StreamId, protocol_error)
        catch
            _:_ -> ok
        end),
    {stop, Reason, S}.

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

exported(Mod, Fun, Arity) ->
    _ = code:ensure_loaded(Mod),
    erlang:function_exported(Mod, Fun, Arity).

%% Before finalize (pending_actions =/= undefined) the 200 has not been
%% sent and the stream is not claimed, so any outbound capsule would be
%% dropped. Hold these actions and let finalize flush them in order once
%% the stream is open.
apply_actions_noreply(
    Actions,
    #state{
        pending_actions = Pending,
        pending_out = Out
    } = State
) when
    Pending =/= undefined
->
    {noreply, State#state{pending_out = Out ++ Actions}};
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

%%====================================================================
%% Action interpreter
%%====================================================================

do_actions([], S) ->
    {ok, S};
do_actions([{send_ip_packet, Pkt} | Rest], S) ->
    _ = transport_send_datagram(S, ?MASQUE_CONTEXT_ID_IP, Pkt),
    do_actions(Rest, S);
do_actions([{assign, Entries} | Rest], S) ->
    case send_assign(Entries, S) of
        {ok, S2} -> do_actions(Rest, S2);
        {error, _} -> do_actions(Rest, S)
    end;
do_actions([{advertise, Routes} | Rest], S) ->
    _ = send_advertise(Routes, S),
    do_actions(Rest, S);
do_actions([{request_addresses, Prefixes} | Rest], S) ->
    _ = send_request(Prefixes, S),
    do_actions(Rest, S);
do_actions([{icmp_error, {Kind, Spec, Invoking}} | Rest], S) when
    is_binary(Invoking)
->
    Pkt = masque_icmp:apply_action(Kind, Spec, Invoking),
    _ = transport_send_datagram(S, ?MASQUE_CONTEXT_ID_IP, Pkt),
    do_actions(Rest, S);
do_actions([{icmp_error, _Bad} | Rest], S) ->
    do_actions(Rest, S);
do_actions([{send_capsule, Type, Value} | Rest], S) ->
    Enc = iolist_to_binary(masque_capsule:encode(Type, Value)),
    _ = transport_send_data(S, Enc, false),
    do_actions(Rest, S);
do_actions([{close, _Reason} | _Rest], S) ->
    {stop, normal, S};
do_actions([close_session | _Rest], S) ->
    {stop, normal, S};
do_actions([_Unknown | Rest], S) ->
    do_actions(Rest, S).

send_assign(Entries, #state{peer_pending = Pend} = S) ->
    %% Non-zero IDs must match an outstanding peer ADDRESS_REQUEST.
    case consume_pending(Entries, Pend) of
        {ok, Pend1} ->
            try masque_ip_capsule:encode_address_assign(Entries) of
                Body ->
                    Cap = iolist_to_binary(
                        masque_capsule:encode(
                            ?MASQUE_CAPSULE_ADDRESS_ASSIGN, Body
                        )
                    ),
                    case transport_send_data(S, Cap, false) of
                        ok -> {ok, S#state{peer_pending = Pend1}};
                        {error, _} = Err -> Err
                    end
            catch
                error:Reason -> {error, Reason}
            end;
        {error, _} = Err ->
            Err
    end.

consume_pending([], Pend) ->
    {ok, Pend};
consume_pending([#ip_assignment{request_id = 0} | Rest], Pend) ->
    consume_pending(Rest, Pend);
consume_pending([#ip_assignment{request_id = Id} | Rest], Pend) ->
    case maps:is_key(Id, Pend) of
        true -> consume_pending(Rest, maps:remove(Id, Pend));
        false -> {error, {no_such_pending_request, Id}}
    end.

send_advertise(Routes, S) ->
    try masque_ip_capsule:encode_route_advertisement(Routes) of
        Body ->
            Cap = iolist_to_binary(
                masque_capsule:encode(
                    ?MASQUE_CAPSULE_ROUTE_ADVERTISEMENT, Body
                )
            ),
            transport_send_data(S, Cap, false)
    catch
        error:Reason -> {error, Reason}
    end.

send_request(Prefixes, S) ->
    %% Server-initiated ADDRESS_REQUEST (§5.2 allows both directions).
    Ids = allocate_request_ids(length(Prefixes)),
    Entries = lists:zipwith(
        fun(Id, {V, A, P}) ->
            #ip_prefix_request{
                request_id = Id,
                version = V,
                address = A,
                prefix_len = P
            }
        end,
        Ids,
        Prefixes
    ),
    try masque_ip_capsule:encode_address_request(Entries) of
        Body ->
            Cap = iolist_to_binary(
                masque_capsule:encode(
                    ?MASQUE_CAPSULE_ADDRESS_REQUEST, Body
                )
            ),
            transport_send_data(S, Cap, false)
    catch
        error:Reason -> {error, Reason}
    end.

%% Simple monotonic ID allocator scoped to one session. A wraparound
%% past 2^31 is more than any sensible use will need.
allocate_request_ids(N) ->
    Base = erlang:unique_integer([positive, monotonic]),
    [Base + I || I <- lists:seq(0, N - 1)].

%%====================================================================
%% Transport send dispatch
%%====================================================================

transport_send_data(#state{transport = h3, conn = C, stream_id = S}, B, F) ->
    quic_h3:send_data(C, S, B, F);
transport_send_data(#state{transport = h2, conn = C, stream_id = S}, B, F) ->
    h2:send_data(C, S, B, F).

transport_send_datagram(
    #state{transport = h3, conn = C, stream_id = S},
    Ctx,
    Payload
) ->
    Enc = masque_datagram:encode(Ctx, Payload),
    quic_h3:send_datagram(C, S, Enc);
transport_send_datagram(
    #state{transport = h2, conn = C, stream_id = S},
    Ctx,
    Payload
) ->
    Inner = iolist_to_binary(masque_datagram:encode(Ctx, Payload)),
    Cap = iolist_to_binary(h2_capsule:encode(datagram, Inner)),
    h2:send_data(C, S, Cap, false).

%%====================================================================
%% Misc
%%====================================================================

safe_apply(M, F, A) ->
    try
        apply(M, F, A)
    catch
        Class:Reason:Stack ->
            error_logger:error_msg(
                "masque ip handler ~p:~p/~p failed: ~p:~p~n~p~n",
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
