%%% Per-tunnel server session for CONNECT-TCP.
%%%
%%% Raw bytes on the HTTP stream body are relayed to/from the handler
%%% module. No datagram framing, no context-IDs, no capsules (the 2xx
%%% carries no `capsule-protocol`). Stream END_STREAM maps to TCP FIN
%%% in each direction: a FIN from one side half-closes the tunnel and
%%% the other direction keeps flowing until it ends too.
-module(masque_tcp_server_session).
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

%% RFC 9114 sec 8.1: H3_CONNECT_ERROR.
-define(H3_CONNECT_ERROR, 16#10f).

-define(DEFAULT_IDLE_MS, 300000).

-record(state, {
    conn :: pid(),
    stream_id :: non_neg_integer(),
    transport :: h3 | h2,
    handler :: module(),
    h_state :: term(),
    req :: map(),
    %% Actions from handler init, applied after finalize (H3 path)
    pending_actions :: [term()] | undefined,
    %% Monitor on the router (H3 path).
    router_ref :: reference() | undefined,
    %% Our side of the stream already ended with FIN.
    fin_sent = false :: boolean(),
    %% H3 path: handler messages (e.g. target bytes) that arrived
    %% before finalize, newest first. Replayed once the 2xx is sent.
    early = [] :: [term()],
    start_time :: integer() | undefined,
    %% Idle timeout (`idle_timeout_ms'), armed once the tunnel is open.
    idle_ms = ?DEFAULT_IDLE_MS :: non_neg_integer() | infinity,
    idle :: masque_idle:idle() | undefined,
    %% The handler kept the last chunk's credit (`hold_credit').
    hold = false :: boolean(),
    %% Bytes whose credit the handler has yet to release.
    held = 0 :: non_neg_integer(),
    %% `raw' bytes (older connect-tcp drafts) or `capsule' framing
    %% (draft-ietf-httpbis-connect-tcp-18), chosen by the request.
    framing = raw :: raw | capsule,
    %% Capsule mode: which capsule codes, and the decoder of the
    %% client's capsules.
    version = final :: masque_tcp_capsule:version(),
    dec :: masque_tcp_capsule:decoder() | undefined,
    %% Capsule mode: the client sent FINAL_DATA.
    final_in = false :: boolean()
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

%% With a `starter' (h2 and h1 listeners) the real start runs in
%% `handle_continue/2' so the session supervisor is not held up (see
%% `masque_session_start'). `start/1' returns `{stop, R}' when nothing
%% was sent, `{stop, R, S}' once the handler started, so `terminate/2'
%% cleans up and the listener stays silent.
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
        req := Req0
    } = Args
) ->
    process_flag(trap_exit, true),
    %% Monitor router (H3 path) so we stop if it dies.
    RouterRef =
        case maps:find(router, Args) of
            {ok, Router} -> erlang:monitor(process, Router);
            error -> undefined
        end,
    {Framing, Version} = framing(Req0, HOpts),
    %% The handler learns the framing: in capsule mode a local timeout
    %% must abort the target (section 3.5).
    Req = Req0#{tcp_framing => Framing, tcp_version => Version},
    ok = continue(Transport, Conn, StreamId, Framing, Req),
    case init_handler(Handler, Req, HOpts) of
        {ok, HState, Actions} ->
            State = #state{
                conn = Conn,
                stream_id = StreamId,
                transport = Transport,
                handler = Handler,
                idle_ms = maps:get(idle_timeout_ms, HOpts, ?DEFAULT_IDLE_MS),
                framing = Framing,
                version = Version,
                dec = masque_tcp_capsule:decoder(Version),
                h_state = HState,
                req = Req,
                router_ref = RouterRef
            },
            case maps:is_key(router, Args) of
                true ->
                    %% H3 path: defer 200 + claim to finalize
                    {ok, State#state{pending_actions = Actions}};
                false ->
                    %% H2 path: immediate finalize
                    case send_response(State, 200, response_headers(State)) of
                        ok ->
                            case claim_stream(State) of
                                {error, _} ->
                                    {stop, stream_dead, State};
                                _ ->
                                    do_actions(Actions, mark_open(State))
                            end;
                        {error, _} ->
                            {stop, stream_dead, State}
                    end
            end;
        {stop, Reason} ->
            {stop, Reason}
    end.

%% A draft interop token fixed the framing and codes in the listener;
%% for plain `connect-tcp' the listener's `tcp_framing' and the
%% request's headers decide, and capsules use the permanent codes.
framing(#{tcp_framing := capsule, tcp_version := Version}, _HOpts) ->
    {capsule, Version};
framing(Req, HOpts) ->
    Framing = masque_tcp_capsule:request_framing(
        maps:get(tcp_framing, HOpts, auto), maps:get(headers, Req, [])
    ),
    {Framing, final}.

%% draft-ietf-httpbis-connect-tcp-18 section 4.3: the proxy confirms an
%% accepted request with `100 Continue' before dialing the target, which
%% can take long when the target does not answer. Raw framing keeps the
%% older behaviour: a 100 only when the request expects one. A reverse
%% connect accept stream (`tcp_continue => false') gets none: its draft
%% answers with the 2xx alone.
continue(Transport, Conn, StreamId, Framing, Req) ->
    case
        (Framing =:= capsule andalso maps:get(tcp_continue, Req, true)) orelse
            masque_tcp_capsule:expects_continue(maps:get(headers, Req, []))
    of
        true ->
            _ = send_interim(Transport, Conn, StreamId),
            ok;
        false ->
            ok
    end.

send_interim(h3, Conn, StreamId) ->
    masque_out:call(fun() -> quic_h3:send_response(Conn, StreamId, 100, []) end);
send_interim(h2, Conn, StreamId) ->
    masque_out:call(fun() -> h2:send_response(Conn, StreamId, 100, []) end).

%% Section 4.3 also asks for `Proxy-Status' on success.
response_headers(#state{framing = capsule}) ->
    [{<<"capsule-protocol">>, <<"?1">>}, {<<"proxy-status">>, <<"masque">>}];
response_headers(_) ->
    [].

send_response(#state{transport = h3, conn = C, stream_id = S}, Status, Hdrs) ->
    masque_out:call(fun() -> quic_h3:send_response(C, S, Status, Hdrs) end);
send_response(#state{transport = h2, conn = C, stream_id = S}, Status, Hdrs) ->
    h2:send_response(C, S, Status, Hdrs).

%% `drain_buffer => false': bytes the client wrote before the claim are
%% replayed as `{data, _, _, Fin}' messages instead of being dropped.
%% H3 path: send the 2xx, claim the stream, run the handler's init
%% actions, then replay the handler messages that arrived meanwhile.
finalize(#state{pending_actions = Actions} = S) ->
    case send_response(S, 200, response_headers(S)) of
        ok ->
            case claim_stream(S) of
                {error, _} ->
                    {error, S};
                _ ->
                    case
                        run_init_actions(
                            Actions, mark_open(S#state{pending_actions = undefined})
                        )
                    of
                        {ok, S1} ->
                            replay_early(lists:reverse(S1#state.early), S1#state{early = []});
                        {stop, _, _} = Stop ->
                            %% `terminate/2' sees the state with `start_time' set.
                            Stop
                    end
            end;
        {error, _} ->
            {error, S}
    end.

replay_early([], S) ->
    {ok, S};
replay_early([Msg | Rest], S) ->
    case handle_info(Msg, S) of
        {noreply, S2} -> replay_early(Rest, S2);
        {stop, Reason, S2} -> {stop, Reason, S2}
    end.

%% Receive credit is returned only once the handler has written the
%% bytes to the target (`consume/3'), so a stalled target stops the
%% client instead of filling this process's mailbox.
claim_stream(#state{transport = h3, conn = C, stream_id = S}) ->
    masque_out:call(fun() ->
        quic_h3:set_stream_handler(C, S, self(), #{drain_buffer => false, flow_control => manual})
    end);
claim_stream(#state{transport = h2, conn = C, stream_id = S}) ->
    masque_out:call(fun() -> h2:set_stream_handler(C, S, self(), #{flow_control => manual}) end).

%% The stream may already be gone (its FIN was the last event).
consume(Tag, Bytes, S) ->
    consume_bytes(Tag, byte_size(Bytes), S).

consume_bytes(_Tag, 0, _S) ->
    ok;
consume_bytes(h2, N, #state{conn = C, stream_id = Sid}) ->
    try
        h2:consume(C, Sid, N)
    catch
        exit:_ -> ok
    end;
consume_bytes(quic_h3, N, #state{conn = C, stream_id = Sid}) ->
    try
        quic_h3:consume(C, Sid, N)
    catch
        exit:_ -> ok
    end.

%%====================================================================
%% Capsule framing (draft-ietf-httpbis-connect-tcp-18)
%%====================================================================

%% Bytes for the stream: as they are in raw mode, as DATA or FINAL_DATA
%% in capsule mode.
frame(#state{framing = capsule, version = V}, Bytes, Fin) ->
    masque_tcp_capsule:encode(V, Bytes, Fin);
frame(_S, Bytes, _Fin) ->
    Bytes.

%% Stream bytes in capsule mode. The capsule headers are consumed at
%% once; the payloads follow the handler's credit, as raw bytes do. A
%% stream that ends without FINAL_DATA, or inside a capsule, is an
%% abort, not a FIN (section 3.5); so is invalid data (section 3.5.1).
capsule_in(Tag, Bytes, Fin, #state{dec = Dec} = S) ->
    case masque_tcp_capsule:decode(Dec, Bytes) of
        {error, Reason} ->
            {stop, {bad_capsule, Reason}, S};
        {ok, Items, Dec2} ->
            Payload = lists:sum([byte_size(P) || {_, P} <- Items]),
            _ = consume_tag(Tag, byte_size(Bytes) - Payload, S),
            case capsule_items(Tag, Items, S#state{dec = Dec2}) of
                {noreply, #state{final_in = false} = S2} when Fin ->
                    {stop, peer_reset, S2};
                {noreply, S2} when Fin ->
                    case masque_tcp_capsule:end_of_stream(Dec2) of
                        ok -> {noreply, S2};
                        {error, Reason} -> {stop, {bad_capsule, Reason}, S2}
                    end;
                Other ->
                    Other
            end
    end.

capsule_items(_Tag, [], S) ->
    {noreply, S};
capsule_items(Tag, [{Kind, Payload} | Rest], S) ->
    case capsule_payload(Tag, Payload, S) of
        {noreply, S2} when Kind =:= final ->
            case dispatch_eof(S2#state{final_in = true}) of
                {noreply, S3} -> capsule_items(Tag, Rest, S3);
                Stop -> Stop
            end;
        {noreply, S2} ->
            capsule_items(Tag, Rest, S2);
        Stop ->
            Stop
    end.

capsule_payload(_Tag, <<>>, S) ->
    {noreply, S};
capsule_payload(none, Payload, S) ->
    case dispatch(handle_data, [Payload], count_in(Payload, S)) of
        {noreply, S2} -> {noreply, S2#state{hold = false}};
        Stop -> Stop
    end;
capsule_payload(Tag, Payload, S) ->
    Result = dispatch(handle_data, [Payload], count_in(Payload, S)),
    settle_credit(Tag, Payload, Result, S).

consume_tag(none, _N, _S) -> ok;
consume_tag(Tag, N, S) -> consume_bytes(Tag, N, S).

%% Credit goes back now, unless the handler keeps it until it has
%% finished with the bytes.
settle_credit(_Tag, Bytes, {noreply, #state{hold = true, held = Held} = S2}, _S) ->
    {noreply, S2#state{hold = false, held = Held + byte_size(Bytes)}};
settle_credit(Tag, Bytes, Result, S) ->
    _ = consume(Tag, Bytes, S),
    Result.

release_credit(N, #state{held = Held, transport = T} = S) ->
    Release = min(N, Held),
    Tag =
        case T of
            h3 -> quic_h3;
            h2 -> h2
        end,
    _ = consume_bytes(Tag, Release, S),
    S#state{held = Held - Release}.

handle_call(Request, From, State) ->
    masque_quiet:stop(handle_call_inner(Request, From, State)).

handle_call_inner(
    finalize,
    _From,
    #state{pending_actions = Actions} = S
) when
    Actions =/= undefined
->
    case finalize(S) of
        {ok, S2} -> {reply, ok, S2};
        {stop, Reason, S2} -> {stop, Reason, ok, S2};
        {error, S2} -> {reply, {error, stream_dead}, S2}
    end;
%% A call for the handler, such as the stream API of a reverse connect
%% accept stream. The reply goes out once the actions ran, so a caller
%% that sends data waits for the blocking write.
handle_call_inner(Req, From, #state{handler = Handler, h_state = HS} = S) ->
    case exported(Handler, handle_call, 3) of
        false ->
            {reply, {error, unknown_call}, S};
        true ->
            case safe_apply(Handler, handle_call, [Req, From, HS]) of
                {reply, Reply, HS2} ->
                    {reply, Reply, S#state{h_state = HS2}};
                {reply, Reply, HS2, Actions} ->
                    case do_actions(Actions, S#state{h_state = HS2}) of
                        {ok, S2} -> {reply, Reply, S2};
                        %% The actions ended the stream cleanly.
                        {stop, normal, S2} -> {stop, normal, Reply, S2};
                        {stop, Reason, S2} -> {stop, Reason, {error, closed}, S2}
                    end;
                {stop, Reason, Reply, HS2} ->
                    {stop, Reason, Reply, S#state{h_state = HS2}};
                {stop, Reason} ->
                    {stop, Reason, {error, closed}, S}
            end
    end;
handle_call_inner(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

%% Asynchronous finalize from the router: run the same steps as the
%% `finalize' call and report back; the session stops if the stream
%% could not be opened.
handle_cast(Msg, State) ->
    masque_quiet:stop(handle_cast_inner(Msg, State)).

handle_cast_inner({finalize, Router}, #state{pending_actions = Actions} = S) when
    Actions =/= undefined
->
    Result = finalize(S),
    Reply =
        case Result of
            {error, _} -> {error, stream_dead};
            _ -> ok
        end,
    Router ! {masque_finalized, S#state.stream_id, self(), Reply},
    case Result of
        {ok, S2} -> {noreply, S2};
        {stop, Reason, S2} -> {stop, Reason, S2};
        {error, S2} -> {stop, stream_dead, S2}
    end;
handle_cast_inner(connection_closed, S) ->
    {stop, connection_closed, S};
%% A reverse connect accept stream nobody waits for any more: reset it.
handle_cast_inner(abandon, S) ->
    {stop, abandoned, S};
handle_cast_inner(_Msg, S) ->
    {noreply, S}.

%% Incoming stream data - raw TCP bytes
%% Every message counts as traffic for the idle timer; the timer's
%% own message checks whether the tunnel has been idle long enough.
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
handle_info_inner(Msg, #state{idle = Idle} = S) when Idle =/= undefined ->
    handle_traffic(Msg, S#state{idle = masque_idle:touch(Idle)});
handle_info_inner(Msg, S) ->
    handle_traffic(Msg, S).

handle_traffic(
    {Tag, _Conn, {data, StreamId, Bytes, Fin}},
    #state{stream_id = StreamId, framing = capsule} = S
) when
    Tag =:= quic_h3; Tag =:= h2
->
    capsule_in(Tag, Bytes, Fin, S);
handle_traffic(
    {masque_stream_data, StreamId, Bytes, Fin},
    #state{stream_id = StreamId, framing = capsule} = S
) ->
    capsule_in(none, Bytes, Fin, S);
handle_traffic(
    {Tag, _Conn, {data, StreamId, Bytes, Fin}},
    #state{stream_id = StreamId} = S
) when
    Tag =:= quic_h3; Tag =:= h2
->
    Result =
        case dispatch(handle_data, [Bytes], count_in(Bytes, S)) of
            {noreply, S2} when Fin -> dispatch_eof(S2);
            Other -> Other
        end,
    settle_credit(Tag, Bytes, Result, S);
handle_traffic(
    {masque_stream_data, StreamId, Bytes, Fin},
    #state{stream_id = StreamId} = S
) ->
    case dispatch(handle_data, [Bytes], count_in(Bytes, S)) of
        {noreply, S2} when Fin -> dispatch_eof(S2#state{hold = false});
        {noreply, S2} -> {noreply, S2#state{hold = false}};
        Result -> Result
    end;
handle_traffic(
    {Tag, _Conn, {stream_reset, StreamId, _}},
    #state{stream_id = StreamId} = S
) when
    Tag =:= quic_h3; Tag =:= h2
->
    {stop, peer_reset, S};
handle_traffic(
    {masque_stream_reset, StreamId, _},
    #state{stream_id = StreamId} = S
) ->
    {stop, peer_reset, S};
%% A `send_ready' that arrives after `masque_stream_send' stopped
%% waiting is not the handler's business.
handle_traffic({quic_h3, _Conn, {send_ready, _}}, S) ->
    {noreply, S};
handle_traffic({h2, _Conn, {closed, _Reason}}, S) ->
    {stop, peer_closed, S};
handle_traffic({'EXIT', _Pid, _Reason}, S) ->
    {noreply, S};
handle_traffic({'DOWN', MRef, process, _Pid, _Reason}, #state{router_ref = MRef} = S) ->
    %% Router died - clean up
    {stop, router_gone, S};
handle_traffic(Msg, #state{pending_actions = Actions, early = Early} = S) when
    Actions =/= undefined
->
    %% Not finalized yet: nothing may be written to the stream before
    %% the 2xx, so keep the message for `finalize'. A TCP target's
    %% `{active, N}' window bounds how many pile up.
    {noreply, S#state{early = [Msg | Early]}};
handle_traffic(Msg, S) ->
    dispatch(handle_info, [Msg], S).

terminate(Reason, State) ->
    terminate_inner(masque_quiet:reason(Reason), State).

terminate_inner(_Reason, {starting, Args}) ->
    masque_session_start:abandon(Args);
terminate_inner(
    Reason,
    #state{
        conn = Conn,
        transport = Transport,
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
    try_callback(Handler, terminate, [Reason, HState]),
    emit_tunnel_closed(S),
    ok;
terminate_inner(
    Reason,
    #state{
        conn = Conn,
        transport = Transport,
        handler = Handler,
        h_state = HState
    } = S
) ->
    maybe_release_h2_tunnel(Transport, Conn),
    _ =
        (try
            end_stream(Reason, S)
        catch
            _:_ -> ok
        end),
    try_callback(Handler, terminate, [Reason, HState]),
    emit_tunnel_closed(S),
    ok.

%% The 2xx is sent and the stream claimed: the tunnel counts as open
%% until `terminate/2'.
mark_open(#state{transport = Transport} = S) ->
    masque_metrics:tunnel_opened(#{protocol => tcp, transport => Transport}),
    S#state{
        start_time = erlang:monotonic_time(millisecond),
        idle = masque_idle:new(S#state.idle_ms)
    }.

emit_tunnel_closed(#state{start_time = undefined}) ->
    ok;
emit_tunnel_closed(#state{start_time = T, transport = Transport}) ->
    masque_metrics:tunnel_closed(
        erlang:monotonic_time(millisecond) - T,
        #{protocol => tcp, transport => Transport}
    ).

maybe_release_h2_tunnel(h2, Conn) -> masque_h2_server:release_tunnel(Conn);
maybe_release_h2_tunnel(_, _) -> ok.

%% A clean end (ours or the target's FIN) closes the stream with FIN,
%% unless a half-close already sent it. Anything else (target reset or
%% error, handler crash) resets it with CONNECT_ERROR so the client
%% does not mistake it for a clean close (RFC 9114 sec 4.4, RFC 9113
%% sec 8.5).
%% Section 3.5: a local timeout is an abrupt close in capsule mode.
end_stream(eof_timeout, #state{framing = capsule} = S) ->
    abort_stream(S);
end_stream(Reason, #state{fin_sent = true}) when
    Reason =:= normal;
    Reason =:= target_closed;
    Reason =:= eof_timeout
->
    ok;
end_stream(Reason, S) when
    Reason =:= normal;
    Reason =:= target_closed;
    Reason =:= eof_timeout
->
    transport_send_data(S, frame(S, <<>>, true), true);
end_stream(_Reason, S) ->
    abort_stream(S).

abort_stream(#state{transport = h3, conn = C, stream_id = Sid}) ->
    quic_h3:cancel(C, Sid, ?H3_CONNECT_ERROR);
abort_stream(#state{transport = h2, conn = C, stream_id = Sid}) ->
    h2:cancel(C, Sid, connect_error).

code_change(_OldVsn, S, _Extra) ->
    {ok, S}.

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
                {stop, Reason} ->
                    {stop, Reason, S};
                _ ->
                    {noreply, S}
            end;
        false ->
            {noreply, S}
    end.

dispatch_eof(#state{handler = Handler} = S) ->
    case exported(Handler, handle_eof, 1) of
        true -> dispatch(handle_eof, [], S);
        false -> {stop, normal, S}
    end.

exported(Mod, Fun, Arity) ->
    _ = code:ensure_loaded(Mod),
    erlang:function_exported(Mod, Fun, Arity).

apply_actions_noreply(Actions, State) ->
    case do_actions(Actions, State) of
        {ok, S2} -> {noreply, S2};
        {stop, Reason, S2} -> {stop, Reason, S2}
    end.

run_init_actions(Actions, S) ->
    do_actions(Actions, S).

do_actions([], S) ->
    {ok, S};
do_actions([{send_data, Bytes} | Rest], S) ->
    do_actions([{send_data, Bytes, false} | Rest], S);
do_actions([{send_data, Bytes, Fin} | Rest], S) ->
    ok = count_out(Bytes, S),
    %% A tunnel write either lands or stops the session: handlers
    %% (e.g. the TCP proxy's `{active, N}' re-arm) rely on every
    %% earlier write having succeeded.
    case tunnel_send(S, frame(S, Bytes, Fin), Fin) of
        ok -> do_actions(Rest, S#state{fin_sent = Fin orelse S#state.fin_sent});
        {error, Reason} -> {stop, {tunnel_send_failed, Reason}, S}
    end;
do_actions([hold_credit | Rest], S) ->
    do_actions(Rest, S#state{hold = true});
do_actions([{release_credit, N} | Rest], S) ->
    do_actions(Rest, release_credit(N, S));
do_actions([close_session | _Rest], #state{fin_sent = true} = S) ->
    {stop, normal, S};
do_actions([close_session | _Rest], S) ->
    _ = transport_send_data(S, frame(S, <<>>, true), true),
    {stop, normal, S#state{fin_sent = true}};
do_actions([_Unknown | Rest], S) ->
    do_actions(Rest, S).

%% Blocking tunnel write (`masque_stream_send'): waits for the transport
%% instead of dropping, and gives up after 30 s without progress.
tunnel_send(#state{transport = T, conn = C, stream_id = Sid}, Bytes, Fin) ->
    masque_stream_send:send(T, C, Sid, Bytes, Fin).

transport_send_data(#state{transport = h3, conn = C, stream_id = Sid}, Bytes, Fin) ->
    quic_h3:send_data(C, Sid, Bytes, Fin);
transport_send_data(#state{transport = h2, conn = C, stream_id = Sid}, Bytes, Fin) ->
    h2:send_data(C, Sid, Bytes, Fin).

safe_apply(M, F, A) ->
    try
        apply(M, F, A)
    catch
        Class:Reason:Stack ->
            logger:error(
                "masque tcp handler ~p:~p/~p failed: ~p:~p~n~p",
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

%% Tunnel payload bytes for the `masque.bytes.*' counters.
count_in(Bytes, #state{transport = T} = S) ->
    masque_metrics:bytes_in(iolist_size(Bytes), #{protocol => tcp, transport => T}),
    S.

count_out(Bytes, #state{transport = T}) ->
    masque_metrics:bytes_out(iolist_size(Bytes), #{protocol => tcp, transport => T}).
