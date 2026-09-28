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
%% How long a tunnel write may wait for the transport to drain before
%% the tunnel is reset.
-define(SEND_TIMEOUT, 30000).

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

%% With a `starter' (h2 and h1 listeners) the real start runs in
%% `handle_continue/2' so the session supervisor is not held up (see
%% `masque_session_start'). `start/1' returns `{stop, R}' when nothing
%% was sent, `{stop, R, S}' once the handler started, so `terminate/2'
%% cleans up and the listener stays silent.
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

start(
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
    %% Monitor router (H3 path) so we stop if it dies.
    RouterRef =
        case maps:find(router, Args) of
            {ok, Router} -> erlang:monitor(process, Router);
            error -> undefined
        end,
    case init_handler(Handler, Req, HOpts) of
        {ok, HState, Actions} ->
            State = #state{
                conn = Conn,
                stream_id = StreamId,
                transport = Transport,
                handler = Handler,
                idle_ms = maps:get(idle_timeout_ms, HOpts, ?DEFAULT_IDLE_MS),
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
                    case send_response(State, 200, []) of
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

send_response(#state{transport = h3, conn = C, stream_id = S}, Status, Hdrs) ->
    quic_h3:send_response(C, S, Status, Hdrs);
send_response(#state{transport = h2, conn = C, stream_id = S}, Status, Hdrs) ->
    h2:send_response(C, S, Status, Hdrs).

%% `drain_buffer => false': bytes the client wrote before the claim are
%% replayed as `{data, _, _, Fin}' messages instead of being dropped.
%% H3 path: send the 2xx, claim the stream, run the handler's init
%% actions, then replay the handler messages that arrived meanwhile.
finalize(#state{pending_actions = Actions} = S) ->
    case send_response(S, 200, []) of
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
    quic_h3:set_stream_handler(C, S, self(), #{drain_buffer => false, flow_control => manual});
claim_stream(#state{transport = h2, conn = C, stream_id = S}) ->
    h2:set_stream_handler(C, S, self(), #{flow_control => manual}).

%% The stream may already be gone (its FIN was the last event).
consume(_Tag, <<>>, _S) ->
    ok;
consume(h2, Bytes, #state{conn = C, stream_id = Sid}) ->
    try
        h2:consume(C, Sid, byte_size(Bytes))
    catch
        exit:_ -> ok
    end;
consume(quic_h3, Bytes, #state{conn = C, stream_id = Sid}) ->
    try
        quic_h3:consume(C, Sid, byte_size(Bytes))
    catch
        exit:_ -> ok
    end.

handle_call(
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
handle_call(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

%% Asynchronous finalize from the router: run the same steps as the
%% `finalize' call and report back; the session stops if the stream
%% could not be opened.
handle_cast({finalize, Router}, #state{pending_actions = Actions} = S) when
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
handle_cast(connection_closed, S) ->
    {stop, connection_closed, S};
handle_cast(_Msg, S) ->
    {noreply, S}.

%% Incoming stream data - raw TCP bytes
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
    _ = consume(Tag, Bytes, S),
    Result;
handle_traffic(
    {masque_stream_data, StreamId, Bytes, Fin},
    #state{stream_id = StreamId} = S
) ->
    case dispatch(handle_data, [Bytes], count_in(Bytes, S)) of
        {noreply, S2} when Fin -> dispatch_eof(S2);
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
%% A `send_ready' that arrives after `tunnel_send_h3/4' stopped
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

terminate(_Reason, {starting, Args}) ->
    masque_session_start:abandon(Args);
terminate(
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
terminate(
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
    transport_send_data(S, <<>>, true);
end_stream(_Reason, #state{transport = h3, conn = C, stream_id = Sid}) ->
    quic_h3:cancel(C, Sid, ?H3_CONNECT_ERROR);
end_stream(_Reason, #state{transport = h2, conn = C, stream_id = Sid}) ->
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
    case tunnel_send(S, Bytes, Fin) of
        ok -> do_actions(Rest, S#state{fin_sent = Fin orelse S#state.fin_sent});
        {error, Reason} -> {stop, {tunnel_send_failed, Reason}, S}
    end;
do_actions([close_session | _Rest], #state{fin_sent = true} = S) ->
    {stop, normal, S};
do_actions([close_session | _Rest], S) ->
    _ = transport_send_data(S, <<>>, true),
    {stop, normal, S#state{fin_sent = true}};
do_actions([_Unknown | Rest], S) ->
    do_actions(Rest, S).

%% Blocking tunnel write. h2 waits for flow-control window; quic_h3
%% reports a full send queue, so retry until it drains or the send
%% timeout passes.
tunnel_send(#state{transport = h2, conn = C, stream_id = Sid}, Bytes, Fin) ->
    h2:send_data(C, Sid, Bytes, Fin, #{block => ?SEND_TIMEOUT});
tunnel_send(S, Bytes, Fin) ->
    Deadline = erlang:monotonic_time(millisecond) + ?SEND_TIMEOUT,
    tunnel_send_h3(S, Bytes, Fin, Deadline).

%% A refused write (`send_queue_full', nothing written) is retried
%% when quic_h3 says the queue drained (`send_ready'), until the
%% deadline.
tunnel_send_h3(#state{conn = C, stream_id = Sid} = S, Bytes, Fin, Deadline) ->
    case transport_send_data(S, Bytes, Fin) of
        {error, send_queue_full} ->
            Left = Deadline - erlang:monotonic_time(millisecond),
            receive
                {quic_h3, C, {send_ready, Sid}} ->
                    tunnel_send_h3(S, Bytes, Fin, Deadline)
            after max(0, Left) ->
                {error, send_timeout}
            end;
        Other ->
            Other
    end.

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
