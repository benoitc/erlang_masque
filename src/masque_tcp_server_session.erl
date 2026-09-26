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
-define(SEND_RETRY_MS, 5).

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
                                ok ->
                                    apply_actions(Actions, mark_open(State));
                                {ok, _} ->
                                    apply_actions(Actions, mark_open(State));
                                {error, _} ->
                                    {stop, stream_dead}
                            end;
                        {error, _} ->
                            {stop, stream_dead}
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
                    S1 = run_init_actions(
                        Actions, mark_open(S#state{pending_actions = undefined})
                    ),
                    replay_early(lists:reverse(S1#state.early), S1#state{early = []})
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

claim_stream(#state{transport = h3, conn = C, stream_id = S}) ->
    quic_h3:set_stream_handler(C, S, self(), #{drain_buffer => false});
claim_stream(#state{transport = h2, conn = C, stream_id = S}) ->
    h2:set_stream_handler(C, S, self()).

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
handle_info(
    {Tag, _Conn, {data, StreamId, Bytes, Fin}},
    #state{stream_id = StreamId} = S
) when
    Tag =:= quic_h3; Tag =:= h2
->
    case dispatch(handle_data, [Bytes], S) of
        {noreply, S2} when Fin -> dispatch_eof(S2);
        Result -> Result
    end;
handle_info(
    {masque_stream_data, StreamId, Bytes, Fin},
    #state{stream_id = StreamId} = S
) ->
    case dispatch(handle_data, [Bytes], S) of
        {noreply, S2} when Fin -> dispatch_eof(S2);
        Result -> Result
    end;
handle_info(
    {Tag, _Conn, {stream_reset, StreamId, _}},
    #state{stream_id = StreamId} = S
) when
    Tag =:= quic_h3; Tag =:= h2
->
    {stop, peer_reset, S};
handle_info(
    {masque_stream_reset, StreamId, _},
    #state{stream_id = StreamId} = S
) ->
    {stop, peer_reset, S};
handle_info({h2, _Conn, {closed, _Reason}}, S) ->
    {stop, peer_closed, S};
handle_info({'EXIT', _Pid, _Reason}, S) ->
    {noreply, S};
handle_info({'DOWN', MRef, process, _Pid, _Reason}, #state{router_ref = MRef} = S) ->
    %% Router died - clean up
    {stop, router_gone, S};
handle_info(Msg, #state{pending_actions = Actions, early = Early} = S) when
    Actions =/= undefined
->
    %% Not finalized yet: nothing may be written to the stream before
    %% the 2xx, so keep the message for `finalize'. A TCP target's
    %% `{active, N}' window bounds how many pile up.
    {noreply, S#state{early = [Msg | Early]}};
handle_info(Msg, S) ->
    dispatch(handle_info, [Msg], S).

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
    S#state{start_time = erlang:monotonic_time(millisecond)}.

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

run_init_actions([], S) ->
    S;
run_init_actions(Actions, S) ->
    case do_actions(Actions, S) of
        {ok, S2} -> S2;
        {stop, Reason, _} -> exit(Reason)
    end.

do_actions([], S) ->
    {ok, S};
do_actions([{send_data, Bytes} | Rest], S) ->
    do_actions([{send_data, Bytes, false} | Rest], S);
do_actions([{send_data, Bytes, Fin} | Rest], S) ->
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

tunnel_send_h3(S, Bytes, Fin, Deadline) ->
    case transport_send_data(S, Bytes, Fin) of
        {error, send_queue_full} ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true ->
                    timer:sleep(?SEND_RETRY_MS),
                    tunnel_send_h3(S, Bytes, Fin, Deadline);
                false ->
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
