%%% @doc Per-tunnel server session for CONNECT-TCP.
%%%
%%% Raw bytes on the HTTP stream body are relayed to/from the handler
%%% module. No datagram framing, no context-IDs. Stream END_STREAM
%%% maps to TCP FIN.
-module(masque_tcp_server_session).
-behaviour(gen_server).

-export([start_link/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include("masque.hrl").

-record(state, {
    conn       :: pid(),
    stream_id  :: non_neg_integer(),
    transport  :: h3 | h2,
    handler    :: module(),
    h_state    :: term(),
    req        :: map()
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

init(#{conn := Conn, stream_id := StreamId, transport := Transport,
       handler := Handler, handler_opts := HOpts, req := Req}) ->
    process_flag(trap_exit, true),
    case init_handler(Handler, Req, HOpts) of
        {ok, HState, Actions} ->
            State = #state{conn = Conn, stream_id = StreamId,
                           transport = Transport, handler = Handler,
                           h_state = HState, req = Req},
            _ = send_response(State, 200, [{<<"capsule-protocol">>, <<"?1">>}]),
            _ = claim_stream(State),
            apply_actions(Actions, State);
        {stop, Reason} ->
            {stop, Reason}
    end.

send_response(#state{transport = h3, conn = C, stream_id = S}, Status, Hdrs) ->
    quic_h3:send_response(C, S, Status, Hdrs);
send_response(#state{transport = h2, conn = C, stream_id = S}, Status, Hdrs) ->
    h2:send_response(C, S, Status, Hdrs).

claim_stream(#state{transport = h3, conn = C, stream_id = S}) ->
    quic_h3:set_stream_handler(C, S, self());
claim_stream(#state{transport = h2, conn = C, stream_id = S}) ->
    h2:set_stream_handler(C, S, self()).

handle_call(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

handle_cast(_Msg, S) ->
    {noreply, S}.

%% Incoming stream data - raw TCP bytes
handle_info({Tag, _Conn, {data, StreamId, Bytes, Fin}},
            #state{stream_id = StreamId} = S)
  when Tag =:= quic_h3; Tag =:= h2 ->
    case dispatch(handle_data, [Bytes], S) of
        {noreply, S2} when Fin ->
            {stop, normal, S2};
        Result ->
            Result
    end;
handle_info({masque_stream_data, StreamId, Bytes, Fin},
            #state{stream_id = StreamId} = S) ->
    case dispatch(handle_data, [Bytes], S) of
        {noreply, S2} when Fin -> {stop, normal, S2};
        Result                 -> Result
    end;
handle_info({Tag, _Conn, {stream_reset, StreamId, _}},
            #state{stream_id = StreamId} = S)
  when Tag =:= quic_h3; Tag =:= h2 ->
    {stop, peer_reset, S};
handle_info({masque_stream_reset, StreamId, _},
            #state{stream_id = StreamId} = S) ->
    {stop, peer_reset, S};
handle_info({h2, _Conn, closed}, S) ->
    {stop, peer_closed, S};
handle_info({'EXIT', _Pid, _Reason}, S) ->
    {noreply, S};
handle_info(Msg, S) ->
    dispatch(handle_info, [Msg], S).

terminate(Reason, #state{handler = Handler, h_state = HState} = S) ->
    %% Signal TCP FIN to the client by sending END_STREAM.
    _ = (catch transport_send_data(S, <<>>, true)),
    try_callback(Handler, terminate, [Reason, HState]),
    ok.

code_change(_OldVsn, S, _Extra) ->
    {ok, S}.

%%====================================================================
%% Handler dispatch
%%====================================================================

init_handler(Handler, Req, HOpts) ->
    case exported(Handler, init, 2) of
        true ->
            case safe_apply(Handler, init, [Req, HOpts]) of
                {ok, HState}          -> {ok, HState, []};
                {ok, HState, Actions} -> {ok, HState, Actions};
                {stop, Reason}        -> {stop, Reason};
                Other                 -> {stop, {bad_init, Other}}
            end;
        false ->
            {ok, undefined, []}
    end.

dispatch(CB, Extra, #state{handler = Handler, h_state = HS} = S) ->
    case exported(Handler, CB, length(Extra) + 1) of
        true ->
            case safe_apply(Handler, CB, Extra ++ [HS]) of
                {ok, HS2}           -> {noreply, S#state{h_state = HS2}};
                {ok, HS2, Actions}  -> apply_actions_noreply(
                                         Actions, S#state{h_state = HS2});
                {stop, Reason, HS2} -> {stop, Reason,
                                              S#state{h_state = HS2}};
                _                   -> {noreply, S}
            end;
        false ->
            {noreply, S}
    end.

exported(Mod, Fun, Arity) ->
    _ = code:ensure_loaded(Mod),
    erlang:function_exported(Mod, Fun, Arity).

apply_actions(Actions, State) ->
    case do_actions(Actions, State) of
        {ok, S2}          -> {ok, S2};
        {stop, Reason, _} -> {stop, Reason}
    end.

apply_actions_noreply(Actions, State) ->
    case do_actions(Actions, State) of
        {ok, S2}           -> {noreply, S2};
        {stop, Reason, S2} -> {stop, Reason, S2}
    end.

do_actions([], S) -> {ok, S};
do_actions([{send_data, Bytes} | Rest], S) ->
    _ = transport_send_data(S, Bytes, false),
    do_actions(Rest, S);
do_actions([{send_data, Bytes, Fin} | Rest], S) ->
    _ = transport_send_data(S, Bytes, Fin),
    do_actions(Rest, S);
do_actions([close_session | _Rest], S) ->
    _ = transport_send_data(S, <<>>, true),
    {stop, normal, S};
do_actions([_Unknown | Rest], S) ->
    do_actions(Rest, S).

transport_send_data(#state{transport = h3, conn = C, stream_id = Sid}, Bytes, Fin) ->
    quic_h3:send_data(C, Sid, Bytes, Fin);
transport_send_data(#state{transport = h2, conn = C, stream_id = Sid}, Bytes, Fin) ->
    h2:send_data(C, Sid, Bytes, Fin).

safe_apply(M, F, A) ->
    try apply(M, F, A)
    catch
        Class:Reason:Stack ->
            error_logger:error_msg(
                "masque tcp handler ~p:~p/~p failed: ~p:~p~n~p~n",
                [M, F, length(A), Class, Reason, Stack]),
            {stop, {handler_crash, Reason}}
    end.

try_callback(Mod, Fun, Args) ->
    Arity = length(Args),
    case erlang:function_exported(Mod, Fun, Arity) of
        true  -> (catch apply(Mod, Fun, Args));
        false -> ok
    end.
