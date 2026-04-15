%%% @doc Per-tunnel server-side session.
%%%
%%% One of these is spawned by the listener's handler fun after a
%%% CONNECT-UDP request passes validation. It receives routed
%%% datagrams from the connection router (`masque_server_connection`)
%%% and invokes the configured user handler module to produce reply
%%% datagrams or close the session.
-module(masque_server_session).
-behaviour(gen_server).

-export([start_link/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include("masque.hrl").

-record(state, {
    conn       :: pid(),
    stream_id  :: non_neg_integer(),
    router     :: pid(),
    handler    :: module(),
    h_state    :: term(),
    req        :: map(),
    cap_buf = <<>> :: binary()
}).

%%====================================================================
%% API
%%====================================================================

start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

%%====================================================================
%% gen_server
%%====================================================================

init(#{conn := Conn, stream_id := StreamId, router := Router,
       handler := Handler, handler_opts := HOpts, req := Req}) ->
    process_flag(trap_exit, true),
    case init_handler(Handler, Req, HOpts) of
        {ok, HState, Actions} ->
            State0 = #state{conn = Conn, stream_id = StreamId,
                            router = Router, handler = Handler,
                            h_state = HState, req = Req},
            %% Claim the request stream so its body bytes (capsules)
            %% are delivered here instead of being buffered inside
            %% `quic_h3'. Any already-buffered bytes are returned
            %% synchronously and fed into the capsule decoder.
            State = claim_stream(State0),
            apply_actions(Actions, State);
        {stop, Reason} ->
            {stop, Reason}
    end.

claim_stream(#state{conn = Conn, stream_id = StreamId,
                    cap_buf = Buf} = S) ->
    case quic_h3:set_stream_handler(Conn, StreamId, self()) of
        ok ->
            S;
        {ok, Chunks} ->
            More = iolist_to_binary([D || {D, _Fin} <- Chunks]),
            S#state{cap_buf = <<Buf/binary, More/binary>>};
        _ ->
            S
    end.

handle_call(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

handle_cast(_Msg, S) ->
    {noreply, S}.

handle_info({masque_datagram_in, StreamId, Payload},
            #state{stream_id = StreamId} = S) ->
    case masque_datagram:decode(Payload) of
        {ok, {?MASQUE_CONTEXT_ID_UDP, UdpBytes}} ->
            dispatch(handle_packet, [UdpBytes], S);
        {ok, {_Ctx, _Bytes}} ->
            %% Unknown context-id: RFC 9298 §5 says silently drop.
            {noreply, S};
        {error, _} ->
            {noreply, S}
    end;
handle_info({masque_stream_data, StreamId, Data, _Fin},
            #state{stream_id = StreamId, cap_buf = Buf} = S) ->
    drain_capsules(<<Buf/binary, Data/binary>>, S);
handle_info({quic_h3, _Conn, {data, StreamId, Data, _Fin}},
            #state{stream_id = StreamId, cap_buf = Buf} = S) ->
    drain_capsules(<<Buf/binary, Data/binary>>, S);
handle_info({masque_stream_reset, StreamId, _ErrorCode},
            #state{stream_id = StreamId} = S) ->
    {stop, peer_reset, S};
handle_info(Msg, S) ->
    dispatch(handle_info, [Msg], S).

terminate(Reason, #state{router = Router, stream_id = StreamId,
                          handler = Handler, h_state = HState}) ->
    _ = (catch masque_server_connection:unregister_session(Router, StreamId)),
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
                {ok, HState}           -> {ok, HState, []};
                {ok, HState, Actions}  -> {ok, HState, Actions};
                {stop, Reason}         -> {stop, Reason};
                Other                  -> {stop, {bad_init, Other}}
            end;
        false ->
            {ok, undefined, []}
    end.

dispatch(CB, Extra, #state{handler = Handler, h_state = HS} = S) ->
    case exported(Handler, CB, length(Extra) + 1) of
        true ->
            case safe_apply(Handler, CB, Extra ++ [HS]) of
                {ok, HS2}          -> {noreply, S#state{h_state = HS2}};
                {ok, HS2, Actions} -> apply_actions_noreply(
                                        Actions, S#state{h_state = HS2});
                {stop, Reason, HS2} -> {stop, Reason, S#state{h_state = HS2}};
                _                  -> {noreply, S}
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

apply_actions(Actions, State) ->
    case do_actions(Actions, State) of
        {ok, S2}          -> {ok, S2};
        {stop, Reason, _} -> {stop, Reason}
    end.

apply_actions_noreply(Actions, State) ->
    case do_actions(Actions, State) of
        {ok, S2}          -> {noreply, S2};
        {stop, Reason, S2} -> {stop, Reason, S2}
    end.

do_actions([], S) -> {ok, S};
do_actions([{send_packet, Data} | Rest], S) ->
    do_actions([{send_packet, ?MASQUE_CONTEXT_ID_UDP, Data} | Rest], S);
do_actions([{send_packet, Ctx, Data} | Rest], S) ->
    %% Silent drop on oversize - RFC 9298 §5 (HTTP Datagrams are
    %% unreliable; application can resend if it cares).
    Max = quic_h3:max_datagram_size(S#state.conn, S#state.stream_id),
    Overhead = ctx_overhead(Ctx),
    case Max > 0 andalso (iolist_size(Data) + Overhead) > Max of
        true ->
            do_actions(Rest, S);
        false ->
            Enc = masque_datagram:encode(Ctx, Data),
            _ = quic_h3:send_datagram(S#state.conn, S#state.stream_id, Enc),
            do_actions(Rest, S)
    end;
do_actions([{send_capsule, Type, Value} | Rest], S) ->
    Enc = masque_capsule:encode(Type, Value),
    _ = quic_h3:send_data(S#state.conn, S#state.stream_id,
                          iolist_to_binary(Enc), false),
    do_actions(Rest, S);
do_actions([close_session | _Rest], S) ->
    {stop, normal, S};
do_actions([{close_session, _Code, _Msg} | _Rest], S) ->
    {stop, normal, S};
do_actions([_Unknown | Rest], S) ->
    do_actions(Rest, S).

%% Pull every complete capsule out of `Buf` and dispatch it to the
%% handler module. Stops when the buffer is empty or decode reports
%% `{more, _}'; malformed capsules terminate the session.
drain_capsules(Buf, S) ->
    case masque_capsule:decode(Buf) of
        {ok, {Type, Value, Rest}} ->
            case dispatch(handle_capsule, [Type, Value], S) of
                {noreply, S2} ->
                    drain_capsules(Rest, S2#state{cap_buf = <<>>});
                {stop, _, _} = Stop ->
                    Stop
            end;
        {more, _} ->
            {noreply, S#state{cap_buf = Buf}};
        {error, _Reason} ->
            {stop, malformed_capsule, S}
    end.

safe_apply(M, F, A) ->
    try apply(M, F, A)
    catch
        Class:Reason:Stack ->
            error_logger:error_msg(
                "masque handler ~p:~p/~p failed: ~p:~p~n~p~n",
                [M, F, length(A), Class, Reason, Stack]),
            {stop, {handler_crash, Reason}}
    end.

try_callback(Mod, Fun, Args) ->
    Arity = length(Args),
    case erlang:function_exported(Mod, Fun, Arity) of
        true -> (catch apply(Mod, Fun, Args));
        false -> ok
    end.

ctx_overhead(V) when V < 64        -> 1;
ctx_overhead(V) when V < 16384     -> 2;
ctx_overhead(V) when V < 1073741824 -> 4;
ctx_overhead(_)                    -> 8.
