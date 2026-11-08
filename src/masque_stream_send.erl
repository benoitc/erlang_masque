-module(masque_stream_send).
-moduledoc false.

%%% Blocking write on an h3 or h2 request stream, for bytes that must not
%%% be dropped: CONNECT-TCP tunnel data and reverse connect control
%%% capsules.
%%%
%%% h2 waits for flow-control window. quic_h3 refuses a write when the
%%% stream's send queue is full (nothing written), so it is retried when
%%% quic_h3 reports the queue drained (`send_ready'). Both give up after
%%% 30 s without progress (application env `stream_send_timeout_ms').
%%% Progress on h3 is measured on the whole connection's send queue, so
%%% a peer draining other streams could keep one write waiting for ever;
%%% a write also gives up after five times the timeout in all. The
%%% caller blocks in a `receive', so it must be the process quic_h3
%%% tells about `send_ready': the one that made the refused write.

-export([send/5]).

-define(DEFAULT_SEND_TIMEOUT, 30000).
%% A blocked write gives up after this many send timeouts in all.
-define(CEILING_FACTOR, 5).
%% How often a blocked h3 write checks whether the send queue moves.
-define(PROGRESS_CHECK_MS, 2000).

-spec send(h3 | h2, pid(), non_neg_integer(), iodata(), boolean()) -> ok | {error, term()}.
send(h2, Conn, Sid, Bytes, Fin) ->
    try
        h2:send_data(Conn, Sid, Bytes, Fin, #{block => send_timeout()})
    catch
        exit:_ -> {error, closed}
    end;
send(h3, Conn, Sid, Bytes, Fin) ->
    Timeout = send_timeout(),
    Ceiling = erlang:monotonic_time(millisecond) + ?CEILING_FACTOR * Timeout,
    send_h3({Conn, Timeout, Ceiling}, Sid, Bytes, Fin, deadline(Timeout, Ceiling), undefined).

%% On a slow path a full queue can take far longer than the timeout to
%% drain while data still flows, so the deadline only runs while the
%% queue is not shrinking.
send_h3({C, Timeout, Ceiling} = W, Sid, Bytes, Fin, Deadline, Queued) ->
    case h3_send(C, Sid, Bytes, Fin) of
        {error, send_queue_full} ->
            Now = erlang:monotonic_time(millisecond),
            Wait = max(0, min(?PROGRESS_CHECK_MS, Deadline - Now)),
            receive
                {quic_h3, C, {send_ready, Sid}} ->
                    send_h3(W, Sid, Bytes, Fin, deadline(Timeout, Ceiling), undefined)
            after Wait ->
                case {queued_bytes(C), Queued} of
                    {Q, Before} when is_integer(Q), is_integer(Before), Q < Before ->
                        send_h3(W, Sid, Bytes, Fin, deadline(Timeout, Ceiling), Q);
                    {Q, _} ->
                        case erlang:monotonic_time(millisecond) >= Deadline of
                            true -> {error, send_timeout};
                            false -> send_h3(W, Sid, Bytes, Fin, Deadline, Q)
                        end
                end
            end;
        Other ->
            Other
    end.

%% The connection may be gone (the peer dropped it) before its close
%% reaches the caller: report it, do not crash the caller.
h3_send(C, Sid, Bytes, Fin) ->
    try
        quic_h3:send_data(C, Sid, Bytes, Fin)
    catch
        exit:_ -> {error, closed}
    end.

%% The no-progress deadline, never past the write's ceiling.
deadline(Timeout, Ceiling) ->
    min(erlang:monotonic_time(millisecond) + Timeout, Ceiling).

send_timeout() ->
    case application:get_env(masque, stream_send_timeout_ms) of
        {ok, Ms} when is_integer(Ms), Ms > 0 -> Ms;
        _ -> ?DEFAULT_SEND_TIMEOUT
    end.

%% Bytes waiting in the QUIC connection's send queue, or `undefined'
%% when the connection cannot tell.
queued_bytes(Conn) ->
    try quic:get_send_queue_info(quic_h3:get_quic_conn(Conn)) of
        {ok, #{bytes := Bytes}} -> Bytes;
        _ -> undefined
    catch
        exit:_ -> undefined
    end.
