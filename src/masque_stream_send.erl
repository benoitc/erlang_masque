-module(masque_stream_send).
-moduledoc false.

%%% Blocking write on an h3 or h2 request stream, for bytes that must not
%%% be dropped: CONNECT-TCP tunnel data and reverse connect control
%%% capsules.
%%%
%%% h2 waits for flow-control window. quic_h3 refuses a write when the
%%% stream's send queue is full (nothing written), so it is retried when
%%% quic_h3 reports the queue drained (`send_ready'). Both give up after
%%% 30 s without progress. The caller blocks in a `receive', so it must be
%%% the process quic_h3 tells about `send_ready': the one that made the
%%% refused write.

-export([send/5]).

-define(SEND_TIMEOUT, 30000).
%% How often a blocked h3 write checks whether the send queue moves.
-define(PROGRESS_CHECK_MS, 2000).

-spec send(h3 | h2, pid(), non_neg_integer(), iodata(), boolean()) -> ok | {error, term()}.
send(h2, Conn, Sid, Bytes, Fin) ->
    h2:send_data(Conn, Sid, Bytes, Fin, #{block => ?SEND_TIMEOUT});
send(h3, Conn, Sid, Bytes, Fin) ->
    send_h3(Conn, Sid, Bytes, Fin, no_progress_deadline(), undefined).

%% On a slow path a full queue can take far longer than the timeout to
%% drain while data still flows, so the deadline only runs while the
%% queue is not shrinking.
send_h3(C, Sid, Bytes, Fin, Deadline, Queued) ->
    case quic_h3:send_data(C, Sid, Bytes, Fin) of
        {error, send_queue_full} ->
            Now = erlang:monotonic_time(millisecond),
            Wait = max(0, min(?PROGRESS_CHECK_MS, Deadline - Now)),
            receive
                {quic_h3, C, {send_ready, Sid}} ->
                    send_h3(C, Sid, Bytes, Fin, no_progress_deadline(), undefined)
            after Wait ->
                case {queued_bytes(C), Queued} of
                    {Q, Before} when is_integer(Q), is_integer(Before), Q < Before ->
                        send_h3(C, Sid, Bytes, Fin, no_progress_deadline(), Q);
                    {Q, _} ->
                        case erlang:monotonic_time(millisecond) >= Deadline of
                            true -> {error, send_timeout};
                            false -> send_h3(C, Sid, Bytes, Fin, Deadline, Q)
                        end
                end
            end;
        Other ->
            Other
    end.

no_progress_deadline() ->
    erlang:monotonic_time(millisecond) + ?SEND_TIMEOUT.

%% Bytes waiting in the QUIC connection's send queue, or `undefined'
%% when the connection cannot tell.
queued_bytes(Conn) ->
    try quic:get_send_queue_info(quic_h3:get_quic_conn(Conn)) of
        {ok, #{bytes := Bytes}} -> Bytes;
        _ -> undefined
    catch
        exit:_ -> undefined
    end.
