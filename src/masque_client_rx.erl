%%% Shared receive-queue rules for queue-mode client sessions.
%%%
%%% A session in `queue` mode buffers what it receives until the
%%% owner pulls it with `masque:recv/2`. The buffer is bounded by
%%% `rx_queue_limit` (default `?MASQUE_DEFAULT_RX_QUEUE_LIMIT` items).
%%%
%%% When the peer ends the tunnel while the owner still has unread
%%% data, the session tears the transport down and parks in a
%%% `closed` state instead of stopping: `recv/2` keeps returning the
%%% buffered items, then `{error, Reason}` (`closed`, or
%%% `rx_overflow` for a CONNECT-TCP tunnel whose queue overflowed),
%%% and the session stops. A session nobody reads from stops after
%%% `?LINGER_MS` or when its owner exits.
-module(masque_client_rx).
-moduledoc false.

-export([limit/1, is_full/2, keep_unread/2, close_queue/2, closed_enter/0, closed/5]).

-include("masque.hrl").

-define(LINGER_MS, 30000).
-define(END_MARK, '$masque_rx_end').

%% The receive-queue bound from connect opts.
-spec limit(map()) -> pos_integer().
limit(Opts) ->
    case maps:get(rx_queue_limit, Opts, ?MASQUE_DEFAULT_RX_QUEUE_LIMIT) of
        N when is_integer(N), N > 0 -> N;
        _ -> ?MASQUE_DEFAULT_RX_QUEUE_LIMIT
    end.

%% True when `Buf` holds `Limit` items or more.
-spec is_full(queue:queue(), pos_integer()) -> boolean().
is_full(Buf, Limit) ->
    queue:len(Buf) >= Limit.

%% True when a tunnel ending now leaves queue-mode data unread.
-spec keep_unread(message | queue, queue:queue()) -> boolean().
keep_unread(queue, Buf) -> not queue:is_empty(Buf);
keep_unread(_Mode, _Buf) -> false.

%% Mark the end of `Buf`: once the owner has read everything
%% before it, `recv/2` returns `{error, Reason}`.
-spec close_queue(queue:queue(), term()) -> queue:queue().
close_queue(Buf, Reason) ->
    queue:in({?END_MARK, Reason}, Buf).

%% Enter actions for the `closed` state.
-spec closed_enter() -> [gen_statem:action()].
closed_enter() ->
    [{state_timeout, ?LINGER_MS, linger_expired}].

%% Event handling for the `closed` state. `Buf` is the session's
%% receive queue (ended with `close_queue/2`), `OwnerRef` its
%% owner monitor, and `Update` stores the queue back in the session
%% data. `recv` items are returned as `{ok, Item}`, or as
%% `{ok, Peer, Bytes}` for udp-bind `{Peer, Bytes}` items when
%% `Update` is given `{bind, Fun}`.
-spec closed(
    gen_statem:event_type(),
    term(),
    queue:queue(),
    reference(),
    fun((queue:queue()) -> term()) | {bind, fun((queue:queue()) -> term())}
) -> gen_statem:event_handler_result(atom()).
closed({call, From}, {recv, _Timeout}, Buf, _OwnerRef, Update) ->
    case queue:out(Buf) of
        {{value, {?END_MARK, Reason}}, _} ->
            {stop_and_reply, normal, [{reply, From, {error, Reason}}]};
        {{value, Item}, Buf2} ->
            {keep_state, update(Update, Buf2), [{reply, From, reply(Update, Item)}]};
        {empty, _} ->
            {stop_and_reply, normal, [{reply, From, {error, closed}}]}
    end;
closed({call, From}, stop, _Buf, _OwnerRef, _Update) ->
    {stop_and_reply, normal, [{reply, From, ok}]};
closed({call, From}, _Other, _Buf, _OwnerRef, _Update) ->
    {keep_state_and_data, [{reply, From, {error, closed}}]};
closed(state_timeout, linger_expired, _Buf, _OwnerRef, _Update) ->
    {stop, normal};
closed(info, {'DOWN', Ref, process, _, _}, _Buf, Ref, _Update) ->
    {stop, normal};
closed(_Type, _Event, _Buf, _OwnerRef, _Update) ->
    keep_state_and_data.

update({bind, Fun}, Buf) -> Fun(Buf);
update(Fun, Buf) -> Fun(Buf).

reply({bind, _}, {Peer, Bytes}) -> {ok, Peer, Bytes};
reply(_Update, Item) -> {ok, Item}.
