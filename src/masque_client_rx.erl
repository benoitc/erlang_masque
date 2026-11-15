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
%%%
%%% The buffer counts its items, so the bound check is O(1): `queue:len/1'
%%% walks the whole queue.
-module(masque_client_rx).
-moduledoc false.

-export([new/0, in/2, out/1, len/1, to_list/1]).
-export([limit/1, is_full/2, keep_unread/2, close_queue/2, closed_enter/0, closed/5]).
-export([backlog/1, owner_behind/2]).

-export_type([buf/0]).

-opaque buf() :: {non_neg_integer(), queue:queue()}.

-include("masque.hrl").

-define(LINGER_MS, 30000).
%% `rx_backlog' default: owner messages past which a CONNECT-TCP session
%% stops reading from the proxy.
-define(DEFAULT_BACKLOG, 64).
-define(END_MARK, '$masque_rx_end').

%% The receive-queue bound from connect opts.
-spec limit(map()) -> pos_integer().
limit(Opts) ->
    case maps:get(rx_queue_limit, Opts, ?MASQUE_DEFAULT_RX_QUEUE_LIMIT) of
        N when is_integer(N), N > 0 -> N;
        _ -> ?MASQUE_DEFAULT_RX_QUEUE_LIMIT
    end.

-spec new() -> buf().
new() -> {0, queue:new()}.

-spec in(term(), buf()) -> buf().
in(Item, {N, Q}) -> {N + 1, queue:in(Item, Q)}.

-spec out(buf()) -> {{value, term()}, buf()} | {empty, buf()}.
out({N, Q} = Buf) ->
    case queue:out(Q) of
        {{value, Item}, Q2} -> {{value, Item}, {N - 1, Q2}};
        {empty, _} -> {empty, Buf}
    end.

-spec len(buf()) -> non_neg_integer().
len({N, _}) -> N.

-spec to_list(buf()) -> [term()].
to_list({_, Q}) -> queue:to_list(Q).

%% The `rx_backlog' bound from connect opts.
-spec backlog(map()) -> pos_integer().
backlog(Opts) ->
    case maps:get(rx_backlog, Opts, ?DEFAULT_BACKLOG) of
        N when is_integer(N), N > 0 -> N;
        _ -> ?DEFAULT_BACKLOG
    end.

%% True when a local `Owner' has `Max' messages or more waiting. A byte
%% stream cannot drop what the owner has not read yet, so a CONNECT-TCP
%% session stops reading instead and the proxy waits for flow-control
%% credit. A remote owner's mailbox cannot be read: never behind.
-spec owner_behind(pid(), pos_integer()) -> boolean().
owner_behind(Owner, Max) when node(Owner) =:= node() ->
    case erlang:process_info(Owner, message_queue_len) of
        {message_queue_len, N} -> N >= Max;
        _ -> false
    end;
owner_behind(_Owner, _Max) ->
    false.

%% True when `Buf` holds `Limit` items or more.
-spec is_full(buf(), pos_integer()) -> boolean().
is_full({N, _}, Limit) ->
    N >= Limit.

%% True when a tunnel ending now leaves queue-mode data unread.
-spec keep_unread(message | queue, buf()) -> boolean().
keep_unread(queue, {N, _}) -> N > 0;
keep_unread(_Mode, _Buf) -> false.

%% Mark the end of `Buf`: once the owner has read everything
%% before it, `recv/2` returns `{error, Reason}`.
-spec close_queue(buf(), term()) -> buf().
close_queue(Buf, Reason) ->
    in({?END_MARK, Reason}, Buf).

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
    buf(),
    reference(),
    fun((buf()) -> term()) | {bind, fun((buf()) -> term())}
) -> gen_statem:event_handler_result(atom()).
closed({call, From}, {recv, _Timeout}, Buf, _OwnerRef, Update) ->
    case out(Buf) of
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
