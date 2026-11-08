%%% Owner delivery for client sessions.
%%%
%%% The transport racer starts every attempt with a race worker as
%%% owner and hands the winner to the real owner with
%%% `{set_owner, Pid}`. Events the session produces between its 2xx
%%% and that call (for example a CONNECT-IP ADDRESS_ASSIGN sent right
%%% after the response) must not end up in the worker's mailbox. A
%%% session started with `defer_owner => true` holds its owner
%%% messages until `release/1` runs on `set_owner`, then flushes
%%% them in order to the new owner. Sessions started without the
%%% option send directly, as before.
%%%
%%% The held messages live in the session process dictionary under a
%%% key private to this module.
-module(masque_client_owner).
-moduledoc false.

-export([init/1, send/2, send_bounded/2, release/1]).

-define(HELD_KEY, {?MODULE, held}).
%% Owner mailbox length past which `send_bounded/2' drops, as the h3
%% router does for datagrams.
-define(OWNER_BACKLOG, 10000).

%% Start holding owner messages when `Opts` asks for it.
-spec init(map()) -> ok.
init(#{defer_owner := true}) ->
    _ = put(?HELD_KEY, []),
    ok;
init(_Opts) ->
    ok.

%% Deliver `Msg` to `Owner`, or hold it until `release/1`.
-spec send(pid(), term()) -> ok.
send(Owner, Msg) ->
    case get(?HELD_KEY) of
        undefined ->
            Owner ! Msg,
            ok;
        Held ->
            _ = put(?HELD_KEY, [Msg | Held]),
            ok
    end.

%% Deliver an event the proxy can send at any rate (capsules of unknown
%% type, CONNECT-IP control capsules): dropped while the owner already
%% has `?OWNER_BACKLOG' messages waiting, so a proxy that floods them
%% cannot grow the owner's mailbox without limit.
-spec send_bounded(pid(), term()) -> ok.
send_bounded(Owner, Msg) ->
    case get(?HELD_KEY) =:= undefined andalso erlang:process_info(Owner, message_queue_len) of
        {message_queue_len, N} when N >= ?OWNER_BACKLOG -> ok;
        _ -> send(Owner, Msg)
    end.

%% Stop holding and flush the held messages, oldest first, to
%% `Owner`.
-spec release(pid()) -> ok.
release(Owner) ->
    case erase(?HELD_KEY) of
        undefined ->
            ok;
        Held ->
            lists:foreach(fun(Msg) -> Owner ! Msg end, lists:reverse(Held))
    end.
