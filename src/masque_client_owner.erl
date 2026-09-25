%%% @doc Owner delivery for client sessions.
%%%
%%% The transport racer starts every attempt with a race worker as
%%% owner and hands the winner to the real owner with
%%% `{set_owner, Pid}'. Events the session produces between its 2xx
%%% and that call (for example a CONNECT-IP ADDRESS_ASSIGN sent right
%%% after the response) must not end up in the worker's mailbox. A
%%% session started with `defer_owner => true' holds its owner
%%% messages until {@link release/1} runs on `set_owner', then flushes
%%% them in order to the new owner. Sessions started without the
%%% option send directly, as before.
%%%
%%% The held messages live in the session process dictionary under a
%%% key private to this module.
-module(masque_client_owner).

-export([init/1, send/2, release/1]).

-define(HELD_KEY, {?MODULE, held}).

%% @doc Start holding owner messages when `Opts' asks for it.
-spec init(map()) -> ok.
init(#{defer_owner := true}) ->
    _ = put(?HELD_KEY, []),
    ok;
init(_Opts) ->
    ok.

%% @doc Deliver `Msg' to `Owner', or hold it until {@link release/1}.
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

%% @doc Stop holding and flush the held messages, oldest first, to
%% `Owner'.
-spec release(pid()) -> ok.
release(Owner) ->
    case erase(?HELD_KEY) of
        undefined ->
            ok;
        Held ->
            lists:foreach(fun(Msg) -> Owner ! Msg end, lists:reverse(Held))
    end.
