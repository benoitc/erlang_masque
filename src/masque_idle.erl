%%% Idle timeout for h3 and h2 server sessions.
%%%
%%% A session touches the timer on every message it handles (client
%%% traffic and target traffic alike). Touching only records the time;
%%% a single timer fires every `idle_timeout_ms` and re-arms itself for
%%% the time left, so a busy tunnel costs no timer churn.
-module(masque_idle).
-moduledoc false.

-export([new/1, touch/1, check/2, cancel/1]).

-export_type([idle/0]).

-opaque idle() :: disabled | {pos_integer(), integer(), reference()}.

%% Start the timer; `infinity' or 0 disables it.
-spec new(non_neg_integer() | infinity) -> idle().
new(infinity) -> disabled;
new(0) -> disabled;
new(Ms) when is_integer(Ms), Ms > 0 -> {Ms, now_ms(), erlang:start_timer(Ms, self(), masque_idle)}.

-spec touch(idle()) -> idle().
touch(disabled) -> disabled;
touch({Ms, _Last, Ref}) -> {Ms, now_ms(), Ref}.

%% Handle `{timeout, Ref, masque_idle}': `expired' when nothing
%% happened for the whole window, otherwise the re-armed timer.
-spec check(reference(), idle()) -> expired | {ok, idle()}.
check(Ref, {Ms, Last, Ref}) ->
    Elapsed = now_ms() - Last,
    case Elapsed >= Ms of
        true -> expired;
        false -> {ok, {Ms, Last, erlang:start_timer(Ms - Elapsed, self(), masque_idle)}}
    end;
check(_StaleRef, Idle) ->
    {ok, Idle}.

-spec cancel(idle()) -> ok.
cancel(disabled) ->
    ok;
cancel({_, _, Ref}) ->
    _ = erlang:cancel_timer(Ref),
    ok.

now_ms() -> erlang:monotonic_time(millisecond).
