-module(masque_crash_log).
-moduledoc false.

%%% One log line per handler crash, safe to keep.
%%%
%%% A handler's exception reason and the arguments in its stack can hold
%%% the request map (headers such as `authorization') and handler state.
%%% So the line names the callback, the class and the shape of the reason
%%% (`badmatch', `function_clause', ...) and lists the stack as
%%% `Module:Function/Arity (file:line)', never the values. The application
%%% env `handler_crash_detail' (default `false') logs the full reason, for
%%% debugging on a trusted node.
%%%
%%% A peer that can make a handler crash on every request could flood the
%%% logs: at most `?PER_SECOND' lines are written a second, and the next
%%% line written says how many were left out.

-export([handler/7]).

-define(PER_SECOND, 10).
-define(KEY, {?MODULE, window}).

-spec handler(string(), module(), atom(), arity(), atom(), term(), list()) -> ok.
handler(Kind, M, F, Arity, Class, Reason, Stack) ->
    case admit() of
        {true, Suppressed} ->
            logger:error(
                "masque ~s handler ~p:~p/~p failed: ~p:~0p~s~n~s",
                [
                    Kind,
                    M,
                    F,
                    Arity,
                    Class,
                    reason(Reason),
                    suppressed(Suppressed),
                    stack(Stack)
                ]
            );
        false ->
            ok
    end.

reason(Reason) ->
    case application:get_env(masque, handler_crash_detail, false) of
        true -> Reason;
        _ -> shape(Reason)
    end.

shape(R) when is_atom(R) -> R;
shape(R) when is_tuple(R), tuple_size(R) > 0, is_atom(element(1, R)) -> {element(1, R), '...'};
shape(_) -> '...'.

stack(Stack) ->
    [["    ", frame(Frame), "\n"] || Frame <- Stack].

frame({M, F, ArgsOrArity, Loc}) ->
    Arity =
        case ArgsOrArity of
            A when is_list(A) -> length(A);
            A -> A
        end,
    case {proplists:get_value(file, Loc), proplists:get_value(line, Loc)} of
        {File, Line} when File =/= undefined, Line =/= undefined ->
            io_lib:format("~p:~p/~p (~s:~p)", [M, F, Arity, filename:basename(File), Line]);
        _ ->
            io_lib:format("~p:~p/~p", [M, F, Arity])
    end;
frame(_) ->
    "?".

suppressed(0) -> "";
suppressed(N) -> io_lib:format(" (~p earlier handler crash reports left out)", [N]).

%% A one-second window: slot 1 the second, slot 2 lines written in it,
%% slot 3 lines left out since the last one written.
admit() ->
    Ref = window(),
    Now = erlang:monotonic_time(second),
    case atomics:get(Ref, 1) of
        Now ->
            ok;
        _ ->
            atomics:put(Ref, 1, Now),
            atomics:put(Ref, 2, 0)
    end,
    case atomics:add_get(Ref, 2, 1) =< ?PER_SECOND of
        true ->
            {true, atomics:exchange(Ref, 3, 0)};
        false ->
            atomics:add(Ref, 3, 1),
            false
    end.

window() ->
    case persistent_term:get(?KEY, undefined) of
        undefined ->
            Ref = atomics:new(3, [{signed, true}]),
            persistent_term:put(?KEY, Ref),
            Ref;
        Ref ->
            Ref
    end.
