-module(masque_crash_log_tests).

-include_lib("eunit/include/eunit.hrl").

-export([log/2]).

%% logger handler: send each formatted error line to the test process.
log(#{level := error, msg := Msg}, #{config := #{to := Pid}}) ->
    Text =
        case Msg of
            {Format, Args} when is_list(Format) -> io_lib:format(Format, Args);
            {string, S} -> S;
            Other -> io_lib:format("~p", [Other])
        end,
    Pid ! {logged, lists:flatten(Text)};
log(_, _) ->
    ok.

with_capture(Fun) ->
    Id = list_to_atom("crash_log_" ++ integer_to_list(erlang:unique_integer([positive]))),
    ok = logger:add_handler(Id, ?MODULE, #{level => error, config => #{to => self()}}),
    try
        Fun()
    after
        logger:remove_handler(Id)
    end.

collect(Acc) ->
    receive
        {logged, L} -> collect([L | Acc])
    after 200 -> lists:reverse(Acc)
    end.

%% Neither the reason nor the stack arguments reach the log.
no_secret_in_log_test() ->
    persistent_term:erase({masque_crash_log, window}),
    Secret = <<"Bearer s3cr3t-token">>,
    Req = #{headers => [{<<"authorization">>, Secret}]},
    Stack = [{some_handler, accept, [Req], [{file, "some_handler.erl"}, {line, 42}]}],
    Lines = with_capture(fun() ->
        ok = masque_crash_log:handler(
            "udp", some_handler, accept, 1, error, {badmatch, Req}, Stack
        ),
        collect([])
    end),
    ?assertMatch([_], Lines),
    [Line] = Lines,
    ?assertEqual(nomatch, string:find(Line, "s3cr3t")),
    ?assertNotEqual(nomatch, string:find(Line, "badmatch")),
    ?assertNotEqual(nomatch, string:find(Line, "some_handler:accept/1 (some_handler.erl:42)")).

%% A flood of crashes writes at most ten lines a second.
rate_limited_test() ->
    persistent_term:erase({masque_crash_log, window}),
    Lines = with_capture(fun() ->
        [
            masque_crash_log:handler("tcp", h, init, 2, error, boom, [])
         || _ <- lists:seq(1, 50)
        ],
        collect([])
    end),
    ?assert(length(Lines) =< 10).
