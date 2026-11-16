-module(masque_reverse_registry_tests).

-include_lib("eunit/include/eunit.hrl").

%% Ids are 62-bit values from a strong random source, distinct, and
%% each one finds its entry.
ids_are_random_62_bit_test() ->
    Owner = spawn(fun() ->
        ok = masque_reverse_registry:new_table(),
        receive
            stop -> ok
        end
    end),
    wait_table(50),
    Entry = #{
        control => self(),
        conn => undefined,
        identity => <<"test">>,
        requester => self(),
        service => #{destination => local, protocol => tcp, port => 22}
    },
    Ids = [masque_reverse_registry:register(Entry) || _ <- lists:seq(1, 1000)],
    ?assertEqual(1000, length(lists:usort(Ids))),
    ?assert(lists:all(fun(Id) -> Id >= 0 andalso Id < (1 bsl 62) end, Ids)),
    [?assertEqual({ok, Entry}, masque_reverse_registry:lookup(Id)) || Id <- Ids],
    Owner ! stop.

wait_table(0) ->
    error(no_table);
wait_table(N) ->
    case ets:whereis(masque_reverse_pending) of
        undefined ->
            timer:sleep(10),
            wait_table(N - 1);
        _ ->
            ok
    end.
