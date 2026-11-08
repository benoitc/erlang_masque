-module(masque_client_owner_tests).

-include_lib("eunit/include/eunit.hrl").

%% Events a proxy can send at any rate are dropped while the owner has a
%% full mailbox, and delivered again once it drains.
send_bounded_test() ->
    Owner = spawn(fun() ->
        receive
            go -> drain()
        end
    end),
    [Owner ! {filler, N} || N <- lists:seq(1, 10000)],
    ok = masque_client_owner:send_bounded(Owner, dropped),
    ?assertEqual({message_queue_len, 10000}, erlang:process_info(Owner, message_queue_len)),
    exit(Owner, kill),
    Empty = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    ok = masque_client_owner:send_bounded(Empty, delivered),
    ?assertEqual({message_queue_len, 1}, erlang:process_info(Empty, message_queue_len)),
    exit(Empty, kill).

drain() ->
    receive
        _ -> drain()
    end.
