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

%% A datagram for an owner with a full mailbox is dropped and counted.
send_datagram_counts_drops_test() ->
    Before = persistent_term:get(masque_owner_drops, undefined),
    persistent_term:put(masque_owner_drops, counters:new(1, [])),
    Owner = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    [Owner ! {filler, N} || N <- lists:seq(1, 10000)],
    ok = masque_client_owner:send_datagram(Owner, {masque_data, self(), <<"x">>}),
    ?assertEqual(1, masque_metrics:owner_drop_count()),
    ?assertEqual({message_queue_len, 10000}, erlang:process_info(Owner, message_queue_len)),
    exit(Owner, kill),
    case Before of
        undefined -> persistent_term:erase(masque_owner_drops);
        Ref -> persistent_term:put(masque_owner_drops, Ref)
    end.
