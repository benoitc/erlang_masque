-module(masque_reverse_ids_tests).

-include_lib("eunit/include/eunit.hrl").

seen_after_add_test() ->
    Ids = masque_reverse_ids:add(7, masque_reverse_ids:new()),
    ?assert(masque_reverse_ids:seen(7, Ids)),
    ?assertNot(masque_reverse_ids:seen(8, Ids)).

%% Only the last 4096 ids are kept: memory stays bounded however many
%% requests a proxy sends, and the most recent ids are still checked.
bounded_test() ->
    Ids = lists:foldl(fun masque_reverse_ids:add/2, masque_reverse_ids:new(), lists:seq(1, 10000)),
    {Set, _} = Ids,
    ?assertEqual(4096, map_size(Set)),
    ?assertNot(masque_reverse_ids:seen(1, Ids)),
    ?assert(masque_reverse_ids:seen(10000, Ids)),
    ?assert(masque_reverse_ids:seen(10000 - 4095, Ids)),
    ?assertNot(masque_reverse_ids:seen(10000 - 4096, Ids)).
