-module(masque_tcp_capsule_tests).

-include_lib("eunit/include/eunit.hrl").
-include("masque.hrl").

round_trip_test() ->
    Bin = <<
        (masque_tcp_capsule:encode(<<"abc">>, false))/binary,
        (masque_tcp_capsule:encode(<<"de">>, true))/binary
    >>,
    ?assertEqual(
        {ok, [{data, <<"abc">>}, {final, <<"de">>}], <<>>},
        masque_tcp_capsule:decode(<<>>, Bin, 65536)
    ).

empty_final_test() ->
    Bin = masque_tcp_capsule:encode(<<>>, true),
    ?assertEqual({ok, [{final, <<>>}], <<>>}, masque_tcp_capsule:decode(<<>>, Bin, 65536)).

split_capsule_test() ->
    Bin = masque_tcp_capsule:encode(binary:copy(<<"x">>, 1000), false),
    <<A:10/binary, B/binary>> = Bin,
    {ok, [], Rest} = masque_tcp_capsule:decode(<<>>, A, 65536),
    ?assertEqual(A, Rest),
    ?assertEqual(
        {ok, [{data, binary:copy(<<"x">>, 1000)}], <<>>}, masque_tcp_capsule:decode(Rest, B, 65536)
    ).

unknown_capsules_skipped_test() ->
    Other = iolist_to_binary(masque_capsule:encode(16#ff37a0, <<"ignore me">>)),
    Bin = <<Other/binary, (masque_tcp_capsule:encode(<<"kept">>, false))/binary>>,
    ?assertEqual({ok, [{data, <<"kept">>}], <<>>}, masque_tcp_capsule:decode(<<>>, Bin, 65536)).

oversize_refused_test() ->
    <<Head:20/binary, _/binary>> = masque_tcp_capsule:encode(binary:copy(<<"x">>, 2000), false),
    ?assertEqual({error, capsule_buffer_overflow}, masque_tcp_capsule:decode(<<>>, Head, 1000)).

codes_test() ->
    ?assertEqual(16#2028d7f0, ?MASQUE_CAPSULE_DATA),
    ?assertEqual(16#2028d7f1, ?MASQUE_CAPSULE_FINAL_DATA).

request_framing_test() ->
    ?assertEqual(capsule, masque_tcp_capsule:request_framing([{<<"capsule-protocol">>, <<"?1">>}])),
    ?assertEqual(raw, masque_tcp_capsule:request_framing([])).

expects_continue_test() ->
    ?assert(masque_tcp_capsule:expects_continue([{<<"expect">>, <<"100-continue">>}])),
    ?assert(masque_tcp_capsule:expects_continue([{<<"Expect">>, <<" 100-Continue ">>}])),
    ?assertNot(masque_tcp_capsule:expects_continue([{<<"expect">>, <<"something">>}])),
    ?assertNot(masque_tcp_capsule:expects_continue([])).
