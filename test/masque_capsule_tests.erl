-module(masque_capsule_tests).

-include_lib("eunit/include/eunit.hrl").

encode_decode_roundtrip_test() ->
    Type = 16#abcd,
    Val = <<"capsule-body">>,
    Enc = iolist_to_binary(masque_capsule:encode(Type, Val)),
    ?assertMatch({ok, {Type, Val, <<>>}}, masque_capsule:decode(Enc)).

decode_more_on_empty_test() ->
    ?assertMatch({more, _}, masque_capsule:decode(<<>>)).

decode_truncated_value_test() ->
    %% Type=0, Length=4, but only 2 body bytes supplied.
    Bin = <<0, 4, 1, 2>>,
    ?assertMatch({more, _}, masque_capsule:decode(Bin)).

no_types_known_by_default_test() ->
    ?assertNot(masque_capsule:known(0)),
    ?assertNot(masque_capsule:known(16#ff37a0)).
