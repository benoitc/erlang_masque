-module(masque_datagram_tests).

-include_lib("eunit/include/eunit.hrl").

-include("masque.hrl").

encode_udp_context_test() ->
    %% Context 0 is a single 0x00 byte (smallest varint).
    Enc = iolist_to_binary(masque_datagram:encode(?MASQUE_CONTEXT_ID_UDP,
                                                  <<"hello">>)),
    ?assertEqual(<<0, "hello">>, Enc).

encode_large_context_test() ->
    %% Context IDs round-trip for any non-negative integer up to the
    %% 62-bit varint limit.
    Enc = iolist_to_binary(masque_datagram:encode(16383, <<"x">>)),
    {ok, {16383, <<"x">>}} = masque_datagram:decode(Enc).

decode_empty_payload_test() ->
    {ok, {0, <<>>}} = masque_datagram:decode(<<0>>).

decode_malformed_test() ->
    ?assertEqual({error, malformed_varint},
                 masque_datagram:decode(<<>>)).

roundtrip_test_() ->
    Cases = [
        {0,     <<>>},
        {0,     <<"udp payload">>},
        {1,     <<1,2,3>>},
        {63,    <<"boundary-1-byte">>},
        {64,    <<"boundary-2-byte">>},
        {16383, <<"boundary-2-byte-max">>},
        {16384, <<"boundary-4-byte">>}
    ],
    [?_test(
        begin
            Enc = iolist_to_binary(masque_datagram:encode(C, P)),
            ?assertEqual({ok, {C, P}}, masque_datagram:decode(Enc))
        end) || {C, P} <- Cases].
