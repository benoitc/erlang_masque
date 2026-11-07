-module(masque_tcp_capsule_tests).

%% Wire vectors for CONNECT-TCP capsules, draft-ietf-httpbis-connect-tcp-18
%% section 3.1 (DATA 0x08, FINAL_DATA 0x09) and the provisional codes of
%% drafts -09 and -10 (0x2028d7f0, 0x2028d7f1).

-include_lib("eunit/include/eunit.hrl").
-include("masque.hrl").

-define(C, masque_tcp_capsule).

%% Figure 1: type, length, payload.
encode_final_codes_test() ->
    ?assertEqual(<<16#08, 3, "abc">>, ?C:encode(final, <<"abc">>, false)),
    ?assertEqual(<<16#09, 3, "abc">>, ?C:encode(final, <<"abc">>, true)),
    %% Section 3.1: the length may be zero.
    ?assertEqual(<<16#09, 0>>, ?C:encode(final, <<>>, true)),
    ?assertEqual(<<16#08, 0>>, ?C:encode(final, <<>>, false)).

encode_provisional_codes_test() ->
    ?assertEqual(<<16#A0, 16#28, 16#D7, 16#F0, 2, "hi">>, ?C:encode(provisional, <<"hi">>, false)),
    ?assertEqual(<<16#A0, 16#28, 16#D7, 16#F1, 0>>, ?C:encode(provisional, <<>>, true)).

%% A 2-byte length varint for a 64-byte payload.
encode_long_length_test() ->
    Payload = binary:copy(<<"x">>, 64),
    ?assertEqual(<<16#08, 16#40, 64, Payload/binary>>, ?C:encode(final, Payload, false)).

codes_test() ->
    ?assertEqual(16#08, ?MASQUE_CAPSULE_DATA),
    ?assertEqual(16#09, ?MASQUE_CAPSULE_FINAL_DATA),
    ?assertEqual(16#2028d7f0, ?MASQUE_CAPSULE_DATA_PROVISIONAL),
    ?assertEqual(16#2028d7f1, ?MASQUE_CAPSULE_FINAL_DATA_PROVISIONAL).

%% Figure 6, endpoint B's view: DATA{"abc"} then FINAL_DATA{""}.
graceful_sequence_test() ->
    Bin = <<16#08, 3, "abc", 16#09, 0>>,
    {ok, Items, Dec} = ?C:decode(?C:decoder(final), Bin),
    ?assertEqual([{data, <<"abc">>}, {final, <<>>}], Items),
    ?assertEqual(ok, ?C:end_of_stream(Dec)).

%% Figure 9: the last bytes travel in FINAL_DATA itself.
final_with_payload_test() ->
    {ok, Items, _} = ?C:decode(?C:decoder(final), <<16#09, 3, "abc">>),
    ?assertEqual([{final, <<"abc">>}], Items).

%% Capsule boundaries carry no meaning: byte by byte gives the same
%% bytes and one FIN.
byte_by_byte_test() ->
    Bin = <<
        (?C:encode(final, <<"hello">>, false))/binary, (?C:encode(final, <<"world">>, true))/binary
    >>,
    {Items, Dec} = feed(?C:decoder(final), [<<B>> || <<B>> <= Bin]),
    ?assertEqual(<<"helloworld">>, iolist_to_binary([P || {_, P} <- Items])),
    ?assertEqual(1, length([F || {final, _} = F <- Items])),
    ?assertMatch({final, _}, lists:last(Items)),
    ?assertEqual(ok, ?C:end_of_stream(Dec)).

%% Section 3.1: payload is passed on before the capsule is complete, so
%% a large capsule never has to fit in memory (section 3.5.1 keeps it
%% valid).
large_capsule_streams_test() ->
    Size = 4 * 1024 * 1024,
    Full = ?C:encode(final, binary:copy(<<"z">>, Size), false),
    %% Type 0x08, then a 4-byte length varint for 4 MiB.
    ?assertEqual(<<16#08, 16#80, 16#40, 0, 0>>, binary:part(Full, 0, 5)),
    {ok, First, Dec} = ?C:decode(?C:decoder(final), binary:part(Full, 0, 1000)),
    ?assertMatch([{data, _}], First),
    ?assertEqual(1000 - 5, byte_size(element(2, hd(First)))),
    {ok, Rest, Dec2} = ?C:decode(Dec, binary:part(Full, 1000, byte_size(Full) - 1000)),
    ?assertEqual(Size, iolist_size([P || {_, P} <- First ++ Rest])),
    ?assertEqual(ok, ?C:end_of_stream(Dec2)).

%% RFC 9297 section 3.3: unknown capsules are skipped, even when split.
unknown_capsule_skipped_test() ->
    Other = iolist_to_binary(masque_capsule:encode(16#ff37a0, binary:copy(<<"i">>, 300))),
    Bin = <<Other/binary, (?C:encode(final, <<"kept">>, false))/binary>>,
    {Items, Dec} = feed(?C:decoder(final), [
        binary:part(Bin, 0, 100), binary:part(Bin, 100, byte_size(Bin) - 100)
    ]),
    ?assertEqual([{data, <<"kept">>}], Items),
    ?assertEqual(ok, ?C:end_of_stream(Dec)).

%% The codes belong to the version: provisional capsules on a -18
%% stream are unknown capsules, and the reverse.
codes_are_per_version_test() ->
    Prov = ?C:encode(provisional, <<"old">>, false),
    ?assertEqual(
        {ok, [], element(3, ?C:decode(?C:decoder(final), Prov))}, ?C:decode(?C:decoder(final), Prov)
    ),
    ?assertMatch({ok, [{data, <<"old">>}], _}, ?C:decode(?C:decoder(provisional), Prov)),
    ?assertMatch(
        {ok, [], _}, ?C:decode(?C:decoder(provisional), ?C:encode(final, <<"new">>, false))
    ).

%% Section 3.5.1: invalid data.
second_final_invalid_test() ->
    Bin = <<16#09, 0, 16#09, 0>>,
    ?assertEqual({error, data_after_final}, ?C:decode(?C:decoder(final), Bin)).

data_after_final_invalid_test() ->
    {ok, [{final, <<>>}], Dec} = ?C:decode(?C:decoder(final), <<16#09, 0>>),
    ?assertEqual({error, data_after_final}, ?C:decode(Dec, <<16#08, 1, "x">>)).

%% Other capsule types may still follow FINAL_DATA.
unknown_after_final_ok_test() ->
    {ok, _, Dec} = ?C:decode(?C:decoder(final), <<16#09, 0>>),
    Other = iolist_to_binary(masque_capsule:encode(16#ff37a0, <<"x">>)),
    ?assertMatch({ok, [], _}, ?C:decode(Dec, Other)).

truncated_payload_test() ->
    {ok, _, Dec} = ?C:decode(?C:decoder(final), <<16#08, 5, "ab">>),
    ?assertEqual({error, truncated_capsule}, ?C:end_of_stream(Dec)).

truncated_header_test() ->
    {ok, [], Dec} = ?C:decode(?C:decoder(final), <<16#40>>),
    ?assertEqual({error, truncated_capsule}, ?C:end_of_stream(Dec)).

truncated_unknown_capsule_test() ->
    {ok, [], Dec} = ?C:decode(?C:decoder(final), <<16#3f, 10, "abc">>),
    ?assertEqual({error, truncated_capsule}, ?C:end_of_stream(Dec)).

empty_stream_ok_test() ->
    ?assertEqual(ok, ?C:end_of_stream(?C:decoder(final))).

token_version_test() ->
    ?assertEqual(auto, ?C:token_version(<<"connect-tcp">>)),
    ?assertEqual({capsule, final}, ?C:token_version(<<"connect-tcp-12">>)),
    ?assertEqual({capsule, provisional}, ?C:token_version(<<"connect-tcp-08">>)),
    ?assertEqual({capsule, provisional}, ?C:token_version(<<"connect-tcp-07">>)),
    ?assertEqual(unknown, ?C:token_version(<<"connect-udp">>)),
    ?assertEqual(unknown, ?C:token_version(undefined)).

client_protocol_test() ->
    ?assertEqual({raw, <<"connect-tcp">>, final}, ?C:client_protocol(#{})),
    ?assertEqual(
        {capsule, <<"connect-tcp-12">>, final}, ?C:client_protocol(#{tcp_framing => capsule})
    ),
    ?assertEqual(
        {capsule, <<"connect-tcp">>, final},
        ?C:client_protocol(#{tcp_framing => capsule, tcp_protocol => <<"connect-tcp">>})
    ),
    ?assertEqual(
        {capsule, <<"connect-tcp-08">>, provisional},
        ?C:client_protocol(#{tcp_framing => capsule, tcp_protocol => <<"connect-tcp-08">>})
    ).

request_framing_test() ->
    ?assertEqual(capsule, ?C:request_framing(auto, [{<<"capsule-protocol">>, <<"?1">>}])),
    ?assertEqual(raw, ?C:request_framing(auto, [])),
    ?assertEqual(capsule, ?C:request_framing(capsule, [])),
    ?assertEqual(raw, ?C:request_framing(raw, [{<<"capsule-protocol">>, <<"?1">>}])).

expects_continue_test() ->
    ?assert(?C:expects_continue([{<<"expect">>, <<"100-continue">>}])),
    ?assert(?C:expects_continue([{<<"Expect">>, <<" 100-Continue ">>}])),
    ?assertNot(?C:expects_continue([{<<"expect">>, <<"something">>}])),
    ?assertNot(?C:expects_continue([])).

feed(Dec, Chunks) ->
    lists:foldl(
        fun(Chunk, {Acc, D}) ->
            {ok, Items, D2} = ?C:decode(D, Chunk),
            {Acc ++ Items, D2}
        end,
        {[], Dec},
        Chunks
    ).
