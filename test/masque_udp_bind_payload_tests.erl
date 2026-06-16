-module(masque_udp_bind_payload_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Compressed: identity
%%====================================================================

compressed_roundtrip_test() ->
    Pkt = <<"hello", 0, 1, 2, 3>>,
    Encoded = masque_udp_bind_payload:encode_compressed(Pkt),
    ?assertEqual(Pkt, Encoded),
    ?assertEqual(
        {ok, Pkt},
        masque_udp_bind_payload:decode_compressed(Encoded)
    ).

compressed_empty_payload_test() ->
    ?assertEqual(
        {ok, <<>>},
        masque_udp_bind_payload:decode_compressed(<<>>)
    ).

%%====================================================================
%% Uncompressed: encode/decode roundtrip
%%====================================================================

uncompressed_v4_roundtrip_test() ->
    Peer = {4, {192, 0, 2, 1}, 53},
    Pkt = <<"dns query bytes">>,
    {ok, Bin} =
        masque_udp_bind_payload:encode_uncompressed(Peer, Pkt, [4, 6]),
    ?assertEqual(
        {ok, Peer, Pkt},
        masque_udp_bind_payload:decode_uncompressed(Bin)
    ).

uncompressed_v6_roundtrip_test() ->
    Peer = {6, {16#2001, 16#0DB8, 0, 0, 0, 0, 0, 1}, 4433},
    Pkt = <<"hello world">>,
    {ok, Bin} =
        masque_udp_bind_payload:encode_uncompressed(Peer, Pkt, [4, 6]),
    ?assertEqual(
        {ok, Peer, Pkt},
        masque_udp_bind_payload:decode_uncompressed(Bin)
    ).

%%====================================================================
%% Wire-format pinning (draft-11 sections 4 and 5)
%%====================================================================

%% Uncompressed v4: 1 byte version + 4 bytes addr + 2 bytes port +
%% UDP payload.
uncompressed_v4_wire_shape_test() ->
    Peer = {4, {192, 0, 2, 1}, 53},
    Pkt = <<"X">>,
    {ok, Bin} =
        masque_udp_bind_payload:encode_uncompressed(Peer, Pkt, [4]),
    ?assertEqual(<<4:8, 192:8, 0:8, 2:8, 1:8, 53:16, "X">>, Bin).

%% Uncompressed v6: 1 byte version + 16 bytes addr + 2 bytes port +
%% UDP payload.
uncompressed_v6_wire_shape_test() ->
    Peer = {6, {16#2001, 16#0DB8, 0, 0, 0, 0, 0, 1}, 5060},
    Pkt = <<"X">>,
    {ok, Bin} =
        masque_udp_bind_payload:encode_uncompressed(Peer, Pkt, [6]),
    ?assertEqual(
        <<6:8, 16#2001:16, 16#0DB8:16, 0:16, 0:16, 0:16, 0:16, 0:16, 1:16, 5060:16, "X">>, Bin
    ).

%%====================================================================
%% Family gating
%%====================================================================

encode_v4_unadvertised_v6_only_test() ->
    Peer = {4, {192, 0, 2, 1}, 53},
    ?assertEqual(
        {error, unadvertised_family},
        masque_udp_bind_payload:encode_uncompressed(
            Peer, <<"x">>, [6]
        )
    ).

encode_v6_unadvertised_v4_only_test() ->
    Peer = {6, {16#2001, 16#0DB8, 0, 0, 0, 0, 0, 1}, 4433},
    ?assertEqual(
        {error, unadvertised_family},
        masque_udp_bind_payload:encode_uncompressed(
            Peer, <<"x">>, [4]
        )
    ).

family_advertised_helper_test() ->
    ?assert(masque_udp_bind_payload:family_advertised(4, [4, 6])),
    ?assert(masque_udp_bind_payload:family_advertised(6, [4, 6])),
    ?assertNot(masque_udp_bind_payload:family_advertised(4, [6])),
    ?assertNot(masque_udp_bind_payload:family_advertised(6, [4])).

%%====================================================================
%% Uncompressed decode error paths
%%====================================================================

decode_uncompressed_truncated_v4_test() ->
    %% missing rest of addr + port
    Bad = <<4:8, 192:8, 0:8, 2:8>>,
    ?assertEqual(
        {error, truncated},
        masque_udp_bind_payload:decode_uncompressed(Bad)
    ).

decode_uncompressed_truncated_v6_test() ->
    %% 1-byte version + 4 bytes (not 16) of addr.
    Bad = <<6:8, 0:32>>,
    ?assertEqual(
        {error, truncated},
        masque_udp_bind_payload:decode_uncompressed(Bad)
    ).

decode_uncompressed_bad_version_test() ->
    Bad = <<7:8, 0:32>>,
    ?assertEqual(
        {error, bad_ip_version},
        masque_udp_bind_payload:decode_uncompressed(Bad)
    ).

decode_uncompressed_empty_test() ->
    ?assertEqual(
        {error, truncated},
        masque_udp_bind_payload:decode_uncompressed(<<>>)
    ).

%% Uncompressed decode payload-only (zero UDP bytes): valid.
decode_uncompressed_zero_payload_test() ->
    Peer = {4, {0, 0, 0, 0}, 0},
    {ok, Bin} =
        masque_udp_bind_payload:encode_uncompressed(Peer, <<>>, [4]),
    ?assertEqual(
        {ok, Peer, <<>>},
        masque_udp_bind_payload:decode_uncompressed(Bin)
    ).
