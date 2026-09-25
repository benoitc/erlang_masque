-module(masque_compression_capsule_tests).

-include_lib("eunit/include/eunit.hrl").
-include("masque_udp_bind.hrl").

%%====================================================================
%% COMPRESSION_ASSIGN: encode + decode roundtrips
%%====================================================================

assign_v4_roundtrip_test() ->
    R = #compression_assign{
        context_id = 2,
        ip_version = 4,
        address = {192, 0, 2, 1},
        port = 4433
    },
    ?assertEqual(
        {ok, R},
        masque_compression_capsule:decode_assign(
            masque_compression_capsule:encode_assign(R)
        )
    ).

assign_v6_roundtrip_test() ->
    R = #compression_assign{
        context_id = 4,
        ip_version = 6,
        address = {16#2001, 16#DB8, 0, 0, 0, 0, 0, 1},
        port = 5060
    },
    ?assertEqual(
        {ok, R},
        masque_compression_capsule:decode_assign(
            masque_compression_capsule:encode_assign(R)
        )
    ).

%% IP Version 0 - uncompressed registration. The body is just
%% (Context ID varint || 0x00); IP and port are absent.
assign_uncompressed_roundtrip_test() ->
    R = #compression_assign{
        context_id = 6,
        ip_version = 0,
        address = undefined,
        port = undefined
    },
    Body = masque_compression_capsule:encode_assign(R),
    %% Sanity-check the wire shape: starts with the varint-encoded id
    %% (single byte for 6) followed by 0x00 and nothing else.
    ?assertEqual(<<6:8, 0:8>>, Body),
    ?assertEqual(
        {ok, R},
        masque_compression_capsule:decode_assign(Body)
    ).

%% Encoding rejects context_id = 0 (cannot be zero per draft-11).
assign_encode_rejects_zero_id_test() ->
    R = #compression_assign{
        context_id = 0,
        ip_version = 4,
        address = {10, 0, 0, 1},
        port = 1
    },
    ?assertError(_, masque_compression_capsule:encode_assign(R)).

%% Decoding rejects context_id = 0 explicitly.
assign_decode_rejects_zero_id_test() ->
    %% Manually-crafted body with context-id 0, IP version 4.
    Bad = <<0:8, 4:8, 10:8, 0:8, 0:8, 1:8, 1:16>>,
    ?assertEqual(
        {error, zero_context_id},
        masque_compression_capsule:decode_assign(Bad)
    ).

%% Truncated v4 body (missing port).
assign_decode_truncated_v4_test() ->
    Bad = <<2:8, 4:8, 10:8, 0:8, 0:8, 1:8>>,
    ?assertEqual(
        {error, truncated},
        masque_compression_capsule:decode_assign(Bad)
    ).

%% Bad IP version byte.
assign_decode_bad_ip_version_test() ->
    Bad = <<2:8, 9:8>>,
    ?assertEqual(
        {error, bad_ip_version},
        masque_compression_capsule:decode_assign(Bad)
    ).

%% Trailing bytes after a valid uncompressed assign.
assign_decode_trailing_bytes_after_uncompressed_test() ->
    Bad = <<2:8, 0:8, 16#FF:8>>,
    ?assertEqual(
        {error, trailing_bytes},
        masque_compression_capsule:decode_assign(Bad)
    ).

%%====================================================================
%% COMPRESSION_ACK
%%====================================================================

ack_roundtrip_test() ->
    R = #compression_ack{context_id = 8},
    ?assertEqual(
        {ok, R},
        masque_compression_capsule:decode_ack(
            masque_compression_capsule:encode_ack(R)
        )
    ).

ack_decode_rejects_zero_id_test() ->
    ?assertEqual(
        {error, zero_context_id},
        masque_compression_capsule:decode_ack(<<0:8>>)
    ).

ack_decode_trailing_bytes_test() ->
    %% varint id = 1, then a stray byte.
    ?assertEqual(
        {error, trailing_bytes},
        masque_compression_capsule:decode_ack(<<1:8, 0:8>>)
    ).

%%====================================================================
%% COMPRESSION_CLOSE
%%====================================================================

close_roundtrip_test() ->
    R = #compression_close{context_id = 12},
    ?assertEqual(
        {ok, R},
        masque_compression_capsule:decode_close(
            masque_compression_capsule:encode_close(R)
        )
    ).

%% Draft-11: a CLOSE with Context ID 0 is malformed.
close_decode_rejects_zero_id_test() ->
    ?assertEqual(
        {error, zero_context_id},
        masque_compression_capsule:decode_close(<<0:8>>)
    ).

close_decode_trailing_bytes_test() ->
    ?assertEqual(
        {error, trailing_bytes},
        masque_compression_capsule:decode_close(<<7:8, 0:8>>)
    ).

%%====================================================================
%% Capsule-level encode/1 wraps with the matching IANA type code.
%%====================================================================

encode1_assign_uses_assign_type_test() ->
    R = #compression_assign{
        context_id = 2,
        ip_version = 0,
        address = undefined,
        port = undefined
    },
    Bytes = iolist_to_binary(masque_compression_capsule:encode(R)),
    %% First byte is the capsule type varint; for type 0x11 it's a
    %% single-byte 0x11 (single-byte varint).
    ?assertEqual(?MASQUE_CAPSULE_COMPRESSION_ASSIGN, binary:at(Bytes, 0)).

encode1_ack_uses_ack_type_test() ->
    R = #compression_ack{context_id = 2},
    Bytes = iolist_to_binary(masque_compression_capsule:encode(R)),
    ?assertEqual(?MASQUE_CAPSULE_COMPRESSION_ACK, binary:at(Bytes, 0)).

encode1_close_uses_close_type_test() ->
    R = #compression_close{context_id = 2},
    Bytes = iolist_to_binary(masque_compression_capsule:encode(R)),
    ?assertEqual(?MASQUE_CAPSULE_COMPRESSION_CLOSE, binary:at(Bytes, 0)).

%% decode_body/2 dispatches on the IANA capsule type code.
decode_body_dispatches_assign_test() ->
    R = #compression_assign{
        context_id = 2,
        ip_version = 4,
        address = {1, 2, 3, 4},
        port = 5678
    },
    Body = masque_compression_capsule:encode_assign(R),
    ?assertEqual(
        {ok, R},
        masque_compression_capsule:decode_body(
            ?MASQUE_CAPSULE_COMPRESSION_ASSIGN, Body
        )
    ).

decode_body_dispatches_ack_test() ->
    R = #compression_ack{context_id = 3},
    Body = masque_compression_capsule:encode_ack(R),
    ?assertEqual(
        {ok, R},
        masque_compression_capsule:decode_body(
            ?MASQUE_CAPSULE_COMPRESSION_ACK, Body
        )
    ).

decode_body_dispatches_close_test() ->
    R = #compression_close{context_id = 3},
    Body = masque_compression_capsule:encode_close(R),
    ?assertEqual(
        {ok, R},
        masque_compression_capsule:decode_body(
            ?MASQUE_CAPSULE_COMPRESSION_CLOSE, Body
        )
    ).

%% Multi-byte varint Context IDs round-trip too.
assign_large_context_id_test() ->
    %% encoded as a 2-byte varint
    Id = 1234,
    R = #compression_assign{
        context_id = Id,
        ip_version = 4,
        address = {10, 0, 0, 1},
        port = 9999
    },
    ?assertEqual(
        {ok, R},
        masque_compression_capsule:decode_assign(
            masque_compression_capsule:encode_assign(R)
        )
    ).

decode_body_unknown_type_test() ->
    ?assertEqual(
        {error, unknown_capsule_type},
        masque_compression_capsule:decode_body(16#01, <<1>>)
    ).
