-module(masque_ip_datagram_tests).

-include_lib("eunit/include/eunit.hrl").
-include("masque_ip.hrl").

%% RFC 9484 §6 datagram payload format is the same
%% `Context ID (varint) | Payload` shape as RFC 9298, carried by
%% `masque_datagram'. Context ID 0 = full IP packet. These tests
%% pin that mapping so later CONNECT-IP code can rely on it.

encode_context_zero_test() ->
    IPPkt = <<16#45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0,
              192, 0, 2, 1, 192, 0, 2, 2>>,
    Encoded = iolist_to_binary(
                masque_datagram:encode(?MASQUE_CONTEXT_ID_IP, IPPkt)),
    %% Context ID 0 varint is a single zero byte.
    ?assertEqual(<<0, IPPkt/binary>>, Encoded).

decode_context_zero_test() ->
    IPPkt = <<16#60, 0, 0, 0, 0, 8, 0, 0,
              16#FE, 16#80, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 1,
              16#FE, 16#80, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 2>>,
    Frame = <<0, IPPkt/binary>>,
    ?assertEqual({ok, {?MASQUE_CONTEXT_ID_IP, IPPkt}},
                 masque_datagram:decode(Frame)).

roundtrip_context_zero_test() ->
    IPPkt = <<16#45:8, 0:8, 0:16, 0:16, 0:16, 64:8, 1:8, 0:16,
              10:8, 0:8, 0:8, 1:8,
              10:8, 0:8, 0:8, 2:8>>,
    Frame = iolist_to_binary(
              masque_datagram:encode(?MASQUE_CONTEXT_ID_IP, IPPkt)),
    ?assertEqual({ok, {?MASQUE_CONTEXT_ID_IP, IPPkt}},
                 masque_datagram:decode(Frame)).

encode_nonzero_context_roundtrip_test() ->
    %% Non-zero context IDs are permitted in the framing (used by
    %% future extensions). The session layer is responsible for
    %% buffering or dropping unregistered context IDs; the codec
    %% itself is context-agnostic.
    Payload = <<"extension-payload">>,
    Frame = iolist_to_binary(masque_datagram:encode(42, Payload)),
    ?assertEqual({ok, {42, Payload}}, masque_datagram:decode(Frame)).

decode_malformed_varint_test() ->
    ?assertEqual({error, malformed_varint},
                 masque_datagram:decode(<<>>)).
