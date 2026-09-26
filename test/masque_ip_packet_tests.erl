-module(masque_ip_packet_tests).

-include_lib("eunit/include/eunit.hrl").
-include("masque_ip.hrl").

%%====================================================================
%% destination/1
%%====================================================================

destination_v4_test() ->
    Pkt = ipv4_packet(17, {10, 0, 0, 1}, {192, 0, 2, 1}, <<"payload">>),
    ?assertEqual({ok, 4, {192, 0, 2, 1}}, masque_ip_packet:destination(Pkt)).

destination_v6_test() ->
    Pkt = ipv6_packet(
        17,
        {16#FE80, 0, 0, 0, 0, 0, 0, 1},
        {16#2001, 16#DB8, 0, 0, 0, 0, 0, 1},
        <<>>,
        <<"payload">>
    ),
    ?assertEqual(
        {ok, 6, {16#2001, 16#DB8, 0, 0, 0, 0, 0, 1}},
        masque_ip_packet:destination(Pkt)
    ).

destination_malformed_test() ->
    ?assertEqual(
        {error, malformed},
        masque_ip_packet:destination(<<5:4, 0:4>>)
    ).

%%====================================================================
%% upper_protocol/1 — including IPv6 extension header walking
%%====================================================================

upper_protocol_v4_test() ->
    Pkt = ipv4_packet(6, {10, 0, 0, 1}, {192, 0, 2, 1}, <<>>),
    ?assertEqual({ok, 6}, masque_ip_packet:upper_protocol(Pkt)).

upper_protocol_v6_no_ext_test() ->
    Pkt = ipv6_packet(
        17,
        {16#FE80, 0, 0, 0, 0, 0, 0, 1},
        {16#2001, 16#DB8, 0, 0, 0, 0, 0, 1},
        <<>>,
        <<>>
    ),
    ?assertEqual({ok, 17}, masque_ip_packet:upper_protocol(Pkt)).

%% Hop-by-Hop (0) preceding TCP (6).
upper_protocol_v6_hop_by_hop_test() ->
    %% NextHdr=TCP, Hdr_Ext_Len=0, padding
    Hbh = <<6:8, 0:8, 0:48>>,
    Pkt = ipv6_packet(
        0,
        {16#FE80, 0, 0, 0, 0, 0, 0, 1},
        {16#2001, 16#DB8, 0, 0, 0, 0, 0, 1},
        Hbh,
        <<>>
    ),
    ?assertEqual({ok, 6}, masque_ip_packet:upper_protocol(Pkt)).

%% Routing (43) preceding UDP (17).
upper_protocol_v6_routing_test() ->
    Rh = <<17:8, 0:8, 0:48>>,
    Pkt = ipv6_packet(
        43,
        {16#FE80, 0, 0, 0, 0, 0, 0, 1},
        {16#2001, 16#DB8, 0, 0, 0, 0, 0, 1},
        Rh,
        <<>>
    ),
    ?assertEqual({ok, 17}, masque_ip_packet:upper_protocol(Pkt)).

%% Fragment (44) is fixed 8 bytes; preceding UDP.
upper_protocol_v6_fragment_test() ->
    Frag = <<17:8, 0:8, 0:16, 0:32>>,
    Pkt = ipv6_packet(
        44,
        {16#FE80, 0, 0, 0, 0, 0, 0, 1},
        {16#2001, 16#DB8, 0, 0, 0, 0, 0, 1},
        Frag,
        <<>>
    ),
    ?assertEqual({ok, 17}, masque_ip_packet:upper_protocol(Pkt)).

%%====================================================================
%% scope_passes/3
%%====================================================================

scope_passes_wildcard_test() ->
    Pkt = ipv4_packet(17, {10, 0, 0, 1}, {192, 0, 2, 1}, <<>>),
    ?assertEqual(true, masque_ip_packet:scope_passes(Pkt, '*', '*')).

scope_passes_target_match_test() ->
    Pkt = ipv4_packet(17, {10, 0, 0, 1}, {192, 0, 2, 1}, <<>>),
    ?assertEqual(
        true,
        masque_ip_packet:scope_passes(Pkt, {192, 0, 2, 1}, '*')
    ).

scope_passes_target_mismatch_test() ->
    Pkt = ipv4_packet(17, {10, 0, 0, 1}, {192, 0, 2, 1}, <<>>),
    ?assertEqual(
        false,
        masque_ip_packet:scope_passes(Pkt, {198, 51, 100, 1}, '*')
    ).

scope_passes_target_prefix_match_test() ->
    Pkt = ipv4_packet(17, {10, 0, 0, 1}, {192, 0, 2, 128}, <<>>),
    ?assertEqual(
        true,
        masque_ip_packet:scope_passes(
            Pkt, {4, {192, 0, 2, 0}, 24}, '*'
        )
    ).

scope_passes_ipproto_match_test() ->
    Pkt = ipv4_packet(6, {10, 0, 0, 1}, {192, 0, 2, 1}, <<>>),
    ?assertEqual(true, masque_ip_packet:scope_passes(Pkt, '*', 6)).

scope_passes_ipproto_mismatch_test() ->
    Pkt = ipv4_packet(17, {10, 0, 0, 1}, {192, 0, 2, 1}, <<>>),
    ?assertEqual(false, masque_ip_packet:scope_passes(Pkt, '*', 6)).

%% Combined scoping with IPv6 extension header in front of TCP.
scope_passes_v6_with_hbh_test() ->
    Hbh = <<6:8, 0:8, 0:48>>,
    Pkt = ipv6_packet(
        0,
        {16#FE80, 0, 0, 0, 0, 0, 0, 1},
        {16#2001, 16#DB8, 0, 0, 0, 0, 0, 1},
        Hbh,
        <<>>
    ),
    ?assertEqual(
        true,
        masque_ip_packet:scope_passes(
            Pkt, {16#2001, 16#DB8, 0, 0, 0, 0, 0, 1}, 6
        )
    ),
    ?assertEqual(
        false,
        masque_ip_packet:scope_passes(
            Pkt, {16#2001, 16#DB8, 0, 0, 0, 0, 0, 1}, 17
        )
    ).

%% Hostname targets are scoped to the advertised routes.
scope_check_hostname_test() ->
    Pkt = ipv4_packet(17, {10, 0, 0, 1}, {93, 184, 216, 34}, <<>>),
    Route = #ip_route{
        version = 4,
        start_addr = {93, 184, 216, 34},
        end_addr = {93, 184, 216, 34},
        ip_protocol = 0
    },
    ?assertEqual(ok, masque_ip_packet:scope_check(Pkt, <<"example.com">>, '*', [Route])),
    Off = ipv4_packet(17, {10, 0, 0, 1}, {93, 184, 216, 35}, <<>>),
    ?assertEqual(
        {error, scope_target},
        masque_ip_packet:scope_check(Off, <<"example.com">>, '*', [Route])
    ),
    %% Without routes a hostname target matches nothing.
    ?assertEqual(
        {error, scope_target},
        masque_ip_packet:scope_check(Pkt, <<"example.com">>, '*')
    ).

%%====================================================================
%% decrement_ttl/1
%%====================================================================

decrement_ttl_v4_test() ->
    Pkt = with_v4_checksum(ipv4_packet(17, {10, 0, 0, 1}, {192, 0, 2, 1}, <<"x">>)),
    {ok, Out} = masque_ip_packet:decrement_ttl(Pkt),
    <<_:8/binary, TTL:8, _/binary>> = Out,
    ?assertEqual(63, TTL),
    <<Hdr:20/binary, Payload/binary>> = Out,
    ?assertEqual(0, masque_ip_packet:checksum(Hdr)),
    ?assertEqual(<<"x">>, Payload).

decrement_ttl_v4_expired_test() ->
    <<Pre:8/binary, _:8, Rest/binary>> =
        ipv4_packet(17, {10, 0, 0, 1}, {192, 0, 2, 1}, <<>>),
    ?assertEqual({error, ttl_zero}, masque_ip_packet:decrement_ttl(<<Pre/binary, 1, Rest/binary>>)),
    ?assertEqual({error, ttl_zero}, masque_ip_packet:decrement_ttl(<<Pre/binary, 0, Rest/binary>>)).

decrement_ttl_v6_test() ->
    Src = {16#2001, 16#DB8, 0, 0, 0, 0, 0, 1},
    Dst = {16#2001, 16#DB8, 0, 0, 0, 0, 0, 2},
    Pkt = ipv6_packet(17, Src, Dst, <<>>, <<"x">>),
    {ok, Out} = masque_ip_packet:decrement_ttl(Pkt),
    <<Head:7/binary, 63:8, Rest/binary>> = Out,
    <<Head:7/binary, 64:8, Rest/binary>> = Pkt,
    <<Pre:7/binary, _:8, Tail/binary>> = Pkt,
    ?assertEqual({error, ttl_zero}, masque_ip_packet:decrement_ttl(<<Pre/binary, 1, Tail/binary>>)).

decrement_ttl_malformed_test() ->
    ?assertEqual({error, malformed}, masque_ip_packet:decrement_ttl(<<4:4, 5:4, 0:8>>)),
    ?assertEqual({error, malformed}, masque_ip_packet:decrement_ttl(<<>>)).

with_v4_checksum(<<Pre:10/binary, _:16, Rest:8/binary, Payload/binary>>) ->
    Csum = masque_ip_packet:checksum(<<Pre/binary, 0:16, Rest/binary>>),
    <<Pre/binary, Csum:16, Rest/binary, Payload/binary>>.

%%====================================================================
%% Helpers — minimal packet builders, only enough header for the
%% destination address and the protocol byte to be in the right place.
%%====================================================================

ipv4_packet(Proto, {SA, SB, SC, SD}, {DA, DB, DC, DD}, Payload) ->
    IHL = 5,
    Total = (IHL * 4) + byte_size(Payload),
    <<4:4, IHL:4, 0:8, Total:16, 0:16, 0:16, 64:8, Proto:8, 0:16, SA:8, SB:8, SC:8, SD:8, DA:8,
        DB:8, DC:8, DD:8, Payload/binary>>.

ipv6_packet(
    NextHdr,
    {SA, SB, SC, SD, SE, SF, SG, SH},
    {DA, DB, DC, DD, DE, DF, DG, DH},
    Ext,
    Payload
) ->
    Plen = byte_size(Ext) + byte_size(Payload),
    <<6:4, 0:8, 0:20, Plen:16, NextHdr:8, 64:8, SA:16, SB:16, SC:16, SD:16, SE:16, SF:16, SG:16,
        SH:16, DA:16, DB:16, DC:16, DD:16, DE:16, DF:16, DG:16, DH:16, Ext/binary, Payload/binary>>.
