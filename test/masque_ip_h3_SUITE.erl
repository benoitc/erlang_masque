%%% @doc End-to-end HTTP/3 loopback tests for CONNECT-IP (RFC 9484).
%%%
%%% Spins up a masque listener with `masque_ip_echo_handler' and drives
%%% `masque:connect/3' against it over `quic_h3'. Covers the 2xx
%%% handshake, a data-plane IPv4 round-trip, and the ADDRESS_REQUEST
%%% flow (reject-all pattern via the echo handler).
-module(masque_ip_h3_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("masque_ip.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1,
         init_per_testcase/2, end_per_testcase/2]).

-export([connect_and_close/1,
         roundtrip_ipv4_packet/1,
         request_addresses_reject_all/1]).

all() ->
    [connect_and_close,
     roundtrip_ipv4_packet,
     request_addresses_reject_all].

init_per_suite(Config) ->
    application:ensure_all_started(quic),
    application:ensure_all_started(masque),
    {ok, Ctx} = masque_test_helpers:generate_certs(),
    [{ctx, Ctx} | Config].

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(ctx, Config)),
    ok.

init_per_testcase(_Case, Config) ->
    Ctx = ?config(ctx, Config),
    Listener = list_to_atom(
                 "ip_h3_" ++ integer_to_list(
                               erlang:unique_integer([positive]))),
    {ok, _} = masque:start_listener(Listener, #{
        port => 0,
        cert => maps:get(cert, Ctx),
        key  => maps:get(key, Ctx),
        ip_handler => masque_ip_echo_handler
    }),
    {ok, Port} = quic:get_server_port(Listener),
    [{listener, Listener}, {port, Port} | Config].

end_per_testcase(_Case, Config) ->
    _ = masque:stop_listener(?config(listener, Config)),
    ok.

%%====================================================================
%% Cases
%%====================================================================

connect_and_close(Config) ->
    Port = ?config(port, Config),
    {ok, Sess} = do_connect(Port),
    ?assertMatch(#{transport := h3, protocol := ip},
                 masque:info(Sess)),
    ok = masque:close(Sess).

roundtrip_ipv4_packet(Config) ->
    Port = ?config(port, Config),
    {ok, Sess} = do_connect(Port),
    %% Minimal well-formed IPv4 ICMP echo request (84 bytes incl. 20 B
    %% IP header + 8 B ICMP header + 56 B payload).
    Packet = sample_ipv4_icmp(),
    ok = masque:send_ip_packet(Sess, Packet),
    receive
        {masque_ip_packet, Sess, Got} ->
            ?assertEqual(Packet, Got)
    after 2000 ->
            ct:fail("no ip packet echo within 2s")
    end,
    ok = masque:close(Sess).

request_addresses_reject_all(Config) ->
    Port = ?config(port, Config),
    {ok, Sess} = do_connect(Port),
    {ok, [Id]} = masque:request_addresses(Sess,
                   [{4, {10,0,0,1}, 32}]),
    ?assert(is_integer(Id) andalso Id > 0),
    receive
        {masque_address_assign, Sess, [Assign]} ->
            %% Reject-all sugar replies with the all-zero + max-prefix
            %% entry for the same Request ID (RFC 9484 §5.2).
            ?assertMatch(#ip_assignment{request_id = Id,
                                        version = 4,
                                        address = {0,0,0,0},
                                        prefix_len = 32},
                         Assign)
    after 2000 ->
            ct:fail("no ADDRESS_ASSIGN reply within 2s")
    end,
    ok = masque:close(Sess).

%%====================================================================
%% Internal
%%====================================================================

do_connect(Port) ->
    Url = iolist_to_binary(
            ["https://127.0.0.1:", integer_to_binary(Port)]),
    masque:connect(Url, {'*', '*'},
                   #{protocol => ip,
                     transports => [h3],
                     verify => verify_none}).

%% ICMPv4 Echo Request from 192.0.2.1 to 192.0.2.2, minimal payload.
sample_ipv4_icmp() ->
    TotalLen = 28,
    IPHdr = <<16#45:8, 0:8, TotalLen:16,
              0:16, 0:16, 64:8, 1:8, 0:16,
              192:8, 0:8, 2:8, 1:8,
              192:8, 0:8, 2:8, 2:8>>,
    %% ICMP Echo Request (type=8) with id=1, seq=1, no payload.
    Icmp0 = <<8:8, 0:8, 0:16, 1:16, 1:16>>,
    Csum = inet_checksum(Icmp0),
    Icmp = <<8:8, 0:8, Csum:16, 1:16, 1:16>>,
    <<IPHdr/binary, Icmp/binary>>.

%% 16-bit one's complement Internet checksum.
inet_checksum(Bin) ->
    inet_checksum(Bin, 0).
inet_checksum(<<A:16, Rest/binary>>, Acc) ->
    inet_checksum(Rest, Acc + A);
inet_checksum(<<A:8>>, Acc) ->
    finish_checksum(Acc + (A bsl 8));
inet_checksum(<<>>, Acc) ->
    finish_checksum(Acc).

finish_checksum(Sum) ->
    S = (Sum band 16#FFFF) + (Sum bsr 16),
    (bnot S) band 16#FFFF.
