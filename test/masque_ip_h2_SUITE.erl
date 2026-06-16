%%% @doc End-to-end HTTP/2 loopback tests for CONNECT-IP (RFC 9484).
%%%
%%% On H2 the datagram channel is RFC 9297 DATAGRAM-type capsules on
%%% the stream body; the transport-generic `masque_ip_client_session'
%%% and `masque_ip_server_session' dispatch accordingly. This suite
%%% mirrors `masque_ip_h3_SUITE' against an H2 listener.
-module(masque_ip_h2_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("masque_ip.hrl").

-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([
    connect_and_close/1,
    roundtrip_ipv4_packet/1,
    request_addresses_reject_all/1
]).

all() ->
    [
        connect_and_close,
        roundtrip_ipv4_packet,
        request_addresses_reject_all
    ].

init_per_suite(Config) ->
    application:ensure_all_started(h2),
    application:ensure_all_started(masque),
    {ok, Ctx} = masque_test_helpers:generate_certs(),
    [{ctx, Ctx} | Config].

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(ctx, Config)),
    ok.

init_per_testcase(_Case, Config) ->
    Ctx = ?config(ctx, Config),
    Listener = list_to_atom(
        "ip_h2_" ++
            integer_to_list(
                erlang:unique_integer([positive])
            )
    ),
    Self = self(),
    Opts = #{
        port => 0,
        cert => maps:get(cert_file, Ctx),
        key => maps:get(key_file, Ctx),
        ip_handler => masque_ip_echo_handler,
        handler_opts => #{ping => Self}
    },
    {ok, Ref} = masque_h2_server:start_listener(Listener, Opts),
    {_, _, Port} = Ref,
    [{listener, Listener}, {port, Port}, {h2_ref, Ref} | Config].

end_per_testcase(_Case, Config) ->
    _ = masque_h2_server:stop_listener(?config(h2_ref, Config)),
    ok.

%%====================================================================
%% Cases
%%====================================================================

connect_and_close(Config) ->
    Port = ?config(port, Config),
    {ok, Sess} = do_connect(Port),
    ?assertMatch(
        #{transport := h2, protocol := ip},
        masque:info(Sess)
    ),
    ok = masque:close(Sess).

roundtrip_ipv4_packet(Config) ->
    Port = ?config(port, Config),
    {ok, Sess} = do_connect(Port),
    %% Confirm handler init fired.
    receive
        {echo_handler, {init, _}} -> ok
    after 2000 -> ct:fail("handler init never ran")
    end,
    Packet = sample_ipv4_icmp(),
    ok = masque:send_ip_packet(Sess, Packet),
    receive
        {echo_handler, {ip_packet, Sz}} ->
            ?assertEqual(byte_size(Packet), Sz)
    after 2000 -> ct:fail("handler never saw ip packet")
    end,
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
    {ok, [Id]} = masque:request_addresses(
        Sess,
        [{6, {16#2001, 16#DB8, 0, 0, 0, 0, 0, 1}, 128}]
    ),
    ?assert(is_integer(Id) andalso Id > 0),
    receive
        {masque_address_assign, Sess, [Assign]} ->
            ?assertMatch(
                #ip_assignment{
                    request_id = Id,
                    version = 6,
                    address = {0, 0, 0, 0, 0, 0, 0, 0},
                    prefix_len = 128
                },
                Assign
            )
    after 2000 ->
        ct:fail("no ADDRESS_ASSIGN reply within 2s")
    end,
    ok = masque:close(Sess).

%%====================================================================
%% Internal
%%====================================================================

do_connect(Port) ->
    Url = iolist_to_binary(
        ["https://127.0.0.1:", integer_to_binary(Port)]
    ),
    masque:connect(
        Url,
        {'*', '*'},
        #{
            protocol => ip,
            transports => [h2],
            verify => verify_none
        }
    ).

sample_ipv4_icmp() ->
    IPHdr =
        <<16#45:8, 0:8, 28:16, 0:16, 0:16, 64:8, 1:8, 0:16, 192:8, 0:8, 2:8, 1:8, 192:8, 0:8, 2:8,
            2:8>>,
    Icmp0 = <<8:8, 0:8, 0:16, 1:16, 1:16>>,
    Csum = inet_checksum(Icmp0),
    Icmp = <<8:8, 0:8, Csum:16, 1:16, 1:16>>,
    <<IPHdr/binary, Icmp/binary>>.

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
