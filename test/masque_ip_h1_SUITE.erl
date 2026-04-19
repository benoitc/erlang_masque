%%% @doc End-to-end HTTP/1.1 loopback tests for CONNECT-IP (RFC 9484).
%%%
%%% On h1 the handshake is `GET' + `Upgrade: connect-ip'; after 101
%%% the raw TLS socket carries RFC 9297 capsules. IP packets ride the
%%% DATAGRAM capsule; ADDRESS_* / ROUTE_ADVERTISEMENT are RFC 9484
%%% control capsules. Mirrors `masque_ip_h2_SUITE' against an h1
%%% listener.
-module(masque_ip_h1_SUITE).

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
    {ok, _} = application:ensure_all_started(masque),
    {ok, Ctx} = masque_test_helpers:generate_certs(),
    [{ctx, Ctx} | Config].

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(ctx, Config)),
    ok.

init_per_testcase(_Case, Config) ->
    Ctx = ?config(ctx, Config),
    Listener = list_to_atom(
                 "ip_h1_" ++ integer_to_list(
                               erlang:unique_integer([positive]))),
    Self = self(),
    Opts = #{port => 0,
             cert => maps:get(cert_file, Ctx),
             key  => maps:get(key_file, Ctx),
             ip_handler => masque_ip_echo_handler,
             handler_opts => #{ping => Self}},
    %% Host the listener in a keeper so the ssl listen socket outlives
    %% the init_per_testcase frame.
    Parent = self(),
    Keeper = erlang:spawn(fun() -> keeper_loop(Parent, Listener, Opts) end),
    Port = receive
        {Keeper, started, P} -> P
    after 5000 ->
        ct:fail(keeper_start_timeout)
    end,
    [{listener, Listener}, {port, Port}, {keeper, Keeper} | Config].

end_per_testcase(_Case, Config) ->
    ?config(keeper, Config) ! stop,
    ok.

keeper_loop(Parent, Name, Opts) ->
    case masque:start_listener_h1(Name, Opts) of
        {ok, Ref} ->
            Parent ! {self(), started, h1:server_port(Ref)},
            keeper_wait(Name);
        {error, Reason} ->
            Parent ! {self(), start_failed, Reason}
    end.

keeper_wait(Name) ->
    receive
        stop -> _ = masque:stop_listener_h1(Name), ok;
        _    -> keeper_wait(Name)
    end.

%%====================================================================
%% Cases
%%====================================================================

connect_and_close(Config) ->
    Port = ?config(port, Config),
    {ok, Sess} = do_connect(Port),
    ?assertMatch(#{transport := h1, protocol := ip},
                 masque:info(Sess)),
    ok = masque:close(Sess).

roundtrip_ipv4_packet(Config) ->
    Port = ?config(port, Config),
    {ok, Sess} = do_connect(Port),
    receive {echo_handler, {init, _}} -> ok
    after 2000 -> ct:fail("handler init never ran") end,
    Packet = sample_ipv4_icmp(),
    ok = masque:send_ip_packet(Sess, Packet),
    receive {echo_handler, {ip_packet, Sz}} ->
        ?assertEqual(byte_size(Packet), Sz)
    after 2000 -> ct:fail("handler never saw ip packet") end,
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
                   [{6, {16#2001,16#DB8,0,0,0,0,0,1}, 128}]),
    ?assert(is_integer(Id) andalso Id > 0),
    receive
        {masque_address_assign, Sess, [Assign]} ->
            ?assertMatch(#ip_assignment{request_id = Id,
                                        version = 6,
                                        address = {0,0,0,0,0,0,0,0},
                                        prefix_len = 128},
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
                   #{protocol   => ip,
                     transports => [h1],
                     verify     => verify_none,
                     ssl_opts   => [{verify, verify_none}]}).

sample_ipv4_icmp() ->
    IPHdr = <<16#45:8, 0:8, 28:16, 0:16, 0:16, 64:8, 1:8, 0:16,
              192:8, 0:8, 2:8, 1:8,
              192:8, 0:8, 2:8, 2:8>>,
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
