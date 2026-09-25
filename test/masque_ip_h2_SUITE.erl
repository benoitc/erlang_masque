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
    request_addresses_reject_all/1,
    race_delivers_early_address_assign/1,
    deferred_owner_gets_early_address_assign/1
]).

all() ->
    [
        connect_and_close,
        roundtrip_ipv4_packet,
        request_addresses_reject_all,
        race_delivers_early_address_assign,
        deferred_owner_gets_early_address_assign
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

%% The proxy sends ADDRESS_ASSIGN right after the 2xx. Through a
%% two-transport race the session belongs to a race worker at that
%% point; the assignment must still reach the caller.
race_delivers_early_address_assign(Config) ->
    {Ref, Port} = start_assign_on_init_listener(Config),
    try
        Url = iolist_to_binary(["https://127.0.0.1:", integer_to_binary(Port)]),
        {ok, Sess} = masque:connect(
            Url,
            {'*', '*'},
            #{
                protocol => ip,
                transports => [h2, h1],
                prefer_timeout_ms => 1000,
                verify => verify_none
            }
        ),
        receive
            {masque_address_assign, Sess, [Assign]} ->
                ?assertEqual({10, 77, 0, 1}, Assign#ip_assignment.address)
        after 2000 ->
            ct:fail(address_assign_lost)
        end,
        ok = masque:close(Sess)
    after
        _ = masque_h2_server:stop_listener(Ref)
    end.

%% Same event, made deterministic: a session started the way the
%% racer starts it holds the ADDRESS_ASSIGN that arrives before
%% `set_owner' and hands it to the new owner.
deferred_owner_gets_early_address_assign(Config) ->
    {Ref, Port} = start_assign_on_init_listener(Config),
    Holder = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    try
        {ok, Sess} = masque_ip_client_session:start(
            {'*', '*'},
            #{
                proxy => {<<"127.0.0.1">>, Port},
                transport => h2,
                capsule_protocol => true,
                verify => verify_none,
                defer_owner => true
            },
            Holder
        ),
        ok = gen_statem:call(Sess, handshake_await, 5000),
        timer:sleep(300),
        {messages, Held} = erlang:process_info(Holder, messages),
        ?assertEqual([], Held),
        ok = gen_statem:call(Sess, {set_owner, self()}),
        receive
            {masque_address_assign, Sess, [Assign]} ->
                ?assertEqual({10, 77, 0, 1}, Assign#ip_assignment.address)
        after 2000 ->
            ct:fail(address_assign_lost)
        end,
        ok = masque:close(Sess)
    after
        Holder ! stop,
        _ = masque_h2_server:stop_listener(Ref)
    end.

%%====================================================================
%% Internal
%%====================================================================

start_assign_on_init_listener(Config) ->
    Ctx = ?config(ctx, Config),
    Name = list_to_atom(
        "ip_h2_assign_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),
    {ok, Ref} = masque_h2_server:start_listener(Name, #{
        port => 0,
        cert => maps:get(cert_file, Ctx),
        key => maps:get(key_file, Ctx),
        ip_handler => masque_ip_unprompted_handler,
        handler_opts => #{assign_on_init => true}
    }),
    {_, _, Port} = Ref,
    {Ref, Port}.

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
