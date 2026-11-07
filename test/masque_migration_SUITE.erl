%%% @doc A real network change under open h3 tunnels.
%%%
%%% Tunnels run through `masque_path_relay', which plays the network: on
%%% a change the old path goes dead and the proxy sees packets from a new
%%% source IP, while `masque:migrate/1' moves the client. Each case checks
%%% the proxy really saw the new address.
%%%
%%% The second address is 127.0.0.2 where the OS routes it (Linux), else a
%%% non-loopback address of this machine. On macOS with neither the suite
%%% is skipped; `sudo ifconfig lo0 alias 127.0.0.2' adds one.
-module(masque_migration_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("masque/include/masque_ip.hrl").

-export([suite/0, all/0, init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    tcp_stream_survives/1,
    tcp_download_survives/1,
    tcp_upload_survives/1,
    tcp_full_duplex_survives/1,
    tcp_outage_then_migrate/1,
    tcp_repeated_changes/1,
    tcp_quiet_after_change/1,
    udp_survives/1,
    ip_survives/1,
    bind_survives/1,
    nat_rebind_same_ip/1,
    nat_rebind_new_ip/1,
    not_supported_elsewhere/1,
    pooled_refused/1
]).
-export([ip_gateway/2]).

-define(BYTES, 16 * 1024 * 1024).
-define(CHUNK, 16 * 1024).
-define(STALL_MS, 45000).
-define(GATEWAY, {10, 202, 0, 254}).
-define(FIRST_IP, {127, 0, 0, 1}).

suite() -> [{timetrap, {minutes, 4}}].

all() ->
    [
        tcp_stream_survives,
        tcp_download_survives,
        tcp_upload_survives,
        tcp_full_duplex_survives,
        tcp_outage_then_migrate,
        tcp_repeated_changes,
        tcp_quiet_after_change,
        udp_survives,
        ip_survives,
        bind_survives,
        nat_rebind_same_ip,
        nat_rebind_new_ip,
        not_supported_elsewhere,
        pooled_refused
    ].

init_per_suite(Config) ->
    case second_ip() of
        none ->
            {skip, "no second local address; sudo ifconfig lo0 alias 127.0.0.2"};
        IP ->
            ct:log("second address ~p", [IP]),
            {ok, _} = application:ensure_all_started(masque),
            {ok, Certs} = masque_test_helpers:generate_certs(),
            {Tcp, TcpPort} = start_tcp_target(),
            {Udp, UdpPort} = start_udp_echo(),
            [
                {second_ip, IP},
                {certs, Certs},
                {tcp, Tcp},
                {tcp_port, TcpPort},
                {udp, Udp},
                {udp_port, UdpPort}
                | Config
            ]
    end.

end_per_suite(Config) ->
    exit(?config(tcp, Config), kill),
    exit(?config(udp, Config), kill),
    masque_test_helpers:cleanup_certs(?config(certs, Config)),
    ok.

init_per_testcase(_Case, Config) ->
    {ok, #{port := Port} = Srv} = masque_test_helpers:start_masque_server(
        (?config(certs, Config))#{
            accept_bind => true,
            address_pool => {4, {10, 202, 0, 0}, 24},
            routes => [
                #ip_route{
                    version = 4,
                    start_addr = {0, 0, 0, 0},
                    end_addr = {255, 255, 255, 255},
                    ip_protocol = 0
                }
            ],
            handler_opts => #{
                allow_private => true,
                allow_self => true,
                bind_address => {127, 0, 0, 1},
                allow_loopback => true,
                forward_fun => fun ?MODULE:ip_gateway/2
            }
        }
    ),
    Relay = masque_path_relay:start(Port),
    [{srv, Srv}, {relay, Relay} | Config].

end_per_testcase(_Case, Config) ->
    masque_path_relay:stop(?config(relay, Config)),
    masque_test_helpers:stop_masque_server(?config(srv, Config)),
    ok.

%%====================================================================
%% CONNECT-TCP
%%====================================================================

tcp_stream_survives(Config) ->
    Sess = connect_tcp(Config),
    ok = send(Sess, <<"echo">>),
    ok = send(Sess, <<"before">>),
    <<"before">> = recv(Sess, 6),
    change_network(Sess, Config),
    ok = send(Sess, <<"after">>),
    <<"after">> = recv(Sess, 5),
    assert_proxy_sees(Config),
    masque:close(Sess).

%% The network changes with data in flight toward the client.
tcp_download_survives(Config) ->
    Sess = connect_tcp(Config),
    ok = send(Sess, <<"down">>),
    Half = recv(Sess, ?BYTES div 2),
    change_network(Sess, Config),
    Rest = recv(Sess, ?BYTES - byte_size(Half)),
    ?assertEqual(sha(payload()), sha(<<Half/binary, Rest/binary>>)),
    assert_proxy_sees(Config),
    masque:close(Sess).

%% The network changes with data in flight toward the target.
tcp_upload_survives(Config) ->
    Sess = connect_tcp(Config),
    ok = send(Sess, <<"sink">>),
    <<First:(?BYTES div 2)/binary, Second/binary>> = payload(),
    ok = send_all(Sess, First),
    change_network(Sess, Config),
    ok = send_all(Sess, Second),
    Sum = sha(payload()),
    ?assertEqual(Sum, recv(Sess, byte_size(Sum))),
    assert_proxy_sees(Config),
    masque:close(Sess).

tcp_full_duplex_survives(Config) ->
    Sess = connect_tcp(Config),
    ok = send(Sess, <<"echo">>),
    {Sender, MRef} = spawn_monitor(fun() -> exit({sent, send_all(Sess, payload())}) end),
    Half = recv(Sess, ?BYTES div 2),
    change_network(Sess, Config),
    Rest = recv(Sess, ?BYTES - byte_size(Half)),
    receive
        {'DOWN', MRef, process, Sender, {sent, ok}} -> ok;
        {'DOWN', MRef, process, Sender, Other} -> ct:fail({sender, Other})
    after ?STALL_MS -> ct:fail(sender_stuck)
    end,
    ?assertEqual(sha(payload()), sha(<<Half/binary, Rest/binary>>)),
    masque:close(Sess).

%% Moving between networks usually means a gap with no network at all.
tcp_outage_then_migrate(Config) ->
    Relay = ?config(relay, Config),
    Sess = connect_tcp(Config),
    ok = send(Sess, <<"down">>),
    Half = recv(Sess, ?BYTES div 2),
    ok = masque_path_relay:network_down(Relay),
    timer:sleep(3000),
    ok = masque_path_relay:network_up(Relay),
    change_network(Sess, Config),
    Rest = recv(Sess, ?BYTES - byte_size(Half)),
    ?assertEqual(sha(payload()), sha(<<Half/binary, Rest/binary>>)),
    masque:close(Sess).

tcp_repeated_changes(Config) ->
    Second = ?config(second_ip, Config),
    Sess = connect_tcp(Config),
    ok = send(Sess, <<"echo">>),
    lists:foreach(
        fun({N, IP}) ->
            change_network(Sess, Config, IP),
            Msg = integer_to_binary(1000 + N),
            ok = send(Sess, Msg),
            Msg = recv(Sess, 4),
            assert_proxy_sees(IP)
        end,
        [{1, Second}, {2, ?FIRST_IP}, {3, Second}, {4, ?FIRST_IP}, {5, Second}]
    ),
    masque:close(Sess).

%% QUIC keepalives must keep working on the new path.
tcp_quiet_after_change(Config) ->
    Sess = connect_tcp(Config),
    ok = send(Sess, <<"echo">>),
    change_network(Sess, Config),
    ok = send(Sess, <<"x">>),
    <<"x">> = recv(Sess, 1),
    receive
        {masque_closed, Sess, Reason} -> ct:fail({closed_while_quiet, Reason})
    after 40000 -> ok
    end,
    ok = send(Sess, <<"y">>),
    <<"y">> = recv(Sess, 1),
    masque:close(Sess).

%%====================================================================
%% Other protocols
%%====================================================================

udp_survives(Config) ->
    Sess = connect(Config, {<<"127.0.0.1">>, ?config(udp_port, Config)}, #{}),
    ok = echo(Sess, <<"before">>, 20),
    change_network(Sess, Config),
    ok = echo(Sess, <<"after">>, 40),
    assert_proxy_sees(Config),
    masque:close(Sess).

ip_survives(Config) ->
    Sess = connect(Config, {'*', '*'}, #{protocol => ip}),
    {ok, [Id]} = masque:request_addresses(Sess, [{4, {0, 0, 0, 0}, 32}]),
    Addr =
        receive
            {masque_address_assign, Sess, [#ip_assignment{request_id = Id, address = A}]} -> A
        after 5000 -> ct:fail(no_address)
        end,
    Packet = ipv4(Addr, ?GATEWAY),
    ok = ip_echo(Sess, Packet, 20),
    change_network(Sess, Config),
    ok = ip_echo(Sess, Packet, 40),
    masque:close(Sess).

bind_survives(Config) ->
    Uri = uri(Config),
    {ok, Sess} = masque:bind_connect(Uri, unscoped, #{
        transports => [h3], verify => verify_none, timeout => 5000
    }),
    {ok, Ctx} = masque:open_uncompressed_context(Sess),
    receive
        {masque_compression_acked, Sess, Ctx} -> ok
    after 5000 -> ct:fail(no_ack)
    end,
    {ok, Peer} = gen_udp:open(0, [binary, {active, false}, {ip, ?FIRST_IP}]),
    {ok, PeerPort} = inet:port(Peer),
    Addr = {?FIRST_IP, PeerPort},
    ok = bind_exchange(Sess, Peer, Addr, <<"before">>),
    change_network(Sess, Config),
    ok = bind_exchange(Sess, Peer, Addr, <<"after">>),
    gen_udp:close(Peer),
    masque:close(Sess).

%%====================================================================
%% The client does not know
%%====================================================================

%% A NAT drops its mapping and picks a new port.
nat_rebind_same_ip(Config) ->
    Relay = ?config(relay, Config),
    Sess = connect_tcp(Config),
    ok = send(Sess, <<"echo">>),
    ok = send(Sess, <<"before">>),
    <<"before">> = recv(Sess, 6),
    ok = masque_path_relay:nat_rebind(Relay, ?FIRST_IP),
    ok = send(Sess, <<"after">>),
    <<"after">> = recv(Sess, 5),
    masque:close(Sess).

%% A carrier NAT moves the client to another public address.
nat_rebind_new_ip(Config) ->
    Relay = ?config(relay, Config),
    Sess = connect_tcp(Config),
    ok = send(Sess, <<"echo">>),
    ok = send(Sess, <<"before">>),
    <<"before">> = recv(Sess, 6),
    ok = masque_path_relay:nat_rebind(Relay, ?config(second_ip, Config)),
    ok = send(Sess, <<"after">>),
    <<"after">> = recv(Sess, 5),
    assert_proxy_sees(Config),
    masque:close(Sess).

%%====================================================================
%% The API
%%====================================================================

not_supported_elsewhere(Config) ->
    #{cert_file := Cert, key_file := Key} = ?config(certs, Config),
    H2 = list_to_atom("mig_h2_" ++ integer_to_list(erlang:unique_integer([positive]))),
    H1 = list_to_atom("mig_h1_" ++ integer_to_list(erlang:unique_integer([positive]))),
    Opts = #{
        port => 0,
        cert => Cert,
        key => Key,
        handler_opts => #{allow_private => true, allow_self => true}
    },
    {ok, {_, _, P2}} = masque:start_listener_h2(H2, Opts),
    {ok, Ref} = masque:start_listener_h1(H1, Opts),
    P1 = h1:server_port(Ref),
    Target = {<<"127.0.0.1">>, ?config(tcp_port, Config)},
    lists:foreach(
        fun({Transport, Port}) ->
            Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
            {ok, Sess} = masque:connect(Uri, Target, #{
                protocol => tcp, transports => [Transport], verify => verify_none
            }),
            ?assertEqual({error, not_supported}, masque:migrate(Sess)),
            masque:close(Sess)
        end,
        [{h2, P2}, {h1, P1}]
    ),
    masque:stop_listener_h2(H2),
    masque:stop_listener_h1(H1).

pooled_refused(Config) ->
    Sess = connect(
        Config,
        {<<"127.0.0.1">>, ?config(tcp_port, Config)},
        #{protocol => tcp, upstream_pool => true}
    ),
    ?assertEqual({error, pooled}, masque:migrate(Sess)),
    masque:close(Sess).

%%====================================================================
%% Network changes
%%====================================================================

change_network(Sess, Config) ->
    change_network(Sess, Config, ?config(second_ip, Config)).

change_network(Sess, Config, IP) ->
    ok = masque_path_relay:change_network(?config(relay, Config), IP),
    migrate(Sess, 100).

%% The proxy issues its spare connection id just after the handshake.
migrate(Sess, 0) ->
    ct:fail({no_spare_connection_id, cid_state(Sess)});
migrate(Sess, N) ->
    case masque:migrate(Sess) of
        ok ->
            ok;
        {error, no_available_connection_id} ->
            timer:sleep(50),
            migrate(Sess, N - 1)
    end.

%% Every QUIC connection's connection-id pools (ours issued, the peer's
%% held), for a failure report.
cid_state(_Sess) ->
    [
        {P, pools(P)}
     || P <- processes(),
        {dictionary, D} <- [process_info(P, dictionary)],
        {_, {quic_connection, init, 1}} <- [lists:keyfind('$initial_call', 1, D)]
    ].

pools(P) ->
    try sys:get_state(P, 1000) of
        {_StateName, Data} ->
            [
                #{
                    local => quic_cid:local_entries(Pool),
                    peer => quic_cid:peer_entries(Pool),
                    peer_active => quic_cid:peer_active_count(Pool)
                }
             || Pool <- tuple_to_list(Data),
                is_tuple(Pool),
                tuple_size(Pool) > 0,
                element(1, Pool) =:= cid_pool_state
            ]
    catch
        _:R -> {unavailable, R}
    end.

%% The proxy's connection really moved to the new address.
assert_proxy_sees(Config) when is_list(Config) ->
    assert_proxy_sees(?config(second_ip, Config));
assert_proxy_sees(IP) ->
    assert_proxy_sees(IP, 100).

assert_proxy_sees(IP, 0) ->
    ct:fail({proxy_never_saw, IP, proxy_peers()});
assert_proxy_sees(IP, N) ->
    case lists:member(IP, proxy_peers()) of
        true ->
            ok;
        false ->
            timer:sleep(50),
            assert_proxy_sees(IP, N - 1)
    end.

proxy_peers() ->
    [
        PeerIP
     || P <- server_sessions(),
        {ok, {PeerIP, _}} <- [quic:peername(quic_h3:get_quic_conn(element(2, sys:get_state(P))))]
    ].

server_sessions() ->
    [
        P
     || P <- processes(),
        {dictionary, Dict} <- [process_info(P, dictionary)],
        {_, {Mod, init, 1}} <- [lists:keyfind('$initial_call', 1, Dict)],
        lists:suffix("server_session", atom_to_list(Mod))
    ].

second_ip() ->
    case bindable({127, 0, 0, 2}) of
        true ->
            {127, 0, 0, 2};
        false ->
            {ok, Ifs} = inet:getifaddrs(),
            Addrs = [
                A
             || {_, Opts} <- Ifs,
                {addr, {_, _, _, _} = A} <- Opts,
                A =/= ?FIRST_IP,
                element(1, A) =/= 169
            ],
            case Addrs of
                [First | _] -> First;
                [] -> none
            end
    end.

bindable(IP) ->
    case gen_udp:open(0, [{ip, IP}]) of
        {ok, S} ->
            gen_udp:close(S),
            true;
        {error, _} ->
            false
    end.

%%====================================================================
%% Clients
%%====================================================================

uri(Config) ->
    Port = masque_path_relay:port(?config(relay, Config)),
    iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]).

connect_tcp(Config) ->
    connect(Config, {<<"127.0.0.1">>, ?config(tcp_port, Config)}, #{protocol => tcp}).

connect(Config, Target, Opts) ->
    {ok, Sess} = masque:connect(uri(Config), Target, Opts#{
        transports => [h3], verify => verify_none, timeout => 5000
    }),
    Sess.

send(Sess, Bytes) ->
    send(Sess, Bytes, 3000).

send(_Sess, _Bytes, 0) ->
    {error, send_stuck};
send(Sess, Bytes, N) ->
    case masque:send(Sess, Bytes) of
        ok ->
            ok;
        {error, send_queue_full} ->
            timer:sleep(10),
            send(Sess, Bytes, N - 1);
        Err ->
            Err
    end.

send_all(_Sess, <<>>) ->
    ok;
send_all(Sess, Bin) ->
    Size = min(?CHUNK, byte_size(Bin)),
    <<Chunk:Size/binary, Rest/binary>> = Bin,
    case send(Sess, Chunk) of
        ok -> send_all(Sess, Rest);
        Err -> Err
    end.

recv(Sess, Want) ->
    recv(Sess, Want, [], 0).

recv(_Sess, Want, Acc, Got) when Got >= Want ->
    iolist_to_binary(lists:reverse(Acc));
recv(Sess, Want, Acc, Got) ->
    receive
        {masque_data, Sess, Bin} -> recv(Sess, Want, [Bin | Acc], Got + byte_size(Bin));
        {masque_closed, Sess, Reason} -> ct:fail({closed, Reason, Got, Want})
    after ?STALL_MS ->
        ct:fail({stalled, Got, Want})
    end.

%% Datagrams may be lost while the path changes, so try a few times.
echo(_Sess, Payload, 0) ->
    ct:fail({no_echo, Payload});
echo(Sess, Payload, N) ->
    _ = masque:send(Sess, Payload),
    receive
        {masque_data, Sess, Payload} -> ok;
        {masque_closed, Sess, Reason} -> ct:fail({closed, Reason})
    after 250 -> echo(Sess, Payload, N - 1)
    end.

ip_echo(_Sess, _Packet, 0) ->
    ct:fail(no_ip_echo);
ip_echo(Sess, Packet, N) ->
    _ = masque:send_ip_packet(Sess, Packet),
    receive
        {masque_ip_packet, Sess, _} -> ok;
        {masque_closed, Sess, Reason} -> ct:fail({closed, Reason})
    after 250 -> ip_echo(Sess, Packet, N - 1)
    end.

bind_exchange(Sess, Peer, Addr, Msg) ->
    bind_exchange(Sess, Peer, Addr, Msg, 40).

bind_exchange(_Sess, _Peer, _Addr, Msg, 0) ->
    ct:fail({no_bind_exchange, Msg});
bind_exchange(Sess, Peer, Addr, Msg, N) ->
    _ = masque:send_to(Sess, Addr, Msg),
    case gen_udp:recv(Peer, 0, 250) of
        {ok, {IP, Port, Msg}} ->
            ok = gen_udp:send(Peer, IP, Port, <<Msg/binary, "-back">>),
            Back = <<Msg/binary, "-back">>,
            receive
                {masque_bind_packet, Sess, Addr, Back} -> ok
            after 1000 -> bind_exchange(Sess, Peer, Addr, Msg, N - 1)
            end;
        {error, timeout} ->
            bind_exchange(Sess, Peer, Addr, Msg, N - 1)
    end.

payload() ->
    binary:copy(<<"0123456789abcdef">>, ?BYTES div 16).

sha(Bin) -> crypto:hash(sha256, Bin).

ip_gateway(Packet, State) ->
    {reply, Packet, State}.

ipv4({A, B, C, D}, {E, F, G, H}) ->
    Body = <<"ping">>,
    Total = 20 + byte_size(Body),
    H0 = <<4:4, 5:4, 0, Total:16, 0:16, 0:16, 64, 17, 0:16, A, B, C, D, E, F, G, H>>,
    Sum = masque_ip_packet:checksum(H0),
    <<Before:10/binary, 0:16, After/binary>> = H0,
    <<Before/binary, Sum:16, After/binary, Body/binary>>.

%%====================================================================
%% Targets
%%====================================================================

start_tcp_target() ->
    {ok, Listen} = gen_tcp:listen(0, [
        binary, {active, false}, {ip, ?FIRST_IP}, {reuseaddr, true}, {exit_on_close, false}
    ]),
    {ok, Port} = inet:port(Listen),
    Pid = spawn(fun() -> tcp_accept(Listen) end),
    ok = gen_tcp:controlling_process(Listen, Pid),
    {Pid, Port}.

tcp_accept(Listen) ->
    {ok, Sock} = gen_tcp:accept(Listen),
    Pid = spawn(fun() ->
        receive
            go -> tcp_mode(Sock)
        end
    end),
    _ = gen_tcp:controlling_process(Sock, Pid),
    Pid ! go,
    tcp_accept(Listen).

tcp_mode(Sock) ->
    case gen_tcp:recv(Sock, 4) of
        {ok, <<"echo">>} ->
            tcp_echo(Sock);
        {ok, <<"down">>} ->
            _ = gen_tcp:send(Sock, payload()),
            tcp_hold(Sock);
        {ok, <<"sink">>} ->
            {ok, Bin} = gen_tcp:recv(Sock, ?BYTES),
            _ = gen_tcp:send(Sock, sha(Bin)),
            tcp_hold(Sock);
        {error, _} ->
            gen_tcp:close(Sock)
    end.

tcp_echo(Sock) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, Bin} ->
            _ = gen_tcp:send(Sock, Bin),
            tcp_echo(Sock);
        {error, _} ->
            gen_tcp:close(Sock)
    end.

tcp_hold(Sock) ->
    _ = gen_tcp:recv(Sock, 0),
    gen_tcp:close(Sock).

start_udp_echo() ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}, {ip, ?FIRST_IP}]),
    {ok, Port} = inet:port(Sock),
    Pid = spawn(fun() -> udp_echo(Sock) end),
    ok = gen_udp:controlling_process(Sock, Pid),
    {Pid, Port}.

udp_echo(Sock) ->
    case gen_udp:recv(Sock, 0) of
        {ok, {IP, Port, Data}} ->
            _ = gen_udp:send(Sock, IP, Port, Data),
            udp_echo(Sock);
        {error, _} ->
            ok
    end.
