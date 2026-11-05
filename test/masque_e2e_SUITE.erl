%%% @doc End-to-end tests: real sockets through real listeners.
%%%
%%% Every case runs a real `gen_tcp' or `gen_udp' target behind a real
%%% listener and checks what reaches the far side, over h3, h2 and h1.
-module(masque_e2e_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("masque/include/masque_ip.hrl").

-export([suite/0, all/0, groups/0]).
-export([init_per_suite/1, end_per_suite/1, init_per_group/2, end_per_group/2]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    tcp_download/1,
    tcp_upload/1,
    tcp_full_duplex/1,
    tcp_full_duplex_large/1,
    tcp_stalled_target/1,
    tcp_quiet_tunnel/1,
    h3_client_vanishes/1,
    h1_udp_stalled_client/1,
    tcp_first_bytes_survive_handover/1,
    tcp_half_close_client/1,
    tcp_half_close_target/1,
    tcp_target_reset/1,
    tcp_client_close_reaches_target/1,
    tcp_concurrent_tunnels/1,
    tcp_stalled_client/1,
    udp_echo_sizes/1,
    udp_oversize_refused/1,
    udp_burst/1,
    h3_udp_quiet_tunnel/1,
    bind_two_peers/1,
    bind_compressed_peer/1,
    bind_peer_filter/1,
    ip_gateway_echo/1,
    ip_two_clients/1,
    chain_tcp_full_duplex/1,
    chain_tcp_upload/1,
    chain_tcp_upload_large/1,
    chain_udp_echo/1,
    chain_ip_echo/1,
    stop_listener_with_open_tunnels/1,
    owner_crash_cleans_up/1,
    goaway_keeps_open_tunnel/1,
    h3_goaway_transfer_continues/1,
    h2_goaway_tells_client/1,
    goaway_refuses_new_requests/1,
    goaway_pool_moves_on/1
]).
%% Called through a fun in `handler_opts'.
-export([ip_router/2]).

-define(TRANSFER_BYTES, 16 * 1024 * 1024).
-define(LARGE_BYTES, 64 * 1024 * 1024).
-define(CHUNK_BYTES, 16 * 1024).
%% Window and socket messages a session may hold, plus some margin.
-define(MAX_MAILBOX, 2000).
%% Longer than the 30 s tunnel write timeouts, so a stall is reported
%% by the test and not by the transport.
-define(STALL_MS, 45000).
%% Past QUIC's 30 s default idle timeout.
-define(QUIET_MS, 40000).
%% A keepalive ping after 15 s restarts QUIC's 30 s idle timer once, so
%% the proxy gives up after 45 s, plus teardown.
-define(VANISH_MS, 70000).
%% Field `conn' of the h3 client session records.
-define(H3_CONN_ELEMENT, 10).
-define(LEAK_MS, 10000).
-define(IP_GATEWAY, {10, 200, 0, 254}).
%% The target reports to the running test case under this name.
-define(PROBE, masque_e2e_probe).
-define(CONCURRENT_TUNNELS, 50).
-define(HANDOVER_ROUNDS, 20).
-define(H1_HANDOVER_WAIT_MS, 50).
-define(CONCURRENT_BYTES, 256 * 1024).

suite() -> [{timetrap, {minutes, 5}}].

all() ->
    [{group, h3}, {group, h2}, {group, h1}].

groups() ->
    Tcp = [
        tcp_download,
        tcp_upload,
        tcp_full_duplex,
        tcp_full_duplex_large,
        tcp_stalled_target,
        tcp_quiet_tunnel,
        tcp_target_reset,
        tcp_client_close_reaches_target,
        tcp_concurrent_tunnels,
        tcp_stalled_client,
        tcp_first_bytes_survive_handover
    ],
    HalfClose = [tcp_half_close_client, tcp_half_close_target],
    GoAway = [goaway_keeps_open_tunnel, goaway_refuses_new_requests, goaway_pool_moves_on],
    Other = [
        udp_echo_sizes,
        udp_oversize_refused,
        udp_burst,
        bind_two_peers,
        bind_compressed_peer,
        bind_peer_filter,
        ip_gateway_echo,
        ip_two_clients,
        chain_tcp_full_duplex,
        chain_tcp_upload,
        chain_tcp_upload_large,
        chain_udp_echo,
        chain_ip_echo,
        stop_listener_with_open_tunnels,
        owner_crash_cleans_up
    ],
    [
        {h3, [],
            Tcp ++ HalfClose ++ Other ++
                [
                    h3_client_vanishes,
                    h3_udp_quiet_tunnel,
                    h3_goaway_transfer_continues
                    | GoAway
                ]},
        {h2, [], Tcp ++ HalfClose ++ Other ++ [h2_goaway_tells_client | GoAway]},
        {h1, [], Tcp ++ Other ++ [h1_udp_stalled_client]}
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Certs} = masque_test_helpers:generate_certs(),
    {ok, Listen} = gen_tcp:listen(0, [
        binary,
        {active, false},
        {ip, {127, 0, 0, 1}},
        {reuseaddr, true},
        {backlog, 128},
        {exit_on_close, false}
    ]),
    {ok, TargetPort} = inet:port(Listen),
    Target = spawn(fun() -> target_accept(Listen) end),
    ok = gen_tcp:controlling_process(Listen, Target),
    {UdpEcho, UdpPort} = start_udp_echo(),
    [
        {certs, Certs},
        {target_port, TargetPort},
        {target, Target},
        {udp_echo, UdpEcho},
        {udp_port, UdpPort}
        | Config
    ].

end_per_suite(Config) ->
    exit(?config(target, Config), kill),
    exit(?config(udp_echo, Config), kill),
    masque_test_helpers:cleanup_certs(?config(certs, Config)),
    ok.

init_per_group(Transport, Config) ->
    [{transport, Transport} | Config].

end_per_group(_Transport, _Config) ->
    ok.

%% Listeners link to the process that starts them, and a group's init
%% process exits at once, so each case starts its own.
init_per_testcase(Case, Config) ->
    true = register(?PROBE, self()),
    Transport = ?config(transport, Config),
    Certs = ?config(certs, Config),
    Server = start_server(Transport, Certs, case_opts(Case)),
    [{server, Server} | Config].

case_opts(bind_peer_filter) ->
    #{accept_bind => true, handler_opts => #{bind_address => {127, 0, 0, 1}}};
case_opts(_) ->
    #{}.

%% Every case must leave no session behind, whatever else it checks.
end_per_testcase(_Case, Config) ->
    try
        unregister(?PROBE)
    catch
        error:badarg -> ok
    end,
    Left = wait_no_server_sessions(?LEAK_MS),
    Detail = [{session_module(P), sys:get_state(P)} || P <- Left],
    stop_server(?config(transport, Config), ?config(server, Config)),
    case Left of
        [] -> ok;
        _ -> {fail, {sessions_left_behind, Detail}}
    end.

wait_no_server_sessions(Left) when Left =< 0 ->
    server_sessions();
wait_no_server_sessions(Left) ->
    case server_sessions() of
        [] ->
            [];
        _ ->
            timer:sleep(200),
            wait_no_server_sessions(Left - 200)
    end.

%%====================================================================
%% CONNECT-TCP
%%====================================================================

tcp_download(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"down">>),
    Got = recv_bytes(Sess, ?TRANSFER_BYTES),
    ?assertEqual(sha(payload()), sha(Got)),
    close(Sess).

tcp_upload(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"sink">>),
    ok = send_all(Sess, payload()),
    Sum = sha(payload()),
    ?assertEqual(Sum, recv_bytes(Sess, byte_size(Sum))),
    close(Sess).

%% The target sends everything back on one thread while the client is
%% still sending, as an echo service or a busy bidirectional protocol
%% does. Neither direction may wait for the other to finish.
tcp_full_duplex(Config) ->
    full_duplex(Config, payload()).

tcp_full_duplex_large(Config) ->
    full_duplex(Config, binary:copy(<<"0123456789abcdef">>, ?LARGE_BYTES div 16)).

full_duplex(Config, Payload) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"echo">>),
    {Sender, MRef} = spawn_monitor(fun() -> exit({sent, send_all(Sess, Payload)}) end),
    Got = recv_bytes(Sess, byte_size(Payload)),
    receive
        {'DOWN', MRef, process, Sender, {sent, ok}} -> ok;
        {'DOWN', MRef, process, Sender, Other} -> ct:fail({sender, Other})
    after ?STALL_MS -> ct:fail(sender_stuck)
    end,
    ?assertEqual(sha(Payload), sha(Got)),
    close(Sess).

%% A target that stops reading ends the tunnel within the write timeout
%% and the proxy holds a bounded amount in the meantime.
tcp_stalled_target(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"stal">>),
    {Sender, MRef} = spawn_monitor(fun() ->
        try send_all(Sess, binary:copy(payload(), 8)) of
            R -> exit(R)
        catch
            exit:R -> exit(R)
        end
    end),
    timer:sleep(5000),
    Peak = max_session_mailbox(),
    ?assert(Peak < ?MAX_MAILBOX),
    receive
        {masque_closed, Sess, _Reason} -> ok
    after ?STALL_MS -> ct:fail({tunnel_not_ended, tunnel_stacks()})
    end,
    exit(Sender, kill),
    receive
        {'DOWN', MRef, process, Sender, _} -> ok
    end,
    close(Sess).

%% A tunnel with no traffic stays open until the 300 s session idle
%% timeout, so a quiet SSH or database connection is not cut.
tcp_quiet_tunnel(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"echo">>),
    ok = masque:send(Sess, <<"before">>),
    <<"before">> = recv_bytes(Sess, 6),
    receive
        {masque_closed, Sess, Reason} -> ct:fail({closed_while_quiet, Reason})
    after ?QUIET_MS -> ok
    end,
    ok = masque:send(Sess, <<"after">>),
    <<"after">> = recv_bytes(Sess, 5),
    close(Sess).

%% Keepalive must not hide a client that disappears without a word:
%% no CONNECTION_CLOSE reaches the proxy, and its pings go unanswered.
h3_client_vanishes(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"echo">>),
    ok = masque:send(Sess, <<"x">>),
    <<"x">> = recv_bytes(Sess, 1),
    {_, Data} = sys:get_state(Sess),
    QConn = quic_h3:get_quic_conn(element(?H3_CONN_ELEMENT, Data)),
    ?assertMatch([_ | _], server_sessions()),
    exit(Sess, kill),
    exit(QConn, kill),
    await_no_server_sessions(?VANISH_MS).

await_no_server_sessions(Left) when Left =< 0 ->
    ct:fail({server_session_left_behind, server_sessions()});
await_no_server_sessions(Left) ->
    case server_sessions() of
        [] ->
            ok;
        _ ->
            timer:sleep(500),
            await_no_server_sessions(Left - 500)
    end.

server_sessions() ->
    [
        P
     || P <- processes(),
        Mod <- session_module(P),
        lists:suffix("server_session", atom_to_list(Mod))
    ].

%% FIN from the client leaves the path back open.
tcp_half_close_client(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"gath">>),
    ok = send_all(Sess, payload()),
    ok = masque:shutdown_write(Sess),
    Sum = sha(payload()),
    ?assertEqual(Sum, recv_bytes(Sess, byte_size(Sum))),
    close(Sess).

%% FIN from the target leaves the client's path open.
tcp_half_close_target(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"fin1">>),
    <<"bye">> = recv_bytes(Sess, 3),
    receive
        {masque_closed, Sess, peer_fin} -> ok
    after 5000 -> ct:fail(no_peer_fin)
    end,
    ok = masque:send(Sess, <<"late">>),
    receive
        {target, got, <<"late">>} -> ok
    after 5000 -> ct:fail(late_bytes_lost)
    end,
    close(Sess).

%% A target reset is not reported as a clean end.
tcp_target_reset(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"rset">>),
    <<"x">> = recv_bytes(Sess, 1),
    Expected =
        case ?config(transport, Config) of
            h1 -> peer_closed;
            _ -> peer_reset
        end,
    receive
        {masque_closed, Sess, Reason} -> ?assertEqual(Expected, Reason)
    after 5000 -> ct:fail(no_close_after_reset)
    end.

tcp_client_close_reaches_target(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"wclo">>),
    <<"x">> = recv_bytes(Sess, 1),
    close(Sess),
    receive
        {target, closed, Reason} -> ct:log("target saw ~p", [Reason])
    after 5000 -> ct:fail(target_not_told)
    end,
    await_no_server_sessions(5000).

%% Bytes sent the moment the tunnel opens must reach the target, under
%% enough load to expose a race in handing the socket to the session.
tcp_first_bytes_survive_handover(Config) ->
    case ?config(transport, Config) of
        h1 -> {skip, "erlang_h1 loses bytes that race the socket handover; needs its fix"};
        _ -> first_bytes_rounds(Config)
    end.

first_bytes_rounds(Config) ->
    Parent = self(),
    Pids = [
        spawn_link(fun() ->
            [first_bytes_round(Config) || _ <- lists:seq(1, ?HANDOVER_ROUNDS)],
            Parent ! {done, self()}
        end)
     || _ <- lists:seq(1, ?CONCURRENT_TUNNELS)
    ],
    lists:foreach(
        fun(Pid) ->
            receive
                {done, Pid} -> ok
            after ?STALL_MS -> ct:fail(handover_stuck)
            end
        end,
        Pids
    ).

first_bytes_round(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"echo">>),
    ok = masque:send(Sess, <<"z">>),
    <<"z">> = recv_bytes(Sess, 1),
    close(Sess).

%% Many tunnels at once, sharing a connection where the transport can.
tcp_concurrent_tunnels(Config) ->
    Parent = self(),
    Pids = [
        spawn_link(fun() -> Parent ! {done, self(), concurrent_tunnel(Config, N)} end)
     || N <- lists:seq(1, ?CONCURRENT_TUNNELS)
    ],
    lists:foreach(
        fun(Pid) ->
            receive
                {done, Pid, ok} -> ok;
                {done, Pid, Other} -> ct:fail({tunnel_failed, Other})
            after ?STALL_MS -> ct:fail(concurrent_tunnel_stuck)
            end
        end,
        Pids
    ).

concurrent_tunnel(Config, N) ->
    Target = {<<"127.0.0.1">>, ?config(target_port, Config)},
    Sess = connect(Config, Target, #{protocol => tcp, upstream_pool => true}),
    ok = masque:send(Sess, <<"echo">>),
    Payload = binary:copy(<<N:32>>, ?CONCURRENT_BYTES div 4),
    {Sender, MRef} = spawn_monitor(fun() -> exit(send_all(Sess, Payload)) end),
    Got = recv_bytes(Sess, byte_size(Payload)),
    receive
        {'DOWN', MRef, process, Sender, ok} -> ok
    after ?STALL_MS -> ct:fail(sender_stuck)
    end,
    close(Sess),
    case Got =:= Payload of
        true -> ok;
        false -> {corrupt, N}
    end.

%% A client that takes bytes and then stops reading must not hold a
%% proxy session forever, and the session must not buffer without limit.
tcp_stalled_client(Config) ->
    Handle = raw_stalled_client(?config(transport, Config), Config),
    timer:sleep(5000),
    ?assertMatch([_ | _], server_sessions()),
    Peak = max_session_mailbox(),
    ct:log("peak session mailbox ~p", [Peak]),
    ?assert(Peak < ?MAX_MAILBOX),
    await_no_server_sessions(?STALL_MS),
    raw_close(?config(transport, Config), Handle).

raw_stalled_client(h1, Config) ->
    #{port := Port} = ?config(server, Config),
    Host = iolist_to_binary(["127.0.0.1:", integer_to_list(?config(target_port, Config))]),
    {ok, Sock} = ssl:connect(
        "127.0.0.1",
        Port,
        [
            binary,
            {active, false},
            {verify, verify_none},
            {alpn_advertised_protocols, [<<"http/1.1">>]}
        ],
        5000
    ),
    ok = ssl:send(Sock, [
        <<"CONNECT ">>, Host, <<" HTTP/1.1\r\nHost: ">>, Host, <<"\r\n\r\n">>
    ]),
    {ok, Reply} = ssl:recv(Sock, 0, 5000),
    ?assertMatch(<<"HTTP/1.1 200", _/binary>>, Reply),
    ok = ssl:send(Sock, <<"floo">>),
    Sock;
raw_stalled_client(h3, Config) ->
    Conn = raw_h3_connect(Config),
    {ok, Sid} = quic_h3:request(Conn, tcp_request(Config), #{
        end_stream => false, flow_control => manual
    }),
    receive
        {quic_h3, Conn, {response, Sid, 200, _}} -> ok
    after 5000 -> ct:fail(no_response)
    end,
    ok = quic_h3:send_data(Conn, Sid, <<"floo">>, false),
    Conn;
raw_stalled_client(h2, Config) ->
    Conn = raw_h2_connect(Config),
    {ok, Sid} = h2:request(Conn, tcp_request(Config), #{
        protocol => <<"connect-tcp">>, flow_control => manual
    }),
    receive
        {h2, Conn, {response, Sid, 200, _}} -> ok
    after 5000 -> ct:fail(no_response)
    end,
    ok = h2:send_data(Conn, Sid, <<"floo">>, false),
    Conn.

raw_h3_connect(Config) ->
    #{port := Port} = ?config(server, Config),
    {ok, Conn} = quic_h3:connect("127.0.0.1", Port, #{
        verify => verify_none,
        sync => true,
        settings => #{enable_connect_protocol => 1, h3_datagram => 1},
        h3_datagram_enabled => true,
        quic_opts => #{alpn => [<<"h3">>], max_datagram_frame_size => 65535}
    }),
    Conn.

raw_h2_connect(Config) ->
    #{port := Port} = ?config(server, Config),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{
        transport => ssl,
        ssl_opts => [{verify, verify_none}, {alpn_advertised_protocols, [<<"h2">>]}],
        sync => true,
        settings => #{enable_connect_protocol => 1}
    }),
    Conn.

tcp_request(Config) ->
    #{port := Port} = ?config(server, Config),
    TargetPort = integer_to_binary(?config(target_port, Config)),
    Base = [
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, iolist_to_binary(["127.0.0.1:", integer_to_list(Port)])},
        {<<":path">>, <<"/.well-known/masque/tcp/127.0.0.1/", TargetPort/binary, "/">>}
    ],
    case ?config(transport, Config) of
        h3 -> Base ++ [{<<":protocol">>, <<"connect-tcp">>}];
        h2 -> Base
    end.

raw_close(h1, Sock) -> ssl:close(Sock);
raw_close(h3, Conn) -> quic_h3:close(Conn);
raw_close(h2, Conn) -> h2:close(Conn).

%%====================================================================
%% CONNECT-UDP
%%====================================================================

%% Capsule writes on h1 ignore errors, so a client that stops reading
%% must still end the session once the write timeout closes the socket.
h1_udp_stalled_client(Config) ->
    {Flood, FloodPort} = start_udp_flood(),
    #{port := Port} = ?config(server, Config),
    {ok, Sock} = ssl:connect(
        "127.0.0.1",
        Port,
        [
            binary,
            {active, false},
            {verify, verify_none},
            {alpn_advertised_protocols, [<<"http/1.1">>]}
        ],
        5000
    ),
    Host = iolist_to_binary(["127.0.0.1:", integer_to_list(Port)]),
    Path = iolist_to_binary(["/.well-known/masque/udp/127.0.0.1/", integer_to_list(FloodPort), "/"]),
    ok = ssl:send(Sock, [
        <<"GET ">>,
        Path,
        <<" HTTP/1.1\r\nHost: ">>,
        Host,
        <<"\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n">>
    ]),
    {ok, Reply} = ssl:recv(Sock, 0, 5000),
    ?assertMatch(<<"HTTP/1.1 101", _/binary>>, Reply),
    Inner = iolist_to_binary(masque_datagram:encode(0, <<"floo">>)),
    ok = ssl:send(Sock, h1_capsule:encode(datagram, Inner)),
    timer:sleep(5000),
    ?assertMatch([_ | _], server_sessions()),
    Peak = max_session_mailbox(),
    ct:log("peak session mailbox ~p", [Peak]),
    ?assert(Peak < ?MAX_MAILBOX),
    await_no_server_sessions(?STALL_MS),
    exit(Flood, kill),
    ssl:close(Sock).

start_udp_flood() ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Sock),
    Pid = spawn(fun() ->
        {ok, {IP, From, _}} = gen_udp:recv(Sock, 0),
        udp_flood(Sock, IP, From, binary:copy(<<"f">>, 1024))
    end),
    ok = gen_udp:controlling_process(Sock, Pid),
    {Pid, Port}.

udp_flood(Sock, IP, Port, Chunk) ->
    _ = gen_udp:send(Sock, IP, Port, Chunk),
    udp_flood(Sock, IP, Port, Chunk).

udp_echo_sizes(Config) ->
    Sess = connect_udp(Config),
    lists:foreach(
        fun(Size) ->
            Payload = binary:copy(<<"u">>, Size),
            ok = echo_datagram(Sess, Payload)
        end,
        [1, 100, 1200]
    ),
    %% Only h2 and h1 can carry this, in capsules. On h3 it is refused
    %% rather than lost silently. 8000 bytes stays under macOS's 9216
    %% byte limit on a UDP send to the target.
    Big = binary:copy(<<"b">>, 8000),
    case ?config(transport, Config) of
        h3 -> ?assertEqual({error, datagram_too_large_for_path}, masque:send(Sess, Big));
        _ -> ok = echo_datagram(Sess, Big)
    end,
    close(Sess).

udp_oversize_refused(Config) ->
    Sess = connect_udp(Config),
    ?assertMatch(
        {error, {payload_too_large, _, _}},
        masque:send(Sess, binary:copy(<<"o">>, 65528))
    ),
    ok = echo_datagram(Sess, <<"still fine">>),
    close(Sess).

%% UDP may lose packets under a burst, but it must not break the
%% tunnel, and what arrives must be intact.
udp_burst(Config) ->
    Sess = connect_udp(Config),
    Count = 2000,
    Payload = binary:copy(<<"p">>, 1024),
    [ok = masque:send(Sess, Payload) || _ <- lists:seq(1, Count)],
    Got = count_datagrams(Sess, Payload, 0),
    ct:log("udp burst: ~p of ~p echoed", [Got, Count]),
    ?assert(Got > 0),
    ok = echo_datagram(Sess, <<"after burst">>),
    close(Sess).

h3_udp_quiet_tunnel(Config) ->
    Sess = connect_udp(Config),
    ok = echo_datagram(Sess, <<"before">>),
    receive
        {masque_closed, Sess, Reason} -> ct:fail({closed_while_quiet, Reason})
    after ?QUIET_MS -> ok
    end,
    ok = echo_datagram(Sess, <<"after">>),
    close(Sess).

connect_udp(Config) ->
    connect(Config, {<<"127.0.0.1">>, ?config(udp_port, Config)}, #{}).

count_datagrams(Sess, Payload, N) ->
    receive
        {masque_data, Sess, Payload} -> count_datagrams(Sess, Payload, N + 1);
        {masque_data, Sess, Other} -> ct:fail({corrupt_datagram, byte_size(Other)});
        {masque_closed, Sess, Reason} -> ct:fail({closed, Reason, N})
    after 2000 -> N
    end.

%% Datagrams may be lost, so a few attempts are allowed.
echo_datagram(Sess, Payload) ->
    echo_datagram(Sess, Payload, 20).

echo_datagram(_Sess, Payload, 0) ->
    ct:fail({no_echo, byte_size(Payload)});
echo_datagram(Sess, Payload, N) ->
    ok = masque:send(Sess, Payload),
    receive
        {masque_data, Sess, Payload} -> ok;
        {masque_closed, Sess, Reason} -> ct:fail({closed, Reason})
    after 250 -> echo_datagram(Sess, Payload, N - 1)
    end.

%%====================================================================
%% Connect-UDP-Bind
%%====================================================================

bind_two_peers(Config) ->
    Sess = connect_bind(Config),
    {ok, Ctx} = masque:open_uncompressed_context(Sess),
    await_acked(Sess, Ctx),
    {PeerA, AddrA} = open_peer(),
    {PeerB, AddrB} = open_peer(),
    ok = masque:send_to(Sess, AddrA, <<"to a">>),
    ok = masque:send_to(Sess, AddrB, <<"to b">>),
    From = peer_recv(PeerA, <<"to a">>),
    From = peer_recv(PeerB, <<"to b">>),
    ok = gen_udp:send(PeerA, From, <<"from a">>),
    ok = gen_udp:send(PeerB, From, <<"from b">>),
    await_bind_packet(Sess, AddrA, <<"from a">>),
    await_bind_packet(Sess, AddrB, <<"from b">>),
    close(Sess).

bind_compressed_peer(Config) ->
    Sess = connect_bind(Config),
    {ok, Uncompressed} = masque:open_uncompressed_context(Sess),
    await_acked(Sess, Uncompressed),
    {Peer, Addr} = open_peer(),
    {ok, Ctx} = masque:assign_compression(Sess, Addr),
    await_acked(Sess, Ctx),
    ok = masque:send_to(Sess, Addr, <<"compressed">>),
    From = peer_recv(Peer, <<"compressed">>),
    ok = gen_udp:send(Peer, From, <<"back">>),
    await_bind_packet(Sess, Addr, <<"back">>),
    ok = masque:close_compression(Sess, Ctx),
    timer:sleep(100),
    ok = masque:send_to(Sess, Addr, <<"plain again">>),
    From = peer_recv(Peer, <<"plain again">>),
    close(Sess).

%% By default the proxy only talks to public peers.
bind_peer_filter(Config) ->
    Sess = connect_bind(Config),
    {ok, Ctx} = masque:open_uncompressed_context(Sess),
    await_acked(Sess, Ctx),
    {Peer, Addr} = open_peer(),
    ok = masque:send_to(Sess, Addr, <<"refused">>),
    ?assertEqual({error, timeout}, gen_udp:recv(Peer, 0, 1000)),
    close(Sess).

connect_bind(Config) ->
    #{port := Port} = ?config(server, Config),
    Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
    {ok, Sess} = masque:bind_connect(Uri, unscoped, #{
        transports => [?config(transport, Config)], verify => verify_none, timeout => 5000
    }),
    Sess.

await_acked(Sess, Ctx) ->
    receive
        {masque_compression_acked, Sess, Ctx} -> ok
    after 5000 -> ct:fail({no_ack, Ctx})
    end.

open_peer() ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Sock),
    {Sock, {{127, 0, 0, 1}, Port}}.

peer_recv(Peer, Expected) ->
    {ok, {IP, Port, Expected}} = gen_udp:recv(Peer, 0, 5000),
    {IP, Port}.

await_bind_packet(Sess, Addr, Bytes) ->
    receive
        {masque_bind_packet, Sess, Addr, Bytes} -> ok;
        {masque_closed, Sess, Reason} -> ct:fail({closed, Reason})
    after 5000 -> ct:fail({no_bind_packet, Bytes})
    end.

%%====================================================================
%% CONNECT-IP
%%====================================================================

%% An ICMP echo answered by a gateway address behind `forward_fun'.
ip_gateway_echo(Config) ->
    {Sess, Addr} = connect_ip(Config),
    Request = icmp_echo(Addr, ?IP_GATEWAY, 8),
    ok = masque:send_ip_packet(Sess, Request),
    receive
        {masque_ip_packet, Sess, Reply} ->
            ?assertEqual(?IP_GATEWAY, ipv4_src(Reply)),
            ?assertEqual(Addr, ipv4_dst(Reply)),
            ?assertEqual(0, masque_ip_packet:checksum(ipv4_header(Reply)))
    after 5000 -> ct:fail(no_icmp_reply)
    end,
    close(Sess).

%% Two clients reach each other through the address registry, the way
%% a site-to-site deployment routes between tunnels.
ip_two_clients(Config) ->
    {SessA, AddrA} = connect_ip(Config),
    {SessB, AddrB} = connect_ip(Config),
    ?assertNotEqual(AddrA, AddrB),
    ToB = ipv4_udp(AddrA, AddrB, <<"hello b">>),
    ok = masque:send_ip_packet(SessA, ToB),
    receive
        {masque_ip_packet, SessB, GotB} ->
            ?assertEqual(AddrA, ipv4_src(GotB)),
            ?assertMatch({_, <<"hello b">>}, split_binary(GotB, byte_size(GotB) - 7))
    after 5000 -> ct:fail(b_got_nothing)
    end,
    ToA = ipv4_udp(AddrB, AddrA, <<"hello a">>),
    ok = masque:send_ip_packet(SessB, ToA),
    receive
        {masque_ip_packet, SessA, GotA} -> ?assertEqual(AddrB, ipv4_src(GotA))
    after 5000 -> ct:fail(a_got_nothing)
    end,
    close(SessA),
    close(SessB).

connect_ip(Config) ->
    Sess = connect(Config, {'*', '*'}, #{protocol => ip}),
    {ok, [Id]} = masque:request_addresses(Sess, [{4, {0, 0, 0, 0}, 32}]),
    receive
        {masque_address_assign, Sess, [#ip_assignment{request_id = Id, address = Addr}]} ->
            {Sess, Addr}
    after 5000 -> ct:fail(no_address)
    end.

%% `forward_fun': the proxy's routing decision for an accepted packet.
ip_router(Packet, State) ->
    case ipv4_dst(Packet) of
        ?IP_GATEWAY ->
            {reply, icmp_echo(?IP_GATEWAY, ipv4_src(Packet), 0), State};
        Dst ->
            case masque_ip_session_registry:lookup(Dst) of
                {ok, Pid, _} ->
                    ok = masque_ip:inject_packet(Pid, Packet),
                    {forward, State};
                not_found ->
                    {drop, State}
            end
    end.

ipv4_src(<<_:96, A, B, C, D, _/binary>>) -> {A, B, C, D}.
ipv4_dst(<<_:128, A, B, C, D, _/binary>>) -> {A, B, C, D}.
ipv4_header(<<Header:20/binary, _/binary>>) -> Header.

ipv4(Src, Dst, Proto, Body) ->
    {SA, SB, SC, SD} = Src,
    {DA, DB, DC, DD} = Dst,
    Total = 20 + byte_size(Body),
    H0 =
        <<4:4, 5:4, 0, Total:16, 0:16, 0:16, 64, Proto, 0:16, SA, SB, SC, SD, DA, DB, DC, DD>>,
    Sum = masque_ip_packet:checksum(H0),
    <<Before:10/binary, 0:16, After/binary>> = H0,
    <<Before/binary, Sum:16, After/binary, Body/binary>>.

icmp_echo(Src, Dst, Type) ->
    Body0 = <<Type, 0, 0:16, 1:16, 1:16, "ping">>,
    Sum = masque_ip_packet:checksum(Body0),
    <<Head:2/binary, 0:16, Rest/binary>> = Body0,
    ipv4(Src, Dst, 1, <<Head/binary, Sum:16, Rest/binary>>).

ipv4_udp(Src, Dst, Payload) ->
    Len = 8 + byte_size(Payload),
    ipv4(Src, Dst, 17, <<4000:16, 4001:16, Len:16, 0:16, Payload/binary>>).

%%====================================================================
%% Relay
%%====================================================================

chain_tcp_full_duplex(Config) ->
    with_chain(Config, fun(Cfg) -> full_duplex(Cfg, payload()) end).

%% Bytes refused by a full upstream queue must not be lost.
chain_tcp_upload(Config) ->
    with_chain(Config, fun(Cfg) ->
        Sess = connect_tcp(Cfg),
        ok = masque:send(Sess, <<"sink">>),
        ok = send_all(Sess, payload()),
        Sum = sha(payload()),
        ?assertEqual(Sum, recv_bytes(Sess, byte_size(Sum))),
        close(Sess)
    end).

%% A target slower than the client fills the upstream leg's send queue.
chain_tcp_upload_large(Config) ->
    with_chain(Config, fun(Cfg) ->
        Sess = connect_tcp(Cfg),
        ok = masque:send(Sess, <<"slow">>),
        Payload = binary:copy(<<"0123456789abcdef">>, ?LARGE_BYTES div 16),
        ok = send_all(Sess, Payload),
        Sum = sha(Payload),
        ?assertEqual(Sum, recv_bytes(Sess, byte_size(Sum))),
        close(Sess)
    end).

chain_udp_echo(Config) ->
    with_chain(Config, fun(Cfg) ->
        Sess = connect_udp(Cfg),
        ok = echo_datagram(Sess, <<"over two hops">>),
        close(Sess)
    end).

chain_ip_echo(Config) ->
    with_chain(Config, fun(Cfg) ->
        {Sess, Addr} = connect_ip(Cfg),
        ok = masque:send_ip_packet(Sess, icmp_echo(Addr, ?IP_GATEWAY, 8)),
        receive
            {masque_ip_packet, Sess, Reply} -> ?assertEqual(?IP_GATEWAY, ipv4_src(Reply))
        after 5000 -> ct:fail(no_icmp_reply)
        end,
        close(Sess)
    end).

%% The case's server is the egress; clients dial a chain listener of
%% the same transport in front of it.
with_chain(Config, Fun) ->
    Transport = ?config(transport, Config),
    #{port := EgressPort} = ?config(server, Config),
    Ingress = start_chain(Transport, ?config(certs, Config), EgressPort),
    Cfg = lists:keystore(server, 1, Config, {server, Ingress}),
    try
        Fun(Cfg)
    after
        stop_chain(Transport, Ingress)
    end.

start_chain(Transport, Certs, EgressPort) ->
    Name = unique_name(chain),
    Upstream = #{
        upstream_proxy => iolist_to_binary(["https://127.0.0.1:", integer_to_list(EgressPort)]),
        upstream_opts => #{transports => [Transport], verify => verify_none}
    },
    case Transport of
        h3 ->
            #{cert := Cert, key := Key} = Certs,
            {ok, _} = masque:start_chain_listener(Name, #{
                port => 0, cert => Cert, key => Key, handler_opts => Upstream
            }),
            {ok, Port} = quic:get_server_port(Name),
            #{name => Name, port => Port};
        h2 ->
            #{cert_file := Cert, key_file := Key} = Certs,
            {ok, {_, _, Port}} = masque:start_chain_listener_h2(Name, #{
                port => 0, cert => Cert, key => Key, handler_opts => Upstream
            }),
            #{name => Name, port => Port};
        h1 ->
            #{cert_file := Cert, key_file := Key} = Certs,
            {ok, Ref} = masque:start_chain_listener_h1(Name, #{
                port => 0, cert => Cert, key => Key, handler_opts => Upstream
            }),
            #{name => Name, port => h1:server_port(Ref)}
    end.

stop_chain(h3, #{name := Name}) -> masque:stop_listener(Name);
stop_chain(h2, #{name := Name}) -> masque:stop_listener_h2(Name);
stop_chain(h1, #{name := Name}) -> masque:stop_listener_h1(Name).

%%====================================================================
%% Lifecycle
%%====================================================================

%% Stopping a listener refuses new work. Open tunnels end, or carry on
%% until they finish, but none may be left without an owner.
stop_listener_with_open_tunnels(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"echo">>),
    ok = masque:send(Sess, <<"x">>),
    <<"x">> = recv_bytes(Sess, 1),
    stop_server(?config(transport, Config), ?config(server, Config)),
    Ended =
        receive
            {masque_closed, Sess, Reason} -> {closed, Reason}
        after 5000 -> still_open
        end,
    ct:log("after listener stop: ~p", [Ended]),
    close(Sess),
    await_no_server_sessions(10000).

%% The owner dying ends its tunnels at the target and leaks nothing.
owner_crash_cleans_up(Config) ->
    Ports = length(erlang:ports()),
    Parent = self(),
    Owner = spawn(fun() ->
        Sess = connect_tcp(Config),
        ok = masque:send(Sess, <<"wclo">>),
        <<"x">> = recv_bytes(Sess, 1),
        Parent ! connected,
        receive
            never -> ok
        end
    end),
    receive
        connected -> ok
    after 10000 -> ct:fail(owner_never_connected)
    end,
    exit(Owner, kill),
    receive
        {target, closed, Reason} -> ct:log("target saw ~p", [Reason])
    after 10000 -> ct:fail(target_not_told)
    end,
    await_no_server_sessions(10000),
    %% Sockets close just after their owners exit.
    timer:sleep(500),
    ?assert(length(erlang:ports()) =< Ports + 1).

%% GOAWAY refuses new streams and leaves running tunnels alone.
goaway_keeps_open_tunnel(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"echo">>),
    ok = masque:send(Sess, <<"before">>),
    <<"before">> = recv_bytes(Sess, 6),
    [Pid | _] = server_sessions(),
    ServerConn = element(2, sys:get_state(Pid)),
    %% `h2:goaway/1' closes the connection after a 100 ms drain, so the
    %% tunnel only has to work inside that window there.
    ok =
        case ?config(transport, Config) of
            h3 -> quic_h3:goaway(ServerConn);
            h2 -> h2:goaway(ServerConn)
        end,
    ok = masque:send(Sess, <<"after">>),
    <<"after">> = recv_bytes(Sess, 5),
    close(Sess).

%% RFC 9114 section 5.2: streams under the GOAWAY id run to completion.
%% A whole transfer in both directions starts after it.
h3_goaway_transfer_continues(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"echo">>),
    ok = masque:send(Sess, <<"before">>),
    <<"before">> = recv_bytes(Sess, 6),
    ok = quic_h3:goaway(server_conn()),
    timer:sleep(500),
    {Sender, MRef} = spawn_monitor(fun() -> exit({sent, send_all(Sess, payload())}) end),
    Got = recv_bytes(Sess, ?TRANSFER_BYTES),
    receive
        {'DOWN', MRef, process, Sender, {sent, ok}} -> ok;
        {'DOWN', MRef, process, Sender, Other} -> ct:fail({sender, Other})
    after ?STALL_MS -> ct:fail(sender_stuck)
    end,
    ?assertEqual(sha(payload()), sha(Got)),
    close(Sess).

%% `h2:goaway/1' closes the connection after its drain. The client has
%% to hear about it and not hang.
h2_goaway_tells_client(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"echo">>),
    ok = masque:send(Sess, <<"x">>),
    <<"x">> = recv_bytes(Sess, 1),
    ok = h2:goaway(server_conn()),
    receive
        {masque_closed, Sess, Reason} -> ct:log("client told ~p", [Reason])
    after 5000 -> ct:fail(client_not_told)
    end.

%% After a GOAWAY the client may not open new streams on the connection.
goaway_refuses_new_requests(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"echo">>),
    ok = masque:send(Sess, <<"x">>),
    <<"x">> = recv_bytes(Sess, 1),
    close(Sess),
    await_no_server_sessions(5000),
    case ?config(transport, Config) of
        h3 -> h3_refused_after_goaway(Config);
        h2 -> h2_refused_after_goaway(Config)
    end.

h3_refused_after_goaway(Config) ->
    Conn = raw_h3_connect(Config),
    {ok, Sid} = quic_h3:request(Conn, tcp_request(Config), #{end_stream => false}),
    receive
        {quic_h3, Conn, {response, Sid, 200, _}} -> ok
    after 5000 -> ct:fail(no_response)
    end,
    ok = quic_h3:goaway(server_conn()),
    receive
        {quic_h3, Conn, {goaway, _}} -> ok
    after 5000 -> ct:fail(no_goaway)
    end,
    ?assertMatch({error, _}, quic_h3:request(Conn, tcp_request(Config), #{end_stream => false})),
    quic_h3:close(Conn).

h2_refused_after_goaway(Config) ->
    Conn = raw_h2_connect(Config),
    {ok, Sid} = h2:request(Conn, tcp_request(Config), #{protocol => <<"connect-tcp">>}),
    receive
        {h2, Conn, {response, Sid, 200, _}} -> ok
    after 5000 -> ct:fail(no_response)
    end,
    ok = h2:goaway(server_conn()),
    receive
        {h2, Conn, {goaway, _, _}} -> ok
    after 5000 -> ct:fail(no_goaway)
    end,
    ?assertMatch(
        {error, _}, h2:request(Conn, tcp_request(Config), #{protocol => <<"connect-tcp">>})
    ),
    h2:close(Conn).

%% The pool stops using a connection that got a GOAWAY: new tunnels get
%% a new connection, and they work.
goaway_pool_moves_on(Config) ->
    Target = {<<"127.0.0.1">>, ?config(target_port, Config)},
    Opts = #{protocol => tcp, upstream_pool => true},
    First = connect(Config, Target, Opts),
    ok = masque:send(First, <<"echo">>),
    ok = masque:send(First, <<"1">>),
    <<"1">> = recv_bytes(First, 1),
    [Before] = server_connections(),
    Goaway =
        case ?config(transport, Config) of
            h3 -> fun quic_h3:goaway/1;
            h2 -> fun h2:goaway/1
        end,
    ok = Goaway(Before),
    timer:sleep(300),
    Second = connect(Config, Target, Opts),
    ok = masque:send(Second, <<"echo">>),
    ok = masque:send(Second, <<"2">>),
    <<"2">> = recv_bytes(Second, 1),
    ?assert(lists:any(fun(C) -> C =/= Before end, server_connections())),
    case ?config(transport, Config) of
        h3 ->
            ok = masque:send(First, <<"3">>),
            <<"3">> = recv_bytes(First, 1);
        h2 ->
            ok
    end,
    close(First),
    close(Second).

server_conn() ->
    [Conn | _] = server_connections(),
    Conn.

server_connections() ->
    lists:usort([element(2, sys:get_state(P)) || P <- server_sessions()]).

%%====================================================================
%% Client helpers
%%====================================================================

connect_tcp(Config) ->
    Target = {<<"127.0.0.1">>, ?config(target_port, Config)},
    connect(Config, Target, #{protocol => tcp}).

connect(Config, Target, Opts) ->
    #{port := Port} = ?config(server, Config),
    Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
    {ok, Sess} = masque:connect(
        Uri,
        Target,
        Opts#{transports => [?config(transport, Config)], verify => verify_none, timeout => 5000}
    ),
    %% Until erlang_h1 fixes its handover race, bytes sent right after
    %% the 200 can be lost (see `tcp_first_bytes_survive_handover').
    case ?config(transport, Config) of
        h1 -> timer:sleep(?H1_HANDOVER_WAIT_MS);
        _ -> ok
    end,
    Sess.

close(Sess) ->
    _ = masque:close(Sess),
    ok.

payload() ->
    binary:copy(<<"0123456789abcdef">>, ?TRANSFER_BYTES div 16).

sha(Bin) -> crypto:hash(sha256, Bin).

%% A refused write wrote nothing, so the caller tries again.
send_all(_Sess, <<>>) ->
    ok;
send_all(Sess, Bin) ->
    Size = min(?CHUNK_BYTES, byte_size(Bin)),
    <<Chunk:Size/binary, Rest/binary>> = Bin,
    case send_chunk(Sess, Chunk, 3000) of
        ok -> send_all(Sess, Rest);
        Err -> Err
    end.

send_chunk(_Sess, _Chunk, 0) ->
    {error, send_stuck};
send_chunk(Sess, Chunk, N) ->
    case masque:send(Sess, Chunk) of
        ok ->
            ok;
        {error, Full} when Full =:= send_queue_full; Full =:= send_buffer_full ->
            timer:sleep(10),
            send_chunk(Sess, Chunk, N - 1);
        Err ->
            Err
    end.

recv_bytes(Sess, Want) ->
    recv_bytes(Sess, Want, [], 0).

recv_bytes(_Sess, Want, Acc, Got) when Got >= Want ->
    iolist_to_binary(lists:reverse(Acc));
recv_bytes(Sess, Want, Acc, Got) ->
    receive
        {masque_data, Sess, Bin} ->
            recv_bytes(Sess, Want, [Bin | Acc], Got + byte_size(Bin));
        {masque_closed, Sess, Reason} ->
            ct:fail({closed, Reason, Got, tunnel_stacks()})
    after ?STALL_MS ->
        ct:fail({stalled, Got, Want, tunnel_stacks()})
    end.

max_session_mailbox() ->
    lists:max([0 | [L || {_, [_, {message_queue_len, L}]} <- tunnel_stacks()]]).

%% Where the server sessions are, for the failure report.
tunnel_stacks() ->
    [
        {Mod, process_info(P, [current_stacktrace, message_queue_len])}
     || P <- processes(),
        Mod <- session_module(P),
        lists:suffix("session", atom_to_list(Mod))
    ].

session_module(P) ->
    case process_info(P, dictionary) of
        {dictionary, Dict} ->
            case lists:keyfind('$initial_call', 1, Dict) of
                {_, {Mod, init, 1}} ->
                    case atom_to_list(Mod) of
                        "masque_" ++ _ -> [Mod];
                        _ -> []
                    end;
                _ ->
                    []
            end;
        _ ->
            []
    end.

%%====================================================================
%% Servers
%%====================================================================

server_opts(Extra) ->
    Defaults = #{
        allow_private => true,
        allow_self => true,
        bind_address => {127, 0, 0, 1},
        allow_loopback => true,
        address_pool => {4, {10, 200, 0, 0}, 24},
        routes => [
            #ip_route{
                version = 4,
                start_addr = {0, 0, 0, 0},
                end_addr = {255, 255, 255, 255},
                ip_protocol = 0
            }
        ],
        forward_fun => fun ?MODULE:ip_router/2
    },
    Handler =
        case Extra of
            #{handler_opts := H} -> H;
            _ -> Defaults
        end,
    Extra#{accept_bind => true, handler_opts => Handler}.

start_server(h3, Certs, Extra) ->
    {ok, Srv} = masque_test_helpers:start_masque_server(maps:merge(Certs, server_opts(Extra))),
    Srv;
start_server(h2, #{cert_file := Cert, key_file := Key}, Extra) ->
    Name = unique_name(h2),
    {ok, {_, _, Port}} = masque:start_listener_h2(
        Name, (server_opts(Extra))#{port => 0, cert => Cert, key => Key}
    ),
    #{name => Name, port => Port};
start_server(h1, #{cert_file := Cert, key_file := Key}, Extra) ->
    Name = unique_name(h1),
    {ok, Ref} = masque:start_listener_h1(
        Name, (server_opts(Extra))#{port => 0, cert => Cert, key => Key}
    ),
    #{name => Name, port => h1:server_port(Ref)}.

stop_server(h3, Srv) -> masque_test_helpers:stop_masque_server(Srv);
stop_server(h2, #{name := Name}) -> masque:stop_listener_h2(Name);
stop_server(h1, #{name := Name}) -> masque:stop_listener_h1(Name).

unique_name(Prefix) ->
    list_to_atom(
        "e2e_" ++ atom_to_list(Prefix) ++ "_" ++
            integer_to_list(erlang:unique_integer([positive]))
    ).

%%====================================================================
%% Target
%%====================================================================

start_udp_echo() ->
    {ok, Sock} = gen_udp:open(0, [
        binary, {active, false}, {ip, {127, 0, 0, 1}}, {recbuf, 8 * 1024 * 1024}
    ]),
    {ok, Port} = inet:port(Sock),
    Pid = spawn(fun() -> udp_echo_loop(Sock) end),
    ok = gen_udp:controlling_process(Sock, Pid),
    {Pid, Port}.

udp_echo_loop(Sock) ->
    case gen_udp:recv(Sock, 0) of
        {ok, {IP, Port, Data}} ->
            _ = gen_udp:send(Sock, IP, Port, Data),
            udp_echo_loop(Sock);
        {error, _} ->
            ok
    end.

target_accept(Listen) ->
    {ok, Sock} = gen_tcp:accept(Listen),
    Pid = spawn(fun() -> target_wait(Sock) end),
    %% A tunnel may already have closed this socket.
    _ = gen_tcp:controlling_process(Sock, Pid),
    Pid ! go,
    target_accept(Listen).

target_wait(Sock) ->
    receive
        go ->
            {ok, Mode} = gen_tcp:recv(Sock, 4),
            target_mode(Mode, Sock)
    end.

target_mode(<<"echo">>, Sock) ->
    target_echo(Sock);
target_mode(<<"down">>, Sock) ->
    ok = gen_tcp:send(Sock, payload()),
    target_hold(Sock);
target_mode(<<"slow">>, Sock) ->
    Sum = target_slow_sink(Sock, ?LARGE_BYTES, crypto:hash_init(sha256)),
    ok = gen_tcp:send(Sock, Sum),
    target_hold(Sock);
target_mode(<<"gath">>, Sock) ->
    Bin = target_read_all(Sock, []),
    ok = gen_tcp:send(Sock, sha(Bin)),
    gen_tcp:close(Sock);
target_mode(<<"fin1">>, Sock) ->
    ok = gen_tcp:send(Sock, <<"bye">>),
    ok = gen_tcp:shutdown(Sock, write),
    {ok, Late} = gen_tcp:recv(Sock, 4, 5000),
    probe({target, got, Late}),
    gen_tcp:close(Sock);
target_mode(<<"rset">>, Sock) ->
    ok = gen_tcp:send(Sock, <<"x">>),
    timer:sleep(200),
    ok = inet:setopts(Sock, [{linger, {true, 0}}]),
    gen_tcp:close(Sock);
target_mode(<<"wclo">>, Sock) ->
    ok = gen_tcp:send(Sock, <<"x">>),
    {error, Reason} = gen_tcp:recv(Sock, 0),
    probe({target, closed, Reason}),
    gen_tcp:close(Sock);
target_mode(<<"floo">>, Sock) ->
    target_flood(Sock, binary:copy(<<"f">>, 64 * 1024));
target_mode(<<"stal">>, Sock) ->
    receive
    after infinity -> gen_tcp:close(Sock)
    end;
target_mode(<<"sink">>, Sock) ->
    {ok, Bin} = gen_tcp:recv(Sock, ?TRANSFER_BYTES),
    ok = gen_tcp:send(Sock, sha(Bin)),
    target_hold(Sock).

target_slow_sink(_Sock, 0, Ctx) ->
    crypto:hash_final(Ctx);
target_slow_sink(Sock, Left, Ctx) ->
    Size = min(Left, 256 * 1024),
    case gen_tcp:recv(Sock, Size, 20000) of
        {ok, Bin} ->
            timer:sleep(1),
            target_slow_sink(Sock, Left - byte_size(Bin), crypto:hash_update(Ctx, Bin));
        {error, Reason} ->
            probe({target, slow_sink_failed, Reason, Left}),
            exit(normal)
    end.

target_read_all(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, Bin} -> target_read_all(Sock, [Bin | Acc]);
        {error, closed} -> iolist_to_binary(lists:reverse(Acc))
    end.

target_flood(Sock, Chunk) ->
    case gen_tcp:send(Sock, Chunk) of
        ok -> target_flood(Sock, Chunk);
        {error, _} -> gen_tcp:close(Sock)
    end.

probe(Msg) ->
    try
        ?PROBE ! Msg,
        ok
    catch
        error:badarg -> ok
    end.

target_echo(Sock) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, Bin} ->
            case gen_tcp:send(Sock, Bin) of
                ok -> target_echo(Sock);
                {error, _} -> gen_tcp:close(Sock)
            end;
        {error, _} ->
            gen_tcp:close(Sock)
    end.

target_hold(Sock) ->
    _ = gen_tcp:recv(Sock, 0),
    gen_tcp:close(Sock).
