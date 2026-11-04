%%% @doc End-to-end tests: real sockets through real listeners.
%%%
%%% Every case runs a real `gen_tcp' or `gen_udp' target behind a real
%%% listener and checks what reaches the far side, over h3, h2 and h1.
-module(masque_e2e_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

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
    tcp_half_close_client/1,
    tcp_half_close_target/1,
    tcp_target_reset/1,
    tcp_client_close_reaches_target/1,
    tcp_concurrent_tunnels/1,
    tcp_stalled_client/1
]).

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
%% QUIC's 30 s idle timeout plus retransmission and teardown.
-define(VANISH_MS, 45000).
%% Field `conn' of the h3 client session records.
-define(H3_CONN_ELEMENT, 10).
%% The target reports to the running test case under this name.
-define(PROBE, masque_e2e_probe).
-define(CONCURRENT_TUNNELS, 50).
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
        tcp_stalled_client
    ],
    HalfClose = [tcp_half_close_client, tcp_half_close_target],
    [
        {h3, [], Tcp ++ HalfClose ++ [h3_client_vanishes]},
        {h2, [], Tcp ++ HalfClose},
        {h1, [], Tcp}
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
    [{certs, Certs}, {target_port, TargetPort}, {target, Target} | Config].

end_per_suite(Config) ->
    exit(?config(target, Config), kill),
    masque_test_helpers:cleanup_certs(?config(certs, Config)),
    ok.

init_per_group(Transport, Config) ->
    [{transport, Transport} | Config].

end_per_group(_Transport, _Config) ->
    ok.

%% Listeners link to the process that starts them, and a group's init
%% process exits at once, so each case starts its own.
init_per_testcase(_Case, Config) ->
    true = register(?PROBE, self()),
    Server = start_server(?config(transport, Config), ?config(certs, Config)),
    [{server, Server} | Config].

end_per_testcase(_Case, Config) ->
    try
        unregister(?PROBE)
    catch
        error:badarg -> ok
    end,
    stop_server(?config(transport, Config), ?config(server, Config)),
    ok.

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
        Mod =:= masque_tcp_server_session orelse Mod =:= masque_tcp_h1_server_session
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
    #{port := Port} = ?config(server, Config),
    {ok, Conn} = quic_h3:connect("127.0.0.1", Port, #{
        verify => verify_none,
        sync => true,
        settings => #{enable_connect_protocol => 1, h3_datagram => 1},
        h3_datagram_enabled => true,
        quic_opts => #{alpn => [<<"h3">>], max_datagram_frame_size => 65535}
    }),
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
    #{port := Port} = ?config(server, Config),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{
        transport => ssl,
        ssl_opts => [{verify, verify_none}, {alpn_advertised_protocols, [<<"h2">>]}],
        sync => true,
        settings => #{enable_connect_protocol => 1}
    }),
    {ok, Sid} = h2:request(Conn, tcp_request(Config), #{
        protocol => <<"connect-tcp">>, flow_control => manual
    }),
    receive
        {h2, Conn, {response, Sid, 200, _}} -> ok
    after 5000 -> ct:fail(no_response)
    end,
    ok = h2:send_data(Conn, Sid, <<"floo">>, false),
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
        Mod <- session_module(P)
    ].

session_module(P) ->
    case process_info(P, dictionary) of
        {dictionary, Dict} ->
            case lists:keyfind('$initial_call', 1, Dict) of
                {_, {Mod, init, 1}} ->
                    case atom_to_list(Mod) of
                        "masque_tcp_" ++ _ -> [Mod];
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

handler_opts() ->
    #{allow_private => true, allow_self => true}.

start_server(h3, Certs) ->
    {ok, Srv} = masque_test_helpers:start_masque_server(Certs#{handler_opts => handler_opts()}),
    Srv;
start_server(h2, #{cert_file := Cert, key_file := Key}) ->
    Name = unique_name(h2),
    {ok, {_, _, Port}} = masque:start_listener_h2(
        Name, #{port => 0, cert => Cert, key => Key, handler_opts => handler_opts()}
    ),
    #{name => Name, port => Port};
start_server(h1, #{cert_file := Cert, key_file := Key}) ->
    Name = unique_name(h1),
    {ok, Ref} = masque:start_listener_h1(
        Name, #{port => 0, cert => Cert, key => Key, handler_opts => handler_opts()}
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
