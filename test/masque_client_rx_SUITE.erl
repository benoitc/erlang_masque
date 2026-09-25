%%% @doc Queue-mode receive queues on the client: the `rx_queue_limit'
%%% bound (datagram tunnels drop and count, CONNECT-TCP ends with
%%% `rx_overflow') and `recv/2' after the peer ends the tunnel
%%% (queued data first, then `{error, closed}').
-module(masque_client_rx_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1
]).

-export([
    udp_h3_overflow_drops_and_counts/1,
    udp_h2_overflow_drops_and_counts/1,
    ip_h2_overflow_drops_and_counts/1,
    tcp_h3_overflow_ends_tunnel/1,
    tcp_h1_overflow_ends_tunnel/1,
    tcp_h3_recv_after_fin/1,
    tcp_h1_recv_after_fin/1
]).

all() ->
    [
        udp_h3_overflow_drops_and_counts,
        udp_h2_overflow_drops_and_counts,
        ip_h2_overflow_drops_and_counts,
        tcp_h3_overflow_ends_tunnel,
        tcp_h1_overflow_ends_tunnel,
        tcp_h3_recv_after_fin,
        tcp_h1_recv_after_fin
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Certs} = masque_test_helpers:generate_certs(),
    [{certs, Certs} | Config].

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(certs, Config)),
    ok.

%%====================================================================
%% Datagram tunnels: drop and count past the limit
%%====================================================================

udp_h3_overflow_drops_and_counts(Config) ->
    {ok, Server} = masque_test_helpers:start_masque_server(
        maps:merge(?config(certs, Config), #{handler => masque_echo_handler})
    ),
    try
        udp_overflow(h3, maps:get(port, Server))
    after
        masque_test_helpers:stop_masque_server(Server)
    end.

udp_h2_overflow_drops_and_counts(Config) ->
    Certs = ?config(certs, Config),
    {ok, Ref} = masque:start_listener_h2(unique_name("rx_h2"), #{
        port => 0,
        cert => maps:get(cert_file, Certs),
        key => maps:get(key_file, Certs),
        handler => masque_echo_handler
    }),
    {_, _, Port} = Ref,
    try
        udp_overflow(h2, Port)
    after
        masque:stop_listener_h2(Ref)
    end.

udp_overflow(Transport, Port) ->
    {ok, Sess} = masque:connect(
        proxy_uri(Port),
        {<<"127.0.0.1">>, 9},
        #{
            transports => [Transport],
            verify => verify_none,
            mode => queue,
            rx_queue_limit => 2
        }
    ),
    [
        begin
            ok = masque:send(Sess, <<"pkt", (integer_to_binary(N))/binary>>),
            timer:sleep(10)
        end
     || N <- lists:seq(1, 6)
    ],
    timer:sleep(300),
    ?assertMatch({ok, <<"pkt", _/binary>>}, masque:recv(Sess, 1000)),
    ?assertMatch({ok, <<"pkt", _/binary>>}, masque:recv(Sess, 1000)),
    ?assertEqual({error, timeout}, masque:recv(Sess, 100)),
    #{rx_dropped := Dropped} = masque:info(Sess),
    ?assert(Dropped >= 1),
    ok = masque:close(Sess).

ip_h2_overflow_drops_and_counts(Config) ->
    Certs = ?config(certs, Config),
    {ok, Ref} = masque_h2_server:start_listener(unique_name("rx_ip_h2"), #{
        port => 0,
        cert => maps:get(cert_file, Certs),
        key => maps:get(key_file, Certs),
        ip_handler => masque_ip_echo_handler
    }),
    {_, _, Port} = Ref,
    try
        {ok, Sess} = masque:connect(
            proxy_uri(Port),
            {'*', '*'},
            #{
                protocol => ip,
                transports => [h2],
                verify => verify_none,
                mode => queue,
                rx_queue_limit => 2
            }
        ),
        Packet = sample_ipv4_udp(),
        [ok = masque:send_ip_packet(Sess, Packet) || _ <- lists:seq(1, 5)],
        timer:sleep(300),
        ?assertEqual({ok, Packet}, masque:recv(Sess, 1000)),
        ?assertEqual({ok, Packet}, masque:recv(Sess, 1000)),
        ?assertEqual({error, timeout}, masque:recv(Sess, 100)),
        ?assertMatch(#{rx_dropped := 3}, masque:info(Sess)),
        ok = masque:close(Sess)
    after
        masque_h2_server:stop_listener(Ref)
    end.

%%====================================================================
%% CONNECT-TCP: overflow ends the tunnel, FIN keeps unread data
%%====================================================================

tcp_h3_overflow_ends_tunnel(Config) ->
    with_tcp_h3(Config, {chunks, 20}, fun(Port, TcpPort) ->
        tcp_overflow(h3, Port, TcpPort)
    end).

tcp_h1_overflow_ends_tunnel(Config) ->
    with_tcp_h1(Config, {chunks, 20}, fun(Port, TcpPort) ->
        tcp_overflow(h1, Port, TcpPort)
    end).

tcp_overflow(Transport, Port, TcpPort) ->
    {ok, Sess} = tcp_connect(Transport, Port, TcpPort),
    timer:sleep(1000),
    {Items, End} = drain(Sess),
    ?assert(length(Items) =< 2),
    ?assertEqual({error, rx_overflow}, End),
    ?assertEqual({error, closed}, masque:recv(Sess, 100)).

tcp_h3_recv_after_fin(Config) ->
    with_tcp_h3(Config, {send_and_close, <<"hello">>}, fun(Port, TcpPort) ->
        tcp_after_fin(h3, Port, TcpPort)
    end).

tcp_h1_recv_after_fin(Config) ->
    with_tcp_h1(Config, {send_and_close, <<"hello">>}, fun(Port, TcpPort) ->
        tcp_after_fin(h1, Port, TcpPort)
    end).

tcp_after_fin(Transport, Port, TcpPort) ->
    {ok, Sess} = tcp_connect(Transport, Port, TcpPort),
    %% The target sends and closes; nobody reads until the tunnel is
    %% gone on the proxy side.
    timer:sleep(1000),
    {Items, End} = drain(Sess),
    ?assertEqual(<<"hello">>, iolist_to_binary(Items)),
    ?assertEqual({error, closed}, End),
    ?assertEqual({error, closed}, masque:recv(Sess, 100)).

tcp_connect(Transport, Port, TcpPort) ->
    masque:connect(
        proxy_uri(Port),
        {<<"127.0.0.1">>, TcpPort},
        #{
            transports => [Transport],
            protocol => tcp,
            verify => verify_none,
            mode => queue,
            rx_queue_limit => 2
        }
    ).

drain(Sess) ->
    drain(Sess, []).

drain(Sess, Acc) ->
    case masque:recv(Sess, 1000) of
        {ok, Bytes} -> drain(Sess, [Bytes | Acc]);
        Other -> {lists:reverse(Acc), Other}
    end.

with_tcp_h3(Config, Script, Fun) ->
    {TcpPid, TcpPort} = start_tcp_target(Script),
    {ok, Server} = masque_test_helpers:start_masque_server(
        maps:merge(?config(certs, Config), #{handler_opts => #{allow_private => true}})
    ),
    try
        Fun(maps:get(port, Server), TcpPort)
    after
        masque_test_helpers:stop_masque_server(Server),
        exit(TcpPid, shutdown)
    end.

with_tcp_h1(Config, Script, Fun) ->
    Certs = ?config(certs, Config),
    {TcpPid, TcpPort} = start_tcp_target(Script),
    Name = unique_name("rx_tcp_h1"),
    Opts = #{
        port => 0,
        cert => maps:get(cert_file, Certs),
        key => maps:get(key_file, Certs),
        allow_private => true
    },
    Parent = self(),
    Keeper = spawn(fun() ->
        {ok, R} = masque:start_listener_h1(Name, Opts),
        Parent ! {self(), started, h1:server_port(R)},
        receive
            stop -> masque:stop_listener_h1(Name)
        end
    end),
    Port =
        receive
            {Keeper, started, P} -> P
        after 5000 -> ct:fail(h1_keeper_timeout)
        end,
    try
        Fun(Port, TcpPort)
    after
        Keeper ! stop,
        exit(TcpPid, shutdown)
    end.

%% One-connection TCP target. `{chunks, N}' writes N separate 512-byte
%% chunks and stays open; `{send_and_close, Bin}' writes Bin and
%% closes.
start_tcp_target(Script) ->
    Parent = self(),
    Pid = spawn(fun() ->
        {ok, L} = gen_tcp:listen(0, [binary, {ip, {127, 0, 0, 1}}, {active, false}]),
        {ok, P} = inet:port(L),
        Parent ! {self(), port, P},
        {ok, S} = gen_tcp:accept(L),
        run_script(Script, S),
        receive
            stop -> ok
        end
    end),
    receive
        {Pid, port, Port} -> {Pid, Port}
    after 2000 -> ct:fail(tcp_target_timeout)
    end.

run_script({chunks, N}, S) ->
    [
        begin
            ok = gen_tcp:send(S, binary:copy(<<"x">>, 512)),
            timer:sleep(20)
        end
     || _ <- lists:seq(1, N)
    ],
    ok;
run_script({send_and_close, Bin}, S) ->
    ok = gen_tcp:send(S, Bin),
    timer:sleep(100),
    gen_tcp:close(S).

proxy_uri(Port) ->
    iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]).

unique_name(Prefix) ->
    list_to_atom(Prefix ++ "_" ++ integer_to_list(erlang:unique_integer([positive]))).

%% 192.0.2.1 -> 192.0.2.2 UDP, checksum left at zero.
sample_ipv4_udp() ->
    Udp = <<1000:16, 2000:16, 12:16, 0:16, "ping">>,
    Len = 20 + byte_size(Udp),
    Hdr0 = <<16#45, 0, Len:16, 0:16, 0:16, 64, 17, 0:16, 192, 0, 2, 1, 192, 0, 2, 2>>,
    Sum = checksum(Hdr0, 0),
    <<Pre:10/binary, 0:16, Post/binary>> = Hdr0,
    <<Pre/binary, Sum:16, Post/binary, Udp/binary>>.

checksum(<<A:16, Rest/binary>>, Acc) -> checksum(Rest, Acc + A);
checksum(<<>>, Acc) -> fold(Acc).

fold(Sum) when Sum > 16#FFFF -> fold((Sum band 16#FFFF) + (Sum bsr 16));
fold(Sum) -> bnot Sum band 16#FFFF.
