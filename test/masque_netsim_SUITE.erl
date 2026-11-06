%%% @doc Network changes on simulated Wi-Fi and mobile networks.
%%%
%%% `test/netsim/setup.sh' builds Linux network namespaces: the client has
%%% a Wi-Fi and a mobile interface, each behind its own NAT with its own
%%% delay, loss and MTU, and the proxy sits beyond both. Cases take links
%%% down and up as an OS sees it happen. A watcher here notices through
%%% `inet:getifaddrs/0' and calls `masque:migrate/1', as an agent would.
%%%
%%% Needs root inside the `mq_cli' namespace, so it is skipped unless
%%% `MASQUE_NETSIM=1'. CI runs it; locally use `test/netsim/run-docker.sh'.
-module(masque_netsim_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("masque/include/masque_ip.hrl").

-export([suite/0, all/0, init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    mobile_download_baseline/1,
    wifi_to_mobile_download/1,
    mobile_to_wifi_upload/1,
    back_and_forth_full_duplex/1,
    udp_gap/1,
    ip_tunnel_switch/1,
    bind_switch/1,
    outage_then_mobile/1,
    nat_mapping_expires/1,
    nat_flush_mid_transfer/1,
    small_mtu_mobile/1,
    reordering_mobile/1,
    migrate_without_network/1
]).

-define(PROXY, "203.0.113.1").
-define(WIFI_NAT, {192, 168, 100, 2}).
-define(MOBILE_NAT, {192, 168, 100, 6}).
%% Must match masque_netsim_server.
-define(BYTES, 16 * 1024 * 1024).
-define(REORDER_BYTES, 1024 * 1024).
-define(CHUNK, 16 * 1024).
-define(STALL_MS, 60000).
-define(GATEWAY, {10, 203, 0, 254}).

suite() -> [{timetrap, {minutes, 5}}].

all() ->
    [
        mobile_download_baseline,
        wifi_to_mobile_download,
        mobile_to_wifi_upload,
        back_and_forth_full_duplex,
        udp_gap,
        ip_tunnel_switch,
        bind_switch,
        outage_then_mobile,
        nat_mapping_expires,
        nat_flush_mid_transfer,
        small_mtu_mobile,
        reordering_mobile,
        migrate_without_network
    ].

init_per_suite(Config) ->
    case {os:getenv("MASQUE_NETSIM"), string:trim(os:cmd("ip netns identify"))} of
        {"1", "mq_cli"} -> start(Config);
        _ -> {skip, "needs MASQUE_NETSIM=1 inside the mq_cli namespace; see the moduledoc"}
    end.

start(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Certs} = masque_test_helpers:generate_certs(),
    Paths = [P || P <- code:get_path(), string:find(P, "_build") =/= nomatch],
    {ok, Peer, _Node} = peer:start(#{
        name => masque_netsim_srv,
        exec => {os:find_executable("ip"), ["netns", "exec", "mq_srv", os:find_executable("erl")]},
        connection => standard_io,
        args => lists:append([["-pa", P] || P <- Paths])
    }),
    Log = filename:join(?config(priv_dir, Config), "proxy.log"),
    Ports = peer:call(
        Peer, masque_netsim_server, start, [(maps:with([cert, key], Certs))#{log => Log}], 30000
    ),
    ct:log("proxy ports ~p", [Ports]),
    register(masque_netsim_peer, Peer),
    [{certs, Certs}, {peer, Peer}, {ports, Ports}, {proxy_log, Log} | Config].

end_per_suite(Config) ->
    peer:stop(?config(peer, Config)),
    masque_test_helpers:cleanup_certs(?config(certs, Config)),
    ok.

%% Every case starts on Wi-Fi with both links up.
init_per_testcase(_Case, Config) ->
    sh("ip link set wifi0 up"),
    sh("ip link set lte0 up"),
    sh("ip route replace default via 10.10.1.1 dev wifi0 metric 100"),
    sh("ip route replace default via 10.10.2.1 dev lte0 metric 200"),
    Mtu = os:getenv("LTE_MTU", "1380"),
    sh("ip link set lte0 mtu " ++ Mtu),
    sh("ip netns exec mq_lte ip link set l_in mtu " ++ Mtu),
    sh("ip netns exec mq_wifi sysctl -qw net.netfilter.nf_conntrack_udp_timeout=30"),
    sh("ip netns exec mq_wifi sysctl -qw net.netfilter.nf_conntrack_udp_timeout_stream=120"),
    wait_route("wifi0"),
    Config.

end_per_testcase(Case, Config) ->
    stop_watcher(),
    case Case of
        reordering_mobile -> netem("delay 40ms loss 0.5%");
        _ -> ok
    end,
    case file:read_file(?config(proxy_log, Config)) of
        {ok, Log} -> ct:log("proxy log so far:~n~s", [Log]);
        _ -> ok
    end,
    Config.

%%====================================================================
%% Cases
%%====================================================================

%% The same download on the mobile path with no change, to tell path
%% trouble from migration trouble.
mobile_download_baseline(Config) ->
    to_mobile(),
    Sess = connect_tcp(Config),
    ok = send(Sess, <<"down">>),
    Got = recv(Sess, ?BYTES),
    ?assertEqual(sha(payload()), sha(Got)),
    masque:close(Sess).

wifi_to_mobile_download(Config) ->
    Sess = connect_tcp(Config),
    watch([Sess]),
    ok = send(Sess, <<"down">>),
    First = recv(Sess, ?BYTES div 4),
    to_mobile(),
    Rest = recv(Sess, ?BYTES - byte_size(First)),
    ?assertEqual(sha(payload()), sha(<<First/binary, Rest/binary>>)),
    assert_proxy_sees(Config, ?MOBILE_NAT),
    masque:close(Sess).

mobile_to_wifi_upload(Config) ->
    to_mobile(),
    Sess = connect_tcp(Config),
    watch([Sess]),
    ok = send(Sess, <<"sink">>),
    <<First:(?BYTES div 4)/binary, Rest/binary>> = payload(),
    ok = send_all(Sess, First),
    to_wifi(),
    ok = send_all(Sess, Rest),
    Sum = sha(payload()),
    ?assertEqual(Sum, recv(Sess, byte_size(Sum))),
    assert_proxy_sees(Config, ?WIFI_NAT),
    masque:close(Sess).

%% Three switches while data flows both ways.
back_and_forth_full_duplex(Config) ->
    Sess = connect_tcp(Config),
    watch([Sess]),
    ok = send(Sess, <<"echo">>),
    {Sender, MRef} = spawn_monitor(fun() -> exit({sent, send_all(Sess, payload())}) end),
    Quarter = ?BYTES div 4,
    A = recv(Sess, Quarter),
    to_mobile(),
    B = recv(Sess, Quarter),
    to_wifi(),
    C = recv(Sess, Quarter),
    to_mobile(),
    %% Each `recv' may return a little more than it was asked for.
    D = recv(Sess, ?BYTES - byte_size(A) - byte_size(B) - byte_size(C)),
    receive
        {'DOWN', MRef, process, Sender, {sent, ok}} -> ok;
        {'DOWN', MRef, process, Sender, Other} -> ct:fail({sender, Other})
    after ?STALL_MS -> ct:fail(sender_stuck)
    end,
    ?assertEqual(sha(payload()), sha(<<A/binary, B/binary, C/binary, D/binary>>)),
    masque:close(Sess).

%% Datagrams every 10 ms across a switch: how long is the gap?
udp_gap(Config) ->
    %% Datagrams are timestamped as they arrive, by their own owner.
    Collector = spawn_link(fun() -> udp_collector([]) end),
    Sess = connect(Config, {<<"127.0.0.1">>, port(Config, udp)}, #{owner => Collector}),
    watch([Sess]),
    Sender = spawn_link(fun() -> udp_sender(Sess, 0) end),
    timer:sleep(1000),
    to_mobile(),
    timer:sleep(4000),
    unlink(Sender),
    exit(Sender, kill),
    Collector ! {times, self()},
    Times =
        receive
            {times, T} -> T
        after 5000 -> ct:fail(no_times)
        end,
    Gap = longest_gap(lists:sort(Times)),
    ct:pal("udp: ~p datagrams back, longest gap ~p ms", [length(Times), Gap]),
    ?assert(length(Times) > 100),
    ?assert(Gap < 3000),
    assert_proxy_sees(Config, ?MOBILE_NAT),
    masque:close(Sess).

ip_tunnel_switch(Config) ->
    Sess = connect(Config, {'*', '*'}, #{protocol => ip}),
    watch([Sess]),
    {ok, [Id]} = masque:request_addresses(Sess, [{4, {0, 0, 0, 0}, 32}]),
    Addr =
        receive
            {masque_address_assign, Sess, [#ip_assignment{request_id = Id, address = A}]} -> A
        after 5000 -> ct:fail(no_address)
        end,
    Packet = ipv4(Addr, ?GATEWAY, binary:copy(<<"i">>, 1200)),
    ok = ip_echo(Sess, Packet, 40),
    to_mobile(),
    ok = ip_echo(Sess, Packet, 80),
    masque:close(Sess).

bind_switch(Config) ->
    {ok, Sess} = masque:bind_connect(uri(Config), unscoped, #{
        transports => [h3], verify => verify_none, timeout => 10000
    }),
    watch([Sess]),
    {ok, Ctx} = masque:open_uncompressed_context(Sess),
    receive
        {masque_compression_acked, Sess, Ctx} -> ok
    after 5000 -> ct:fail(no_ack)
    end,
    %% The peer is the proxy's own UDP echo, reached from the bind socket.
    Peer = {{127, 0, 0, 1}, port(Config, udp)},
    ok = bind_echo(Sess, Peer, <<"before">>, 40),
    to_mobile(),
    ok = bind_echo(Sess, Peer, <<"after">>, 80),
    masque:close(Sess).

%% No network at all for 5 s, then only mobile comes back.
outage_then_mobile(Config) ->
    Sess = connect_tcp(Config),
    watch([Sess]),
    ok = send(Sess, <<"down">>),
    First = recv(Sess, ?BYTES div 4),
    sh("ip link set wifi0 down"),
    sh("ip link set lte0 down"),
    timer:sleep(5000),
    sh("ip link set lte0 up"),
    sh("ip route replace default via 10.10.2.1 dev lte0 metric 200"),
    wait_route("lte0"),
    Rest = recv(Sess, ?BYTES - byte_size(First)),
    ?assertEqual(sha(payload()), sha(<<First/binary, Rest/binary>>)),
    assert_proxy_sees(Config, ?MOBILE_NAT),
    masque:close(Sess).

%% A NAT that forgets quiet UDP mappings after 5 s, shorter than the QUIC
%% keepalive. The next packet gets a new mapping the proxy has to follow.
nat_mapping_expires(Config) ->
    sh("ip netns exec mq_wifi sysctl -qw net.netfilter.nf_conntrack_udp_timeout=5"),
    sh("ip netns exec mq_wifi sysctl -qw net.netfilter.nf_conntrack_udp_timeout_stream=5"),
    Sess = connect_tcp(Config),
    ok = send(Sess, <<"echo">>),
    ok = send(Sess, <<"before">>),
    <<"before">> = recv(Sess, 6),
    timer:sleep(25000),
    ok = send(Sess, <<"after">>),
    <<"after">> = recv(Sess, 5),
    masque:close(Sess).

%% The NAT drops every mapping mid-transfer.
nat_flush_mid_transfer(Config) ->
    Sess = connect_tcp(Config),
    ok = send(Sess, <<"down">>),
    First = recv(Sess, ?BYTES div 4),
    sh("ip netns exec mq_wifi conntrack -F"),
    Rest = recv(Sess, ?BYTES - byte_size(First)),
    ?assertEqual(sha(payload()), sha(<<First/binary, Rest/binary>>)),
    masque:close(Sess).

%% Some mobile paths carry only 1280 bytes, QUIC's minimum.
small_mtu_mobile(Config) ->
    sh("ip link set lte0 mtu 1280"),
    sh("ip netns exec mq_lte ip link set l_in mtu 1280"),
    Sess = connect_tcp(Config),
    watch([Sess]),
    ok = send(Sess, <<"down">>),
    First = recv(Sess, ?BYTES div 4),
    to_mobile(),
    Rest = recv(Sess, ?BYTES - byte_size(First)),
    ?assertEqual(sha(payload()), sha(<<First/binary, Rest/binary>>)),
    masque:close(Sess).

%% An agent may notice the change while there is no network at all, and
%% move then. The tunnel has to wait for a network, not die.
migrate_without_network(Config) ->
    Sess = connect_tcp(Config),
    ok = send(Sess, <<"down">>),
    First = recv(Sess, ?BYTES div 4),
    sh("ip link set wifi0 down"),
    sh("ip link set lte0 down"),
    Moved = masque:migrate(Sess),
    ct:log("migrate with no network: ~p", [Moved]),
    timer:sleep(3000),
    sh("ip link set lte0 up"),
    sh("ip route replace default via 10.10.2.1 dev lte0 metric 200"),
    wait_route("lte0"),
    ct:log("migrate on mobile: ~p", [masque:migrate(Sess)]),
    Rest = recv(Sess, ?BYTES - byte_size(First)),
    ?assertEqual(sha(payload()), sha(<<First/binary, Rest/binary>>)),
    masque:close(Sess).

%% Heavy reordering on the mobile path. QUIC slows down badly here (it
%% counts reordered packets as lost), so this checks that tunnels keep
%% going, not how fast.
reordering_mobile(Config) ->
    Sess = connect_tcp(Config),
    netem("delay 40ms 10ms loss 0.5%"),
    watch([Sess]),
    ok = send(Sess, <<"down">>),
    First = recv(Sess, ?REORDER_BYTES div 4),
    to_mobile(),
    Rest = recv(Sess, ?REORDER_BYTES - byte_size(First)),
    Got = binary:part(<<First/binary, Rest/binary>>, 0, ?REORDER_BYTES),
    ?assertEqual(sha(binary:part(payload(), 0, ?REORDER_BYTES)), sha(Got)),
    masque:close(Sess).

%%====================================================================
%% Network control

netem(Spec) ->
    sh("tc qdisc change dev lte0 root netem " ++ Spec),
    sh("ip netns exec mq_lte tc qdisc change dev l_in root netem " ++ Spec),
    sh("tc qdisc change dev wifi0 root netem " ++ Spec),
    sh("ip netns exec mq_wifi tc qdisc change dev w_in root netem " ++ Spec).

%%====================================================================

to_mobile() ->
    sh("ip link set wifi0 down"),
    wait_route("lte0").

%% Linux drops the routes through a link that goes down, so they come
%% back with it, as a network manager would do.
to_wifi() ->
    sh("ip link set wifi0 up"),
    sh("ip route replace default via 10.10.1.1 dev wifi0 metric 100"),
    wait_route("wifi0").

%% Wait until the kernel routes to the proxy through `Dev'.
wait_route(Dev) ->
    wait_route(Dev, 50).

wait_route(Dev, 0) ->
    ct:fail({no_route_via, Dev, os:cmd("ip route")});
wait_route(Dev, N) ->
    case string:find(os:cmd("ip route get " ++ ?PROXY), "dev " ++ Dev) of
        nomatch ->
            timer:sleep(100),
            wait_route(Dev, N - 1);
        _ ->
            ok
    end.

sh(Cmd) ->
    Out = os:cmd(Cmd ++ " 2>&1; echo \"exit:$?\""),
    case string:split(string:trim(Out), "exit:", trailing) of
        [_, "0"] -> ok;
        _ -> ct:fail({command_failed, Cmd, Out})
    end.

%% The watcher plays the agent: it sees the interfaces change and moves
%% every tunnel it was given.
watch(Sessions) ->
    stop_watcher(),
    Pid = spawn(fun() -> watcher(Sessions, interfaces()) end),
    register(masque_netsim_watcher, Pid),
    ok.

stop_watcher() ->
    case whereis(masque_netsim_watcher) of
        undefined -> ok;
        Pid -> exit(Pid, kill)
    end.

%% It moves once a network is up again: moving with none can lose the
%% connection (see `migrate_without_network').
watcher(Sessions, Seen) ->
    timer:sleep(100),
    case interfaces() of
        Seen ->
            watcher(Sessions, Seen);
        [] ->
            ct:log("interfaces ~p -> none, waiting for a network", [Seen]),
            watcher(Sessions, []);
        Now ->
            ct:log("interfaces ~p -> ~p, migrating", [Seen, Now]),
            [migrate(S, 50) || S <- Sessions],
            watcher(Sessions, Now)
    end.

migrate(_Sess, 0) ->
    ct:log("no spare connection id");
migrate(Sess, N) ->
    Result =
        try
            masque:migrate(Sess)
        catch
            exit:Reason -> {exit, Reason}
        end,
    case Result of
        ok ->
            ok;
        {error, no_available_connection_id} ->
            timer:sleep(100),
            migrate(Sess, N - 1);
        Other ->
            ct:log("migrate: ~p", [Other])
    end.

interfaces() ->
    {ok, Ifs} = inet:getifaddrs(),
    lists:sort([
        {Name, A}
     || {Name, Opts} <- Ifs,
        Name =/= "lo",
        lists:member(running, proplists:get_value(flags, Opts, [])),
        {addr, {_, _, _, _} = A} <- Opts
    ]).

assert_proxy_sees(Config, IP) ->
    assert_proxy_sees(Config, IP, 100).

assert_proxy_sees(Config, IP, 0) ->
    ct:fail({proxy_never_saw, IP, proxy_peers(Config)});
assert_proxy_sees(Config, IP, N) ->
    case lists:member(IP, proxy_peers(Config)) of
        true ->
            ok;
        false ->
            timer:sleep(100),
            assert_proxy_sees(Config, IP, N - 1)
    end.

proxy_peers(Config) ->
    peer:call(?config(peer, Config), masque_netsim_server, peers, []).

%%====================================================================
%% Client helpers
%%====================================================================

port(Config, Key) -> maps:get(Key, ?config(ports, Config)).

uri(Config) ->
    iolist_to_binary(["https://", ?PROXY, ":", integer_to_list(port(Config, proxy))]).

connect_tcp(Config) ->
    connect(Config, {<<"127.0.0.1">>, port(Config, tcp)}, #{protocol => tcp}).

connect(Config, Target, Opts) ->
    {ok, Sess} = masque:connect(uri(Config), Target, Opts#{
        transports => [h3], verify => verify_none, timeout => 10000
    }),
    Sess.

send(Sess, Bytes) ->
    send(Sess, Bytes, 6000).

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
        ct:fail({stalled, Got, Want, diagnose(Sess)})
    end.

%% Where a stalled tunnel is stuck, on both sides.
diagnose(Sess) ->
    Client =
        try
            {_, Data} = sys:get_state(Sess, 1000),
            Q = quic_h3:get_quic_conn(element(10, Data)),
            #{queue => quic:get_send_queue_info(Q), stats => quic:get_stats(Q)}
        catch
            C:R -> {C, R}
        end,
    Proxy =
        case whereis(masque_netsim_peer) of
            undefined -> no_peer;
            Peer -> peer:call(Peer, masque_netsim_server, diagnose, [])
        end,
    #{client => Client, proxy => Proxy}.

udp_sender(Sess, N) ->
    _ = masque:send(Sess, <<N:32>>),
    timer:sleep(10),
    udp_sender(Sess, N + 1).

udp_collector(Acc) ->
    receive
        {masque_data, _Sess, <<_:32>>} ->
            udp_collector([erlang:monotonic_time(millisecond) | Acc]);
        {times, From} ->
            From ! {times, Acc};
        _ ->
            udp_collector(Acc)
    end.

longest_gap([First | Rest]) ->
    {_, Gap} = lists:foldl(fun(T, {Prev, G}) -> {T, max(G, T - Prev)} end, {First, 0}, Rest),
    Gap;
longest_gap([]) ->
    infinity.

ip_echo(_Sess, _Packet, 0) ->
    ct:fail(no_ip_echo);
ip_echo(Sess, Packet, N) ->
    _ = masque:send_ip_packet(Sess, Packet),
    receive
        {masque_ip_packet, Sess, _} -> ok;
        {masque_closed, Sess, Reason} -> ct:fail({closed, Reason})
    after 250 -> ip_echo(Sess, Packet, N - 1)
    end.

bind_echo(_Sess, _Peer, Msg, 0) ->
    ct:fail({no_bind_echo, Msg});
bind_echo(Sess, Peer, Msg, N) ->
    _ = masque:send_to(Sess, Peer, Msg),
    receive
        {masque_bind_packet, Sess, Peer, Msg} -> ok;
        {masque_closed, Sess, Reason} -> ct:fail({closed, Reason})
    after 250 -> bind_echo(Sess, Peer, Msg, N - 1)
    end.

payload() ->
    binary:copy(<<"0123456789abcdef">>, ?BYTES div 16).

sha(Bin) -> crypto:hash(sha256, Bin).

ipv4({A, B, C, D}, {E, F, G, H}, Body) ->
    Total = 20 + byte_size(Body),
    H0 = <<4:4, 5:4, 0, Total:16, 0:16, 0:16, 64, 17, 0:16, A, B, C, D, E, F, G, H>>,
    Sum = masque_ip_packet:checksum(H0),
    <<Before:10/binary, 0:16, After/binary>> = H0,
    <<Before/binary, Sum:16, After/binary, Body/binary>>.
