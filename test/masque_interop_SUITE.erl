%%% @doc Interop with quic-go's MASQUE libraries, over HTTP/3.
%%%
%%% Our client and server share code, so a mistake in both would pass
%%% every other suite. These cases run a third-party implementation in
%%% each role: every feature of the quic-go CONNECT-UDP (masque-go) and
%%% CONNECT-IP (connect-ip-go) clients against our proxy, and our
%%% clients against their proxies. The Go helper lives in `test/interop':
%%%
%%%   (cd test/interop && go build -o ../../_build/masque_interop .)
%%%   MASQUE_GO_BIN=$PWD/_build/masque_interop \
%%%     rebar3 ct --suite test/masque_interop_SUITE
%%%
%%% Skipped unless `MASQUE_GO_BIN' is set. CI builds and sets it.
-module(masque_interop_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("masque/include/masque_ip.hrl").

-export([suite/0, all/0, groups/0, init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    peer_udp_client_through_our_proxy/1,
    peer_udp_payload_sizes/1,
    peer_udp_tunnels_share_connection/1,
    peer_udp_ipv6_target/1,
    peer_udp_hostname_target/1,
    peer_udp_refused/1,
    peer_udp_close_ends_session/1,
    peer_udp_proxy_ends_tunnel/1,
    peer_ip_client_through_our_proxy/1,
    peer_ip_ipv6/1,
    peer_ip_routes/1,
    peer_ip_assigns_to_proxy/1,
    peer_ip_answers_proxy_request/1,
    peer_ip_dns_and_pref64_ignored/1,
    peer_ip_too_big_gets_icmp/1,
    peer_ip_tunnels_share_connection/1,
    peer_ip_close_ends_session/1,
    peer_ip_proxy_ends_tunnel/1,
    our_udp_client_through_peer_proxy/1,
    our_pooled_udp_clients_through_peer_proxy/1,
    our_ip_client_through_peer_proxy/1
]).
%% Called through a fun in `handler_opts'.
-export([ip_echo_gateway/2, lifecycle/3]).

-define(BIN_ENV, "MASQUE_GO_BIN").
-define(UDP_TEMPLATE, "/.well-known/masque/udp/{target_host}/{target_port}/").
-define(IP_PATH, "/.well-known/masque/ip/*/*/").
-define(GATEWAY, {10, 201, 0, 254}).
-define(GATEWAY6, {16#fd00, 16#201, 0, 0, 0, 0, 0, 16#fe}).

suite() -> [{timetrap, {seconds, 90}}].

all() ->
    [{group, peer_clients}, {group, our_clients}].

groups() ->
    [
        {peer_clients, [], [
            peer_udp_client_through_our_proxy,
            peer_udp_payload_sizes,
            peer_udp_tunnels_share_connection,
            peer_udp_ipv6_target,
            peer_udp_hostname_target,
            peer_udp_refused,
            peer_udp_close_ends_session,
            peer_udp_proxy_ends_tunnel,
            peer_ip_client_through_our_proxy,
            peer_ip_ipv6,
            peer_ip_routes,
            peer_ip_assigns_to_proxy,
            peer_ip_answers_proxy_request,
            peer_ip_dns_and_pref64_ignored,
            peer_ip_too_big_gets_icmp,
            peer_ip_tunnels_share_connection,
            peer_ip_close_ends_session,
            peer_ip_proxy_ends_tunnel
        ]},
        {our_clients, [], [
            our_udp_client_through_peer_proxy,
            our_pooled_udp_clients_through_peer_proxy,
            our_ip_client_through_peer_proxy
        ]}
    ].

init_per_suite(Config) ->
    case os:getenv(?BIN_ENV) of
        false ->
            {skip, "set MASQUE_GO_BIN to run interop; see the moduledoc"};
        Bin ->
            {ok, _} = application:ensure_all_started(masque),
            {ok, Certs} = masque_test_helpers:generate_certs(),
            {Echo, EchoPort} = start_udp_echo({127, 0, 0, 1}),
            {Echo6, EchoPort6} = start_udp_echo({0, 0, 0, 0, 0, 0, 0, 1}),
            [
                {bin, Bin},
                {certs, Certs},
                {echo, Echo},
                {echo_port, EchoPort},
                {echo6, Echo6},
                {echo_port6, EchoPort6}
                | Config
            ]
    end.

end_per_suite(Config) ->
    exit(?config(echo, Config), kill),
    exit(?config(echo6, Config), kill),
    masque_test_helpers:cleanup_certs(?config(certs, Config)),
    ok.

init_per_testcase(Case, Config) ->
    case lists:prefix("our_", atom_to_list(Case)) of
        true ->
            Config;
        false ->
            {ok, Server} = masque_test_helpers:start_masque_server(
                maps:merge(?config(certs, Config), listener_opts(Case))
            ),
            [{server, Server} | Config]
    end.

end_per_testcase(Case, Config) ->
    case lists:prefix("our_", atom_to_list(Case)) of
        true ->
            ok;
        false ->
            masque_test_helpers:stop_masque_server(?config(server, Config))
    end.

%% The proxy every peer client case talks to: CONNECT-UDP to the local
%% echo servers, CONNECT-IP with IPv4 and IPv6 pools and a gateway that
%% answers pings in both families.
listener_opts(Case) ->
    Handler = #{
        allow_private => true,
        allow_self => true,
        forward_fun => fun ?MODULE:ip_echo_gateway/2,
        lifecycle_fun => fun ?MODULE:lifecycle/3,
        report_to => self()
    },
    Base = #{
        address_pool => [{4, {10, 201, 0, 0}, 24}, {6, {16#fd00, 16#201, 0, 0, 0, 0, 0, 0}, 64}],
        routes => [
            #ip_route{
                version = 4,
                start_addr = {0, 0, 0, 0},
                end_addr = {255, 255, 255, 255},
                ip_protocol = 0
            },
            #ip_route{
                version = 6,
                start_addr = {0, 0, 0, 0, 0, 0, 0, 0},
                end_addr = {16#ffff, 16#ffff, 16#ffff, 16#ffff, 16#ffff, 16#ffff, 16#ffff, 16#ffff},
                ip_protocol = 0
            }
        ],
        handler_opts => Handler
    },
    case Case of
        peer_udp_refused ->
            Base#{handler_opts => Handler#{allow => fun(_) -> false end}};
        peer_ip_too_big_gets_icmp ->
            Base#{handler_opts => Handler#{mtu => 576}};
        Ended when Ended =:= peer_udp_proxy_ends_tunnel; Ended =:= peer_ip_proxy_ends_tunnel ->
            Base#{handler_opts => Handler#{idle_timeout_ms => 1000}};
        Scripted when
            Scripted =:= peer_ip_assigns_to_proxy; Scripted =:= peer_ip_answers_proxy_request
        ->
            Base#{ip_handler => masque_ip_script_handler, handler_opts => #{report => self()}};
        _ ->
            Base
    end.

%%====================================================================
%% quic-go CONNECT-UDP client (masque-go) through our proxy
%%====================================================================

peer_udp_client_through_our_proxy(Config) ->
    Out = udp_client(Config, target(Config), ["-payload", "ping"]),
    ?assertMatch({match, _}, re:run(Out, "^echo:ping$", [multiline])).

%% From one byte to a full datagram: every size comes back whole.
peer_udp_payload_sizes(Config) ->
    Out = udp_client(Config, target(Config), ["-sizes", "1,64,512,1024,1200"]),
    [
        ?assertMatch({match, _}, re:run(Out, "^echo:0:" ++ S ++ "$", [multiline]))
     || S <- ["1", "64", "512", "1024", "1200"]
    ].

%% Three tunnels over one QUIC connection (masque-go `ClientConn').
peer_udp_tunnels_share_connection(Config) ->
    Out = udp_client(Config, target(Config), ["-tunnels", "3", "-sizes", "100"]),
    [
        ?assertMatch({match, _}, re:run(Out, "^echo:" ++ T ++ ":100$", [multiline]))
     || T <- ["0", "1", "2"]
    ].

peer_udp_ipv6_target(Config) ->
    Target = io_lib:format("[::1]:~p", [?config(echo_port6, Config)]),
    Out = udp_client(Config, Target, ["-payload", "ping6"]),
    ?assertMatch({match, _}, re:run(Out, "^echo:ping6$", [multiline])).

peer_udp_hostname_target(Config) ->
    Target = io_lib:format("localhost:~p", [?config(echo_port, Config)]),
    Out = udp_client(Config, Target, ["-payload", "name"]),
    ?assertMatch({match, _}, re:run(Out, "^echo:name$", [multiline])).

%% A refusal reaches the Go client with its status and Proxy-Status.
peer_udp_refused(Config) ->
    Out = run(Config, ["udp-refused", "-t", udp_template(Config), "-target", target(Config)]),
    ?assertMatch(
        {match, _},
        re:run(Out, "^status:403 proxy-status:masque; error=destination_ip_prohibited$", [multiline])
    ).

%% The Go client closes its tunnel while its QUIC connection stays up:
%% our session ends.
peer_udp_close_ends_session(Config) ->
    Port = start_helper(Config, [
        "udp-client", "-t", udp_template(Config), "-target", target(Config), "-mode", "close"
    ]),
    await_line(Port, "closed"),
    ?assertEqual([], wait_no_sessions(1500)),
    stop_helper(Port).

%% Our proxy ends the tunnel (idle timeout): the Go client sees it end.
peer_udp_proxy_ends_tunnel(Config) ->
    Out = udp_client(Config, target(Config), ["-mode", "wait"]),
    ?assertMatch({match, _}, re:run(Out, "^ended$", [multiline])).

%%====================================================================
%% quic-go CONNECT-IP client (connect-ip-go) through our proxy
%%====================================================================

peer_ip_client_through_our_proxy(Config) ->
    Out = ip_client(Config, ["-gateway", "10.201.0.254"]),
    ?assertMatch(
        {match, _}, re:run(Out, "assigned:10\\.201\\.0\\.1 reply-from:10\\.201\\.0\\.254")
    ).

peer_ip_ipv6(Config) ->
    Out = ip_client(Config, ["-family", "6", "-gateway", "fd00:201::fe"]),
    ?assertMatch({match, _}, re:run(Out, "assigned:fd00:201::1 reply-from:fd00:201::fe")).

%% The Go client reads the routes we advertise, in both families.
peer_ip_routes(Config) ->
    Out = ip_client(Config, ["-mode", "routes"]),
    ?assertMatch({match, _}, re:run(Out, "0\\.0\\.0\\.0-255\\.255\\.255\\.255/0")),
    ?assertMatch({match, _}, re:run(Out, "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0")).

%% RFC 9484 section 4.7: the client may assign addresses and advertise
%% routes to the proxy; our handler receives both.
peer_ip_assigns_to_proxy(Config) ->
    Out = ip_client(Config, ["-mode", "to-proxy"]),
    ?assertMatch({match, _}, re:run(Out, "^sent$", [multiline])),
    receive
        {script, address_assign, [#ip_assignment{address = {192, 0, 2, 7}, prefix_len = 32}]} -> ok
    after 5000 -> ct:fail(no_assign_from_client)
    end,
    receive
        {script, route_advertisement, [
            #ip_route{start_addr = {192, 0, 2, 0}, end_addr = {192, 0, 2, 255}}
        ]} ->
            ok
    after 5000 -> ct:fail(no_routes_from_client)
    end.

%% Our proxy asks the Go client for an address and gets its answer.
peer_ip_answers_proxy_request(Config) ->
    Port = start_helper(Config, ["ip-client", "-url", ip_url(Config), "-mode", "answer"]),
    Session =
        receive
            {script, init, Pid} -> Pid
        after 10000 -> ct:fail(no_session)
        end,
    Session ! {script_actions, [{request_addresses, [{4, {0, 0, 0, 0}, 32}]}]},
    await_line(Port, "answered"),
    receive
        {script, address_assign, [#ip_assignment{address = {10, 77, 0, 1}}]} -> ok
    after 5000 -> ct:fail(no_answer_from_client)
    end,
    stop_helper(Port).

%% connect-ip-go sends DNS configuration and PREF64 capsules
%% (draft-ietf-masque-connect-ip-dns), which masque does not implement:
%% they are skipped as unknown capsules and the tunnel goes on.
peer_ip_dns_and_pref64_ignored(Config) ->
    Out = ip_client(Config, ["-mode", "dns", "-gateway", "10.201.0.254"]),
    ?assertMatch({match, _}, re:run(Out, "reply-from:10\\.201\\.0\\.254")).

%% A packet larger than the proxy's MTU (576 here) is dropped and
%% answered with ICMP Fragmentation Needed (type 3, code 4), which the
%% Go client reads (RFC 9484 section 10.1).
peer_ip_too_big_gets_icmp(Config) ->
    Out = ip_client(Config, ["-mode", "too-big", "-size", "700", "-gateway", "10.201.0.254"]),
    ?assertMatch({match, _}, re:run(Out, "^icmp:3/4$", [multiline])).

%% Two CONNECT-IP tunnels over one QUIC connection get different
%% addresses.
peer_ip_tunnels_share_connection(Config) ->
    Out = ip_client(Config, ["-mode", "two"]),
    ?assertMatch({match, _}, re:run(Out, "two:10\\.201\\.0\\.[0-9]+,10\\.201\\.0\\.[0-9]+")).

peer_ip_close_ends_session(Config) ->
    Port = start_helper(Config, ["ip-client", "-url", ip_url(Config), "-mode", "close"]),
    await_line(Port, "closed"),
    ?assertEqual([], wait_no_sessions(1500)),
    stop_helper(Port).

peer_ip_proxy_ends_tunnel(Config) ->
    Out = ip_client(Config, ["-mode", "wait"]),
    ?assertMatch({match, _}, re:run(Out, "^ended$", [multiline])).

%%====================================================================
%% Our clients through quic-go's proxies
%%====================================================================

our_udp_client_through_peer_proxy(Config) ->
    with_peer_proxy(Config, udp, fun(ProxyPort) ->
        Sess = connect_udp(Config, ProxyPort, #{}),
        ok = echo(Sess, <<"ping">>, 20),
        masque:close(Sess)
    end).

%% Two pooled tunnels to the Go proxy share one QUIC connection.
our_pooled_udp_clients_through_peer_proxy(Config) ->
    with_peer_proxy(Config, udp, fun(ProxyPort) ->
        Before = length(upstream_owners()),
        A = connect_udp(Config, ProxyPort, #{upstream_pool => true}),
        B = connect_udp(Config, ProxyPort, #{upstream_pool => true}),
        ok = echo(A, <<"a">>, 20),
        ok = echo(B, <<"b">>, 20),
        ?assertEqual(Before + 1, length(upstream_owners())),
        masque:close(A),
        masque:close(B)
    end).

%% Our CONNECT-IP client through connect-ip-go's proxy: an address, the
%% proxy's route, and a ping answered.
our_ip_client_through_peer_proxy(Config) ->
    with_peer_proxy(Config, ip, fun(ProxyPort) ->
        Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(ProxyPort)]),
        {ok, Sess} = masque:connect(Uri, {'*', '*'}, #{
            protocol => ip,
            transports => [h3],
            verify => verify_none,
            timeout => 5000,
            uri_template => iolist_to_binary([Uri, "/.well-known/masque/ip/{target}/{ipproto}/"])
        }),
        Routes =
            receive
                {masque_route_advertisement, Sess, R} -> R
            after 5000 -> ct:fail(no_routes)
            end,
        ?assertMatch([#ip_route{start_addr = {10, 88, 0, 0}, end_addr = {10, 88, 0, 255}}], Routes),
        {ok, [Id]} = masque:request_addresses(Sess, [{4, {0, 0, 0, 0}, 32}]),
        Addr =
            receive
                {masque_address_assign, Sess, [#ip_assignment{request_id = Id, address = A}]} -> A
            after 5000 -> ct:fail(no_address)
            end,
        ?assertEqual({10, 88, 0, 1}, Addr),
        ok = masque:send_ip_packet(Sess, icmp_echo(Addr, {10, 88, 0, 254})),
        receive
            {masque_ip_packet, Sess, <<4:4, _:92, 10, 88, 0, 254, _/binary>>} -> ok
        after 5000 -> ct:fail(no_echo_reply)
        end,
        masque:close(Sess)
    end).

%%====================================================================
%% Helpers
%%====================================================================

%% `forward_fun': answer pings to the gateway, in both families.
ip_echo_gateway(<<4:4, _/bitstring>> = Packet, State) ->
    <<_:96, Src:4/binary, _/binary>> = Packet,
    {A, B, C, D} = ?GATEWAY,
    <<Head:12/binary, _:8/binary, Rest0/binary>> = Packet,
    %% Turn the echo request (type 8) into a reply (type 0).
    <<_Type, Code, _Sum:16, IcmpRest/binary>> = Rest0,
    Icmp0 = <<0, Code, 0:16, IcmpRest/binary>>,
    IcmpSum = masque_ip_packet:checksum(Icmp0),
    <<_:32, IcmpTail/binary>> = Icmp0,
    Rest = <<0, Code, IcmpSum:16, IcmpTail/binary>>,
    H0 = <<Head/binary, A, B, C, D, Src/binary>>,
    <<Before:10/binary, _:16, After/binary>> = H0,
    Zeroed = <<Before/binary, 0:16, After/binary>>,
    Sum = masque_ip_packet:checksum(Zeroed),
    {reply, <<Before/binary, Sum:16, After/binary, Rest/binary>>, State};
ip_echo_gateway(<<6:4, _/bitstring>> = Packet, State) ->
    case masque_icmp:echo_reply(?GATEWAY6, Packet) of
        {ok, Reply} -> {reply, Reply, State};
        error -> {drop, State}
    end.

%% `lifecycle_fun' of the default handler; the cases above do not need
%% its events.
lifecycle(_Event, _Data, _Opts) ->
    ok.

udp_template(Config) ->
    #{port := Port} = ?config(server, Config),
    io_lib:format("https://127.0.0.1:~p~s", [Port, ?UDP_TEMPLATE]).

ip_url(Config) ->
    #{port := Port} = ?config(server, Config),
    io_lib:format("https://127.0.0.1:~p~s", [Port, ?IP_PATH]).

target(Config) ->
    io_lib:format("127.0.0.1:~p", [?config(echo_port, Config)]).

udp_client(Config, Target, Extra) ->
    Out = run(Config, ["udp-client", "-t", udp_template(Config), "-target", Target | Extra]),
    %% quic-go may log warnings about socket buffers around the result.
    ct:log("~s", [Out]),
    Out.

ip_client(Config, Extra) ->
    Out = run(Config, ["ip-client", "-url", ip_url(Config) | Extra]),
    ct:log("~s", [Out]),
    Out.

run(Config, Args) ->
    Port = open_port(
        {spawn_executable, ?config(bin, Config)},
        [
            binary,
            exit_status,
            stderr_to_stdout,
            {args, [lists:flatten(A) || A <- Args]}
        ]
    ),
    collect(Port, []).

collect(Port, Acc) ->
    receive
        {Port, {data, Bin}} ->
            collect(Port, [Bin | Acc]);
        {Port, {exit_status, 0}} ->
            binary_to_list(iolist_to_binary(lists:reverse(Acc)));
        {Port, {exit_status, Code}} ->
            ct:fail({helper_failed, Code, iolist_to_binary(lists:reverse(Acc))})
    after 45000 ->
        ct:fail(helper_stuck)
    end.

%% A helper that keeps running while the case checks our side.
start_helper(Config, Args) ->
    open_port(
        {spawn_executable, ?config(bin, Config)},
        [
            binary,
            {line, 512},
            exit_status,
            stderr_to_stdout,
            {args, [lists:flatten(A) || A <- Args]}
        ]
    ).

await_line(Port, Line) ->
    Want = list_to_binary(Line),
    receive
        {Port, {data, {eol, Want}}} ->
            ok;
        {Port, {data, {_, Other}}} ->
            ct:log("helper: ~s", [Other]),
            await_line(Port, Line);
        {Port, {exit_status, Code}} ->
            ct:fail({helper_exited, Code})
    after 15000 ->
        ct:fail({helper_did_not_print, Line})
    end.

stop_helper(Port) ->
    case erlang:port_info(Port, os_pid) of
        {os_pid, Pid} -> _ = os:cmd("kill " ++ integer_to_list(Pid));
        undefined -> ok
    end,
    %% On Linux the port may already have closed with the process.
    try
        port_close(Port)
    catch
        error:badarg -> ok
    end.

with_peer_proxy(Config, Kind, Fun) ->
    #{cert_file := Cert, key_file := Key} = ?config(certs, Config),
    Args =
        case Kind of
            udp -> ["proxy", "-t", "https://127.0.0.1:0" ++ ?UDP_TEMPLATE, "-c", Cert, "-k", Key];
            ip -> ["ip-proxy", "-c", Cert, "-k", Key]
        end,
    Port = open_port(
        {spawn_executable, ?config(bin, Config)},
        [binary, {line, 256}, exit_status, {args, Args}]
    ),
    try
        Fun(await_ready(Port))
    after
        stop_helper(Port)
    end.

await_ready(Port) ->
    receive
        {Port, {data, {eol, <<"ready:", P/binary>>}}} ->
            binary_to_integer(P);
        {Port, {data, {_, Other}}} ->
            ct:log("helper: ~s", [Other]),
            await_ready(Port);
        {Port, {exit_status, Code}} ->
            ct:fail({helper_exited, Code})
    after 10000 ->
        ct:fail(helper_not_ready)
    end.

connect_udp(Config, ProxyPort, Opts) ->
    Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(ProxyPort)]),
    {ok, Sess} = masque:connect(
        Uri,
        {<<"127.0.0.1">>, ?config(echo_port, Config)},
        Opts#{transports => [h3], verify => verify_none, timeout => 5000}
    ),
    Sess.

echo(_Sess, _Payload, 0) ->
    ct:fail(no_echo);
echo(Sess, Payload, N) ->
    ok = masque:send(Sess, Payload),
    receive
        {masque_data, Sess, Payload} -> ok
    after 500 -> echo(Sess, Payload, N - 1)
    end.

icmp_echo({SA, SB, SC, SD}, {DA, DB, DC, DD}) ->
    Icmp0 = <<8, 0, 0:16, 0, 1, 0, 1, "ping">>,
    IcmpSum = masque_ip_packet:checksum(Icmp0),
    <<_:32, IcmpTail/binary>> = Icmp0,
    Icmp = <<8, 0, IcmpSum:16, IcmpTail/binary>>,
    Total = 20 + byte_size(Icmp),
    H0 = <<4:4, 5:4, 0, Total:16, 0:16, 0:16, 64, 1, 0:16, SA, SB, SC, SD, DA, DB, DC, DD>>,
    Sum = masque_ip_packet:checksum(H0),
    <<Before:10/binary, 0:16, After/binary>> = H0,
    <<Before/binary, Sum:16, After/binary, Icmp/binary>>.

%% Server sessions still alive on this node.
wait_no_sessions(Left) when Left =< 0 ->
    server_sessions();
wait_no_sessions(Left) ->
    case server_sessions() of
        [] ->
            [];
        _ ->
            timer:sleep(100),
            wait_no_sessions(Left - 100)
    end.

server_sessions() ->
    [
        P
     || P <- processes(),
        {dictionary, D} <- [process_info(P, dictionary)],
        {_, {Mod, _, _}} <- [lists:keyfind('$initial_call', 1, D)],
        lists:suffix("server_session", atom_to_list(Mod))
    ].

upstream_owners() ->
    [
        P
     || P <- processes(),
        {dictionary, D} <- [process_info(P, dictionary)],
        {_, {masque_upstream_owner, _, _}} <- [lists:keyfind('$initial_call', 1, D)]
    ].

start_udp_echo(IP) ->
    Family =
        case tuple_size(IP) of
            4 -> inet;
            8 -> inet6
        end,
    {ok, Sock} = gen_udp:open(0, [binary, Family, {active, false}, {ip, IP}]),
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
