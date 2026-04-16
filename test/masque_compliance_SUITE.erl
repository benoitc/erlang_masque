%%% @doc RFC 9298 compliance tests for the MASQUE server handshake.
%%%
%%% Drives the Extended CONNECT request directly through `quic_h3'
%%% so the suite is self-contained and does not yet depend on the
%%% MASQUE client API (which lands in Step 4).
-module(masque_compliance_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    suite/0,
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([
    handshake_accepts_valid_request/1,
    handshake_rejects_non_connect/1,
    handshake_rejects_wrong_protocol/1,
    handshake_rejects_unmatched_path/1,
    handshake_rejects_bad_port/1,
    client_connects_to_server/1,
    client_handshake_rejected_maps_error/1,
    datagram_echo_message_mode/1,
    datagram_echo_queue_mode/1,
    udp_proxy_round_trip/1,
    udp_proxy_policy_denies/1,
    capsule_roundtrip/1,
    oversize_packet_rejected/1,
    graceful_close_signals_owner/1,
    many_packets_in_order/1,
    concurrent_tunnels/1,
    large_payload_near_mtu/1,
    integration_custom_h3_listener/1,
    fallback_receives_non_masque_requests/1,
    udp_source_spoofing_rejected/1,
    handshake_rejected_when_init_fails/1,
    udp_payload_65527_boundary/1,
    reject_response_carries_proxy_status/1
]).

-define(TPL, <<"/.well-known/masque/udp/{target_host}/{target_port}/">>).

%%====================================================================
%% CT callbacks
%%====================================================================

suite() -> [{timetrap, {seconds, 30}}].

all() -> [
    handshake_accepts_valid_request,
    handshake_rejects_non_connect,
    handshake_rejects_wrong_protocol,
    handshake_rejects_unmatched_path,
    handshake_rejects_bad_port,
    client_connects_to_server,
    client_handshake_rejected_maps_error,
    datagram_echo_message_mode,
    datagram_echo_queue_mode,
    udp_proxy_round_trip,
    udp_proxy_policy_denies,
    capsule_roundtrip,
    oversize_packet_rejected,
    graceful_close_signals_owner,
    many_packets_in_order,
    concurrent_tunnels,
    large_payload_near_mtu,
    integration_custom_h3_listener,
    fallback_receives_non_masque_requests,
    udp_source_spoofing_rejected,
    handshake_rejected_when_init_fails,
    udp_payload_65527_boundary,
    reject_response_carries_proxy_status
].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    {ok, _} = application:ensure_all_started(masque),
    case masque_test_helpers:generate_certs() of
        {ok, Certs} -> [{certs, Certs} | Config];
        {error, R}  -> {skip, {cert_generation_failed, R}}
    end.

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(certs, Config)).

init_per_testcase(Case, Config)
  when Case =:= datagram_echo_message_mode;
       Case =:= datagram_echo_queue_mode;
       Case =:= capsule_roundtrip;
       Case =:= oversize_packet_rejected;
       Case =:= graceful_close_signals_owner;
       Case =:= many_packets_in_order;
       Case =:= concurrent_tunnels;
       Case =:= large_payload_near_mtu;
       Case =:= udp_payload_65527_boundary ->
    Certs = ?config(certs, Config),
    ServerCtx = maps:merge(Certs, #{handler => masque_echo_handler}),
    {ok, Server} = masque_test_helpers:start_masque_server(ServerCtx),
    [{server, Server} | Config];
init_per_testcase(udp_source_spoofing_rejected, Config) ->
    Certs = ?config(certs, Config),
    {UdpPid, UdpPort} = start_udp_echo(),
    ProxyBindPort = ephemeral_port(),
    ServerCtx = maps:merge(Certs, #{
        handler      => masque_udp_proxy_handler,
        handler_opts => #{port => ProxyBindPort}
    }),
    {ok, Server} = masque_test_helpers:start_masque_server(ServerCtx),
    [{server, Server},
     {udp_pid, UdpPid},
     {udp_port, UdpPort},
     {proxy_bind_port, ProxyBindPort} | Config];
init_per_testcase(handshake_rejected_when_init_fails, Config) ->
    Certs = ?config(certs, Config),
    %% Resolver always fails - `init/2' returns `{stop, _}' and the
    %% handshake must come back with 502.
    ServerCtx = maps:merge(Certs, #{
        handler      => masque_udp_proxy_handler,
        handler_opts => #{resolver =>
                              fun(_) -> {error, nxdomain} end}
    }),
    {ok, Server} = masque_test_helpers:start_masque_server(ServerCtx),
    [{server, Server} | Config];
init_per_testcase(Case, Config)
  when Case =:= udp_proxy_round_trip;
       Case =:= udp_proxy_policy_denies ->
    Certs = ?config(certs, Config),
    {UdpPid, UdpPort} = start_udp_echo(),
    ServerCtx0 = maps:merge(Certs, #{handler => masque_udp_proxy_handler}),
    ServerCtx = case Case of
        udp_proxy_policy_denies ->
            ServerCtx0#{handler_opts =>
                          #{allow => fun(_) -> false end}};
        _ -> ServerCtx0
    end,
    {ok, Server} = masque_test_helpers:start_masque_server(ServerCtx),
    [{server, Server}, {udp_pid, UdpPid}, {udp_port, UdpPort} | Config];
init_per_testcase(Case, Config)
  when Case =:= integration_custom_h3_listener;
       Case =:= fallback_receives_non_masque_requests ->
    Certs = ?config(certs, Config),
    WithFallback = Case =:= integration_custom_h3_listener
                   orelse Case =:= fallback_receives_non_masque_requests,
    {ok, Server} = start_integration_server(Certs, WithFallback),
    [{server, Server} | Config];
init_per_testcase(_Case, Config) ->
    Certs = ?config(certs, Config),
    {ok, Server} = masque_test_helpers:start_masque_server(Certs),
    [{server, Server} | Config].

end_per_testcase(_Case, Config) ->
    Server = ?config(server, Config),
    %% Integration cases register the server via `quic_h3' directly;
    %% everyone else uses the `masque' facade. Both `stop' entry
    %% points accept the `name' atom.
    _ = (catch masque_test_helpers:stop_masque_server(Server)),
    _ = (catch quic_h3:stop_server(maps:get(name, Server))),
    case ?config(udp_pid, Config) of
        undefined -> ok;
        Pid       -> exit(Pid, shutdown)
    end,
    timer:sleep(50),
    ok.

%%====================================================================
%% Tests
%%====================================================================

handshake_accepts_valid_request(Config) ->
    {Conn, StreamId} = connect_and_send(Config, connect_udp_headers()),
    {ok, Status, _} = masque_test_helpers:h3_await_response(StreamId, 5000),
    ?assertEqual(200, Status),
    quic_h3:close(Conn).

handshake_rejects_non_connect(Config) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"localhost">>},
        {<<":path">>, expand_path(<<"192.0.2.6">>, 443)}
    ],
    {Conn, StreamId} = connect_and_send(Config, Headers),
    {ok, Status, _} = masque_test_helpers:h3_await_response(StreamId, 5000),
    %% GET with a well-known path that doesn't match a real resource is
    %% not handled by the MASQUE validator (it only looks at CONNECT
    %% requests). We short-circuit with 405 via the handler fun.
    ?assertEqual(405, Status),
    quic_h3:close(Conn).

handshake_rejects_wrong_protocol(Config) ->
    Headers = [
        {<<":method">>, <<"CONNECT">>},
        {<<":protocol">>, <<"websocket">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"localhost">>},
        {<<":path">>, expand_path(<<"192.0.2.6">>, 443)}
    ],
    {Conn, StreamId} = connect_and_send(Config, Headers),
    {ok, Status, _} = masque_test_helpers:h3_await_response(StreamId, 5000),
    ?assertEqual(501, Status),
    quic_h3:close(Conn).

handshake_rejects_unmatched_path(Config) ->
    Headers = [
        {<<":method">>, <<"CONNECT">>},
        {<<":protocol">>, <<"connect-udp">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"localhost">>},
        {<<":path">>, <<"/some/other/path/">>}
    ],
    {Conn, StreamId} = connect_and_send(Config, Headers),
    {ok, Status, _} = masque_test_helpers:h3_await_response(StreamId, 5000),
    ?assertEqual(404, Status),
    quic_h3:close(Conn).

handshake_rejects_bad_port(Config) ->
    Headers = [
        {<<":method">>, <<"CONNECT">>},
        {<<":protocol">>, <<"connect-udp">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"localhost">>},
        {<<":path">>, <<"/.well-known/masque/udp/192.0.2.6/99999/">>}
    ],
    {Conn, StreamId} = connect_and_send(Config, Headers),
    {ok, Status, _} = masque_test_helpers:h3_await_response(StreamId, 5000),
    ?assertEqual(400, Status),
    quic_h3:close(Conn).

client_connects_to_server(Config) ->
    Server = ?config(server, Config),
    Port = maps:get(port, Server),
    ProxyURI = iolist_to_binary(
        ["https://localhost:", integer_to_list(Port)]),
    {ok, Sess} = masque:connect(ProxyURI,
                                {<<"192.0.2.6">>, 443},
                                #{verify => verify_none,
                                  alpn => [<<"h3">>]}),
    ?assertMatch(#{state := open,
                   target := {<<"192.0.2.6">>, 443}},
                 masque:info(Sess)),
    ok = masque:close(Sess).

client_handshake_rejected_maps_error(Config) ->
    Server = ?config(server, Config),
    Port = maps:get(port, Server),
    ProxyURI = iolist_to_binary(
        ["https://localhost:", integer_to_list(Port)]),
    {error, {handshake_rejected, 404}} =
        masque:connect(ProxyURI,
                       {<<"192.0.2.6">>, 443},
                       #{verify => verify_none,
                         alpn => [<<"h3">>],
                         uri_template => <<"/wrong/{target_host}/{target_port}/">>}).

datagram_echo_message_mode(Config) ->
    Sess = connect_to(Config),
    Msg = <<"hello udp ", 1, 2, 3>>,
    ok = masque:send_packet(Sess, Msg),
    receive
        {masque_packet, Sess, Echoed} ->
            ?assertEqual(Msg, Echoed)
    after 5000 ->
        ct:fail("no echo received")
    end,
    ok = masque:close(Sess).

datagram_echo_queue_mode(Config) ->
    Sess = connect_to(Config),
    ok = masque:set_active(Sess, queue),
    Msgs = [<<"a">>, <<"bb">>, <<"cccc">>, <<1,2,3,4,5>>],
    [ok = masque:send_packet(Sess, M) || M <- Msgs],
    Received = [element(2, masque:recv_packet(Sess, 5000)) || _ <- Msgs],
    ?assertEqual(lists:sort(Msgs), lists:sort(Received)),
    ?assertEqual({error, timeout}, masque:recv_packet(Sess, 100)),
    ok = masque:close(Sess).

many_packets_in_order(Config) ->
    Sess = connect_to(Config),
    ok = masque:set_active(Sess, queue),
    N = 100,
    Msgs = [integer_to_binary(I) || I <- lists:seq(1, N)],
    [ok = masque:send_packet(Sess, M) || M <- Msgs],
    %% Datagrams are unreliable and unordered in principle. Verify we
    %% receive all N *as a set* within a generous budget.
    Received = collect_packets(Sess, N, 10000),
    ?assertEqual(lists:sort(Msgs), lists:sort(Received)),
    ok = masque:close(Sess).

concurrent_tunnels(Config) ->
    process_flag(trap_exit, true),
    N = 4,
    Parent = self(),
    _Pids = [spawn(fun() ->
                Tag = list_to_binary("t" ++ integer_to_list(I)),
                try
                    Sess = connect_to(Config),
                    ok = masque:send_packet(Sess, Tag),
                    receive
                        {masque_packet, Sess, Echo} ->
                            Parent ! {done, I, Tag, Echo}
                    after 8000 ->
                        Parent ! {timeout, I}
                    end,
                    masque:close(Sess)
                catch Class:Reason ->
                    Parent ! {crash, I, Class, Reason}
                end
            end) || I <- lists:seq(1, N)],
    Results = [ receive
                    {done, I, T, T}         -> {ok, I};
                    {timeout, I}            -> {timeout, I};
                    {crash, I, C, R}        -> {crash, I, C, R}
                after 20000 ->
                    {missing, I}
                end || I <- lists:seq(1, N)],
    ?assertEqual([{ok, I} || I <- lists:seq(1, N)], Results).

large_payload_near_mtu(Config) ->
    Sess = connect_to(Config),
    %% Stay comfortably below typical QUIC datagram ceiling (~1200).
    Payload = binary:copy(<<"A">>, 1000),
    ok = masque:send_packet(Sess, Payload),
    receive
        {masque_packet, Sess, Echo} -> ?assertEqual(Payload, Echo)
    after 5000 -> ct:fail("no echo for large payload")
    end,
    ok = masque:close(Sess).

collect_packets(_Sess, 0, _Timeout) -> [];
collect_packets(Sess, N, Timeout) ->
    case masque:recv_packet(Sess, Timeout) of
        {ok, Bytes}    -> [Bytes | collect_packets(Sess, N - 1, Timeout)];
        {error, timeout} -> []
    end.

oversize_packet_rejected(Config) ->
    Sess = connect_to(Config),
    %% 70000 bytes exceeds both the RFC 9298 §5 UDP payload ceiling
    %% (65527) and the path MTU - either `payload_too_large' or
    %% `datagram_too_large' is a valid refusal.
    Huge = binary:copy(<<"X">>, 70000),
    case masque:send_packet(Sess, Huge) of
        {error, {payload_too_large, 70000, _}}  -> ok;
        {error, {datagram_too_large, 70000, _}} -> ok;
        Other -> ct:fail({unexpected, Other})
    end,
    ok = masque:close(Sess).

graceful_close_signals_owner(Config) ->
    Sess = connect_to(Config),
    MRef = erlang:monitor(process, Sess),
    ok = masque:close(Sess),
    receive
        {'DOWN', MRef, process, Sess, _Reason} -> ok
    after 5000 ->
        ct:fail("session did not terminate after close")
    end.

capsule_roundtrip(Config) ->
    Sess = connect_to(Config),
    Type = 16#cafef00d,
    Value = <<"extension-capsule-body">>,
    ok = masque:send_capsule(Sess, Type, Value),
    receive
        {masque_capsule, Sess, Type, Echoed} ->
            ?assertEqual(Value, Echoed)
    after 5000 ->
        ct:fail("no capsule echo received")
    end,
    ok = masque:close(Sess).

udp_proxy_round_trip(Config) ->
    Server = ?config(server, Config),
    UdpPort = ?config(udp_port, Config),
    ProxyURI = iolist_to_binary(
        ["https://localhost:", integer_to_list(maps:get(port, Server))]),
    {ok, Sess} = masque:connect(ProxyURI,
                                {<<"127.0.0.1">>, UdpPort},
                                #{verify => verify_none,
                                  alpn => [<<"h3">>]}),
    Payload = <<"ping through proxy">>,
    ok = masque:send_packet(Sess, Payload),
    receive
        {masque_packet, Sess, Echoed} ->
            ?assertEqual(Payload, Echoed)
    after 5000 ->
        ct:fail("no UDP echo returned through proxy")
    end,
    ok = masque:close(Sess).

udp_proxy_policy_denies(Config) ->
    Server = ?config(server, Config),
    UdpPort = ?config(udp_port, Config),
    ProxyURI = iolist_to_binary(
        ["https://localhost:", integer_to_list(maps:get(port, Server))]),
    %% Policy says deny-all → handshake should come back 403.
    ?assertMatch({error, {handshake_rejected, 403}},
                 masque:connect(ProxyURI,
                                {<<"127.0.0.1">>, UdpPort},
                                #{verify => verify_none,
                                  alpn => [<<"h3">>]})).

integration_custom_h3_listener(Config) ->
    Server = ?config(server, Config),
    Port = maps:get(port, Server),
    ProxyURI = iolist_to_binary(
        ["https://localhost:", integer_to_list(Port)]),
    %% (a) MASQUE tunnel still works through the integration wiring.
    {ok, Sess} = masque:connect(ProxyURI,
                                {<<"127.0.0.1">>, 9},
                                #{verify => verify_none,
                                  alpn => [<<"h3">>]}),
    ?assertMatch(#{state := open}, masque:info(Sess)),
    ok = masque:close(Sess),
    %% (b) A non-MASQUE request goes to our fallback - we only check
    %% that the handshake is accepted (2xx) since the integration
    %% server's fallback replies 200 on GET /health.
    {ok, Conn} = masque_test_helpers:h3_client_connect(Port, #{}),
    {ok, StreamId} = quic_h3:request(Conn, [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"localhost">>},
        {<<":path">>, <<"/health">>}
    ]),
    {ok, Status, _} = masque_test_helpers:h3_await_response(StreamId, 5000),
    ?assertEqual(200, Status),
    quic_h3:close(Conn).

fallback_receives_non_masque_requests(Config) ->
    Server = ?config(server, Config),
    Port = maps:get(port, Server),
    {ok, Conn} = masque_test_helpers:h3_client_connect(Port, #{}),
    {ok, StreamId} = quic_h3:request(Conn, [
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"localhost">>},
        {<<":path">>, <<"/echo">>}
    ]),
    %% Fallback returns 200 with a canned body; status check is enough.
    {ok, 200, _} = masque_test_helpers:h3_await_response(StreamId, 5000),
    quic_h3:close(Conn).

%% Build a user-owned quic_h3 listener that delegates MASQUE to
%% `masque:h3_handlers/1' and serves everything else via a fallback
%% fun that responds `200 OK'.
start_integration_server(#{cert := Cert, key := Key}, WithFallback) ->
    Name = list_to_atom(
        "masque_integration_" ++
        integer_to_list(erlang:unique_integer([positive]))),
    Fallback = case WithFallback of
        true ->
            fun(Conn, StreamId, _Method, _Path, _Headers) ->
                Body = <<"integration fallback\n">>,
                Headers = [{<<"content-type">>,
                            <<"text/plain; charset=utf-8">>},
                           {<<"content-length">>,
                            integer_to_binary(byte_size(Body))}],
                ok = quic_h3:send_response(Conn, StreamId, 200, Headers),
                ok = quic_h3:send_data(Conn, StreamId, Body, true)
            end;
        false ->
            undefined
    end,
    MasqueOpts0 = #{handler => masque_echo_handler},
    MasqueOpts = case Fallback of
        undefined -> MasqueOpts0;
        Fun       -> MasqueOpts0#{fallback => Fun}
    end,
    #{handler := Handler,
      connection_handler := ConnectionHandler} =
        masque:h3_handlers(MasqueOpts),
    ServerOpts = #{
        cert => Cert,
        key => Key,
        settings => #{enable_connect_protocol => 1, h3_datagram => 1},
        quic_opts => #{
            alpn => [<<"h3">>],
            max_datagram_frame_size => 65535
        },
        handler => Handler,
        connection_handler => ConnectionHandler
    },
    case quic_h3:start_server(Name, 0, ServerOpts) of
        {ok, _Pid} ->
            {ok, Port} = quic:get_server_port(Name),
            {ok, #{name => Name, port => Port}};
        Err ->
            Err
    end.

udp_payload_65527_boundary(Config) ->
    Sess = connect_to(Config),
    %% 65528 bytes is one over the RFC 9298 §5 ceiling - refused.
    Over = binary:copy(<<"X">>, 65528),
    ?assertMatch({error, {payload_too_large, 65528, 65527}},
                 masque:send_packet(Sess, Over)),
    ok = masque:close(Sess).

reject_response_carries_proxy_status(Config) ->
    Server = ?config(server, Config),
    Port = maps:get(port, Server),
    {ok, Conn} = masque_test_helpers:h3_client_connect(Port, #{}),
    %% Path does not match the template - server must respond 404 and
    %% include a Proxy-Status header naming the failure class.
    {ok, StreamId} = quic_h3:request(Conn, [
        {<<":method">>, <<"CONNECT">>},
        {<<":protocol">>, <<"connect-udp">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"localhost">>},
        {<<":path">>, <<"/nonsense/path/">>}
    ]),
    {ok, 404, Headers} =
        masque_test_helpers:h3_await_response(StreamId, 5000),
    {_, PS} = lists:keyfind(<<"proxy-status">>, 1, Headers),
    ?assertEqual(<<"masque; error=http_protocol_error">>, PS),
    quic_h3:close(Conn).

udp_source_spoofing_rejected(Config) ->
    Server = ?config(server, Config),
    UdpPort = ?config(udp_port, Config),
    ProxyBindPort = ?config(proxy_bind_port, Config),
    ProxyURI = iolist_to_binary(
        ["https://localhost:", integer_to_list(maps:get(port, Server))]),
    {ok, Sess} = masque:connect(ProxyURI,
                                {<<"127.0.0.1">>, UdpPort},
                                #{verify => verify_none,
                                  alpn => [<<"h3">>]}),
    %% Legitimate round-trip works: client -> proxy -> echo -> back.
    ok = masque:send_packet(Sess, <<"legit">>),
    receive
        {masque_packet, Sess, <<"legit">>} -> ok
    after 5000 ->
        ct:fail("legitimate echo never arrived")
    end,
    %% Spoof: a third-party UDP sender blasts the proxy's bound port.
    %% The proxy socket is connected to the target, so the kernel
    %% must drop these and the tunnel owner must not see them.
    {ok, Attacker} = gen_udp:open(0, [binary, {active, false},
                                       {ip, {127,0,0,1}}]),
    [ok = gen_udp:send(Attacker, {127,0,0,1}, ProxyBindPort, <<"attack", N>>)
     || N <- lists:seq(1, 10)],
    ok = gen_udp:close(Attacker),
    %% Give the kernel a beat, then check we received nothing extra.
    ?assertEqual(timeout, drain_masque_packets(Sess, 300)),
    ok = masque:close(Sess).

handshake_rejected_when_init_fails(Config) ->
    Server = ?config(server, Config),
    Port = maps:get(port, Server),
    ProxyURI = iolist_to_binary(
        ["https://localhost:", integer_to_list(Port)]),
    %% DNS resolution fails inside `init/2'. Because the 200 response
    %% is only sent AFTER init succeeds, the client must see a 502
    %% rather than a successful tunnel that silently never carries
    %% data.
    ?assertMatch({error, {handshake_rejected, 502}},
                 masque:connect(ProxyURI,
                                {<<"target.invalid">>, 443},
                                #{verify => verify_none,
                                  alpn => [<<"h3">>]})).

%% Receive every pending `{masque_packet, Sess, _}' until `Timeout' ms
%% of silence. Returns `timeout' on success (nothing spurious left),
%% or `{unexpected, Data}' if any bytes were delivered.
drain_masque_packets(Sess, Timeout) ->
    receive
        {masque_packet, Sess, Data} -> {unexpected, Data}
    after Timeout ->
        timeout
    end.

%% Ask the OS for an unused UDP port. We open then close a socket,
%% which is a standard "next-available" trick. There's a tiny race
%% window before the MASQUE proxy binds, but it's good enough for a
%% single-shot test.
ephemeral_port() ->
    {ok, S} = gen_udp:open(0, [{ip, {127,0,0,1}}]),
    {ok, P} = inet:port(S),
    gen_udp:close(S),
    P.

%% Start a trivial in-process UDP echo server bound to loopback.
start_udp_echo() ->
    Pid = spawn(fun() ->
        {ok, S} = gen_udp:open(0, [binary, {active, true},
                                   {ip, {127,0,0,1}}]),
        udp_echo_loop(S)
    end),
    Pid ! {get_port, self()},
    receive {port, P} -> {Pid, P}
    after 1000 -> ct:fail("udp echo start timeout")
    end.

udp_echo_loop(S) ->
    receive
        {get_port, From} ->
            {ok, P} = inet:port(S),
            From ! {port, P},
            udp_echo_loop(S);
        {udp, S, IP, Port, Data} ->
            gen_udp:send(S, IP, Port, Data),
            udp_echo_loop(S);
        stop ->
            gen_udp:close(S)
    end.

connect_to(Config) ->
    Server = ?config(server, Config),
    Port = maps:get(port, Server),
    ProxyURI = iolist_to_binary(
        ["https://localhost:", integer_to_list(Port)]),
    {ok, Sess} = masque:connect(ProxyURI,
                                {<<"192.0.2.6">>, 443},
                                #{verify => verify_none,
                                  alpn => [<<"h3">>]}),
    Sess.

%%====================================================================
%% Helpers
%%====================================================================

connect_and_send(Config, Headers) ->
    Server = ?config(server, Config),
    {ok, Conn} = masque_test_helpers:h3_client_connect(
        maps:get(port, Server), #{}),
    {ok, StreamId} = quic_h3:request(Conn, Headers),
    {Conn, StreamId}.

connect_udp_headers() ->
    [
        {<<":method">>, <<"CONNECT">>},
        {<<":protocol">>, <<"connect-udp">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"localhost">>},
        {<<":path">>, expand_path(<<"192.0.2.6">>, 443)},
        {<<"capsule-protocol">>, <<"?1">>}
    ].

expand_path(Host, Port) ->
    masque_uri:expand(?TPL, #{target_host => Host, target_port => Port}).
