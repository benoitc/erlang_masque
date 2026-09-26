%%% @doc End-to-end tests for the chain listener convenience
%%% wrappers: `masque:start_chain_listener/2' (h3),
%%% `start_chain_listener_h2/2', and `start_chain_listener_h1/2'.
%%%
%%% The chain handler itself is already covered by
%%% `masque_compliance_SUITE'; this suite only proves the new
%%% facade shortcuts end-to-end: you call `start_chain_listener_hX'
%%% once on the ingress, a client dials through, and the UDP echo
%%% round-trips to the egress via `masque_chain_handler'.
-module(masque_chain_listener_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([
    chain_h3_listener_echo/1,
    chain_h2_listener_echo/1,
    chain_h1_listener_echo/1,
    chain_h3_self_loop_detected/1,
    chain_h1_own_via_rejected/1,
    chain_h3_two_listeners_same_node/1
]).

all() ->
    [
        chain_h3_listener_echo,
        chain_h2_listener_echo,
        chain_h1_listener_echo,
        chain_h3_self_loop_detected,
        chain_h1_own_via_rejected,
        chain_h3_two_listeners_same_node
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Certs} = masque_test_helpers:generate_certs(),
    [{certs, Certs} | Config].

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(certs, Config)),
    ok.

init_per_testcase(_Case, Config) ->
    Certs = ?config(certs, Config),
    {UdpPid, UdpPort} = start_udp_echo(),
    %% Egress runs a regular UDP proxy (h3, to keep the fixture
    %% simple). The ingress is what the case under test builds.
    {ok, Egress} = masque_test_helpers:start_masque_server(
        maps:merge(Certs, #{
            handler => masque_udp_proxy_handler,
            handler_opts => #{allow_private => true}
        })
    ),
    EgressPort = maps:get(port, Egress),
    [
        {egress, Egress},
        {egress_port, EgressPort},
        {udp_pid, UdpPid},
        {udp_port, UdpPort}
        | Config
    ].

end_per_testcase(_Case, Config) ->
    _ = masque_test_helpers:stop_masque_server(?config(egress, Config)),
    case ?config(udp_pid, Config) of
        P when is_pid(P) -> exit(P, shutdown);
        _ -> ok
    end,
    case ?config(ingress_h3_name, Config) of
        undefined -> ok;
        N3 -> _ = masque:stop_listener(N3)
    end,
    case ?config(ingress_h2_ref, Config) of
        undefined -> ok;
        R2 -> _ = masque:stop_listener_h2(R2)
    end,
    case ?config(ingress_h1_keeper, Config) of
        undefined -> ok;
        K1 -> K1 ! stop
    end,
    ok.

%%====================================================================
%% Cases
%%====================================================================

chain_h3_listener_echo(Config) ->
    %% `masque:start_chain_listener/2' is the pre-existing h3 facade.
    %% Include it here so the trio is tested side-by-side.
    Certs = ?config(certs, Config),
    EgressPort = ?config(egress_port, Config),
    Name = unique_name("chain_h3"),
    %% h3 takes DER binaries for cert/key.
    Opts = #{
        port => 0,
        cert => maps:get(cert, Certs),
        key => maps:get(key, Certs),
        handler_opts => #{
            upstream_proxy => upstream_uri(EgressPort),
            upstream_opts => #{
                verify => verify_none,
                transports => [h3],
                alpn => [<<"h3">>]
            }
        }
    },
    {ok, _} = masque:start_chain_listener(Name, Opts),
    {ok, IngressPort} = quic:get_server_port(Name),
    Config1 = [{ingress_h3_name, Name} | Config],
    exchange_echo_through(h3, IngressPort, Config1).

chain_h2_listener_echo(Config) ->
    Certs = ?config(certs, Config),
    EgressPort = ?config(egress_port, Config),
    Name = unique_name("chain_h2"),
    %% h2 listener takes PEM file paths for cert/key (DER is h3-only).
    Opts = #{
        port => 0,
        cert => maps:get(cert_file, Certs),
        key => maps:get(key_file, Certs),
        handler_opts => #{
            upstream_proxy => upstream_uri(EgressPort),
            upstream_opts => #{
                verify => verify_none,
                transports => [h3],
                alpn => [<<"h3">>]
            }
        }
    },
    {ok, Ref} = masque:start_chain_listener_h2(Name, Opts),
    {_, _, IngressPort} = Ref,
    Config1 = [{ingress_h2_ref, Ref} | Config],
    exchange_echo_through(h2, IngressPort, Config1).

chain_h1_listener_echo(Config) ->
    %% `ssl:listen' ties the listen socket to the caller, so host
    %% the h1 listener in a keeper process that outlives this case.
    Certs = ?config(certs, Config),
    EgressPort = ?config(egress_port, Config),
    Name = unique_name("chain_h1"),
    Opts = #{
        port => 0,
        cert => maps:get(cert_file, Certs),
        key => maps:get(key_file, Certs),
        handler_opts => #{
            upstream_proxy => upstream_uri(EgressPort),
            upstream_opts => #{
                verify => verify_none,
                transports => [h3],
                alpn => [<<"h3">>]
            }
        }
    },
    Parent = self(),
    Keeper = erlang:spawn(fun() ->
        case masque:start_chain_listener_h1(Name, Opts) of
            {ok, R} ->
                Parent ! {self(), started, h1:server_port(R)},
                receive
                    stop ->
                        _ = masque:stop_listener_h1(Name),
                        ok
                end;
            {error, E} ->
                Parent ! {self(), failed, E}
        end
    end),
    IngressPort =
        receive
            {Keeper, started, P} -> P
        after 5000 -> ct:fail(h1_keeper_timeout)
        end,
    Config1 = [{ingress_h1_keeper, Keeper} | Config],
    exchange_echo_through(h1, IngressPort, Config1).

%% An h3 chain listener whose upstream is itself: the second hop sees
%% its own `via' entry and answers 508 instead of dialing again.
chain_h3_self_loop_detected(Config) ->
    Certs = ?config(certs, Config),
    {ok, Probe} = gen_udp:open(0, [{ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Probe),
    ok = gen_udp:close(Probe),
    Name = unique_name("chain_h3_loop"),
    Opts = #{
        port => Port,
        cert => maps:get(cert, Certs),
        key => maps:get(key, Certs),
        handler_opts => #{
            upstream_proxy => upstream_uri(Port),
            upstream_opts => #{verify => verify_none, transports => [h3]}
        }
    },
    {ok, _} = masque:start_chain_listener(Name, Opts),
    try
        ?assertEqual(
            {error, {handshake_rejected, 508}},
            loop_connect(h3, Port, ?config(udp_port, Config))
        )
    after
        _ = masque:stop_listener(Name)
    end.

%% A request that already names this listener in `via' is refused by
%% an h1 chain listener with 508 and the matching Proxy-Status.
chain_h1_own_via_rejected(Config) ->
    Certs = ?config(certs, Config),
    Name = unique_name("chain_h1_loop"),
    Opts = #{
        port => 0,
        cert => maps:get(cert_file, Certs),
        key => maps:get(key_file, Certs),
        handler_opts => #{
            upstream_proxy => upstream_uri(?config(egress_port, Config)),
            upstream_opts => #{verify => verify_none, transports => [h3]},
            via_token => <<"masque-h1-loop-test">>
        }
    },
    Parent = self(),
    Keeper = erlang:spawn(fun() ->
        {ok, R} = masque:start_chain_listener_h1(Name, Opts),
        Parent ! {self(), started, h1:server_port(R)},
        receive
            stop -> _ = masque:stop_listener_h1(Name)
        end
    end),
    Port =
        receive
            {Keeper, started, P} -> P
        after 5000 -> ct:fail(h1_keeper_timeout)
        end,
    try
        {ok, Sock} = ssl:connect(
            "127.0.0.1",
            Port,
            [binary, {active, false}, {verify, verify_none}],
            5000
        ),
        Path = iolist_to_binary([
            "/.well-known/masque/udp/127.0.0.1/",
            integer_to_list(?config(udp_port, Config)),
            "/"
        ]),
        Via = <<"1.1 masque-h1-loop-test">>,
        ok = ssl:send(Sock, [
            <<"GET ">>,
            Path,
            <<" HTTP/1.1\r\nhost: localhost\r\nconnection: Upgrade\r\n">>,
            <<"upgrade: connect-udp\r\ncapsule-protocol: ?1\r\nvia: ">>,
            Via,
            <<"\r\n\r\n">>
        ]),
        {ok, Resp} = ssl:recv(Sock, 0, 5000),
        _ = ssl:close(Sock),
        ?assertMatch(<<"HTTP/1.1 508", _/binary>>, Resp),
        ?assertNotEqual(nomatch, binary:match(Resp, <<"proxy_loop_detected">>))
    after
        Keeper ! stop
    end.

%% Two chain listeners on the same node chained together (client ->
%% A -> B -> egress) are a legit multi-hop: each listener has its own
%% `via' token, so B does not mistake A's entry for a loop.
chain_h3_two_listeners_same_node(Config) ->
    Certs = ?config(certs, Config),
    EgressPort = ?config(egress_port, Config),
    UpOpts = #{verify => verify_none, transports => [h3], alpn => [<<"h3">>]},
    NameB = unique_name("chain_h3_b"),
    {ok, _} = masque:start_chain_listener(NameB, #{
        port => 0,
        cert => maps:get(cert, Certs),
        key => maps:get(key, Certs),
        handler_opts => #{
            upstream_proxy => upstream_uri(EgressPort),
            upstream_opts => UpOpts
        }
    }),
    {ok, PortB} = quic:get_server_port(NameB),
    NameA = unique_name("chain_h3_a"),
    {ok, _} = masque:start_chain_listener(NameA, #{
        port => 0,
        cert => maps:get(cert, Certs),
        key => maps:get(key, Certs),
        handler_opts => #{
            upstream_proxy => upstream_uri(PortB),
            upstream_opts => UpOpts
        }
    }),
    {ok, PortA} = quic:get_server_port(NameA),
    try
        exchange_echo_through(h3, PortA, Config)
    after
        _ = masque:stop_listener(NameA),
        _ = masque:stop_listener(NameB)
    end.

%%====================================================================
%% Helpers
%%====================================================================

loop_connect(Transport, Port, UdpPort) ->
    masque:connect(
        iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
        {<<"127.0.0.1">>, UdpPort},
        #{transports => [Transport], verify => verify_none, timeout => 8000}
    ).

upstream_uri(Port) ->
    iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]).

unique_name(Prefix) ->
    list_to_atom(
        Prefix ++ "_" ++
            integer_to_list(erlang:unique_integer([positive]))
    ).

exchange_echo_through(Transport, IngressPort, Config) ->
    UdpPort = ?config(udp_port, Config),
    ProxyURI = iolist_to_binary([
        "https://127.0.0.1:",
        integer_to_list(IngressPort)
    ]),
    ConnectOpts = #{
        transports => [Transport],
        protocol => udp,
        timeout => 5000,
        owner => self(),
        verify => verify_none,
        ssl_opts => [{verify, verify_none}]
    },
    {ok, Sess} = masque:connect(
        ProxyURI,
        {<<"127.0.0.1">>, UdpPort},
        ConnectOpts
    ),
    try
        ok = masque:send(Sess, <<"hello">>),
        receive
            {masque_data, Sess, <<"hello">>} -> ok
        after 3000 ->
            ct:fail({no_echo, Transport})
        end
    after
        ok = masque:close(Sess)
    end.

start_udp_echo() ->
    Pid = spawn(fun() ->
        {ok, S} = gen_udp:open(0, [
            binary,
            {active, true},
            {ip, {127, 0, 0, 1}}
        ]),
        udp_echo_loop(S)
    end),
    Pid ! {get_port, self()},
    receive
        {port, P} -> {Pid, P}
    after 1000 -> ct:fail("udp echo start timeout")
    end.

udp_echo_loop(S) ->
    receive
        {get_port, From} ->
            {ok, P} = inet:port(S),
            From ! {port, P},
            udp_echo_loop(S);
        {udp, S, Ip, Port, Data} ->
            gen_udp:send(S, Ip, Port, Data),
            udp_echo_loop(S);
        stop ->
            gen_udp:close(S)
    end.
