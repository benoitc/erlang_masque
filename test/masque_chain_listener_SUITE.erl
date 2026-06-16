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
    chain_h1_listener_echo/1
]).

all() ->
    [
        chain_h3_listener_echo,
        chain_h2_listener_echo,
        chain_h1_listener_echo
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

%%====================================================================
%% Helpers
%%====================================================================

upstream_uri(Port) ->
    iolist_to_binary(["https://localhost:", integer_to_list(Port)]).

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
