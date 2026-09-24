%%% @doc End-to-end tests for the upstream connection pool.
%%%
%%% Runs a real MASQUE egress (UDP proxy) and a real chain ingress
%%% on loopback, pointed at the egress with `upstream_pool => true'
%%% in `upstream_opts'. Multiple tunnels opened through the ingress
%%% must share a single pooled owner on the upstream side; disabling
%%% the pool must fall back to one owner per tunnel.
-module(masque_upstream_pool_SUITE).

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
    h3_pool_shares_one_owner/1,
    h2_pool_shares_one_owner/1,
    pool_disabled_opens_per_tunnel/1,
    different_verify_uses_different_owner/1
]).

all() ->
    [
        h3_pool_shares_one_owner,
        h2_pool_shares_one_owner,
        pool_disabled_opens_per_tunnel,
        different_verify_uses_different_owner
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Certs} = masque_test_helpers:generate_certs(),
    [{certs, Certs} | Config].

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(certs, Config)),
    ok.

init_per_testcase(Case, Config) ->
    _ = masque_upstream_pool:close_all(),
    Certs = ?config(certs, Config),
    {UdpPid, UdpPort} = start_udp_echo(),
    %% h3 egress always; h2 egress only when the case needs it.
    {ok, EgressH3} = masque_test_helpers:start_masque_server(
        maps:merge(Certs, #{
            handler => masque_udp_proxy_handler,
            handler_opts => #{allow_private => true}
        })
    ),
    EgressH3Port = maps:get(port, EgressH3),
    {EgressH2Ref, EgressH2Port} = maybe_start_h2_egress(Case, Certs),
    [
        {egress_h3, EgressH3},
        {egress_h3_port, EgressH3Port},
        {egress_h2_ref, EgressH2Ref},
        {egress_h2_port, EgressH2Port},
        {udp_pid, UdpPid},
        {udp_port, UdpPort}
        | Config
    ].

end_per_testcase(_Case, Config) ->
    _ = masque_test_helpers:stop_masque_server(?config(egress_h3, Config)),
    case ?config(egress_h2_ref, Config) of
        undefined -> ok;
        R2 -> _ = masque:stop_listener_h2(R2)
    end,
    case ?config(udp_pid, Config) of
        P when is_pid(P) -> exit(P, shutdown);
        _ -> ok
    end,
    _ = masque_upstream_pool:close_all(),
    case ?config(ingress_name, Config) of
        undefined -> ok;
        N -> _ = masque:stop_listener(N)
    end,
    ok.

maybe_start_h2_egress(h2_pool_shares_one_owner, Certs) ->
    Name = unique_name("egress_h2"),
    Opts = #{
        port => 0,
        cert => maps:get(cert_file, Certs),
        key => maps:get(key_file, Certs),
        handler => masque_udp_proxy_handler,
        handler_opts => #{allow_private => true}
    },
    {ok, Ref} = masque:start_listener_h2(Name, Opts),
    {_, _, Port} = Ref,
    {Ref, Port};
maybe_start_h2_egress(_Other, _Certs) ->
    {undefined, undefined}.

%%====================================================================
%% Cases
%%====================================================================

h3_pool_shares_one_owner(Config) ->
    run_pool_case(h3, true, 3, 1, Config).

h2_pool_shares_one_owner(Config) ->
    %% Dial the h2 egress directly with the pool enabled.
    EgressPort = ?config(egress_h2_port, Config),
    UdpPort = ?config(udp_port, Config),
    Sessions = [
        direct_connect(
            EgressPort,
            UdpPort,
            h2,
            #{upstream_pool => true}
        )
     || _ <- lists:seq(1, 3)
    ],
    [round_trip(S) || S <- Sessions],
    ?assertEqual(1, pool_entry_count()),
    close_all_sessions(Sessions).

pool_disabled_opens_per_tunnel(Config) ->
    %% Pool disabled: each tunnel owns its own upstream conn, so the
    %% pool registry never caches anything.
    run_pool_case(h3, false, 3, 0, Config).

different_verify_uses_different_owner(Config) ->
    %% Two direct dials to the same h3 egress, same pool enabled, but
    %% different `verify' values: the fingerprint split means two
    %% distinct pool entries.
    EgressPort = ?config(egress_h3_port, Config),
    UdpPort = ?config(udp_port, Config),
    Sess1 = direct_connect(
        EgressPort,
        UdpPort,
        h3,
        #{
            upstream_pool => true,
            verify => verify_none
        }
    ),
    Sess2 = direct_connect(
        EgressPort,
        UdpPort,
        h3,
        #{
            upstream_pool => true,
            verify => verify_peer,
            cacerts => [cert_der(Config)]
        }
    ),
    round_trip(Sess1),
    round_trip(Sess2),
    ?assertEqual(2, pool_entry_count()),
    close_all_sessions([Sess1, Sess2]).

cert_der(Config) ->
    maps:get(cert, ?config(certs, Config)).

direct_connect(EgressPort, UdpPort, Transport, Extra) ->
    %% Dial the loopback IP literal, not "localhost". A dual-stack name
    %% sends the connect down quic's Happy-Eyeballs race (::1 has no
    %% listener), which under load can exceed the handshake timeout. The
    %% test cert carries an IP:127.0.0.1 SAN so verify_peer still holds.
    ProxyURI = iolist_to_binary([
        "https://127.0.0.1:",
        integer_to_list(EgressPort)
    ]),
    Base = #{
        transports => [Transport],
        protocol => udp,
        timeout => 5000,
        owner => self(),
        verify => verify_none,
        ssl_opts => [{verify, verify_none}]
    },
    Opts = maps:merge(Base, Extra),
    {ok, Sess} = masque:connect(
        ProxyURI,
        {<<"127.0.0.1">>, UdpPort},
        Opts
    ),
    Sess.

%%====================================================================
%% Helpers
%%====================================================================

run_pool_case(Transport, PoolEnabled, TunnelCount, ExpectedOwners, Config) ->
    Certs = ?config(certs, Config),
    EgressPort = ?config(egress_h3_port, Config),
    UdpPort = ?config(udp_port, Config),
    Name = unique_name("ingress"),
    UpstreamOpts0 = #{
        verify => verify_none,
        transports => [Transport],
        alpn => [<<"h3">>]
    },
    UpstreamOpts =
        case PoolEnabled of
            true -> UpstreamOpts0#{upstream_pool => true};
            false -> UpstreamOpts0
        end,
    Opts = chain_listener_opts(Certs, EgressPort, UpstreamOpts),
    {ok, _} = masque:start_chain_listener(Name, Opts),
    {ok, IngressPort} = quic:get_server_port(Name),
    try
        Sessions = [
            open_ingress_tunnel(IngressPort, UdpPort, #{})
         || _ <- lists:seq(1, TunnelCount)
        ],
        [round_trip(S) || S <- Sessions],
        ?assertEqual(ExpectedOwners, pool_entry_count()),
        close_all_sessions(Sessions)
    after
        _ = masque:stop_listener(Name)
    end.

chain_listener_opts(Certs, EgressPort, UpstreamOpts) ->
    #{
        port => 0,
        cert => maps:get(cert, Certs),
        key => maps:get(key, Certs),
        handler_opts => #{
            upstream_proxy => upstream_uri(EgressPort),
            upstream_opts => UpstreamOpts
        }
    }.

open_ingress_tunnel(IngressPort, UdpPort, Extra) ->
    ProxyURI = iolist_to_binary([
        "https://127.0.0.1:",
        integer_to_list(IngressPort)
    ]),
    Opts = maps:merge(
        #{
            transports => [h3],
            protocol => udp,
            timeout => 5000,
            owner => self(),
            verify => verify_none,
            ssl_opts => [{verify, verify_none}]
        },
        Extra
    ),
    {ok, Sess} = masque:connect(
        ProxyURI,
        {<<"127.0.0.1">>, UdpPort},
        Opts
    ),
    Sess.

round_trip(Sess) ->
    Payload = iolist_to_binary(
        io_lib:format(
            "hello-~p",
            [erlang:unique_integer()]
        )
    ),
    ok = masque:send(Sess, Payload),
    receive
        {masque_data, Sess, Payload} -> ok
    after 3000 ->
        ct:fail({no_echo, Sess})
    end.

close_all_sessions(Sessions) ->
    _ = [
        try
            masque:close(S)
        catch
            _:_ -> ok
        end
     || S <- Sessions
    ],
    ok.

%% Count the live owner entries in the pool registry (one per
%% fingerprint). Uses sys:get_state so we do not have to expose a
%% test-only API on the registry.
pool_entry_count() ->
    St = sys:get_state(whereis(masque_upstream_pool)),
    %% Record shape: #state{cache = #{FP => [#entry{} | ...]}}.
    Cache = element(2, St),
    maps:fold(fun(_, Entries, Acc) -> Acc + length(Entries) end, 0, Cache).

upstream_uri(Port) ->
    iolist_to_binary(["https://localhost:", integer_to_list(Port)]).

unique_name(Prefix) ->
    list_to_atom(
        Prefix ++ "_" ++
            integer_to_list(erlang:unique_integer([positive]))
    ).

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
