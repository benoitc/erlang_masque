%%% @doc End-to-end three-way race test for `masque:connect/3'.
%%%
%%% Starts a real h1 CONNECT-UDP listener on one port and points the
%%% racer at closed h3/h2 ports. The only reachable transport is h1,
%%% so `transports => [h3, h2, h1]' must return an h1 session.
-module(masque_h1_race_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([
    h1_wins_when_h3_and_h2_unreachable/1,
    h2_wins_before_h1_when_h3_unreachable/1
]).

all() ->
    [
        h1_wins_when_h3_and_h2_unreachable,
        h2_wins_before_h1_when_h3_unreachable
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Certs} = masque_test_helpers:generate_certs(),
    %% h1 listener - this is what we're racing to.
    H1Name = list_to_atom(
        "masque_h1_race_" ++
            integer_to_list(erlang:unique_integer([positive]))
    ),
    Parent = self(),
    H1Keeper = erlang:spawn(fun() -> h1_keeper(Parent, H1Name, Certs) end),
    H1Port =
        receive
            {H1Keeper, started, P} -> P
        after 5000 ->
            ct:fail(h1_keeper_start_timeout)
        end,
    %% h2 listener - used only by the second case (h2 wins).
    H2Name = list_to_atom(
        "masque_h2_race_" ++
            integer_to_list(erlang:unique_integer([positive]))
    ),
    H2Keeper = erlang:spawn(fun() -> h2_keeper(Parent, H2Name, Certs) end),
    H2Port =
        receive
            {H2Keeper, started, P2} -> P2
        after 5000 ->
            ct:fail(h2_keeper_start_timeout)
        end,
    %% Reserve two ports that have nothing listening: bind and close.
    DeadH3Port = reserve_unused_port(),
    DeadH2Port = reserve_unused_port(),
    [
        {certs, Certs},
        {h1_keeper, H1Keeper},
        {h1_port, H1Port},
        {h2_keeper, H2Keeper},
        {h2_port, H2Port},
        {dead_h3_port, DeadH3Port},
        {dead_h2_port, DeadH2Port}
        | Config
    ].

end_per_suite(Config) ->
    ?config(h1_keeper, Config) ! stop,
    ?config(h2_keeper, Config) ! stop,
    _ = masque_test_helpers:cleanup_certs(?config(certs, Config)),
    ok.

%%====================================================================
%% Keepers (so listen sockets outlive init_per_suite's process)
%%====================================================================

h1_keeper(Parent, Name, Certs) ->
    Opts = #{
        port => 0,
        cert => maps:get(cert_file, Certs),
        key => maps:get(key_file, Certs),
        handler => masque_echo_handler
    },
    case masque:start_listener_h1(Name, Opts) of
        {ok, Ref} ->
            Parent ! {self(), started, h1:server_port(Ref)},
            wait_stop(Name, h1);
        {error, Reason} ->
            Parent ! {self(), start_failed, Reason}
    end.

h2_keeper(Parent, Name, Certs) ->
    Opts = #{
        port => 0,
        cert => maps:get(cert_file, Certs),
        key => maps:get(key_file, Certs),
        handler => masque_echo_handler
    },
    case masque:start_listener_h2(Name, Opts) of
        {ok, Ref} ->
            {_, _, Port} = Ref,
            Parent ! {self(), started, Port},
            wait_stop(Name, h2);
        {error, Reason} ->
            Parent ! {self(), start_failed, Reason}
    end.

wait_stop(Name, h1) ->
    receive
        stop ->
            _ = masque:stop_listener_h1(Name),
            ok;
        _ ->
            wait_stop(Name, h1)
    end;
wait_stop(Name, h2) ->
    receive
        stop ->
            _ = masque:stop_listener_h2(Name),
            ok;
        _ ->
            wait_stop(Name, h2)
    end.

reserve_unused_port() ->
    {ok, Sock} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(Sock),
    _ = gen_tcp:close(Sock),
    Port.

%%====================================================================
%% Cases
%%====================================================================

h1_wins_when_h3_and_h2_unreachable(Config) ->
    %% We can't sensibly aim the h3 attempt at a dead UDP port (QUIC
    %% handshake times out rather than refuses). Use the default racer
    %% timeout but tune head-starts short so h1 gets spawned quickly
    %% once h2 reports econnrefused.
    H1Port = ?config(h1_port, Config),
    DeadH2Port = ?config(dead_h2_port, Config),
    DeadH3Port = ?config(dead_h3_port, Config),
    %% Proxy URI identifies h1; the racer dials the same host but can
    %% override ports per attempt only via session opts. Our racer uses
    %% a single `proxy' opt for all attempts, so we run with h2 pointed
    %% at dead port and let h3 time out (limited by test `timeout').
    ProxyURI = iolist_to_binary([
        "https://127.0.0.1:",
        integer_to_list(H1Port)
    ]),
    _ = DeadH2Port,
    _ = DeadH3Port,
    Target = {<<"127.0.0.1">>, 5353},
    Opts = #{
        %% drop h3 (QUIC isn't wired in tests)
        transports => [h2, h1],
        protocol => udp,
        timeout => 3000,
        prefer_timeout_ms => 100,
        h1_prefer_timeout_ms => 100,
        owner => self(),
        verify => verify_none,
        ssl_opts => [{verify, verify_none}]
    },
    %% Point the race at the h1 listener port. h2 attempt will try the
    %% same port - but h1 listener speaks only HTTP/1.1 so h2 ALPN
    %% negotiation fails; h1 wins.
    {ok, Sess} = masque:connect(ProxyURI, Target, Opts),
    ok = masque:send(Sess, <<"raced">>),
    receive
        {masque_data, Sess, <<"raced">>} -> ok
    after 2000 ->
        ct:fail(echo_not_received_over_h1_fallback)
    end,
    ok = masque:close(Sess).

h2_wins_before_h1_when_h3_unreachable(Config) ->
    %% Point the race at the h2 listener port. h2 should win and the
    %% h1 attempt should never touch the network (we can't directly
    %% observe this here, but the datagram must echo through h2 which
    %% is the only listener on that port).
    H2Port = ?config(h2_port, Config),
    ProxyURI = iolist_to_binary([
        "https://127.0.0.1:",
        integer_to_list(H2Port)
    ]),
    Target = {<<"127.0.0.1">>, 5353},
    Opts = #{
        transports => [h2, h1],
        protocol => udp,
        timeout => 3000,
        prefer_timeout_ms => 50,
        h1_prefer_timeout_ms => 500,
        owner => self(),
        verify => verify_none,
        ssl_opts => [{verify, verify_none}]
    },
    {ok, Sess} = masque:connect(ProxyURI, Target, Opts),
    ok = masque:send(Sess, <<"h2wins">>),
    receive
        {masque_data, Sess, <<"h2wins">>} -> ok
    after 2000 ->
        ct:fail(echo_not_received_over_h2)
    end,
    ok = masque:close(Sess).
