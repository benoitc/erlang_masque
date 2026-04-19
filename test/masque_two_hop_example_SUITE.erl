%%% @doc End-to-end tests for `examples/two_hop_relay.erl'.
%%%
%%% Exercises the example module's public entry points (`start/0',
%%% `run_udp/0', `run_tcp/0', `stop/0') so the reference shape
%%% stays correct as the library evolves. This is a smoke test on
%%% the example, not on the chain handler - the chain handler
%%% itself is covered by `masque_compliance_SUITE' and
%%% `masque_chain_ip_SUITE'.
-module(masque_two_hop_example_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([udp_round_trip_through_example/1,
         tcp_round_trip_through_example/1]).

all() ->
    [udp_round_trip_through_example,
     tcp_round_trip_through_example].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Ports} = two_hop_relay:start(),
    [{ports, Ports} | Config].

end_per_suite(_Config) ->
    _ = two_hop_relay:stop(),
    ok.

%%====================================================================
%% Cases
%%====================================================================

udp_round_trip_through_example(_Config) ->
    {ok, <<"hello two-hop">>} =
        two_hop_relay:run_udp(#{transports => [h3]}),
    ok.

tcp_round_trip_through_example(_Config) ->
    {ok, <<"hello two-hop over tcp">>} =
        two_hop_relay:run_tcp(#{transports => [h3]}),
    ok.
