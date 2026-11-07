%%% @doc Smoke test of `examples/reverse_tunnel.erl' on h3, h2 and h1:
%%% a public TCP client reaches the agent's local service through the
%%% edge and a reverse connect stream. Reverse connect itself is covered
%%% by `masque_reverse_SUITE'.
-module(masque_reverse_tunnel_example_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1]).
-export([init_per_group/2, end_per_group/2]).
-export([round_trip/1, large_round_trip/1, many_clients/1]).

all() -> [{group, h3}, {group, h2}, {group, h1}].

groups() ->
    Cases = [round_trip, large_round_trip, many_clients],
    [{h3, [], Cases}, {h2, [], Cases}, {h1, [], Cases}].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(Transport, Config) ->
    {ok, Ports} = reverse_tunnel:start(#{transport => Transport}),
    [{ports, Ports} | Config].

end_per_group(_Transport, _Config) ->
    reverse_tunnel:stop().

round_trip(_Config) ->
    ?assertEqual(
        {ok, <<"hello through the tunnel">>}, reverse_tunnel:run(<<"hello through the tunnel">>)
    ).

large_round_trip(_Config) ->
    Payload = crypto:strong_rand_bytes(1024 * 1024),
    ?assertEqual({ok, Payload}, reverse_tunnel:run(Payload)).

%% Each public client gets its own stream.
many_clients(_Config) ->
    Self = self(),
    Pids = [
        spawn_link(fun() ->
            Msg = integer_to_binary(N),
            Self ! {done, self(), reverse_tunnel:run(Msg) =:= {ok, Msg}}
        end)
     || N <- lists:seq(1, 20)
    ],
    [
        receive
            {done, P, Ok} -> ?assert(Ok)
        after 20000 -> ct:fail({stuck, P})
        end
     || P <- Pids
    ].
