-module(masque_tcp_dial_tests).

-include_lib("eunit/include/eunit.hrl").

%% RFC 8305 section 4: families interleaved, IPv6 first.
order_test() ->
    V6a = {0, 0, 0, 0, 0, 0, 0, 1},
    V6b = {16#2001, 16#db8, 0, 0, 0, 0, 0, 1},
    V4a = {127, 0, 0, 1},
    V4b = {192, 0, 2, 1},
    ?assertEqual([V6a, V4a, V6b, V4b], masque_tcp_dial:order([V4a, V4b, V6a, V6b])),
    ?assertEqual([V4a, V4b], masque_tcp_dial:order([V4a, V4b])),
    ?assertEqual([V6a], masque_tcp_dial:order([V6a])).

%% The first address has nothing listening (127.0.0.2 refuses, or is
%% not configured and fails); the next one answers.
falls_through_refused_test() ->
    {Listen, Port} = listen(),
    {ok, Sock} = masque_tcp_dial:connect(
        [{127, 0, 0, 2}, {127, 0, 0, 1}], Port, fun(_) -> [binary] end, 5000
    ),
    ?assertMatch({ok, {{127, 0, 0, 1}, Port}}, inet:peername(Sock)),
    %% The caller owns the socket and it is passive.
    ?assertEqual({ok, [{active, false}]}, inet:getopts(Sock, [active])),
    gen_tcp:close(Sock),
    gen_tcp:close(Listen).

%% An address that never answers does not hold up the next one for more
%% than the attempt delay.
does_not_wait_for_a_silent_address_test() ->
    {Listen, Port} = listen(),
    %% TEST-NET-1 is not routed; the attempt hangs or fails.
    T0 = erlang:monotonic_time(millisecond),
    {ok, Sock} = masque_tcp_dial:connect(
        [{192, 0, 2, 1}, {127, 0, 0, 1}], Port, fun(_) -> [binary] end, 5000
    ),
    ?assert(erlang:monotonic_time(millisecond) - T0 < 2000),
    ?assertMatch({ok, {{127, 0, 0, 1}, Port}}, inet:peername(Sock)),
    gen_tcp:close(Sock),
    gen_tcp:close(Listen).

all_refused_test() ->
    {ok, Closed} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Closed),
    ok = gen_tcp:close(Closed),
    ?assertEqual(
        {error, econnrefused},
        masque_tcp_dial:connect(
            [{127, 0, 0, 1}, {127, 0, 0, 1}], Port, fun(_) -> [binary] end, 5000
        )
    ).

%% The winning socket carries data to the target.
winner_carries_data_test() ->
    {Listen, Port} = listen(),
    {ok, Sock} = masque_tcp_dial:connect(
        [{127, 0, 0, 1}, {127, 0, 0, 1}, {127, 0, 0, 1}], Port, fun(_) -> [binary] end, 5000
    ),
    {ok, Server} = gen_tcp:accept(Listen, 1000),
    ok = gen_tcp:send(Sock, <<"hi">>),
    ?assertEqual({ok, <<"hi">>}, gen_tcp:recv(Server, 2, 1000)),
    gen_tcp:close(Sock),
    gen_tcp:close(Server),
    gen_tcp:close(Listen).

listen() ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Listen),
    {Listen, Port}.
