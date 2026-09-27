%%% @doc Edge cases of the built-in proxy handlers and listener input.
-module(masque_handler_edge_tests).

-include_lib("eunit/include/eunit.hrl").

%% A name with only IPv6 addresses is dialled over IPv6.
tcp_ipv6_only_name_test() ->
    case gen_tcp:listen(0, [inet6, {ip, {0, 0, 0, 0, 0, 0, 0, 1}}]) of
        {error, _} ->
            ok;
        {ok, L} ->
            {ok, Port} = inet:port(L),
            Opts = #{
                resolver => fun(_) -> {ok, [{0, 0, 0, 0, 0, 0, 0, 1}]} end,
                allow_private => true
            },
            Req = #{target_host => <<"v6only.test">>, target_port => Port},
            {ok, S} = masque_tcp_proxy_handler:init(Req, Opts),
            ok = masque_tcp_proxy_handler:terminate(normal, S),
            gen_tcp:close(L)
    end.

%% A client that aborts the tunnel aborts the target connection (RST).
tcp_abort_sends_rst_test() ->
    {ok, L} = gen_tcp:listen(0, [binary, {ip, {127, 0, 0, 1}}, {active, false}]),
    {ok, Port} = inet:port(L),
    Opts = #{resolver => fun(_) -> {ok, [{127, 0, 0, 1}]} end, allow_private => true},
    Req = #{target_host => <<"target.test">>, target_port => Port},
    {ok, S} = masque_tcp_proxy_handler:init(Req, Opts),
    {ok, Peer} = gen_tcp:accept(L, 2000),
    ok = inet:setopts(Peer, [{show_econnreset, true}]),
    ok = masque_tcp_proxy_handler:terminate(peer_reset, S),
    ?assertEqual({error, econnreset}, gen_tcp:recv(Peer, 0, 2000)),
    gen_tcp:close(L).

tcp_clean_end_sends_fin_test() ->
    {ok, L} = gen_tcp:listen(0, [binary, {ip, {127, 0, 0, 1}}, {active, false}]),
    {ok, Port} = inet:port(L),
    Opts = #{resolver => fun(_) -> {ok, [{127, 0, 0, 1}]} end, allow_private => true},
    Req = #{target_host => <<"target.test">>, target_port => Port},
    {ok, S} = masque_tcp_proxy_handler:init(Req, Opts),
    {ok, Peer} = gen_tcp:accept(L, 2000),
    ok = inet:setopts(Peer, [{show_econnreset, true}]),
    ok = masque_tcp_proxy_handler:terminate(normal, S),
    ?assertEqual({error, closed}, gen_tcp:recv(Peer, 0, 2000)),
    gen_tcp:close(L).

%% An ICMP port unreachable does not end a CONNECT-UDP tunnel.
udp_econnrefused_keeps_tunnel_test() ->
    Opts = #{resolver => fun(_) -> {ok, [{127, 0, 0, 1}]} end, allow_private => true},
    {ok, S} = masque_udp_proxy_handler:init(#{target_host => <<"t">>, target_port => 9}, Opts),
    Sock = element(2, S),
    ?assertEqual({ok, S}, masque_udp_proxy_handler:handle_info({udp_error, Sock, econnrefused}, S)),
    ok = masque_udp_proxy_handler:terminate(normal, S).

%% h1 CONNECT targets follow the same host rules as h3 and h2.
h1_connect_invalid_host_rejected_test() ->
    Hdrs = [{<<"host">>, <<"bad_host!:443">>}],
    ?assertEqual(
        {error, bad_host},
        masque_h1_server:validate(<<"CONNECT">>, <<"bad_host!:443">>, Hdrs, <<>>, <<>>)
    ),
    Ok = [{<<"host">>, <<"example.com:443">>}],
    ?assertMatch(
        {ok, #{target_host := <<"example.com">>}},
        masque_h1_server:validate(<<"CONNECT">>, <<"example.com:443">>, Ok, <<>>, <<>>)
    ).
