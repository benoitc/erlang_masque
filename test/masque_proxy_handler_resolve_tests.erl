%%% @doc The UDP and TCP proxy handlers accept both resolver result
%%% shapes: the list a listener-level `resolver' returns and the single
%%% address a handler-level one may return.
-module(masque_proxy_handler_resolve_tests).

-include_lib("eunit/include/eunit.hrl").

req() ->
    #{target_host => <<"target.test">>, target_port => 9}.

list_resolver() -> fun(_) -> {ok, [{127, 0, 0, 1}]} end.
single_resolver() -> fun(_) -> {ok, {127, 0, 0, 1}} end.
empty_resolver() -> fun(_) -> {ok, []} end.

udp_list_resolver_opens_socket_test() ->
    Opts = #{resolver => list_resolver(), allow_private => true},
    {ok, State} = masque_udp_proxy_handler:init(req(), Opts),
    ok = masque_udp_proxy_handler:terminate(normal, State).

udp_single_resolver_opens_socket_test() ->
    Opts = #{resolver => single_resolver(), allow_private => true},
    {ok, State} = masque_udp_proxy_handler:init(req(), Opts),
    ok = masque_udp_proxy_handler:terminate(normal, State).

udp_list_resolver_private_refused_test() ->
    ?assertEqual(
        {stop, {resolution_failed, private_address}},
        masque_udp_proxy_handler:init(req(), #{resolver => list_resolver()})
    ).

udp_empty_resolver_test() ->
    ?assertEqual(
        {stop, {resolution_failed, {resolve, nxdomain}}},
        masque_udp_proxy_handler:init(req(), #{resolver => empty_resolver()})
    ).

tcp_list_resolver_private_refused_test() ->
    ?assertEqual(
        {stop, {resolution_failed, private_address}},
        masque_tcp_proxy_handler:init(req(), #{resolver => list_resolver()})
    ).

tcp_single_resolver_private_refused_test() ->
    ?assertEqual(
        {stop, {resolution_failed, private_address}},
        masque_tcp_proxy_handler:init(req(), #{resolver => single_resolver()})
    ).
