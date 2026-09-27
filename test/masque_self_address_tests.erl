%%% @doc The proxy's own addresses are refused as targets unless
%%% `allow_self' is set.
-module(masque_self_address_tests).

-include_lib("eunit/include/eunit.hrl").
-include("masque_ip.hrl").

req() -> #{target_host => <<"target.test">>, target_port => 9}.

resolver(IP) -> fun(_) -> {ok, [IP]} end.

%% A non-loopback address of this host, if it has one.
interface_address() ->
    {ok, Ifs} = inet:getifaddrs(),
    case [A || {_, P} <- Ifs, {addr, {X, _, _, _} = A} <- P, X =/= 127] of
        [A | _] -> {ok, A};
        [] -> none
    end.

self_addresses_option_refused_test() ->
    Opts = #{resolver => resolver({8, 8, 8, 8}), self_addresses => [{8, 8, 8, 8}]},
    ?assertEqual(
        {stop, {resolution_failed, self_address}},
        masque_tcp_proxy_handler:init(req(), Opts)
    ),
    ?assertEqual(
        {stop, {resolution_failed, self_address}},
        masque_udp_proxy_handler:init(req(), Opts)
    ).

allow_self_lets_it_through_test() ->
    Opts = #{
        resolver => resolver({8, 8, 8, 8}),
        self_addresses => [{8, 8, 8, 8}],
        allow_self => true
    },
    {ok, S} = masque_udp_proxy_handler:init(req(), Opts),
    ok = masque_udp_proxy_handler:terminate(normal, S).

interface_address_refused_test() ->
    case interface_address() of
        none ->
            ok;
        {ok, A} ->
            Opts = #{resolver => resolver(A), allow_private => true},
            ?assertEqual(
                {stop, {resolution_failed, self_address}},
                masque_udp_proxy_handler:init(req(), Opts)
            )
    end.

bind_public_address_is_self_test() ->
    ?assert(masque_ip:is_self({203, 0, 113, 7}, #{public_addresses => [{{203, 0, 113, 7}, 443}]})),
    ?assertNot(masque_ip:is_self({203, 0, 113, 8}, #{})).

%% An IP packet to a self address is dropped by the CONNECT-IP handler.
ip_packet_to_self_dropped_test() ->
    Self = self(),
    Opts = #{
        self_addresses => [{8, 8, 4, 4}],
        allowed_source_prefixes => [{4, {10, 0, 0, 0}, 8}],
        allow_private => true,
        forward_fun => fun(P, St) ->
            Self ! {forwarded, P},
            {forward, St}
        end
    },
    {ok, S} = masque_ip_proxy_handler:init(#{ip_target => '*', ip_ipproto => '*'}, Opts),
    Pkt = <<4:4, 5:4, 0:8, 20:16, 0:16, 0:16, 64:8, 17:8, 0:16, 10, 0, 0, 1, 8, 8, 4, 4>>,
    {ok, _} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S),
    receive
        {forwarded, _} -> ?assert(false)
    after 50 -> ok
    end.
