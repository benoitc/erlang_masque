-module(masque_udp_df_tests).

-include_lib("eunit/include/eunit.hrl").

%% The CONNECT-UDP socket forbids fragmentation (RFC 9298 section 3.1).
udp_proxy_socket_sets_dont_fragment_test() ->
    with_proxy_socket(#{}, fun(Sock) ->
        case expected(inet) of
            [] -> ok;
            Opts -> ?assertEqual(on(Opts), getopts(Sock, Opts))
        end
    end).

udp_proxy_dont_fragment_false_leaves_socket_test() ->
    with_proxy_socket(#{dont_fragment => false}, fun(Sock) ->
        case expected(inet) of
            [] -> ok;
            Opts -> ?assertNotEqual(on(Opts), getopts(Sock, Opts))
        end
    end).

udp_bind_socket_sets_dont_fragment_test() ->
    {ok, S, _} = masque_udp_bind_proxy_handler:init(#{}, #{bind_address => {127, 0, 0, 1}}),
    Sock = element(2, S),
    try
        case expected(inet) of
            [] -> ok;
            Opts -> ?assertEqual(on(Opts), getopts(Sock, Opts))
        end
    after
        masque_udp_bind_proxy_handler:terminate(normal, S)
    end.

%% A datagram the kernel refuses (larger than the path MTU with DF set)
%% is dropped; the tunnel stays up.
oversized_send_drops_test() ->
    with_proxy_state(#{}, fun(S) ->
        ?assertMatch({ok, _}, masque_udp_proxy_handler:handle_packet(binary:copy(<<1>>, 65000), S))
    end).

unknown_os_has_no_options_test() ->
    ?assertEqual([], masque_udp_df:options({win32, nt}, inet)).

with_proxy_socket(Opts, Fun) ->
    with_proxy_state(Opts, fun(S) -> Fun(element(2, S)) end).

with_proxy_state(Opts, Fun) ->
    {ok, Target} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Target),
    {ok, S} = masque_udp_proxy_handler:init(
        #{target_host => <<"127.0.0.1">>, target_port => Port},
        Opts#{allow_private => true, allow_self => true}
    ),
    try
        Fun(S)
    after
        masque_udp_proxy_handler:terminate(normal, S),
        gen_udp:close(Target)
    end.

expected(Family) -> masque_udp_df:options(os:type(), Family).

getopts(Sock, Opts) ->
    {ok, Got} = inet:getopts(Sock, [{raw, L, O, byte_size(V)} || {raw, L, O, V} <- Opts]),
    Got.

on(Opts) -> Opts.
