-module(masque_udp_bind_proxy_handler_tests).

-include_lib("eunit/include/eunit.hrl").
-include("masque_udp_bind.hrl").

%%====================================================================
%% init/2: response headers, public-address resolution
%%====================================================================

%% A sockname-fallback init succeeds when the socket is bound to a
%% specific interface (loopback here).
init_with_loopback_yields_response_headers_test() ->
    Opts = #{bind_address => {127, 0, 0, 1}},
    {ok, State, Actions} = masque_udp_bind_proxy_handler:init(req(), Opts),
    cleanup(State),
    [{response_headers, Hdrs}] = Actions,
    %% Connect-UDP-Bind: ?1
    ?assert(lists:member({<<"connect-udp-bind">>, <<"?1">>}, Hdrs)),
    %% Proxy-Public-Address present and parses to one v4 entry on
    %% loopback.
    {<<"proxy-public-address">>, PpaBin} =
        lists:keyfind(<<"proxy-public-address">>, 1, Hdrs),
    {ok, [{Addr, _Port}]} =
        masque_uri_udp_bind:parse_proxy_public_address(
            [{<<"proxy-public-address">>, PpaBin}]
        ),
    ?assertEqual({127, 0, 0, 1}, Addr).

%% Wildcard sockname (any) without public_addresses must refuse.
init_wildcard_without_public_addresses_rejected_test() ->
    Opts = #{bind_address => any},
    case masque_udp_bind_proxy_handler:init(req(), Opts) of
        {stop, no_public_addresses} -> ok;
        Other -> ct:fail({unexpected_result, Other})
    end.

%% Wildcard with explicit public_addresses passes.
init_wildcard_with_public_addresses_test() ->
    Opts = #{
        bind_address => any,
        public_addresses => [{{198, 51, 100, 1}, 4433}]
    },
    {ok, State, _} = masque_udp_bind_proxy_handler:init(req(), Opts),
    cleanup(State).

%% Empty public_addresses list refused.
init_empty_public_addresses_rejected_test() ->
    Opts = #{
        bind_address => {127, 0, 0, 1},
        public_addresses => []
    },
    case masque_udp_bind_proxy_handler:init(req(), Opts) of
        {stop, no_public_addresses} -> ok;
        Other -> ct:fail({unexpected_result, Other})
    end.

%% public_address_fun takes precedence and gets the sockname.
init_uses_public_address_fun_test() ->
    Self = self(),
    Fun = fun(Sn) ->
        Self ! {got_sockname, Sn},
        [{{203, 0, 113, 1}, 4433}]
    end,
    Opts = #{
        bind_address => {127, 0, 0, 1},
        public_addresses => [{{198, 51, 100, 1}, 999}],
        public_address_fun => Fun
    },
    {ok, State, [{response_headers, Hdrs}]} =
        masque_udp_bind_proxy_handler:init(req(), Opts),
    cleanup(State),
    receive
        {got_sockname, _} -> ok
    after 100 -> ct:fail("public_address_fun was not invoked")
    end,
    {<<"proxy-public-address">>, Bin} =
        lists:keyfind(<<"proxy-public-address">>, 1, Hdrs),
    {ok, [{{203, 0, 113, 1}, 4433}]} =
        masque_uri_udp_bind:parse_proxy_public_address(
            [{<<"proxy-public-address">>, Bin}]
        ).

%%====================================================================
%% peer_filter_fun
%%====================================================================

handle_bind_packet_loopback_passes_test() ->
    {Listener, ListenerSock, ListenerPort} = open_listener(),
    Opts = #{bind_address => {127, 0, 0, 1}, allow_loopback => true},
    {ok, State, _} = masque_udp_bind_proxy_handler:init(req(), Opts),
    {ok, _NewState} =
        masque_udp_bind_proxy_handler:handle_bind_packet(
            {{127, 0, 0, 1}, ListenerPort}, <<"hello">>, State
        ),
    receive
        {udp, ListenerSock, _, _, <<"hello">>} -> ok
    after 1000 -> ct:fail("listener did not receive packet")
    end,
    cleanup(State),
    stop_listener(Listener, ListenerSock).

handle_bind_packet_private_address_filtered_by_default_test() ->
    Opts = #{bind_address => {127, 0, 0, 1}},
    {ok, State, _} = masque_udp_bind_proxy_handler:init(req(), Opts),
    %% 10.0.0.0/8 is RFC 1918 - default peer_filter rejects it.
    ?assertMatch(
        {drop, peer_filter, _},
        masque_udp_bind_proxy_handler:handle_bind_packet(
            {{10, 0, 0, 1}, 1234}, <<"x">>, State
        )
    ),
    cleanup(State).

%% The scrub_fun runs after the peer filter, so `{drop, scrubbed, _}'
%% means the filter let the peer through.
filter_verdict(Peer, Extra) ->
    Scrub = fun(_Pkt, US) -> {drop, scrubbed, US} end,
    Opts = maps:merge(#{bind_address => {127, 0, 0, 1}, scrub_fun => Scrub}, Extra),
    {ok, State, _} = masque_udp_bind_proxy_handler:init(req(), Opts),
    {drop, Reason, _} =
        masque_udp_bind_proxy_handler:handle_bind_packet({Peer, 1234}, <<"x">>, State),
    cleanup(State),
    Reason.

default_filter_drops_loopback_test() ->
    ?assertEqual(peer_filter, filter_verdict({127, 0, 0, 1}, #{})),
    ?assertEqual(peer_filter, filter_verdict({0, 0, 0, 0, 0, 0, 0, 1}, #{})),
    ?assertEqual(scrubbed, filter_verdict({127, 0, 0, 1}, #{allow_loopback => true})).

default_filter_unwraps_mapped_v6_test() ->
    Mapped = fun({A, B, C, D}) -> {0, 0, 0, 0, 0, 16#FFFF, (A bsl 8) bor B, (C bsl 8) bor D} end,
    ?assertEqual(peer_filter, filter_verdict(Mapped({127, 0, 0, 1}), #{})),
    ?assertEqual(peer_filter, filter_verdict(Mapped({10, 0, 0, 1}), #{})),
    ?assertEqual(scrubbed, filter_verdict(Mapped({8, 8, 8, 8}), #{})).

default_filter_drops_cgnat_and_broadcast_test() ->
    ?assertEqual(peer_filter, filter_verdict({100, 64, 0, 1}, #{})),
    ?assertEqual(peer_filter, filter_verdict({255, 255, 255, 255}, #{})),
    ?assertEqual(scrubbed, filter_verdict({8, 8, 8, 8}, #{})).

allow_private_passes_everything_test() ->
    ?assertEqual(scrubbed, filter_verdict({10, 0, 0, 1}, #{allow_private => true})),
    ?assertEqual(scrubbed, filter_verdict({127, 0, 0, 1}, #{allow_private => true})).

%% Custom peer_filter_fun overrides the default.
handle_bind_packet_custom_filter_test() ->
    DenyAll = fun(_IP, _Port) -> {drop, my_reason} end,
    Opts = #{
        bind_address => {127, 0, 0, 1},
        peer_filter_fun => DenyAll
    },
    {ok, State, _} = masque_udp_bind_proxy_handler:init(req(), Opts),
    ?assertMatch(
        {drop, my_reason, _},
        masque_udp_bind_proxy_handler:handle_bind_packet(
            {{127, 0, 0, 1}, 1234}, <<"x">>, State
        )
    ),
    cleanup(State).

%%====================================================================
%% scrub_fun seam
%%====================================================================

scrub_fun_can_drop_packets_test() ->
    Drop = fun(_Pkt, US) -> {drop, scrubbed, US} end,
    Opts = #{bind_address => {127, 0, 0, 1}, allow_loopback => true, scrub_fun => Drop},
    {ok, State, _} = masque_udp_bind_proxy_handler:init(req(), Opts),
    ?assertMatch(
        {drop, scrubbed, _},
        masque_udp_bind_proxy_handler:handle_bind_packet(
            {{127, 0, 0, 1}, 1234}, <<"x">>, State
        )
    ),
    cleanup(State).

scrub_fun_can_rewrite_payload_test() ->
    {Listener, Sock, Port} = open_listener(),
    Rewrite = fun(_Pkt, US) -> {pass, <<"REWRITTEN">>, US} end,
    Opts = #{bind_address => {127, 0, 0, 1}, allow_loopback => true, scrub_fun => Rewrite},
    {ok, State, _} = masque_udp_bind_proxy_handler:init(req(), Opts),
    {ok, _} =
        masque_udp_bind_proxy_handler:handle_bind_packet(
            {{127, 0, 0, 1}, Port}, <<"orig">>, State
        ),
    receive
        {udp, Sock, _, _, <<"REWRITTEN">>} -> ok
    after 1000 -> ct:fail("listener did not receive rewritten packet")
    end,
    cleanup(State),
    stop_listener(Listener, Sock).

%%====================================================================
%% handle_info: {udp, ...} -> send_bind_packet action
%%====================================================================

handle_info_udp_emits_send_bind_packet_test() ->
    Opts = #{bind_address => {127, 0, 0, 1}},
    {ok, State, _} = masque_udp_bind_proxy_handler:init(req(), Opts),
    %% #state.socket
    Sock = element(2, State),
    Msg = {udp, Sock, {198, 51, 100, 1}, 4433, <<"reply">>},
    {ok, _State2, [{send_bind_packet, {{198, 51, 100, 1}, 4433}, <<"reply">>}]} =
        masque_udp_bind_proxy_handler:handle_info(Msg, State),
    cleanup(State).

handle_info_unrelated_messages_ignored_test() ->
    Opts = #{bind_address => {127, 0, 0, 1}},
    {ok, State, _} = masque_udp_bind_proxy_handler:init(req(), Opts),
    {ok, State2} =
        masque_udp_bind_proxy_handler:handle_info(stray_message, State),
    ?assertEqual(State, State2),
    cleanup(State).

%%====================================================================
%% Helpers
%%====================================================================

req() ->
    %% Bind sessions don't carry target_host / target_port for
    %% unscoped binds, but the handler does not require them.
    #{
        method => <<"CONNECT">>,
        protocol => udp_bind,
        path => <<"/.well-known/masque/udp/%2A/%2A/">>,
        authority => <<"proxy.example">>,
        scheme => <<"https">>,
        headers => []
    }.

open_listener() ->
    {ok, Sock} = gen_udp:open(0, [
        binary,
        {ip, {127, 0, 0, 1}},
        {active, true}
    ]),
    {ok, Port} = inet:port(Sock),
    {self(), Sock, Port}.

stop_listener(_Owner, Sock) ->
    gen_udp:close(Sock).

cleanup(State) ->
    masque_udp_bind_proxy_handler:terminate(normal, State).
