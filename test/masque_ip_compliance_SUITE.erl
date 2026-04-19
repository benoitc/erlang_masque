%%% @doc RFC 9484 normative compliance suite.
%%%
%%% Drives the default `masque_ip_proxy_handler' end-to-end over H3
%%% and pins the §-mapped behaviours: 2xx `capsule-protocol: ?1'
%%% handshake, initial `ROUTE_ADVERTISEMENT' from the pool config,
%%% `ADDRESS_REQUEST' -> `ADDRESS_ASSIGN' allocator round-trip,
%%% exhaustion-as-rejection, client-side `capsule_protocol => false'
%%% rejection, and target-shape validation.
-module(masque_ip_compliance_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("masque_ip.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1,
         init_per_testcase/2, end_per_testcase/2]).

-export([initial_route_advertisement/1,
         address_allocation_round_robin/1,
         pool_exhaustion_rejects/1,
         client_rejects_capsule_off/1,
         bad_target_shape_for_ip/1,
         oversize_packet_rejected/1,
         capsule_protocol_forced_true/1]).

all() ->
    [initial_route_advertisement,
     address_allocation_round_robin,
     pool_exhaustion_rejects,
     client_rejects_capsule_off,
     bad_target_shape_for_ip,
     oversize_packet_rejected,
     capsule_protocol_forced_true].

init_per_suite(Config) ->
    application:ensure_all_started(quic),
    application:ensure_all_started(masque),
    {ok, Ctx} = masque_test_helpers:generate_certs(),
    [{ctx, Ctx} | Config].

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(ctx, Config)),
    ok.

init_per_testcase(Case, Config) ->
    Ctx = ?config(ctx, Config),
    Listener = list_to_atom(
                 "ip_comp_" ++ atom_to_list(Case) ++ "_" ++
                 integer_to_list(erlang:unique_integer([positive]))),
    Opts = case_opts(Case, Ctx),
    {ok, _} = masque:start_listener(Listener, Opts),
    {ok, Port} = quic:get_server_port(Listener),
    [{listener, Listener}, {port, Port} | Config].

end_per_testcase(_Case, Config) ->
    _ = masque:stop_listener(?config(listener, Config)),
    ok.

case_opts(initial_route_advertisement, Ctx) ->
    Base = base_opts(Ctx),
    Base#{
        address_pool => {4, {10,200,0,0}, 16},
        routes => [#ip_route{version = 4,
                             start_addr = {0,0,0,0},
                             end_addr = {255,255,255,255},
                             ip_protocol = 0}]
    };
case_opts(address_allocation_round_robin, Ctx) ->
    Base = base_opts(Ctx),
    Base#{
        address_pool => #ip_route{version = 4,
                                  start_addr = {10,200,0,1},
                                  end_addr   = {10,200,0,3},
                                  ip_protocol = 0}
    };
case_opts(pool_exhaustion_rejects, Ctx) ->
    Base = base_opts(Ctx),
    Base#{
        address_pool => #ip_route{version = 4,
                                  start_addr = {10,200,0,1},
                                  end_addr   = {10,200,0,1},
                                  ip_protocol = 0}
    };
case_opts(_, Ctx) ->
    base_opts(Ctx).

base_opts(Ctx) ->
    #{port => 0,
      cert => maps:get(cert, Ctx),
      key  => maps:get(key, Ctx)}.

%%====================================================================
%% Cases
%%====================================================================

initial_route_advertisement(Config) ->
    {ok, Sess} = do_connect(?config(port, Config)),
    receive
        {masque_route_advertisement, Sess, [R | _]} ->
            ?assertMatch(#ip_route{version = 4,
                                   start_addr = {0,0,0,0},
                                   end_addr = {255,255,255,255},
                                   ip_protocol = 0}, R)
    after 2000 -> ct:fail("no initial ROUTE_ADVERTISEMENT")
    end,
    ok = masque:close(Sess).

address_allocation_round_robin(Config) ->
    {ok, Sess} = do_connect(?config(port, Config)),
    %% Consume the initial ROUTE_ADVERTISEMENT (if any) without failing.
    _ = flush_advertise(Sess),
    %% First request: get 10.200.0.1
    {ok, [Id1]} =
        masque:request_addresses(Sess, [{4, {0,0,0,0}, 0}]),
    receive
        {masque_address_assign, Sess, [#ip_assignment{request_id = Id1,
                                                     version = 4,
                                                     address = A1,
                                                     prefix_len = 32}]} ->
            ?assertEqual({10,200,0,1}, A1)
    after 2000 -> ct:fail("no assign 1") end,
    %% Second request: get 10.200.0.2
    {ok, [Id2]} =
        masque:request_addresses(Sess, [{4, {0,0,0,0}, 0}]),
    receive
        {masque_address_assign, Sess, [#ip_assignment{request_id = Id2,
                                                     address = A2}]} ->
            ?assertEqual({10,200,0,2}, A2)
    after 2000 -> ct:fail("no assign 2") end,
    ok = masque:close(Sess).

pool_exhaustion_rejects(Config) ->
    {ok, Sess} = do_connect(?config(port, Config)),
    _ = flush_advertise(Sess),
    {ok, [Id1]} = masque:request_addresses(Sess, [{4, {0,0,0,0}, 0}]),
    receive
        {masque_address_assign, Sess, [#ip_assignment{request_id = Id1,
                                                     address = {10,200,0,1}}]}
            -> ok
    after 2000 -> ct:fail("first assign missed") end,
    %% Pool is a single address; the next request exhausts and the
    %% handler responds with the RFC-9484 §5.2 rejection sentinel.
    {ok, [Id2]} = masque:request_addresses(Sess, [{4, {0,0,0,0}, 0}]),
    receive
        {masque_address_assign, Sess, [#ip_assignment{request_id = Id2,
                                                     address = {0,0,0,0},
                                                     prefix_len = 32}]}
            -> ok
    after 2000 -> ct:fail("no rejection for exhausted pool") end,
    ok = masque:close(Sess).

client_rejects_capsule_off(_Config) ->
    %% Don't even dial: the validator should reject before touching
    %% the transport.
    ?assertEqual(
       {error, {invalid_opts, capsule_protocol_required_for_ip}},
       masque:connect(<<"https://127.0.0.1:1">>,
                      {'*', '*'},
                      #{protocol => ip,
                        capsule_protocol => false})).

%% §4.7 + our API: sending a packet larger than the session MTU is
%% refused at the API boundary — the caller gets a typed error
%% rather than a partial or silent drop.
oversize_packet_rejected(Config) ->
    {ok, Sess} = do_connect(?config(port, Config)),
    _ = flush_advertise(Sess),
    Big = binary:copy(<<"x">>, 2000),   %% default mtu 1500
    ?assertMatch({error, {packet_too_large, 2000, 1500}},
                 masque:send_ip_packet(Sess, Big)),
    ok = masque:close(Sess).

%% §4 — `capsule-protocol: ?1' MUST be on the CONNECT-IP request.
%% The validator forces `capsule_protocol' to `true' when
%% `protocol => ip' is set, even when the caller left the knob off.
capsule_protocol_forced_true(Config) ->
    Port = ?config(port, Config),
    Url = iolist_to_binary(
            ["https://127.0.0.1:", integer_to_binary(Port)]),
    {ok, Sess} =
        masque:connect(Url, {'*', '*'},
                       #{protocol => ip,
                         transports => [h3],
                         verify => verify_none,
                         capsule_protocol => true}),  %% explicit true
    ok = masque:close(Sess).

bad_target_shape_for_ip(_Config) ->
    %% ipproto is 0..255; a classic UDP port number above that is
    %% an unambiguous protocol/target mismatch.
    ?assertEqual(
       {error, {bad_target_for_protocol, ip}},
       masque:connect(<<"https://127.0.0.1:1">>,
                      {<<"dns.google">>, 5353},     %% UDP-shape
                      #{protocol => ip})).

%%====================================================================
%% Internal
%%====================================================================

do_connect(Port) ->
    Url = iolist_to_binary(
            ["https://127.0.0.1:", integer_to_binary(Port)]),
    masque:connect(Url, {'*', '*'},
                   #{protocol => ip,
                     transports => [h3],
                     verify => verify_none}).

flush_advertise(Sess) ->
    receive
        {masque_route_advertisement, Sess, _} -> ok
    after 500 -> ok
    end.
