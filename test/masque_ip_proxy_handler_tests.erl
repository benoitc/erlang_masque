-module(masque_ip_proxy_handler_tests).

-include_lib("eunit/include/eunit.hrl").

%% Test packets are sent from 10.0.0.1 without an assignment.
-define(SRC10, [{4, {10, 0, 0, 0}, 8}]).
-include("masque_ip.hrl").

%%====================================================================
%% Drop telemetry: counter + lifecycle_fun
%%====================================================================

drop_counter_setup_test() ->
    %% setup/0 must be idempotent and create the IP drop counters.
    ok = masque_metrics:setup_ip_counters(),
    ?assert(is_integer(masque_metrics:ip_drop_count(bcp38))).

drop_counter_increments_for_known_reason_test() ->
    ok = masque_metrics:setup_ip_counters(),
    Before = masque_metrics:ip_drop_count(scope_target),
    ok = masque_metrics:ip_drop_inc(scope_target),
    ok = masque_metrics:ip_drop_inc(scope_target),
    After = masque_metrics:ip_drop_count(scope_target),
    ?assertEqual(Before + 2, After).

drop_counter_unknown_reason_lands_in_other_test() ->
    ok = masque_metrics:setup_ip_counters(),
    Before = masque_metrics:ip_drop_count(other),
    ok = masque_metrics:ip_drop_inc(some_custom_reason_not_listed),
    After = masque_metrics:ip_drop_count(other),
    ?assertEqual(Before + 1, After).

%%====================================================================
%% accept_inbound -> emit_drop -> lifecycle_fun
%%====================================================================

%% Drive handle_ip_packet/2 through reflection on the module's
%% behaviour callbacks. We construct the state via init/2 so that
%% target/ipproto/assigned are set up exactly the way the real
%% session would.

init_with(Req, Opts) ->
    case masque_ip_proxy_handler:init(Req, Opts) of
        {ok, S} -> S;
        {ok, S, _Acts} -> S
    end.

%% A v4 packet with src=10.0.0.1, dst=192.0.2.1, proto=UDP, no payload.
v4_packet(SA, SB, SC, SD, DA, DB, DC, DD, Proto) ->
    IHL = 5,
    Total = IHL * 4,
    <<4:4, IHL:4, 0:8, Total:16, 0:16, 0:16, 64:8, Proto:8, 0:16, SA:8, SB:8, SC:8, SD:8, DA:8,
        DB:8, DC:8, DD:8>>.

bcp38_drop_emits_lifecycle_test() ->
    ok = masque_metrics:setup_ip_counters(),
    Self = self(),
    LifecycleFun = fun(Event, Detail) -> Self ! {hook, Event, Detail} end,
    %% Configure an assigned address that does NOT match the packet's
    %% source so the BCP-38 check fails first.
    Req = #{ip_target => '*', ip_ipproto => '*'},
    Opts = #{
        address_pool => {4, {10, 0, 0, 0}, 24},
        allow_private => false,
        lifecycle_fun => LifecycleFun
    },
    S0 = init_with(Req, Opts),
    %% Manually mark an address as assigned so src_filter has a rule
    %% but our forged packet's source doesn't match.
    {Reqs, _} = {
        [
            #ip_prefix_request{
                request_id = 1,
                version = 4,
                address = {10, 0, 0, 0},
                prefix_len = 32
            }
        ],
        unused
    },
    {ok, S1, _Actions} = masque_ip_proxy_handler:handle_address_request(
        Reqs, S0
    ),
    Before = masque_metrics:ip_drop_count(bcp38),
    Pkt = v4_packet(192, 168, 1, 1, 192, 0, 2, 1, 17),
    %% RFC 9484 section 7.2.1: the drop is signalled with ICMP
    %% Destination Unreachable, administratively prohibited (code 13).
    {ok, _S2, [{send_ip_packet, Icmp}]} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S1),
    ?assertMatch(<<4:4, _:68, 1, _:80, 3, 13, _/binary>>, Icmp),
    After = masque_metrics:ip_drop_count(bcp38),
    ?assertEqual(Before + 1, After),
    receive
        {hook, packet_dropped, #{reason := bcp38} = D} ->
            ?assert(maps:is_key(packet_size, D))
    after 100 ->
        ct:fail("lifecycle_fun was not invoked for bcp38 drop")
    end.

scope_target_drop_emits_lifecycle_test() ->
    ok = masque_metrics:setup_ip_counters(),
    Self = self(),
    Hook = fun(Event, Detail) -> Self ! {hook, Event, Detail} end,
    Req = #{ip_target => {198, 51, 100, 1}, ip_ipproto => '*'},
    Opts = #{allow_private => true, allowed_source_prefixes => ?SRC10, lifecycle_fun => Hook},
    S = init_with(Req, Opts),
    Before = masque_metrics:ip_drop_count(scope_target),
    %% wrong target
    Pkt = v4_packet(10, 0, 0, 1, 192, 0, 2, 1, 17),
    {ok, _S2, [{send_ip_packet, _}]} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S),
    ?assertEqual(Before + 1, masque_metrics:ip_drop_count(scope_target)),
    receive
        {hook, packet_dropped, #{reason := scope_target}} -> ok
    after 100 ->
        ct:fail("lifecycle_fun was not invoked for scope_target drop")
    end.

scope_ipproto_drop_emits_lifecycle_test() ->
    ok = masque_metrics:setup_ip_counters(),
    Self = self(),
    Hook = fun(E, D) -> Self ! {hook, E, D} end,
    %% TCP only
    Req = #{ip_target => '*', ip_ipproto => 6},
    Opts = #{allow_private => true, allowed_source_prefixes => ?SRC10, lifecycle_fun => Hook},
    S = init_with(Req, Opts),
    Before = masque_metrics:ip_drop_count(scope_ipproto),
    %% UDP, blocked
    Pkt = v4_packet(10, 0, 0, 1, 192, 0, 2, 1, 17),
    {ok, _S2, [{send_ip_packet, _}]} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S),
    ?assertEqual(Before + 1, masque_metrics:ip_drop_count(scope_ipproto)),
    receive
        {hook, packet_dropped, #{reason := scope_ipproto}} -> ok
    after 100 ->
        ct:fail("lifecycle_fun was not invoked for scope_ipproto drop")
    end.

forward_drop_counted_test() ->
    ok = masque_metrics:setup_ip_counters(),
    Self = self(),
    Hook = fun(E, D) -> Self ! {hook, E, D} end,
    Req = #{ip_target => '*', ip_ipproto => '*'},
    Opts = #{
        allow_private => true,
        allowed_source_prefixes => ?SRC10,
        lifecycle_fun => Hook,
        forward_fun => fun(_Pkt, St) -> {drop, St} end
    },
    S = init_with(Req, Opts),
    Before = masque_metrics:ip_drop_count(forward_drop),
    Pkt = v4_packet(10, 0, 0, 1, 192, 0, 2, 1, 17),
    {ok, _S2} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S),
    ?assertEqual(Before + 1, masque_metrics:ip_drop_count(forward_drop)),
    receive
        {hook, packet_dropped, #{reason := forward_drop}} -> ok
    after 100 ->
        ct:fail("lifecycle_fun was not invoked for forward_drop")
    end.

%%====================================================================
%% Allocation lifecycle telemetry: address_assigned, route_advertised
%%====================================================================

%% Drain any leftover hook messages so each test starts clean.
drain() ->
    receive
        _ -> drain()
    after 0 -> ok
    end.

route_advertised_emits_lifecycle_test() ->
    ok = masque_metrics:setup_ip_counters(),
    drain(),
    Self = self(),
    Hook = fun(E, D) -> Self ! {hook, E, D} end,
    Routes = [
        #ip_route{
            version = 4,
            start_addr = {10, 0, 0, 0},
            end_addr = {10, 0, 0, 255},
            ip_protocol = 0
        }
    ],
    Req = #{ip_target => '*', ip_ipproto => '*'},
    Opts = #{routes => Routes, lifecycle_fun => Hook},
    Before = masque_metrics:ip_advertised_count(),
    {ok, _S, [{advertise, _}]} = masque_ip_proxy_handler:init(Req, Opts),
    ?assertEqual(Before + 1, masque_metrics:ip_advertised_count()),
    receive
        {hook, route_advertised, #{routes := Routes}} -> ok
    after 100 ->
        ct:fail("lifecycle_fun was not invoked for route_advertised")
    end.

address_assigned_emits_lifecycle_test() ->
    ok = masque_metrics:setup_ip_counters(),
    drain(),
    Self = self(),
    Hook = fun(E, D) -> Self ! {hook, E, D} end,
    Req = #{ip_target => '*', ip_ipproto => '*'},
    Opts = #{
        address_pool => {4, {10, 0, 0, 0}, 30},
        lifecycle_fun => Hook
    },
    {ok, S0} = masque_ip_proxy_handler:init(Req, Opts),
    Reqs = [
        #ip_prefix_request{
            request_id = 1,
            version = 4,
            address = {0, 0, 0, 0},
            prefix_len = 32
        }
    ],
    Before = masque_metrics:ip_assigned_count(),
    {ok, _S1, [{assign, [Assign]}]} =
        masque_ip_proxy_handler:handle_address_request(Reqs, S0),
    ?assertMatch(
        #ip_assignment{
            request_id = 1,
            version = 4,
            prefix_len = 32
        },
        Assign
    ),
    ?assertEqual(Before + 1, masque_metrics:ip_assigned_count()),
    receive
        {hook, address_assigned, #{version := 4, prefix_len := 32, address := {10, 0, 0, 1}}} -> ok
    after 100 ->
        ct:fail("lifecycle_fun was not invoked for address_assigned")
    end.

%%====================================================================
%% Per-session prefix assignments
%%====================================================================

allocate_prefix_aligned_test() ->
    drain(),
    Req = #{ip_target => '*', ip_ipproto => '*'},
    %% Pool spans 10.0.0.0/24 (256 addresses); allow up to /28 wide.
    Opts = #{
        address_pool => {4, {10, 0, 0, 0}, 24},
        min_assignable_prefix => #{4 => 28},
        max_assignments => 2
    },
    {ok, S0} = masque_ip_proxy_handler:init(Req, Opts),
    Reqs = [
        #ip_prefix_request{
            request_id = 1,
            version = 4,
            address = {0, 0, 0, 0},
            prefix_len = 28
        }
    ],
    {ok, S1, [{assign, [Assign1]}]} =
        masque_ip_proxy_handler:handle_address_request(Reqs, S0),
    %% First /28 is 10.0.0.0/28.
    ?assertMatch(
        #ip_assignment{
            prefix_len = 28,
            address = {10, 0, 0, 0}
        },
        Assign1
    ),
    %% Second /28 must be aligned to the next 16-address boundary.
    Reqs2 = [
        #ip_prefix_request{
            request_id = 2,
            version = 4,
            address = {0, 0, 0, 0},
            prefix_len = 28
        }
    ],
    {ok, _S2, [{assign, [Assign2, Kept]}]} =
        masque_ip_proxy_handler:handle_address_request(Reqs2, S1),
    ?assertMatch(
        #ip_assignment{
            prefix_len = 28,
            address = {10, 0, 0, 16}
        },
        Assign2
    ),
    %% The first /28 is still held, so it is listed again (unprompted).
    ?assertEqual(Assign1#ip_assignment{request_id = 0}, Kept).

%% Even when the client asks for a wider prefix than `min_assignable',
%% the proxy clamps the response to `min_assignable'.
allocate_clamps_to_min_assignable_test() ->
    drain(),
    Req = #{ip_target => '*', ip_ipproto => '*'},
    Opts = #{
        address_pool => {4, {10, 0, 0, 0}, 24},
        min_assignable_prefix => #{4 => 30}
    },
    {ok, S0} = masque_ip_proxy_handler:init(Req, Opts),
    %% Client asks for /24, but server's `min_assignable' is /30 so
    %% we must answer with /30.
    Reqs = [
        #ip_prefix_request{
            request_id = 1,
            version = 4,
            address = {0, 0, 0, 0},
            prefix_len = 24
        }
    ],
    {ok, _, [{assign, [A]}]} =
        masque_ip_proxy_handler:handle_address_request(Reqs, S0),
    ?assertEqual(30, A#ip_assignment.prefix_len).

%% Default behaviour (no min_assignable_prefix opt) still gives /32.
allocate_default_is_host_route_test() ->
    drain(),
    Req = #{ip_target => '*', ip_ipproto => '*'},
    Opts = #{address_pool => {4, {10, 0, 0, 0}, 24}},
    {ok, S0} = masque_ip_proxy_handler:init(Req, Opts),
    Reqs = [
        #ip_prefix_request{
            request_id = 1,
            version = 4,
            address = {0, 0, 0, 0},
            prefix_len = 32
        }
    ],
    {ok, _, [{assign, [A]}]} =
        masque_ip_proxy_handler:handle_address_request(Reqs, S0),
    ?assertEqual(32, A#ip_assignment.prefix_len),
    ?assertEqual({10, 0, 0, 1}, A#ip_assignment.address).

%% A host address never takes the IPv6 subnet-router anycast address.
allocate_v6_skips_anycast_test() ->
    Req = #{ip_target => '*', ip_ipproto => '*'},
    {ok, S0} = masque_ip_proxy_handler:init(Req, #{
        address_pool => {6, {16#fd00, 0, 0, 0, 0, 0, 0, 0}, 64}
    }),
    {ok, _, [{assign, [A]}]} =
        masque_ip_proxy_handler:handle_address_request([host_request(1, 6)], S0),
    ?assertEqual({16#fd00, 0, 0, 0, 0, 0, 0, 1}, A#ip_assignment.address).

%% In IPv4 neither the network nor the broadcast address is handed out.
allocate_v4_skips_network_and_broadcast_test() ->
    Req = #{ip_target => '*', ip_ipproto => '*'},
    {ok, S0} = masque_ip_proxy_handler:init(Req, #{
        address_pool => {4, {10, 0, 0, 0}, 30}, max_assignments => 4
    }),
    {ok, S1, _} = masque_ip_proxy_handler:handle_address_request([host_request(1, 4)], S0),
    {ok, S2, _} = masque_ip_proxy_handler:handle_address_request([host_request(2, 4)], S1),
    %% The pool is exhausted: the third request is refused, and the full
    %% set sent back holds only the two host addresses.
    {ok, _, [{assign, Set}]} =
        masque_ip_proxy_handler:handle_address_request([host_request(3, 4)], S2),
    ?assertEqual(
        [{0, 0, 0, 0}, {10, 0, 0, 1}, {10, 0, 0, 2}],
        lists:sort([A#ip_assignment.address || A <- Set])
    ).

%% An explicit range that is not a subnet is used as given.
allocate_explicit_range_used_as_given_test() ->
    Req = #{ip_target => '*', ip_ipproto => '*'},
    Range = #ip_route{
        version = 4, start_addr = {10, 0, 0, 0}, end_addr = {10, 0, 0, 2}, ip_protocol = 0
    },
    {ok, S0} = masque_ip_proxy_handler:init(Req, #{address_pool => Range}),
    {ok, _, [{assign, [A]}]} =
        masque_ip_proxy_handler:handle_address_request([host_request(1, 4)], S0),
    ?assertEqual({10, 0, 0, 0}, A#ip_assignment.address).

%% A two-address pool has no reserved address to skip.
allocate_v4_pool_of_two_test() ->
    Req = #{ip_target => '*', ip_ipproto => '*'},
    {ok, S0} = masque_ip_proxy_handler:init(Req, #{address_pool => {4, {10, 0, 0, 0}, 31}}),
    {ok, _, [{assign, [A]}]} =
        masque_ip_proxy_handler:handle_address_request([host_request(1, 4)], S0),
    ?assertEqual({10, 0, 0, 0}, A#ip_assignment.address).

host_request(Id, 4) ->
    #ip_prefix_request{request_id = Id, version = 4, address = {0, 0, 0, 0}, prefix_len = 32};
host_request(Id, 6) ->
    #ip_prefix_request{
        request_id = Id, version = 6, address = {0, 0, 0, 0, 0, 0, 0, 0}, prefix_len = 128
    }.

%%====================================================================
%% forward_fun {actions, _, _} shape
%%====================================================================

forward_actions_emit_drop_and_send_test() ->
    ok = masque_metrics:setup_ip_counters(),
    drain(),
    Self = self(),
    Hook = fun(E, D) -> Self ! {hook, E, D} end,
    Reply = <<"reply payload">>,
    Forward = fun(_Pkt, St) ->
        {actions,
            [
                {send_ip_packet, Reply},
                {drop, ttl_zero}
            ],
            St}
    end,
    Req = #{ip_target => '*', ip_ipproto => '*'},
    Opts = #{
        allow_private => true,
        allowed_source_prefixes => ?SRC10,
        lifecycle_fun => Hook,
        forward_fun => Forward
    },
    S = init_with(Req, Opts),
    Before = masque_metrics:ip_drop_count(ttl_zero),
    Pkt = v4_packet(10, 0, 0, 1, 192, 0, 2, 1, 17),
    %% The handler returns a 3-tuple `{ok, S, Actions}' with the
    %% non-drop actions ready for the session's interpreter.
    {ok, _S2, Actions} =
        masque_ip_proxy_handler:handle_ip_packet(Pkt, S),
    ?assertEqual([{send_ip_packet, Reply}], Actions),
    ?assertEqual(Before + 1, masque_metrics:ip_drop_count(ttl_zero)),
    receive
        {hook, packet_dropped, #{reason := ttl_zero}} -> ok
    after 100 ->
        ct:fail("lifecycle_fun was not invoked for {drop, ttl_zero}")
    end.

terminate_releases_assignments_test() ->
    ok = masque_metrics:setup_ip_counters(),
    drain(),
    Self = self(),
    Hook = fun(E, D) -> Self ! {hook, E, D} end,
    Req = #{ip_target => '*', ip_ipproto => '*'},
    Opts = #{
        address_pool => {4, {10, 0, 0, 0}, 30},
        lifecycle_fun => Hook
    },
    {ok, S0} = masque_ip_proxy_handler:init(Req, Opts),
    Reqs = [
        #ip_prefix_request{
            request_id = 1,
            version = 4,
            address = {0, 0, 0, 0},
            prefix_len = 32
        }
    ],
    {ok, S1, _} =
        masque_ip_proxy_handler:handle_address_request(Reqs, S0),
    %% Drop the address_assigned message we already exercised.
    drain(),
    Before = masque_metrics:ip_released_count(),
    ok = masque_ip_proxy_handler:terminate(normal, S1),
    receive
        {hook, address_released, #{version := 4, address := {10, 0, 0, 1}, prefix_len := 32}} -> ok
    after 100 ->
        ct:fail("lifecycle_fun was not invoked for address_released")
    end,
    %% The release counter only goes up when the registry is running
    %% (a release through a no-op registry doesn't bump). The test
    %% does not require the registry to be active.
    ?assert(masque_metrics:ip_released_count() >= Before).

%%====================================================================
%% Target scoping
%%====================================================================

accept_req(Target, Resolved, HOpts) ->
    #{ip_target => Target, resolved_addresses => Resolved, handler_opts => HOpts}.

accept_wildcard_needs_allow_private_test() ->
    ?assertEqual(
        {reject, forbidden},
        masque_ip_proxy_handler:accept(accept_req('*', [], #{}))
    ),
    ?assertEqual(
        accept,
        masque_ip_proxy_handler:accept(accept_req('*', [], #{allow_private => true}))
    ).

accept_private_prefix_rejected_test() ->
    ?assertEqual(
        {reject, forbidden},
        masque_ip_proxy_handler:accept(accept_req({4, {10, 0, 0, 0}, 8}, [], #{}))
    ),
    ?assertEqual(
        {reject, forbidden},
        masque_ip_proxy_handler:accept(accept_req({4, {0, 0, 0, 0}, 0}, [], #{}))
    ),
    ?assertEqual(
        {reject, forbidden},
        masque_ip_proxy_handler:accept(accept_req({6, {16#FD00, 0, 0, 0, 0, 0, 0, 0}, 8}, [], #{}))
    ),
    ?assertEqual(
        accept,
        masque_ip_proxy_handler:accept(accept_req({4, {8, 8, 8, 0}, 24}, [], #{}))
    ).

accept_hostname_checks_resolved_test() ->
    ?assertEqual(
        {reject, forbidden},
        masque_ip_proxy_handler:accept(accept_req(<<"internal">>, [{127, 0, 0, 1}], #{}))
    ),
    ?assertEqual(
        accept,
        masque_ip_proxy_handler:accept(accept_req(<<"example.com">>, [{93, 184, 216, 34}], #{}))
    ).

%% forward_fun that reports the packets it sees.
forward_probe() ->
    Self = self(),
    fun(Pkt, St) ->
        Self ! {forwarded, Pkt},
        {forward, St}
    end.

%% The handler forwards the client's packet as it came: the TTL is
%% decremented on encapsulation, not decapsulation (RFC 9484 7.2).
assert_forwarded(Pkt) ->
    receive
        {forwarded, Pkt} -> ok
    after 100 -> ct:fail("packet not forwarded")
    end.

%% Either result shape of handle_ip_packet/2.
ip(Pkt, S) ->
    case masque_ip_proxy_handler:handle_ip_packet(Pkt, S) of
        {ok, _} -> ok;
        {ok, _, _} -> ok
    end.

assert_not_forwarded() ->
    receive
        {forwarded, _} -> ct:fail("packet forwarded")
    after 50 -> ok
    end.

%% Assign 10.0.0.0/30 through the allocator.
assigned_state(Req, Opts) ->
    S0 = init_with(Req, Opts#{
        address_pool => {4, {10, 0, 0, 0}, 24},
        min_assignable_prefix => #{4 => 30}
    }),
    Reqs = [
        #ip_prefix_request{
            request_id = 1,
            version = 4,
            address = {0, 0, 0, 0},
            prefix_len = 30
        }
    ],
    {ok, S1, [{assign, [#ip_assignment{address = {10, 0, 0, 0}, prefix_len = 30}]}]} =
        masque_ip_proxy_handler:handle_address_request(Reqs, S0),
    S1.

hostname_off_route_dropped_test() ->
    ok = masque_metrics:setup_ip_counters(),
    drain(),
    Req = #{
        ip_target => <<"example.com">>,
        ip_ipproto => '*',
        resolved_addresses => [{93, 184, 216, 34}]
    },
    S = assigned_state(Req, #{forward_fun => forward_probe()}),
    Before = masque_metrics:ip_drop_count(scope_target),
    Off = v4_packet(10, 0, 0, 1, 8, 8, 8, 8, 17),
    ok = ip(Off, S),
    assert_not_forwarded(),
    ?assertEqual(Before + 1, masque_metrics:ip_drop_count(scope_target)),
    On = v4_packet(10, 0, 0, 1, 93, 184, 216, 34, 17),
    ok = ip(On, S),
    assert_forwarded(On).

prefix_target_private_destination_dropped_test() ->
    drain(),
    %% 8.0.0.0/5 starts and ends public but covers 10.0.0.0/8.
    Req = #{ip_target => {4, {8, 0, 0, 0}, 5}, ip_ipproto => '*'},
    S = assigned_state(Req, #{forward_fun => forward_probe()}),
    Priv = v4_packet(10, 0, 0, 1, 10, 1, 1, 1, 17),
    ok = ip(Priv, S),
    assert_not_forwarded(),
    Pub = v4_packet(10, 0, 0, 1, 8, 8, 8, 8, 17),
    ok = ip(Pub, S),
    assert_forwarded(Pub).

unassigned_source_dropped_test() ->
    ok = masque_metrics:setup_ip_counters(),
    drain(),
    Req = #{ip_target => {8, 8, 8, 8}, ip_ipproto => '*'},
    S = init_with(Req, #{forward_fun => forward_probe()}),
    Before = masque_metrics:ip_drop_count(bcp38),
    Pkt = v4_packet(10, 0, 0, 1, 8, 8, 8, 8, 17),
    ok = ip(Pkt, S),
    assert_not_forwarded(),
    ?assertEqual(Before + 1, masque_metrics:ip_drop_count(bcp38)).

prefix_assigned_source_passes_test() ->
    drain(),
    Req = #{ip_target => {8, 8, 8, 8}, ip_ipproto => '*'},
    S = assigned_state(Req, #{forward_fun => forward_probe()}),
    %% 10.0.0.2 is inside the assigned 10.0.0.0/30.
    In = v4_packet(10, 0, 0, 2, 8, 8, 8, 8, 17),
    ok = ip(In, S),
    assert_forwarded(In),
    Out = v4_packet(10, 0, 0, 4, 8, 8, 8, 8, 17),
    ok = ip(Out, S),
    assert_not_forwarded().

%%====================================================================
%% Router duties: TTL and MTU
%%====================================================================

router_state(Opts) ->
    Req = #{ip_target => '*', ip_ipproto => '*'},
    init_with(Req, Opts#{
        allow_private => true,
        allowed_source_prefixes => [
            {4, {10, 0, 0, 0}, 8}, {6, {16#2001, 16#DB8, 0, 0, 0, 0, 0, 0}, 32}
        ],
        forward_fun => forward_probe()
    }).

v4_packet_ttl(TTL, Size) ->
    Payload = binary:copy(<<0>>, Size - 20),
    Hdr0 = <<16#45, 0, Size:16, 0:16, 2#010:3, 0:13, TTL, 17, 0:16, 10, 0, 0, 1, 8, 8, 8, 8>>,
    Csum = masque_ip_packet:checksum(Hdr0),
    <<16#45, 0, Size:16, 0:16, 2#010:3, 0:13, TTL, 17, Csum:16, 10, 0, 0, 1, 8, 8, 8, 8,
        Payload/binary>>.

v6_packet_hl(HopLimit, Size) ->
    Plen = Size - 40,
    <<6:4, 0:8, 0:20, Plen:16, 17, HopLimit, 16#2001:16, 16#DB8:16, 0:80, 1:16, 16#2606:16,
        16#4700:16, 0:80, 1:16, (binary:copy(<<0>>, Plen))/binary>>.

ttl_decremented_on_forward_test() ->
    drain(),
    S = router_state(#{ttl_decrement => decapsulation}),
    Pkt = v4_packet_ttl(64, 40),
    ok = ip(Pkt, S),
    receive
        {forwarded, <<_:8/binary, 63, _:8, Csum:16, _/binary>> = Fwd} ->
            <<Hdr:20/binary, _/binary>> = Fwd,
            %% A valid header sums to zero.
            ?assertEqual(0, masque_ip_packet:checksum(Hdr)),
            ?assertNotEqual(0, Csum)
    after 100 -> ct:fail("packet not forwarded")
    end.

ttl_one_yields_time_exceeded_test() ->
    ok = masque_metrics:setup_ip_counters(),
    drain(),
    S = router_state(#{ttl_decrement => decapsulation}),
    Before = masque_metrics:ip_drop_count(ttl_zero),
    Pkt = v4_packet_ttl(1, 40),
    {ok, _, [{send_ip_packet, Icmp}]} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S),
    assert_not_forwarded(),
    %% IPv4 + ICMP type 11 code 0.
    ?assertMatch(<<4:4, _:68, 1, _:80, 11, 0, _/binary>>, Icmp),
    ?assertEqual(Before + 1, masque_metrics:ip_drop_count(ttl_zero)).

hop_limit_one_yields_time_exceeded_test() ->
    drain(),
    S = router_state(#{ttl_decrement => decapsulation}),
    Pkt = v6_packet_hl(1, 60),
    {ok, _, [{send_ip_packet, Icmp}]} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S),
    assert_not_forwarded(),
    %% IPv6 next header 58 (ICMPv6), type 3 code 0.
    ?assertMatch(<<6:4, _:44, 58, _:8, _:256, 3, 0, _/binary>>, Icmp).

oversize_v6_yields_packet_too_big_test() ->
    ok = masque_metrics:setup_ip_counters(),
    drain(),
    S = router_state(#{mtu => 1280}),
    Before = masque_metrics:ip_drop_count(mtu_exceeded),
    Pkt = v6_packet_hl(64, 1300),
    {ok, _, [{send_ip_packet, Icmp}]} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S),
    assert_not_forwarded(),
    %% ICMPv6 type 2 code 0 carrying the MTU.
    ?assertMatch(<<6:4, _:44, 58, _:8, _:256, 2, 0, _:16, 1280:32, _/binary>>, Icmp),
    ?assertEqual(Before + 1, masque_metrics:ip_drop_count(mtu_exceeded)),
    %% At the MTU it goes through.
    Fits = v6_packet_hl(64, 1280),
    ok = ip(Fits, S),
    assert_forwarded(Fits).

oversize_v4_yields_frag_needed_test() ->
    drain(),
    S = router_state(#{mtu => 576}),
    Pkt = v4_packet_ttl(64, 600),
    {ok, _, [{send_ip_packet, Icmp}]} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S),
    assert_not_forwarded(),
    %% ICMP type 3 code 4, next-hop MTU in the low 16 bits.
    ?assertMatch(<<4:4, _:68, 1, _:80, 3, 4, _:16, 0:16, 576:16, _/binary>>, Icmp).

icmp_v4_packet(TTL, Type, Size) ->
    Payload = <<Type, 0, (binary:copy(<<0>>, Size - 22))/binary>>,
    Hdr0 = <<16#45, 0, Size:16, 0:16, 0:16, TTL, 1, 0:16, 10, 0, 0, 1, 8, 8, 8, 8>>,
    Csum = masque_ip_packet:checksum(Hdr0),
    <<16#45, 0, Size:16, 0:16, 0:16, TTL, 1, Csum:16, 10, 0, 0, 1, 8, 8, 8, 8, Payload/binary>>.

icmp_v6_packet(HopLimit, Type, Size) ->
    Plen = Size - 40,
    <<6:4, 0:8, 0:20, Plen:16, 58, HopLimit, 16#2001:16, 16#DB8:16, 0:80, 1:16, 16#2606:16,
        16#4700:16, 0:80, 1:16, Type, 0, (binary:copy(<<0>>, Plen - 2))/binary>>.

%% RFC 1122 §3.2.2: no ICMP error in reply to an ICMP error; the drop
%% is still counted.
icmp_v4_error_gets_no_time_exceeded_test() ->
    ok = masque_metrics:setup_ip_counters(),
    drain(),
    S = router_state(#{ttl_decrement => decapsulation}),
    Before = masque_metrics:ip_drop_count(ttl_zero),
    [
        ?assertMatch({ok, _}, masque_ip_proxy_handler:handle_ip_packet(icmp_v4_packet(1, T, 60), S))
     || T <- [3, 4, 5, 11, 12]
    ],
    assert_not_forwarded(),
    ?assertEqual(Before + 5, masque_metrics:ip_drop_count(ttl_zero)),
    %% An echo request is not an error message and still gets one.
    ?assertMatch(
        {ok, _, [{send_ip_packet, _}]},
        masque_ip_proxy_handler:handle_ip_packet(icmp_v4_packet(1, 8, 60), S)
    ).

%% RFC 4443 §2.4 (e): same rule for ICMPv6 error messages (type < 128).
icmp_v6_error_gets_no_time_exceeded_test() ->
    drain(),
    S = router_state(#{ttl_decrement => decapsulation}),
    [
        ?assertMatch({ok, _}, masque_ip_proxy_handler:handle_ip_packet(icmp_v6_packet(1, T, 80), S))
     || T <- [1, 2, 3, 4]
    ],
    assert_not_forwarded(),
    ?assertMatch(
        {ok, _, [{send_ip_packet, _}]},
        masque_ip_proxy_handler:handle_ip_packet(icmp_v6_packet(1, 128, 80), S)
    ).

icmp_v6_error_gets_no_packet_too_big_test() ->
    ok = masque_metrics:setup_ip_counters(),
    drain(),
    S = router_state(#{mtu => 1280}),
    Before = masque_metrics:ip_drop_count(mtu_exceeded),
    ok = ip(icmp_v6_packet(64, 2, 1300), S),
    assert_not_forwarded(),
    ?assertEqual(Before + 1, masque_metrics:ip_drop_count(mtu_exceeded)).

peer_capsules_recorded_test() ->
    drain(),
    Self = self(),
    Hook = fun(E, D) -> Self ! {hook, E, D} end,
    S0 = router_state(#{lifecycle_fun => Hook}),
    Route = #ip_route{
        version = 4,
        start_addr = {192, 0, 2, 0},
        end_addr = {192, 0, 2, 255},
        ip_protocol = 0
    },
    {ok, _} = masque_ip_proxy_handler:handle_route_advertisement([Route], S0),
    receive
        {hook, peer_routes_advertised, #{routes := [Route]}} -> ok
    after 100 -> ct:fail("no peer_routes_advertised")
    end,
    Assign = #ip_assignment{
        request_id = 0, version = 4, address = {192, 0, 2, 1}, prefix_len = 32
    },
    {ok, _} = masque_ip_proxy_handler:handle_address_assign([Assign], S0),
    receive
        {hook, peer_address_assigned, #{entries := [Assign]}} -> ok
    after 100 -> ct:fail("no peer_address_assigned")
    end.

%%====================================================================
%% Policy: hostname scope, sources, quota, peer assignments
%%====================================================================

%% A static route covering private space does not widen a hostname
%% target's scope.
hostname_scope_ignores_static_private_route_test() ->
    drain(),
    Req = #{
        ip_target => <<"example.com">>,
        ip_ipproto => '*',
        resolved_addresses => [{8, 8, 8, 8}]
    },
    Static = #ip_route{
        version = 4, start_addr = {10, 1, 0, 0}, end_addr = {10, 1, 255, 255}, ip_protocol = 0
    },
    S = assigned_state(Req, #{forward_fun => forward_probe(), routes => [Static]}),
    Priv = v4_packet(10, 0, 0, 1, 10, 1, 0, 7, 17),
    ok = ip(Priv, S),
    assert_not_forwarded(),
    Pub = v4_packet(10, 0, 0, 1, 8, 8, 8, 8, 17),
    ok = ip(Pub, S),
    assert_forwarded(Pub).

%% `allow_private' governs destinations only: an unassigned source is
%% still dropped.
unassigned_source_dropped_with_allow_private_test() ->
    drain(),
    Req = #{ip_target => '*', ip_ipproto => '*'},
    S = init_with(Req, #{allow_private => true, forward_fun => forward_probe()}),
    Pkt = v4_packet(1, 2, 3, 4, 8, 8, 8, 8, 17),
    ok = ip(Pkt, S),
    assert_not_forwarded().

allowed_source_prefix_passes_test() ->
    drain(),
    Req = #{ip_target => '*', ip_ipproto => '*'},
    S = init_with(Req, #{
        allow_private => true,
        allowed_source_prefixes => [{4, {1, 2, 3, 0}, 24}],
        forward_fun => forward_probe()
    }),
    Pkt = v4_packet(1, 2, 3, 4, 8, 8, 8, 8, 17),
    ok = ip(Pkt, S),
    assert_forwarded(Pkt).

request(Id) ->
    #ip_prefix_request{request_id = Id, version = 4, address = {0, 0, 0, 0}, prefix_len = 32}.

%% A later request for the other family keeps the first address in the
%% answer: every ADDRESS_ASSIGN is the full set (RFC 9484 4.7.1).
second_family_keeps_first_address_test() ->
    drain(),
    Req = #{ip_target => '*', ip_ipproto => '*'},
    S0 = init_with(Req, #{
        address_pool => [{4, {10, 0, 0, 0}, 24}, {6, {16#fd00, 0, 0, 0, 0, 0, 0, 0}, 64}]
    }),
    {ok, S1, [{assign, [V4]}]} =
        masque_ip_proxy_handler:handle_address_request([request(1)], S0),
    V6Req = #ip_prefix_request{
        request_id = 2, version = 6, address = {0, 0, 0, 0, 0, 0, 0, 0}, prefix_len = 128
    },
    {ok, _S2, [{assign, [V6, Kept]}]} =
        masque_ip_proxy_handler:handle_address_request([V6Req], S1),
    ?assertMatch(#ip_assignment{request_id = 2, version = 6}, V6),
    ?assertEqual(V4#ip_assignment{request_id = 0}, Kept).

%% A rejected request is not retained: the next answer lists only what
%% the client really holds.
rejection_not_retained_test() ->
    drain(),
    Req = #{ip_target => '*', ip_ipproto => '*'},
    S0 = init_with(Req, #{address_pool => {4, {10, 0, 0, 0}, 24}}),
    V6Req = #ip_prefix_request{
        request_id = 1, version = 6, address = {0, 0, 0, 0, 0, 0, 0, 0}, prefix_len = 128
    },
    {ok, S1, [{assign, [Reject]}]} =
        masque_ip_proxy_handler:handle_address_request([V6Req], S0),
    ?assertMatch(#ip_assignment{request_id = 1, prefix_len = 128}, Reject),
    {ok, _S2, [{assign, [V4]}]} =
        masque_ip_proxy_handler:handle_address_request([request(2)], S1),
    ?assertMatch(#ip_assignment{request_id = 2, version = 4}, V4).

%% One session cannot drain the pool: past `max_assignments' (1 per
%% family by default) a request gets the address already held.
quota_returns_held_address_test() ->
    drain(),
    Req = #{ip_target => '*', ip_ipproto => '*'},
    S0 = init_with(Req, #{address_pool => {4, {10, 0, 0, 0}, 24}}),
    {ok, S1, [{assign, [A1]}]} =
        masque_ip_proxy_handler:handle_address_request([request(1)], S0),
    {ok, _S2, [{assign, Many}]} =
        masque_ip_proxy_handler:handle_address_request([request(I) || I <- lists:seq(2, 300)], S1),
    ?assertEqual(299, length(Many)),
    ?assert(
        lists:all(
            fun(#ip_assignment{address = A}) -> A =:= A1#ip_assignment.address end, Many
        )
    ).

%% Each ADDRESS_ASSIGN replaces the previous list (RFC 9484 4.7.1).
peer_assign_replaces_previous_test() ->
    drain(),
    S0 = router_state(#{}),
    A = fun(Id, Last) ->
        #ip_assignment{request_id = Id, version = 4, address = {192, 0, 2, Last}, prefix_len = 32}
    end,
    {ok, S1} = masque_ip_proxy_handler:handle_address_assign([A(1, 1)], S0),
    {ok, S2} = masque_ip_proxy_handler:handle_address_assign([A(2, 2)], S1),
    {ok, Only2} = masque_ip_proxy_handler:handle_address_assign([A(2, 2)], S0),
    ?assertEqual(Only2, S2),
    Big = [A(I, I rem 250) || I <- lists:seq(1, 200)],
    {ok, S3} = masque_ip_proxy_handler:handle_address_assign(Big, S0),
    {ok, Bounded} = masque_ip_proxy_handler:handle_address_assign(lists:sublist(Big, 64), S0),
    ?assertEqual(Bounded, S3).

allow_ip_rejects_test() ->
    Deny = fun({_Target, _Proto}) -> false end,
    ?assertEqual(
        {reject, forbidden},
        masque_ip_proxy_handler:accept(
            accept_req(<<"example.com">>, [{93, 184, 216, 34}], #{allow_ip => Deny})
        )
    ).

%%====================================================================
%% RFC 9484 compliance: routes, ICMP, TTL on encapsulation
%%====================================================================

%% A resolved address inside a static route no longer makes the
%% initial advertisement invalid (section 4.7.3).
overlapping_routes_are_merged_test() ->
    Req = #{
        ip_target => {93, 184, 216, 34},
        ip_ipproto => '*',
        resolved_addresses => [{93, 184, 216, 34}]
    },
    All = #ip_route{
        version = 4, start_addr = {0, 0, 0, 0}, end_addr = {255, 255, 255, 255}, ip_protocol = 0
    },
    {ok, _, [{advertise, Routes}]} = masque_ip_proxy_handler:init(Req, #{routes => [All]}),
    ?assertEqual([All], Routes),
    _ = masque_ip_capsule:encode_route_advertisement(Routes).

v6_addr_bin(T) -> <<<<X:16>> || X <- tuple_to_list(T)>>.

v6_echo(Src, Dst, DataLen) ->
    Body0 = <<128, 0, 0:16, 1:16, 1:16, (binary:copy(<<0>>, DataLen))/binary>>,
    Len = byte_size(Body0),
    S = v6_addr_bin(Src),
    D = v6_addr_bin(Dst),
    Csum = masque_ip_packet:checksum(<<S/binary, D/binary, Len:32, 0:24, 58, Body0/binary>>),
    <<_:16, 0:16, Rest/binary>> = Body0,
    <<6:4, 0:8, 0:20, Len:16, 58, 64, S/binary, D/binary, 128, 0, Csum:16, Rest/binary>>.

%% Section 7.2: an echo request to ff02::1 (the MTU check) or to the
%% proxy's link-local address is answered, whatever the scope.
link_local_echo_answered_test() ->
    drain(),
    Req = #{ip_target => {8, 8, 8, 8}, ip_ipproto => 6},
    S = init_with(Req, #{forward_fun => forward_probe()}),
    Src = {16#FE80, 0, 0, 0, 0, 0, 0, 2},
    Probe = v6_echo(Src, {16#FF02, 0, 0, 0, 0, 0, 0, 1}, 1232),
    {ok, _, [{send_ip_packet, Reply}]} = masque_ip_proxy_handler:handle_ip_packet(Probe, S),
    ?assertEqual(1280, byte_size(Reply)),
    ?assertMatch(<<6:4, _:44, 58, _:8, 16#FE80:16, 0:96, 1:16, _:128, 129, 0, _/binary>>, Reply),
    Own = {16#FE80, 0, 0, 0, 0, 0, 0, 16#AA},
    S2 = init_with(Req, #{link_local_address => Own}),
    {ok, _, [{send_ip_packet, Reply2}]} =
        masque_ip_proxy_handler:handle_ip_packet(v6_echo(Src, Own, 8), S2),
    ?assertMatch(<<6:4, _:44, 58, _:8, 16#FE80:16, 0:96, 16#AA:16, _/binary>>, Reply2),
    assert_not_forwarded().

v6_udp(Src, Dst) ->
    <<6:4, 0:8, 0:20, 8:16, 17, 64, (v6_addr_bin(Src))/binary, (v6_addr_bin(Dst))/binary, 0:64>>.

%% Section 7.2.1: an IPv6 source outside the assignment gets code 5,
%% a destination outside the scope code 1.
v6_policy_drops_signal_icmp_test() ->
    Req = #{ip_target => {16#2606, 16#4700, 0, 0, 0, 0, 0, 1}, ip_ipproto => '*'},
    S = init_with(Req, #{
        allowed_source_prefixes => [{6, {16#2001, 16#DB8, 0, 0, 0, 0, 0, 0}, 32}]
    }),
    Ok = {16#2001, 16#DB8, 0, 0, 0, 0, 0, 1},
    Bad = {16#2002, 0, 0, 0, 0, 0, 0, 1},
    {ok, _, [{send_ip_packet, Src5}]} =
        masque_ip_proxy_handler:handle_ip_packet(
            v6_udp(Bad, {16#2606, 16#4700, 0, 0, 0, 0, 0, 1}), S
        ),
    ?assertMatch(<<6:4, _:44, 58, _:8, _:256, 1, 5, _/binary>>, Src5),
    {ok, _, [{send_ip_packet, Dst1}]} =
        masque_ip_proxy_handler:handle_ip_packet(
            v6_udp(Ok, {16#2606, 16#4700, 0, 0, 0, 0, 0, 2}), S
        ),
    ?assertMatch(<<6:4, _:44, 58, _:8, _:256, 1, 1, _/binary>>, Dst1).

%% Policy ICMP errors are rate limited per tunnel; the drops are still
%% counted. No error goes to a multicast destination.
policy_icmp_is_rate_limited_test() ->
    ok = masque_metrics:setup_ip_counters(),
    Req = #{ip_target => {8, 8, 8, 8}, ip_ipproto => '*'},
    S0 = init_with(Req, #{icmp_rate_limit => 2}),
    Pkt = v4_packet(10, 0, 0, 1, 8, 8, 8, 8, 17),
    Before = masque_metrics:ip_drop_count(bcp38),
    {ok, S1, [_]} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S0),
    {ok, S2, [_]} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S1),
    {ok, _} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S2),
    ?assertEqual(Before + 3, masque_metrics:ip_drop_count(bcp38)),
    Multicast = v4_packet(10, 0, 0, 1, 224, 0, 0, 1, 17),
    ?assertMatch({ok, _}, masque_ip_proxy_handler:handle_ip_packet(Multicast, S0)).

%% Section 7.2: the client's packet is not decremented on
%% decapsulation, so a TTL of 1 is forwarded as is.
ttl_one_forwarded_by_default_test() ->
    drain(),
    S = router_state(#{}),
    Pkt = v4_packet_ttl(1, 40),
    {ok, _} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S),
    assert_forwarded(Pkt).

%% Packets `forward_fun' sends into the tunnel are decremented; one
%% that runs out is dropped and its Time Exceeded goes back out
%% through `handle_info/2'.
replies_decremented_on_encapsulation_test() ->
    ok = masque_metrics:setup_ip_counters(),
    drain(),
    Self = self(),
    Reply = fun(TTL) ->
        fun(Pkt, St) ->
            Self ! {forwarded, Pkt},
            {reply, v4_packet_ttl(TTL, 40), St}
        end
    end,
    Req = #{ip_target => '*', ip_ipproto => '*'},
    Base = #{allow_private => true, allowed_source_prefixes => ?SRC10},
    S = init_with(Req, Base#{forward_fun => Reply(64)}),
    {ok, _, [{send_ip_packet, <<_:8/binary, 63, _/binary>>}]} =
        masque_ip_proxy_handler:handle_ip_packet(v4_packet(10, 0, 0, 1, 8, 8, 8, 8, 17), S),
    drain(),
    Before = masque_metrics:ip_drop_count(ttl_zero),
    S1 = init_with(Req, Base#{forward_fun => Reply(1)}),
    {ok, S2, []} =
        masque_ip_proxy_handler:handle_ip_packet(v4_packet(10, 0, 0, 1, 8, 8, 8, 8, 17), S1),
    ?assertEqual(Before + 1, masque_metrics:ip_drop_count(ttl_zero)),
    drain_forwarded(),
    Icmp =
        receive
            {masque_ip_icmp, I} -> I
        after 100 -> ct:fail("no Time Exceeded for the expired reply")
        end,
    ?assertMatch(<<4:4, _:68, 1, _:80, 11, 0, _/binary>>, Icmp),
    %% handle_info/2 hands it to forward_fun, toward the reply's source.
    {ok, _, _} = masque_ip_proxy_handler:handle_info({masque_ip_icmp, Icmp}, S2),
    receive
        {forwarded, Icmp} -> ok
    after 100 -> ct:fail("Time Exceeded not forwarded")
    end.

drain_forwarded() ->
    receive
        {forwarded, _} -> drain_forwarded()
    after 0 -> ok
    end.

%% `ttl_decrement => decapsulation' keeps the replies as they are.
replies_kept_with_decapsulation_test() ->
    Reply = v4_packet_ttl(1, 40),
    Req = #{ip_target => '*', ip_ipproto => '*'},
    S = init_with(Req, #{
        allow_private => true,
        allowed_source_prefixes => ?SRC10,
        ttl_decrement => decapsulation,
        forward_fun => fun(_Pkt, St) -> {reply, Reply, St} end
    }),
    ?assertMatch(
        {ok, _, [{send_ip_packet, Reply}]},
        masque_ip_proxy_handler:handle_ip_packet(v4_packet_ttl(64, 40), S)
    ).
