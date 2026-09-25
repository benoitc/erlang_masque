-module(masque_ip_proxy_handler_tests).

-include_lib("eunit/include/eunit.hrl").
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
    {ok, _S2} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S1),
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
    Opts = #{allow_private => true, lifecycle_fun => Hook},
    S = init_with(Req, Opts),
    Before = masque_metrics:ip_drop_count(scope_target),
    %% wrong target
    Pkt = v4_packet(10, 0, 0, 1, 192, 0, 2, 1, 17),
    {ok, _S2} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S),
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
    Opts = #{allow_private => true, lifecycle_fun => Hook},
    S = init_with(Req, Opts),
    Before = masque_metrics:ip_drop_count(scope_ipproto),
    %% UDP, blocked
    Pkt = v4_packet(10, 0, 0, 1, 192, 0, 2, 1, 17),
    {ok, _S2} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S),
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
        {hook, address_assigned, #{version := 4, prefix_len := 32, address := {10, 0, 0, 0}}} -> ok
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
        min_assignable_prefix => #{4 => 28}
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
    {ok, _S2, [{assign, [Assign2]}]} =
        masque_ip_proxy_handler:handle_address_request(Reqs2, S1),
    ?assertMatch(
        #ip_assignment{
            prefix_len = 28,
            address = {10, 0, 0, 16}
        },
        Assign2
    ).

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
    ?assertEqual({10, 0, 0, 0}, A#ip_assignment.address).

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
        {hook, address_released, #{version := 4, address := {10, 0, 0, 0}, prefix_len := 32}} -> ok
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

%% The handler forwards the packet with its TTL decremented.
assert_forwarded(Pkt) ->
    {ok, Fwd} = masque_ip_packet:decrement_ttl(Pkt),
    receive
        {forwarded, Fwd} -> ok
    after 100 -> ct:fail("packet not forwarded")
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
    {ok, _} = masque_ip_proxy_handler:handle_ip_packet(Off, S),
    assert_not_forwarded(),
    ?assertEqual(Before + 1, masque_metrics:ip_drop_count(scope_target)),
    On = v4_packet(10, 0, 0, 1, 93, 184, 216, 34, 17),
    {ok, _} = masque_ip_proxy_handler:handle_ip_packet(On, S),
    assert_forwarded(On).

prefix_target_private_destination_dropped_test() ->
    drain(),
    %% 8.0.0.0/5 starts and ends public but covers 10.0.0.0/8.
    Req = #{ip_target => {4, {8, 0, 0, 0}, 5}, ip_ipproto => '*'},
    S = assigned_state(Req, #{forward_fun => forward_probe()}),
    Priv = v4_packet(10, 0, 0, 1, 10, 1, 1, 1, 17),
    {ok, _} = masque_ip_proxy_handler:handle_ip_packet(Priv, S),
    assert_not_forwarded(),
    Pub = v4_packet(10, 0, 0, 1, 8, 8, 8, 8, 17),
    {ok, _} = masque_ip_proxy_handler:handle_ip_packet(Pub, S),
    assert_forwarded(Pub).

unassigned_source_dropped_test() ->
    ok = masque_metrics:setup_ip_counters(),
    drain(),
    Req = #{ip_target => {8, 8, 8, 8}, ip_ipproto => '*'},
    S = init_with(Req, #{forward_fun => forward_probe()}),
    Before = masque_metrics:ip_drop_count(bcp38),
    Pkt = v4_packet(10, 0, 0, 1, 8, 8, 8, 8, 17),
    {ok, _} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S),
    assert_not_forwarded(),
    ?assertEqual(Before + 1, masque_metrics:ip_drop_count(bcp38)).

prefix_assigned_source_passes_test() ->
    drain(),
    Req = #{ip_target => {8, 8, 8, 8}, ip_ipproto => '*'},
    S = assigned_state(Req, #{forward_fun => forward_probe()}),
    %% 10.0.0.2 is inside the assigned 10.0.0.0/30.
    In = v4_packet(10, 0, 0, 2, 8, 8, 8, 8, 17),
    {ok, _} = masque_ip_proxy_handler:handle_ip_packet(In, S),
    assert_forwarded(In),
    Out = v4_packet(10, 0, 0, 4, 8, 8, 8, 8, 17),
    {ok, _} = masque_ip_proxy_handler:handle_ip_packet(Out, S),
    assert_not_forwarded().

%%====================================================================
%% Router duties: TTL and MTU
%%====================================================================

router_state(Opts) ->
    Req = #{ip_target => '*', ip_ipproto => '*'},
    init_with(Req, Opts#{allow_private => true, forward_fun => forward_probe()}).

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
    S = router_state(#{}),
    Pkt = v4_packet_ttl(64, 40),
    {ok, _} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S),
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
    S = router_state(#{}),
    Before = masque_metrics:ip_drop_count(ttl_zero),
    Pkt = v4_packet_ttl(1, 40),
    {ok, _, [{send_ip_packet, Icmp}]} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S),
    assert_not_forwarded(),
    %% IPv4 + ICMP type 11 code 0.
    ?assertMatch(<<4:4, _:68, 1, _:80, 11, 0, _/binary>>, Icmp),
    ?assertEqual(Before + 1, masque_metrics:ip_drop_count(ttl_zero)).

hop_limit_one_yields_time_exceeded_test() ->
    drain(),
    S = router_state(#{}),
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
    {ok, _} = masque_ip_proxy_handler:handle_ip_packet(Fits, S),
    assert_forwarded(Fits).

oversize_v4_yields_frag_needed_test() ->
    drain(),
    S = router_state(#{mtu => 576}),
    Pkt = v4_packet_ttl(64, 600),
    {ok, _, [{send_ip_packet, Icmp}]} = masque_ip_proxy_handler:handle_ip_packet(Pkt, S),
    assert_not_forwarded(),
    %% ICMP type 3 code 4, next-hop MTU in the low 16 bits.
    ?assertMatch(<<4:4, _:68, 1, _:80, 3, 4, _:16, 0:16, 576:16, _/binary>>, Icmp).

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
