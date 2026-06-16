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
