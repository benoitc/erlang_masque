%%% @doc RFC 9484 normative compliance suite.
%%%
%%% Drives the IP sessions over real listeners and pins the
%%% section-mapped behaviours on the wire: the handshake, the initial
%%% ROUTE_ADVERTISEMENT, the ADDRESS_REQUEST / ADDRESS_ASSIGN round
%%% trips in both directions, aborts on invalid capsules on both roles,
%%% the pending-request cap, the link-local echo used for the MTU
%%% check and the h3 datagram size rules. The `h3' and `h2' groups run
%%% every case; `h1' runs the wire cases (the older ones are in
%%% `masque_ip_compliance_h1_SUITE'). Every case checks that no server
%%% session is left behind.
-module(masque_ip_compliance_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("masque_ip.hrl").

-export([
    suite/0,
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([
    initial_route_advertisement/1,
    address_allocation_round_robin/1,
    pool_exhaustion_rejects/1,
    client_rejects_capsule_off/1,
    bad_target_shape_for_ip/1,
    oversize_packet_rejected/1,
    capsule_protocol_forced_true/1,
    inject_packet_via_registry/1,
    proxy_aborts_malformed_capsule/1,
    proxy_aborts_empty_address_request/1,
    proxy_aborts_misordered_routes/1,
    client_capsules_reach_proxy/1,
    reject_keeps_held_addresses/1,
    server_pending_cap/1,
    unanswered_ids_rejected/1,
    handler_without_request_callback_rejects/1,
    proxy_request_on_wire/1,
    client_withdraws_left_out_address/1,
    client_aborts_malformed_capsule/1,
    client_aborts_empty_address_request/1,
    client_aborts_misordered_routes/1,
    client_rejects_excess_proxy_requests/1,
    client_ip_info_hides_rejections/1,
    client_source_filter/1,
    hostname_dns_failure/1,
    link_local_echo/1,
    icmp_passes_ipproto_scope/1,
    overlapping_routes_advertised/1,
    mtu_too_low_client_aborts/1,
    mtu_too_low_server_aborts/1,
    tunnel_too_big_reports_icmp/1
]).

-define(WAIT, 3000).
-define(LEAK_MS, 10000).
-define(SCRIPT, masque_ip_script_handler).

suite() -> [{timetrap, {minutes, 3}}].

all() ->
    [{group, h3}, {group, h2}, {group, h1}].

groups() ->
    Basic = [
        initial_route_advertisement,
        address_allocation_round_robin,
        pool_exhaustion_rejects,
        client_rejects_capsule_off,
        bad_target_shape_for_ip,
        oversize_packet_rejected,
        capsule_protocol_forced_true,
        inject_packet_via_registry
    ],
    Wire = [
        proxy_aborts_malformed_capsule,
        proxy_aborts_empty_address_request,
        proxy_aborts_misordered_routes,
        client_capsules_reach_proxy,
        reject_keeps_held_addresses,
        server_pending_cap,
        unanswered_ids_rejected,
        handler_without_request_callback_rejects,
        proxy_request_on_wire,
        client_withdraws_left_out_address,
        client_aborts_malformed_capsule,
        client_aborts_empty_address_request,
        client_aborts_misordered_routes,
        client_rejects_excess_proxy_requests,
        client_ip_info_hides_rejections,
        client_source_filter,
        hostname_dns_failure,
        link_local_echo,
        icmp_passes_ipproto_scope,
        overlapping_routes_advertised
    ],
    H3Only = [mtu_too_low_client_aborts, mtu_too_low_server_aborts, tunnel_too_big_reports_icmp],
    [
        {h3, [], Basic ++ Wire ++ H3Only},
        {h2, [], Basic ++ Wire},
        {h1, [], Wire}
    ].

init_per_suite(Config) ->
    application:ensure_all_started(quic),
    application:ensure_all_started(masque),
    {ok, Ctx} = masque_test_helpers:generate_certs(),
    [{ctx, Ctx} | Config].

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(ctx, Config)),
    ok.

init_per_group(Transport, Config) ->
    [{transport, Transport} | Config].

end_per_group(_Transport, _Config) ->
    ok.

init_per_testcase(Case, Config) ->
    Transport = ?config(transport, Config),
    Name = list_to_atom(
        "ip_comp_" ++ atom_to_list(Transport) ++ "_" ++ atom_to_list(Case) ++ "_" ++
            integer_to_list(erlang:unique_integer([positive]))
    ),
    Port = start(Transport, Name, ?config(ctx, Config), case_opts(Case)),
    [{listener, Name}, {port, Port} | Config].

%% A case that passed must not leave a server session behind.
end_per_testcase(_Case, Config) ->
    Left =
        case ?config(tc_status, Config) of
            ok -> wait_no_server_sessions(?LEAK_MS);
            _ -> []
        end,
    stop(?config(transport, Config), ?config(listener, Config)),
    case Left of
        [] -> ok;
        _ -> {fail, {sessions_left_behind, Left}}
    end.

%%====================================================================
%% Listener options per case
%%====================================================================

case_opts(initial_route_advertisement) ->
    #{
        address_pool => {4, {10, 200, 0, 0}, 16},
        routes => [route(4, {0, 0, 0, 0}, {255, 255, 255, 255})]
    };
case_opts(Case) when
    Case =:= address_allocation_round_robin; Case =:= pool_exhaustion_rejects
->
    Last =
        case Case of
            address_allocation_round_robin -> 3;
            pool_exhaustion_rejects -> 1
        end,
    #{
        max_assignments => 2,
        address_pool => route(4, {10, 200, 0, 1}, {10, 200, 0, Last})
    };
case_opts(Case) when
    Case =:= inject_packet_via_registry; Case =:= reject_keeps_held_addresses
->
    #{address_pool => route(4, {10, 200, 0, 1}, {10, 200, 0, 3})};
case_opts(client_capsules_reach_proxy) ->
    Self = self(),
    #{
        handler_opts => #{
            allow_private => true,
            lifecycle_fun => fun(Event, Detail) -> Self ! {hook, Event, Detail} end
        }
    };
case_opts(server_pending_cap) ->
    script(#{on_request => none});
case_opts(unanswered_ids_rejected) ->
    script(#{on_request => answer_first});
case_opts(handler_without_request_callback_rejects) ->
    #{ip_handler => masque_ip_unprompted_handler, handler_opts => #{}};
case_opts(Case) when
    Case =:= proxy_request_on_wire;
    Case =:= client_withdraws_left_out_address;
    Case =:= client_aborts_malformed_capsule;
    Case =:= client_aborts_empty_address_request;
    Case =:= client_aborts_misordered_routes;
    Case =:= client_rejects_excess_proxy_requests;
    Case =:= client_ip_info_hides_rejections;
    Case =:= client_source_filter
->
    script(#{});
case_opts(hostname_dns_failure) ->
    #{resolver => fun(_Host) -> {error, nxdomain} end};
case_opts(Case) when
    Case =:= icmp_passes_ipproto_scope; Case =:= tunnel_too_big_reports_icmp
->
    Self = self(),
    #{
        handler_opts => #{
            allow_private => true,
            address_pool => {4, {10, 200, 0, 0}, 24},
            forward_fun => fun(Pkt, St) ->
                Self ! {forwarded, Pkt},
                {forward, St}
            end
        }
    };
case_opts(overlapping_routes_advertised) ->
    %% A host route inside the default route: overlapping ranges the
    %% handler merges before advertising (RFC 9484 section 4.7.3).
    #{
        routes => [
            route(4, {0, 0, 0, 0}, {255, 255, 255, 255}),
            route(4, {93, 184, 216, 34}, {93, 184, 216, 34})
        ]
    };
case_opts(mtu_too_low_client_aborts) ->
    %% The client could not send a 1280-byte packet to this proxy.
    #{max_datagram_frame_size => 1200};
case_opts(_) ->
    #{}.

script(Extra) ->
    #{ip_handler => ?SCRIPT, handler_opts => Extra#{report => self()}}.

route(V, Start, End) ->
    #ip_route{version = V, start_addr = Start, end_addr = End, ip_protocol = 0}.

%%====================================================================
%% Basic cases (h3, h2)
%%====================================================================

initial_route_advertisement(Config) ->
    Sess = connect(Config),
    receive
        {masque_route_advertisement, Sess, [R | _]} ->
            ?assertEqual(route(4, {0, 0, 0, 0}, {255, 255, 255, 255}), R)
    after ?WAIT -> ct:fail("no initial ROUTE_ADVERTISEMENT")
    end,
    ok = masque:close(Sess).

address_allocation_round_robin(Config) ->
    Sess = connect(Config),
    _ = flush_advertise(Sess),
    {ok, [Id1]} = masque:request_addresses(Sess, [{4, {0, 0, 0, 0}, 0}]),
    receive
        {masque_address_assign, Sess, [
            #ip_assignment{request_id = Id1, version = 4, address = A1, prefix_len = 32}
        ]} ->
            ?assertEqual({10, 200, 0, 1}, A1)
    after ?WAIT -> ct:fail("no assign 1")
    end,
    %% RFC 9484 section 4.7.1: the answer is the full set, so
    %% 10.200.0.1 follows, unprompted (id 0).
    {ok, [Id2]} = masque:request_addresses(Sess, [{4, {0, 0, 0, 0}, 0}]),
    receive
        {masque_address_assign, Sess, [
            #ip_assignment{request_id = Id2, address = A2},
            #ip_assignment{request_id = 0, address = Kept}
        ]} ->
            ?assertEqual({10, 200, 0, 2}, A2),
            ?assertEqual({10, 200, 0, 1}, Kept)
    after ?WAIT -> ct:fail("no assign 2")
    end,
    ok = masque:close(Sess).

pool_exhaustion_rejects(Config) ->
    Sess = connect(Config),
    _ = flush_advertise(Sess),
    {ok, [Id1]} = masque:request_addresses(Sess, [{4, {0, 0, 0, 0}, 0}]),
    receive
        {masque_address_assign, Sess, [
            #ip_assignment{request_id = Id1, address = {10, 200, 0, 1}}
        ]} ->
            ok
    after ?WAIT -> ct:fail("first assign missed")
    end,
    %% The pool is a single address: the next request gets the "no
    %% address" entry, and the address already held is still listed.
    {ok, [Id2]} = masque:request_addresses(Sess, [{4, {0, 0, 0, 0}, 0}]),
    receive
        {masque_address_assign, Sess, [
            #ip_assignment{request_id = Id2, address = {0, 0, 0, 0}, prefix_len = 32},
            #ip_assignment{request_id = 0, address = {10, 200, 0, 1}}
        ]} ->
            ok
    after ?WAIT -> ct:fail("no rejection for exhausted pool")
    end,
    ok = masque:close(Sess).

client_rejects_capsule_off(_Config) ->
    %% Refused before touching the transport.
    ?assertEqual(
        {error, {invalid_opts, capsule_protocol_required_for_ip}},
        masque:connect(
            <<"https://127.0.0.1:1">>,
            {'*', '*'},
            #{protocol => ip, capsule_protocol => false}
        )
    ).

%% A packet larger than the session MTU is refused at the API with a
%% typed error.
oversize_packet_rejected(Config) ->
    Sess = connect(Config),
    _ = flush_advertise(Sess),
    Big = binary:copy(<<"x">>, 2000),
    ?assertMatch({error, {packet_too_large, 2000, 1500}}, masque:send_ip_packet(Sess, Big)),
    ok = masque:close(Sess).

%% Section 4: `capsule-protocol: ?1' is on the request even when the
%% caller sets the knob explicitly.
capsule_protocol_forced_true(Config) ->
    Sess = connect(Config, {'*', '*'}, #{capsule_protocol => true}),
    ok = masque:close(Sess).

bad_target_shape_for_ip(_Config) ->
    ?assertEqual(
        {error, {bad_target_for_protocol, ip}},
        masque:connect(<<"https://127.0.0.1:1">>, {<<"dns.google">>, 5353}, #{protocol => ip})
    ).

%% An out-of-band injector finds the session in the registry and its
%% packet reaches the client with the TTL decremented on encapsulation
%% (section 7.2).
inject_packet_via_registry(Config) ->
    {Sess, Assigned} = connect_with_address(Config),
    {ok, ServerPid, _Ctx} = masque_ip_session_registry:lookup(Assigned),
    Pkt = ipv4({203, 0, 113, 1}, Assigned, 17, 64, <<>>),
    ok = masque_ip:inject_packet(ServerPid, Pkt),
    {ok, Want} = masque_ip_packet:decrement_ttl(Pkt),
    receive
        {masque_ip_packet, Sess, Want} -> ok
    after ?WAIT -> ct:fail("injected packet did not arrive at client")
    end,
    ok = masque:close(Sess).

%%====================================================================
%% Proxy role: capsules from the client
%%====================================================================

%% RFC 9297 section 3.3 via RFC 9484 section 4.7: a malformed capsule
%% aborts the request stream.
proxy_aborts_malformed_capsule(Config) ->
    %% IP version 9.
    proxy_aborts(Config, ?MASQUE_CAPSULE_ADDRESS_REQUEST, <<1, 9, 0, 0, 0, 0, 32>>).

%% Section 4.7.2: an ADDRESS_REQUEST with no entry aborts the stream.
proxy_aborts_empty_address_request(Config) ->
    proxy_aborts(Config, ?MASQUE_CAPSULE_ADDRESS_REQUEST, <<>>).

%% Section 4.7.3: ranges out of order abort the stream.
proxy_aborts_misordered_routes(Config) ->
    proxy_aborts(Config, ?MASQUE_CAPSULE_ROUTE_ADVERTISEMENT, misordered_routes()).

proxy_aborts(Config, Type, Body) ->
    Sess = connect(Config),
    ok = masque:send_capsule(Sess, Type, Body),
    await_closed(Sess).

%% Section 4.7: the client may assign addresses and advertise routes
%% to the proxy; the handler sees both.
client_capsules_reach_proxy(Config) ->
    Sess = connect(Config),
    Route = #ip_route{
        version = 4, start_addr = {192, 0, 2, 0}, end_addr = {192, 0, 2, 255}, ip_protocol = 0
    },
    Assign = #ip_assignment{request_id = 0, version = 4, address = {192, 0, 2, 0}, prefix_len = 24},
    ok = masque:advertise_routes(Sess, [Route]),
    ok = masque:assign_addresses(Sess, [Assign]),
    receive
        {hook, peer_routes_advertised, #{routes := [Route]}} -> ok
    after ?WAIT -> ct:fail(no_peer_routes)
    end,
    receive
        {hook, peer_address_assigned, #{entries := [Assign]}} -> ok
    after ?WAIT -> ct:fail(no_peer_assign)
    end,
    ok = masque:close(Sess).

%% Section 4.7.1: the "no address" answer the session sends for
%% requests past the pending cap repeats the address the client holds.
reject_keeps_held_addresses(Config) ->
    {Sess, Held} = connect_with_address(Config),
    {ok, Ids} = masque:request_addresses(Sess, lists:duplicate(70, {4, {0, 0, 0, 0}, 32})),
    Extra = lists:nthtail(64, Ids),
    receive
        {masque_address_assign, Sess, [#ip_assignment{request_id = 0, address = Held} | Rejects]} ->
            ?assertEqual(Extra, [Id || #ip_assignment{request_id = Id} <- Rejects]),
            ?assert(lists:all(fun masque_ip:is_rejection/1, Rejects))
    after ?WAIT -> ct:fail(no_early_rejection)
    end,
    receive
        {masque_address_assign, Sess, Answers} -> ?assertEqual(64, length(Answers))
    after ?WAIT -> ct:fail(no_answer)
    end,
    ok = masque:close(Sess).

%% At most 64 request ids wait for a handler that answers later; the
%% rest get "no address" at once, on every transport.
server_pending_cap(Config) ->
    Sess = connect(Config),
    _ = script_session(),
    {ok, Ids} = masque:request_addresses(Sess, lists:duplicate(70, {4, {0, 0, 0, 0}, 32})),
    receive
        {script, address_request, Seen} -> ?assertEqual(64, length(Seen))
    after ?WAIT -> ct:fail(no_request_at_handler)
    end,
    receive
        {masque_address_assign, Sess, Rejects} ->
            ?assertEqual(lists:nthtail(64, Ids), [Id || #ip_assignment{request_id = Id} <- Rejects])
    after ?WAIT -> ct:fail(no_rejection)
    end,
    %% Full: the next request is answered at once too.
    {ok, [Next]} = masque:request_addresses(Sess, [{4, {0, 0, 0, 0}, 32}]),
    receive
        {masque_address_assign, Sess, [#ip_assignment{request_id = Next} = R]} ->
            ?assert(masque_ip:is_rejection(R))
    after ?WAIT -> ct:fail(no_rejection_when_full)
    end,
    ok = masque:close(Sess).

%% Section 4.7.2 "SHALL respond": an id the handler's ADDRESS_ASSIGN
%% leaves out gets the "no address" entry, next to the held address.
unanswered_ids_rejected(Config) ->
    Sess = connect(Config),
    {ok, [Id1, Id2]} = masque:request_addresses(Sess, lists:duplicate(2, {4, {0, 0, 0, 0}, 32})),
    A = {10, 99, 0, 1},
    receive
        {masque_address_assign, Sess, [#ip_assignment{request_id = Id1, address = A}]} -> ok
    after ?WAIT -> ct:fail(no_answer)
    end,
    receive
        {masque_address_assign, Sess, [
            #ip_assignment{request_id = 0, address = A},
            #ip_assignment{request_id = Id2} = R
        ]} ->
            ?assert(masque_ip:is_rejection(R))
    after ?WAIT -> ct:fail(no_rejection_for_left_out_id)
    end,
    ok = masque:close(Sess).

%% A handler without `handle_address_request/2' still answers.
handler_without_request_callback_rejects(Config) ->
    Sess = connect(Config),
    {ok, [Id]} = masque:request_addresses(Sess, [{6, {0, 0, 0, 0, 0, 0, 0, 0}, 128}]),
    receive
        {masque_address_assign, Sess, [#ip_assignment{request_id = Id} = R]} ->
            ?assert(masque_ip:is_rejection(R))
    after ?WAIT -> ct:fail(no_rejection)
    end,
    ok = masque:close(Sess).

%%====================================================================
%% Client role: capsules from the proxy
%%====================================================================

%% The proxy may ask the client for addresses; the answer reaches the
%% handler under the proxy's request id.
proxy_request_on_wire(Config) ->
    Sess = connect(Config),
    Pid = script_session(),
    Pid ! {script_actions, [{request_addresses, [{4, {0, 0, 0, 0}, 32}]}]},
    Id =
        receive
            {masque_address_request, Sess, [#ip_prefix_request{request_id = I, version = 4}]} -> I
        after ?WAIT -> ct:fail(no_address_request)
        end,
    Answer = #ip_assignment{
        request_id = Id, version = 4, address = {192, 0, 2, 1}, prefix_len = 32
    },
    ok = masque:assign_addresses(Sess, [Answer]),
    receive
        {script, address_assign, [Answer]} -> ok
    after ?WAIT -> ct:fail(answer_not_at_proxy)
    end,
    ok = masque:close(Sess).

%% Section 4.7.1: an address left out of a later ADDRESS_ASSIGN is
%% withdrawn.
client_withdraws_left_out_address(Config) ->
    Sess = connect(Config),
    Pid = script_session(),
    A = #ip_assignment{request_id = 0, version = 4, address = {10, 99, 0, 1}, prefix_len = 32},
    B = A#ip_assignment{address = {10, 99, 0, 2}},
    Pid ! {script_actions, [{assign, [A, B]}]},
    receive
        {masque_address_assign, Sess, [A, B]} -> ok
    after ?WAIT -> ct:fail(no_first_assign)
    end,
    Pid ! {script_actions, [{assign, [A]}]},
    receive
        {masque_address_assign, Sess, [A]} -> ok
    after ?WAIT -> ct:fail(no_second_assign)
    end,
    ?assertMatch(#{assigned := [A]}, masque:ip_info(Sess)),
    ok = masque:close(Sess).

client_aborts_malformed_capsule(Config) ->
    client_aborts(Config, ?MASQUE_CAPSULE_ADDRESS_ASSIGN, <<0, 9, 0, 0, 0, 0, 32>>).

client_aborts_empty_address_request(Config) ->
    client_aborts(Config, ?MASQUE_CAPSULE_ADDRESS_REQUEST, <<>>).

client_aborts_misordered_routes(Config) ->
    client_aborts(Config, ?MASQUE_CAPSULE_ROUTE_ADVERTISEMENT, misordered_routes()).

client_aborts(Config, Type, Body) ->
    Sess = connect(Config),
    Pid = script_session(),
    Pid ! {script_actions, [{send_capsule, Type, Body}]},
    await_closed(Sess).

%% The client keeps 64 of the proxy's requests waiting for its owner
%% and answers the rest at once with the "no address" entry.
client_rejects_excess_proxy_requests(Config) ->
    Sess = connect(Config),
    Pid = script_session(),
    Pid ! {script_actions, [{request_addresses, lists:duplicate(70, {4, {0, 0, 0, 0}, 32})}]},
    receive
        {masque_address_request, Sess, Kept} -> ?assertEqual(64, length(Kept))
    after ?WAIT -> ct:fail(no_address_request)
    end,
    receive
        {script, address_assign, Rejects} ->
            ?assertEqual(6, length(Rejects)),
            ?assert(lists:all(fun masque_ip:is_rejection/1, Rejects))
    after ?WAIT -> ct:fail(no_rejection_at_proxy)
    end,
    ok = masque:close(Sess).

%% A rejection answers a request; `ip_info/1' does not list it as held.
client_ip_info_hides_rejections(Config) ->
    Sess = connect(Config),
    _ = script_session(),
    {ok, [Id]} = masque:request_addresses(Sess, [{4, {0, 0, 0, 0}, 32}]),
    receive
        {masque_address_assign, Sess, [#ip_assignment{request_id = Id}]} -> ok
    after ?WAIT -> ct:fail(no_rejection)
    end,
    ?assertMatch(#{assigned := []}, masque:ip_info(Sess)),
    ok = masque:close(Sess).

%% Section 11 (BCP 38), opt-in: with `source_filter' the client drops
%% packets whose source is outside what it assigned to the proxy.
client_source_filter(Config) ->
    Sess = connect(Config, {'*', '*'}, #{source_filter => true}),
    Pid = script_session(),
    Prefix = #ip_assignment{request_id = 0, version = 4, address = {192, 0, 2, 0}, prefix_len = 24},
    ok = masque:assign_addresses(Sess, [Prefix]),
    receive
        {script, address_assign, [Prefix]} -> ok
    after ?WAIT -> ct:fail(no_assign_at_proxy)
    end,
    Good = ipv4({192, 0, 2, 5}, {10, 0, 0, 1}, 17, 64, <<"good">>),
    Spoofed = ipv4({198, 51, 100, 1}, {10, 0, 0, 1}, 17, 64, <<"spoofed">>),
    Pid ! {script_actions, [{send_ip_packet, Spoofed}, {send_ip_packet, Good}]},
    receive
        {masque_ip_packet, Sess, Got} -> ?assertEqual(Good, Got)
    after ?WAIT -> ct:fail(no_packet)
    end,
    receive
        {masque_ip_packet, Sess, Late} -> ct:fail({spoofed_delivered, Late})
    after 300 -> ok
    end,
    ok = masque:close(Sess).

%% Section 4.7.1: a host name that does not resolve is refused (502).
hostname_dns_failure(Config) ->
    {error, Reason} = connect_result(Config, {<<"no-such-host.example">>, '*'}, #{}),
    %% On h1 too: since h1 0.13.1 a refused upgrade returns its status.
    ?assertMatch({handshake_rejected, 502}, rejected_status(Reason)).

%% Section 7.2: an ICMPv6 Echo Request with 1232 bytes of data sent to
%% ff02::1, the MTU check, is answered with a 1280-byte Echo Reply.
link_local_echo(Config) ->
    Sess = connect(Config),
    _ = flush_advertise(Sess),
    Src = {16#FE80, 0, 0, 0, 0, 0, 0, 2},
    ok = masque:send_ip_packet(Sess, echo6(Src, {16#FF02, 0, 0, 0, 0, 0, 0, 1}, 1232)),
    receive
        {masque_ip_packet, Sess, Reply} ->
            ?assertEqual(1280, byte_size(Reply)),
            ?assertMatch(
                <<6:4, _:44, 58, _:8, _:128, Dst:16/binary, 129, 0, _/binary>> when
                    Dst =:= <<16#FE80:16, 0:96, 2:16>>,
                Reply
            )
    after ?WAIT -> ct:fail(no_echo_reply)
    end,
    ok = masque:close(Sess).

%% Section 4.6: ICMP is allowed whatever the `ipproto' scope.
icmp_passes_ipproto_scope(Config) ->
    Sess = connect(Config, {'*', 17}, #{}),
    Addr = request_address(Sess),
    Echo = ipv4(Addr, {192, 0, 2, 1}, 1, 64, <<8, 0, 0, 0, 0, 1, 0, 1>>),
    ok = masque:send_ip_packet(Sess, Echo),
    receive
        {forwarded, Echo} -> ok
    after ?WAIT -> ct:fail(icmp_not_forwarded)
    end,
    ok = masque:close(Sess).

%% Section 4.7.3: overlapping routes are merged, so the advertisement
%% goes out instead of failing to encode.
overlapping_routes_advertised(Config) ->
    Sess = connect(Config),
    receive
        {masque_route_advertisement, Sess, Routes} ->
            ?assertEqual([route(4, {0, 0, 0, 0}, {255, 255, 255, 255})], Routes)
    after ?WAIT -> ct:fail(no_route_advertisement)
    end,
    ok = masque:close(Sess).

%%====================================================================
%% h3 datagram size (sections 7.2 and 10.1)
%%====================================================================

%% The client cannot send 1280-byte packets to this proxy: it aborts.
mtu_too_low_client_aborts(Config) ->
    ?assertMatch(
        {error, {mtu_too_low, _, 1280}},
        connect_result(Config, {'*', '*'}, #{})
    ).

%% The proxy cannot send 1280-byte packets to this client: it refuses.
mtu_too_low_server_aborts(Config) ->
    ?assertMatch(
        {error, _},
        connect_result(Config, {'*', '*'}, #{quic_opts => #{max_datagram_frame_size => 1200}})
    ).

%% A packet that does not fit a QUIC DATAGRAM frame is not sent into
%% the tunnel; ICMP Fragmentation Needed goes toward its source,
%% through `forward_fun'.
tunnel_too_big_reports_icmp(Config) ->
    {Sess, Addr} = connect_with_address(Config),
    {ok, ServerPid, _} = masque_ip_session_registry:lookup(Addr),
    Big = ipv4({203, 0, 113, 1}, Addr, 17, 64, binary:copy(<<0>>, 4000)),
    ok = masque_ip:inject_packet(ServerPid, Big),
    receive
        {forwarded, <<4:4, _:68, 1, _:16, _:32, 203, 0, 113, 1, 3, 4, _/binary>>} -> ok
    after ?WAIT -> ct:fail(no_frag_needed)
    end,
    receive
        {masque_ip_packet, Sess, _} -> ct:fail(oversize_delivered)
    after 300 -> ok
    end,
    ok = masque:close(Sess).

%%====================================================================
%% Helpers
%%====================================================================

start(h3, Name, Ctx, Opts) ->
    {ok, _} = masque:start_listener(Name, listener_opts(Opts, cert, key, Ctx)),
    {ok, Port} = quic:get_server_port(Name),
    Port;
start(h2, Name, Ctx, Opts) ->
    {ok, {_, _, Port}} = masque:start_listener_h2(
        Name, listener_opts(Opts, cert_file, key_file, Ctx)
    ),
    Port;
start(h1, Name, Ctx, Opts) ->
    {ok, Ref} = masque:start_listener_h1(Name, listener_opts(Opts, cert_file, key_file, Ctx)),
    h1:server_port(Ref).

listener_opts(Opts, CertKey, KeyKey, Ctx) ->
    maps:merge(
        #{
            port => 0,
            %% Tests tunnel to `*' and private addresses.
            allow_private => true,
            cert => maps:get(CertKey, Ctx),
            key => maps:get(KeyKey, Ctx)
        },
        Opts
    ).

stop(h3, Name) -> masque:stop_listener(Name);
stop(h2, Name) -> masque:stop_listener_h2(Name);
stop(h1, Name) -> masque:stop_listener_h1(Name).

connect(Config) ->
    connect(Config, {'*', '*'}, #{}).

connect(Config, Target, Extra) ->
    {ok, Sess} = connect_result(Config, Target, Extra),
    Sess.

connect_result(Config, Target, Extra) ->
    Url = iolist_to_binary(["https://127.0.0.1:", integer_to_binary(?config(port, Config))]),
    Opts = #{protocol => ip, transports => [?config(transport, Config)], verify => verify_none},
    masque:connect(Url, Target, maps:merge(Opts, Extra)).

connect_with_address(Config) ->
    Sess = connect(Config),
    {Sess, request_address(Sess)}.

request_address(Sess) ->
    {ok, [Id]} = masque:request_addresses(Sess, [{4, {0, 0, 0, 0}, 32}]),
    await_address(Sess, Id).

await_address(Sess, Id) ->
    receive
        {masque_address_assign, Sess, [#ip_assignment{request_id = Id, address = A}]} -> A;
        {masque_route_advertisement, Sess, _} -> await_address(Sess, Id)
    after ?WAIT -> ct:fail(no_address)
    end.

%% The script handler's session pid.
script_session() ->
    receive
        {script, init, Pid} -> Pid
    after ?WAIT -> ct:fail(no_script_session)
    end.

await_closed(Sess) ->
    receive
        {masque_closed, Sess, _Reason} -> ok
    after ?WAIT -> ct:fail(stream_not_aborted)
    end.

flush_advertise(Sess) ->
    receive
        {masque_route_advertisement, Sess, _} -> ok
    after 500 -> ok
    end.

rejected_status({handshake_rejected, Status}) -> {handshake_rejected, Status};
rejected_status({handshake_rejected, Status, _}) -> {handshake_rejected, Status};
rejected_status(Other) -> Other.

%% Two IPv4 ranges, the second starting before the first.
misordered_routes() ->
    <<4, 10, 0, 1, 0, 10, 0, 1, 255, 0, 4, 10, 0, 0, 0, 10, 0, 0, 255, 0>>.

ipv4({SA, SB, SC, SD}, {DA, DB, DC, DD}, Proto, TTL, Body) ->
    Total = 20 + byte_size(Body),
    H0 =
        <<16#45, 0, Total:16, 0:16, 2#010:3, 0:13, TTL, Proto, 0:16, SA, SB, SC, SD, DA, DB, DC,
            DD>>,
    Sum = masque_ip_packet:checksum(H0),
    <<Before:10/binary, 0:16, After/binary>> = H0,
    <<Before/binary, Sum:16, After/binary, Body/binary>>.

echo6(Src, Dst, DataLen) ->
    S = ip6(Src),
    D = ip6(Dst),
    Body0 = <<128, 0, 0:16, 1:16, 1:16, (binary:copy(<<$m>>, DataLen))/binary>>,
    Len = byte_size(Body0),
    Csum = masque_ip_packet:checksum(<<S/binary, D/binary, Len:32, 0:24, 58, Body0/binary>>),
    <<_:16, 0:16, Rest/binary>> = Body0,
    <<6:4, 0:8, 0:20, Len:16, 58, 255, S/binary, D/binary, 128, 0, Csum:16, Rest/binary>>.

ip6(T) -> <<<<X:16>> || X <- tuple_to_list(T)>>.

wait_no_server_sessions(Left) when Left =< 0 ->
    server_sessions();
wait_no_server_sessions(Left) ->
    case server_sessions() of
        [] ->
            [];
        _ ->
            timer:sleep(200),
            wait_no_server_sessions(Left - 200)
    end.

server_sessions() ->
    [
        P
     || P <- processes(),
        {dictionary, Dict} <- [process_info(P, dictionary)],
        {'$initial_call', {Mod, init, 1}} <- [lists:keyfind('$initial_call', 1, Dict)],
        lists:prefix("masque_", atom_to_list(Mod)),
        lists:suffix("server_session", atom_to_list(Mod))
    ].
