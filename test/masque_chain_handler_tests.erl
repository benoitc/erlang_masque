%%% @doc Unit tests for `masque_chain_handler''s IP paths.
%%%
%%% Drives the handler's callbacks directly, routing upstream calls
%%% to a tiny mock session that captures every `gen_statem:call' into
%%% the test's own mailbox. Integration against a real MASQUE session
%%% is covered by `masque_chain_ip_SUITE'.
-module(masque_chain_handler_tests).

-include_lib("eunit/include/eunit.hrl").
-include("masque_ip.hrl").

-define(M, masque_chain_handler).

%%====================================================================
%% handle_ip_packet/2 - client -> upstream
%%====================================================================

handle_ip_packet_forwards_to_upstream_test() ->
    {S, Pid} = state(ip),
    Pkt = <<"ip-packet">>,
    {ok, S1} = ?M:handle_ip_packet(Pkt, S),
    ?assertEqual(S, S1),
    assert_captured({send_ip_packet, Pkt}),
    cleanup(Pid).

handle_packet_forwards_udp_test() ->
    {S, Pid} = state(udp),
    {ok, _} = ?M:handle_packet(<<"udp">>, S),
    assert_captured({send, <<"udp">>}),
    cleanup(Pid).

handle_data_forwards_tcp_test() ->
    {S, Pid} = state(tcp),
    {ok, _} = ?M:handle_data(<<"tcp">>, S),
    assert_captured({send, <<"tcp">>}),
    cleanup(Pid).

%%====================================================================
%% handle_info/2 - upstream -> client (owner-message shapes)
%%====================================================================

info_ip_packet_from_upstream_emits_action_test() ->
    {S, Pid} = state(ip),
    Msg = {masque_ip_packet, Pid, <<"from-upstream">>},
    {ok, S1, Actions} = ?M:handle_info(Msg, S),
    ?assertEqual(S, S1),
    ?assertEqual([{send_ip_packet, <<"from-upstream">>}], Actions),
    cleanup(Pid).

info_route_advertisement_from_upstream_emits_action_test() ->
    {S, Pid} = state(ip),
    Route = #ip_route{version = 4, start_addr = {0,0,0,0},
                      end_addr = {255,255,255,255}, ip_protocol = 0},
    Msg = {masque_route_advertisement, Pid, [Route]},
    {ok, _, Actions} = ?M:handle_info(Msg, S),
    ?assertEqual([{advertise, [Route]}], Actions),
    cleanup(Pid).

info_unprompted_address_assign_is_forwarded_test() ->
    {S, Pid} = state(ip),
    %% request_id = 0 is the unprompted (server-initiated) shape per
    %% RFC 9484 §4.7.1 - safe to forward through the chain.
    Assign = #ip_assignment{request_id = 0, version = 4,
                            address = {10,0,0,5}, prefix_len = 32},
    Msg = {masque_address_assign, Pid, [Assign]},
    {ok, _, Actions} = ?M:handle_info(Msg, S),
    ?assertEqual([{assign, [Assign]}], Actions),
    cleanup(Pid).

info_prompted_address_assign_is_dropped_test() ->
    %% Non-zero request_id would break the client's pending-id map if
    %% forwarded as-is (upstream's id space != client's id space).
    %% Dropping is the conservative choice until the full id-mapping
    %% flow lands (the deferred follow-up noted in the handler doc).
    {S, Pid} = state(ip),
    Assign = #ip_assignment{request_id = 42, version = 4,
                            address = {10,0,0,6}, prefix_len = 32},
    Msg = {masque_address_assign, Pid, [Assign]},
    ?assertMatch({ok, _}, ?M:handle_info(Msg, S)),
    cleanup(Pid).

info_mixed_address_assign_forwards_unprompted_only_test() ->
    {S, Pid} = state(ip),
    Unprompted = #ip_assignment{request_id = 0, version = 4,
                                address = {10,0,0,7}, prefix_len = 32},
    Prompted = #ip_assignment{request_id = 9, version = 4,
                              address = {10,0,0,8}, prefix_len = 32},
    Msg = {masque_address_assign, Pid, [Unprompted, Prompted]},
    {ok, _, Actions} = ?M:handle_info(Msg, S),
    ?assertEqual([{assign, [Unprompted]}], Actions),
    cleanup(Pid).

info_udp_data_from_upstream_emits_send_action_test() ->
    {S, Pid} = state(udp),
    {ok, _, Actions} =
        ?M:handle_info({masque_data, Pid, <<"back">>}, S),
    ?assertEqual([{send, <<"back">>}], Actions),
    cleanup(Pid).

info_tcp_data_from_upstream_emits_send_data_action_test() ->
    {S, Pid} = state(tcp),
    {ok, _, Actions} =
        ?M:handle_info({masque_data, Pid, <<"back">>}, S),
    ?assertEqual([{send_data, <<"back">>}], Actions),
    cleanup(Pid).

info_upstream_closed_stops_session_test() ->
    {S, Pid} = state(udp),
    {stop, upstream_closed, S1} =
        ?M:handle_info({masque_closed, Pid, peer_closed}, S),
    ?assertEqual(S, S1),
    cleanup(Pid).

info_unknown_message_is_ignored_test() ->
    {S, Pid} = state(udp),
    ?assertMatch({ok, _}, ?M:handle_info(something_else, S)),
    cleanup(Pid).

%%====================================================================
%% accept/1 - target shape validation
%%====================================================================

accept_ip_request_test() ->
    Req = #{protocol => ip,
            ip_target => {10,0,0,1},
            ip_ipproto => '*',
            handler_opts => #{}},
    ?assertEqual(accept, ?M:accept(Req)).

accept_ip_request_with_allow_deny_test() ->
    Req = #{protocol => ip,
            ip_target => {10,0,0,1},
            ip_ipproto => '*',
            handler_opts => #{allow => fun(_) -> false end}},
    ?assertEqual({reject, forbidden}, ?M:accept(Req)).

accept_udp_request_test() ->
    Req = #{target_host => <<"host">>, target_port => 80,
            handler_opts => #{}},
    ?assertEqual(accept, ?M:accept(Req)).

%%====================================================================
%% Mock upstream session
%%====================================================================

state(Protocol) ->
    Self = self(),
    Pid = erlang:spawn(fun() -> mock_loop(Self) end),
    S = masque_chain_handler:test_state(Pid, Protocol),
    {S, Pid}.

mock_loop(TestPid) ->
    receive
        {'$gen_call', From, Payload} ->
            TestPid ! {captured, Payload},
            gen_statem:reply(From, ok),
            mock_loop(TestPid);
        stop -> ok;
        _   -> mock_loop(TestPid)
    end.

assert_captured(Expected) ->
    receive
        {captured, Payload} ->
            ?assertEqual(Expected, Payload)
    after 500 ->
        ?assert(false, "no upstream call captured")
    end.

cleanup(Pid) ->
    %% The mock replies via gen_statem:reply; the caller has moved on
    %% but the mock process is still alive. Kill it so it does not
    %% leak between tests.
    _ = exit(Pid, shutdown),
    ok.
