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
    Route = #ip_route{
        version = 4,
        start_addr = {0, 0, 0, 0},
        end_addr = {255, 255, 255, 255},
        ip_protocol = 0
    },
    Msg = {masque_route_advertisement, Pid, [Route]},
    {ok, _, Actions} = ?M:handle_info(Msg, S),
    ?assertEqual([{advertise, [Route]}], Actions),
    cleanup(Pid).

info_unprompted_address_assign_is_forwarded_test() ->
    {S, Pid} = state(ip),
    %% request_id = 0 is the unprompted (server-initiated) shape per
    %% RFC 9484 §4.7.1 - safe to forward through the chain.
    Assign = #ip_assignment{
        request_id = 0,
        version = 4,
        address = {10, 0, 0, 5},
        prefix_len = 32
    },
    Msg = {masque_address_assign, Pid, [Assign]},
    {ok, _, Actions} = ?M:handle_info(Msg, S),
    ?assertEqual([{assign, [Assign]}], Actions),
    cleanup(Pid).

info_prompted_address_assign_is_dropped_test() ->
    %% A prompted entry for a request the chain never forwarded has
    %% no client request id to map to, so it is dropped.
    {S, Pid} = state(ip),
    Assign = #ip_assignment{
        request_id = 42,
        version = 4,
        address = {10, 0, 0, 6},
        prefix_len = 32
    },
    Msg = {masque_address_assign, Pid, [Assign]},
    ?assertMatch({ok, _}, ?M:handle_info(Msg, S)),
    cleanup(Pid).

info_mixed_address_assign_forwards_unprompted_only_test() ->
    {S, Pid} = state(ip),
    Unprompted = #ip_assignment{
        request_id = 0,
        version = 4,
        address = {10, 0, 0, 7},
        prefix_len = 32
    },
    Prompted = #ip_assignment{
        request_id = 9,
        version = 4,
        address = {10, 0, 0, 8},
        prefix_len = 32
    },
    Msg = {masque_address_assign, Pid, [Unprompted, Prompted]},
    {ok, _, Actions} = ?M:handle_info(Msg, S),
    ?assertEqual([{assign, [Unprompted]}], Actions),
    cleanup(Pid).

%%====================================================================
%% ADDRESS_REQUEST forwarding
%%====================================================================

address_request_forwarded_and_answer_mapped_test() ->
    Self = self(),
    Pid = erlang:spawn(fun() -> id_mock(Self, [7, 8]) end),
    S0 = masque_chain_handler:test_state(Pid, ip),
    Reqs = [
        #ip_prefix_request{request_id = 1, version = 4, address = {0, 0, 0, 0}, prefix_len = 32},
        #ip_prefix_request{request_id = 2, version = 4, address = {0, 0, 0, 0}, prefix_len = 32}
    ],
    {ok, S1} = ?M:handle_address_request(Reqs, S0),
    assert_captured(
        {request_addresses, [{4, {0, 0, 0, 0}, 32}, {4, {0, 0, 0, 0}, 32}]}
    ),
    %% Upstream answers id 8 first, then id 7; both map back.
    A8 = #ip_assignment{request_id = 8, version = 4, address = {10, 0, 0, 2}, prefix_len = 32},
    {ok, S2, [{assign, [B]}]} =
        ?M:handle_info({masque_address_assign, Pid, [A8]}, S1),
    ?assertEqual(A8#ip_assignment{request_id = 2}, B),
    A7 = #ip_assignment{request_id = 7, version = 4, address = {10, 0, 0, 1}, prefix_len = 32},
    {ok, S3, [{assign, [C]}]} =
        ?M:handle_info({masque_address_assign, Pid, [A7]}, S2),
    ?assertEqual(A7#ip_assignment{request_id = 1}, C),
    %% A repeat answer for an id already relayed is dropped.
    ?assertMatch({ok, _}, ?M:handle_info({masque_address_assign, Pid, [A7]}, S3)),
    cleanup(Pid).

address_request_upstream_error_rejects_test() ->
    %% The default mock answers `ok', not `{ok, Ids}'.
    {S, Pid} = state(ip),
    Reqs = [
        #ip_prefix_request{request_id = 3, version = 4, address = {0, 0, 0, 0}, prefix_len = 32}
    ],
    {ok, _, [{assign, [R]}]} = ?M:handle_address_request(Reqs, S),
    ?assertMatch(
        #ip_assignment{request_id = 3, address = {0, 0, 0, 0}, prefix_len = 32}, R
    ),
    cleanup(Pid).

id_mock(TestPid, Ids) ->
    receive
        {'$gen_call', From, Payload} ->
            TestPid ! {captured, Payload},
            gen_statem:reply(From, {ok, Ids}),
            id_mock(TestPid, Ids);
        stop ->
            ok;
        _ ->
            id_mock(TestPid, Ids)
    end.

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

info_tcp_upstream_fin_half_closes_test() ->
    {S, Pid} = state(tcp),
    {ok, S1, Actions} = ?M:handle_info({masque_closed, Pid, peer_fin}, S),
    ?assertEqual([{send_data, <<>>, true}], Actions),
    %% The client's FIN then ends both legs cleanly.
    {stop, normal, _} = ?M:handle_eof(S1),
    await_shutdown_write(),
    cleanup(Pid).

info_tcp_upstream_fin_after_client_fin_stops_test() ->
    {S, Pid} = state(tcp),
    {ok, S1} = ?M:handle_eof(S),
    await_shutdown_write(),
    {stop, normal, _} = ?M:handle_info({masque_closed, Pid, peer_fin}, S1),
    cleanup(Pid).

info_unknown_message_is_ignored_test() ->
    {S, Pid} = state(udp),
    ?assertMatch({ok, _}, ?M:handle_info(something_else, S)),
    cleanup(Pid).

%%====================================================================
%% accept/1 - target shape validation
%%====================================================================

accept_ip_request_test() ->
    Req = #{
        protocol => ip,
        ip_target => {10, 0, 0, 1},
        ip_ipproto => '*',
        handler_opts => #{}
    },
    ?assertEqual(accept, ?M:accept(Req)).

accept_ip_request_with_allow_deny_test() ->
    Req = #{
        protocol => ip,
        ip_target => {10, 0, 0, 1},
        ip_ipproto => '*',
        handler_opts => #{allow => fun(_) -> false end}
    },
    ?assertEqual({reject, forbidden}, ?M:accept(Req)).

accept_udp_request_test() ->
    Req = #{
        target_host => <<"host">>,
        target_port => 80,
        handler_opts => #{}
    },
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
        stop ->
            ok;
        _ ->
            mock_loop(TestPid)
    end.

assert_captured(Expected) ->
    receive
        {captured, Payload} ->
            ?assertEqual(Expected, Payload)
    after 500 ->
        ?assert(false, "no upstream call captured")
    end.

await_shutdown_write() ->
    receive
        {captured, shutdown_write} -> ok
    after 500 ->
        ?assert(false, "no shutdown_write captured")
    end.

cleanup(Pid) ->
    %% The mock replies via gen_statem:reply; the caller has moved on
    %% but the mock process is still alive. Kill it so it does not
    %% leak between tests.
    _ = exit(Pid, shutdown),
    ok.

%%====================================================================
%% Loop detection
%%====================================================================

loop_req(Headers) ->
    #{
        method => <<"CONNECT">>,
        path => <<"/">>,
        authority => <<"proxy">>,
        scheme => <<"https">>,
        protocol => udp,
        target_host => <<"192.0.2.1">>,
        target_port => 53,
        headers => Headers
    }.

accept_without_via_test() ->
    ?assertEqual(accept, ?M:accept(loop_req([]))).

accept_foreign_via_test() ->
    Headers = [{<<"via">>, <<"1.1 other-proxy, 2 edge (comment)">>}],
    ?assertEqual(accept, ?M:accept(loop_req(Headers))).

reject_own_via_test() ->
    Own = <<"1.1 ", (?M:node_token())/binary>>,
    Headers = [{<<"via">>, <<"1.1 other-proxy, ", Own/binary>>}],
    ?assertEqual({reject, loop_detected}, ?M:accept(loop_req(Headers))).

reject_own_via_any_case_test() ->
    Headers = [{<<"Via">>, <<"3 ", (?M:node_token())/binary>>}],
    ?assertEqual({reject, loop_detected}, ?M:accept(loop_req(Headers))).

node_token_is_stable_test() ->
    ?assertEqual(?M:node_token(), ?M:node_token()),
    ?assertEqual(?M:node_token(), ?M:init_node_token()).

listener_token_scopes_loop_test() ->
    Token = ?M:new_token(),
    Req = (loop_req([{<<"via">>, <<"1.1 ", Token/binary>>}]))#{
        handler_opts => #{via_token => Token}
    },
    ?assertEqual({reject, loop_detected}, ?M:accept(Req)),
    Other = (loop_req([{<<"via">>, <<"1.1 ", (?M:new_token())/binary>>}]))#{
        handler_opts => #{via_token => Token}
    },
    ?assertEqual(accept, ?M:accept(Other)).
