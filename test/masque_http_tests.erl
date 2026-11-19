%%% @doc Unit tests for the shared HTTP field checks (`masque_http') and
%%% the RFC 9209 mapping in `masque_errors'.
-module(masque_http_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Capsule-Protocol is a Structured Field Boolean (RFC 9297 3.4)
%%====================================================================

sf_boolean_true_test() ->
    [
        ?assert(masque_http:sf_boolean(V), V)
     || V <- [
            <<"?1">>,
            <<" ?1 ">>,
            <<"?1;a">>,
            <<"?1;a=1">>,
            <<"?1; a=1;b=?0">>,
            <<"?1;a=-1.25">>,
            <<"?1;a=\"x \\\" y\"">>,
            <<"?1;a=tok/en:x">>,
            <<"?1;a=:AQID:">>,
            <<"?1;a=@1700000000">>,
            <<"?1;a=%\"caf%c3%a9\"">>,
            <<"?1;*k_1.x-y=*">>
        ]
    ].

sf_boolean_false_test() ->
    [
        ?assertNot(masque_http:sf_boolean(V), V)
     || V <- [
            undefined,
            <<>>,
            <<"?0">>,
            <<"?0;a=1">>,
            <<"1">>,
            <<"?2">>,
            <<"?1x">>,
            <<"?1,?1">>,
            <<"?1;">>,
            <<"?1;A=1">>,
            <<"?1;a=">>,
            <<"?1;a=\"open">>,
            <<"?1;a=1234567890123456">>,
            <<"?1;a=1.2345">>,
            <<"?1;a=:AQ ID:">>,
            <<"?1;a=%\"%C3\"">>,
            <<"true">>
        ]
    ].

capsule_protocol_header_test() ->
    ?assert(masque_http:capsule_protocol([{<<"Capsule-Protocol">>, <<"?1;x=y">>}])),
    ?assertNot(masque_http:capsule_protocol([])),
    %% Two field lines make a list, not a Boolean.
    ?assertNot(
        masque_http:capsule_protocol([
            {<<"capsule-protocol">>, <<"?1">>}, {<<"capsule-protocol">>, <<"?1">>}
        ])
    ).

%%====================================================================
%% RFC 9297 3.2
%%====================================================================

capsule_response_test() ->
    Ack = [{<<"capsule-protocol">>, <<"?1">>}],
    ?assertEqual(ok, masque_http:capsule_response(200, Ack)),
    ?assertEqual(ok, masque_http:capsule_response(101, Ack)),
    [
        ?assertEqual({error, malformed_response}, masque_http:capsule_response(S, Ack))
     || S <- [204, 205, 206]
    ],
    [
        ?assertEqual(
            {error, malformed_response},
            masque_http:capsule_response(200, [{N, <<"x">>} | Ack])
        )
     || N <- [<<"content-length">>, <<"Content-Type">>, <<"transfer-encoding">>]
    ].

capsule_request_test() ->
    Cap = [{<<"capsule-protocol">>, <<"?1">>}],
    ?assertEqual(ok, masque_http:capsule_request(Cap)),
    ?assertEqual(ok, masque_http:capsule_request([{<<"content-length">>, <<"0">>}])),
    [
        ?assertEqual({error, bad_request}, masque_http:capsule_request([{N, <<"1">>} | Cap]))
     || N <- [<<"content-length">>, <<"content-type">>, <<"Transfer-Encoding">>]
    ].

%%====================================================================
%% HTTP/1.1 101 (RFC 9298 3.3)
%%====================================================================

upgrade_ack_test() ->
    Tok = <<"connect-udp">>,
    ?assert(
        masque_http:upgrade_ack([{<<"Connection">>, <<"Upgrade">>}, {<<"Upgrade">>, Tok}], Tok)
    ),
    ?assert(
        masque_http:upgrade_ack(
            [{<<"connection">>, <<"keep-alive, upgrade">>}, {<<"upgrade">>, <<"CONNECT-UDP">>}],
            Tok
        )
    ),
    ?assertNot(masque_http:upgrade_ack([{<<"upgrade">>, Tok}], Tok)),
    ?assertNot(masque_http:upgrade_ack([{<<"connection">>, <<"upgrade">>}], Tok)),
    ?assertNot(
        masque_http:upgrade_ack(
            [{<<"connection">>, <<"upgrade">>}, {<<"upgrade">>, <<"connect-ip">>}], Tok
        )
    ),
    ?assertNot(
        masque_http:upgrade_ack(
            [{<<"connection">>, <<"upgrade">>}, {<<"upgrade">>, Tok}, {<<"upgrade">>, Tok}],
            Tok
        )
    ).

%%====================================================================
%% RFC 9209 mapping
%%====================================================================

start_error_test() ->
    Cases = [
        {{resolution_failed, {resolve, nxdomain}}, 502, <<"dns_error">>},
        {{resolution_failed, private_address}, 502, <<"destination_ip_prohibited">>},
        {{resolution_failed, self_address}, 502, <<"destination_ip_prohibited">>},
        {{resolution_failed, {tcp_connect, econnrefused}}, 502, <<"connection_refused">>},
        {{resolution_failed, {tcp_connect, timeout}}, 504, <<"connection_timeout">>},
        {{resolution_failed, {tcp_connect, ehostunreach}}, 502, <<"destination_ip_unroutable">>},
        {{resolution_failed, {tcp_connect, eperm}}, 502, <<"destination_unavailable">>},
        {{resolution_failed, {connect, econnrefused}}, 502, <<"connection_refused">>},
        {{resolution_failed, {connect, eafnosupport}}, 502, <<"destination_unavailable">>},
        {{resolution_failed, {udp_open, eaddrinuse}}, 502, <<"proxy_internal_error">>},
        {{resolution_failed, {upstream, {connect, econnrefused}}}, 502, <<"connection_refused">>},
        {{resolution_failed, {upstream, handshake_timeout}}, 504, <<"connection_timeout">>},
        {{resolution_failed, something}, 502, <<"dns_error">>},
        {{reject, forbidden}, 403, <<"destination_ip_prohibited">>},
        {{handler_crash, boom}, 502, <<"proxy_internal_error">>},
        {handler_refused, 502, <<"proxy_internal_error">>}
    ],
    [
        begin
            R = masque_errors:start_error(Stop),
            ?assertEqual({Status, <<"masque; error=", Type/binary>>}, {
                masque_errors:handshake_status(R), masque_errors:proxy_status(R)
            })
        end
     || {Stop, Status, Type} <- Cases
    ].

request_errors_test() ->
    [
        ?assertEqual(<<"masque; error=http_request_error">>, masque_errors:proxy_status(R))
     || R <- [bad_method, bad_path, bad_port, bad_host, bad_request, unknown_request]
    ],
    ?assertEqual(<<"masque; error=http_request_denied">>, masque_errors:proxy_status(denied)),
    ?assertEqual(403, masque_errors:handshake_status(denied)).

upstream_status_test() ->
    ?assertEqual(403, masque_errors:handshake_status({upstream_status, 403})),
    ?assertEqual(
        <<"masque; received-status=403">>,
        masque_errors:proxy_status({upstream_status, 403})
    ).
