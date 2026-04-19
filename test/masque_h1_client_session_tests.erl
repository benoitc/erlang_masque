%%% @doc Unit tests for pure helpers in `masque_h1_client_session'.
%%%
%%% Covers the handshake header builder, the response validator, and
%%% the authority formatter. State-machine integration is covered by
%%% `masque_h1_SUITE'.
-module(masque_h1_client_session_tests).

-include_lib("eunit/include/eunit.hrl").

-define(M, masque_h1_client_session).

%%====================================================================
%% request_headers/1
%%====================================================================

headers_contains_path_and_host_test() ->
    Data = ?M:build_data(#{
        proxy_host => <<"proxy.example">>,
        proxy_port => 4433,
        target_host => <<"10.0.0.1">>,
        target_port => 5353
    }),
    Hs = ?M:request_headers(Data),
    ?assertEqual(<<"proxy.example:4433">>,
                 proplists:get_value(<<"host">>, Hs)),
    ?assertEqual(<<"/.well-known/masque/udp/10.0.0.1/5353/">>,
                 proplists:get_value(<<":path">>, Hs)),
    ?assertEqual(<<"?1">>,
                 proplists:get_value(<<"capsule-protocol">>, Hs)).

headers_omits_capsule_protocol_when_disabled_test() ->
    Data = ?M:build_data(#{capsule_protocol => false}),
    Hs = ?M:request_headers(Data),
    ?assertEqual(undefined,
                 proplists:get_value(<<"capsule-protocol">>, Hs)).

headers_ipv6_authority_brackets_test() ->
    Data = ?M:build_data(#{proxy_host => <<"::1">>, proxy_port => 4433}),
    Hs = ?M:request_headers(Data),
    ?assertEqual(<<"[::1]:4433">>,
                 proplists:get_value(<<"host">>, Hs)).

headers_uses_custom_template_test() ->
    Data = ?M:build_data(#{
        uri_template => <<"/proxy?target={target_host}:{target_port}">>,
        target_host => <<"ex.test">>,
        target_port => 80
    }),
    Hs = ?M:request_headers(Data),
    ?assertEqual(<<"/proxy?target=ex.test:80">>,
                 proplists:get_value(<<":path">>, Hs)).

%%====================================================================
%% validate_response/2
%%====================================================================

validate_ok_with_capsule_ack_test() ->
    Data = ?M:build_data(#{capsule_protocol => true}),
    Hs = [{<<"capsule-protocol">>, <<"?1">>}],
    ?assertEqual(ok, ?M:validate_response(Hs, Data)).

validate_fails_when_capsule_requested_but_not_ackd_test() ->
    Data = ?M:build_data(#{capsule_protocol => true}),
    ?assertEqual({error, capsule_protocol_not_acknowledged},
                 ?M:validate_response([], Data)).

validate_ok_when_capsule_not_requested_test() ->
    Data = ?M:build_data(#{capsule_protocol => false}),
    ?assertEqual(ok, ?M:validate_response([], Data)).

validate_rejects_content_length_test() ->
    Data = ?M:build_data(#{capsule_protocol => false}),
    Hs = [{<<"content-length">>, <<"0">>}],
    ?assertEqual({error, malformed_response},
                 ?M:validate_response(Hs, Data)).

validate_rejects_content_type_test() ->
    Data = ?M:build_data(#{capsule_protocol => false}),
    Hs = [{<<"content-type">>, <<"text/plain">>}],
    ?assertEqual({error, malformed_response},
                 ?M:validate_response(Hs, Data)).

validate_accepts_mixed_case_header_names_test() ->
    Data = ?M:build_data(#{capsule_protocol => true}),
    Hs = [{<<"Capsule-Protocol">>, <<"?1">>}],
    ?assertEqual(ok, ?M:validate_response(Hs, Data)).

%%====================================================================
%% build_authority/2
%%====================================================================

build_authority_hostname_test() ->
    ?assertEqual(<<"proxy.example:443">>,
                 ?M:build_authority(<<"proxy.example">>, 443)).

build_authority_ipv4_test() ->
    ?assertEqual(<<"127.0.0.1:8443">>,
                 ?M:build_authority(<<"127.0.0.1">>, 8443)).

build_authority_ipv6_test() ->
    ?assertEqual(<<"[::1]:4433">>,
                 ?M:build_authority(<<"::1">>, 4433)).

build_authority_ipv6_full_test() ->
    ?assertEqual(<<"[2001:db8::1]:443">>,
                 ?M:build_authority(<<"2001:db8::1">>, 443)).

%%====================================================================
%% classify_upgrade_error/1
%%====================================================================

classify_http_status_test() ->
    ?assertMatch({handshake_rejected, 403, _},
                 ?M:classify_upgrade_error({http_status, 403, <<"Forbidden">>})).

classify_timeout_test() ->
    ?assertEqual(handshake_timeout,
                 ?M:classify_upgrade_error(timeout)).

classify_other_test() ->
    ?assertMatch({upgrade, _},
                 ?M:classify_upgrade_error(econnrefused)).
