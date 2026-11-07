-module(masque_reverse_capsule_tests).

%% Wire vectors for the reverse connect capsules and templates
%% (draft-rosomakho-masque-reverse-connect-01 sections 4.1, 4.4, 5.1, 5.2).

-include_lib("eunit/include/eunit.hrl").
-include("masque_reverse.hrl").

-define(C, masque_reverse_capsule).

%% Figure 9, one record per destination type.
service_local_test() ->
    ?assertEqual(
        <<0, 6, 0, 22>>,
        iolist_to_binary(?C:encode_service(#{destination => local, protocol => tcp, port => 22}))
    ).

service_ipv4_test() ->
    ?assertEqual(
        <<4, 192, 0, 2, 1, 17, 16#0D, 16#96>>,
        iolist_to_binary(
            ?C:encode_service(#{destination => {192, 0, 2, 1}, protocol => udp, port => 3478})
        )
    ).

service_ipv6_test() ->
    IP = {16#2001, 16#db8, 0, 0, 0, 0, 0, 1},
    ?assertEqual(
        <<6, 16#20, 16#01, 16#0d, 16#b8, 0:80, 0, 1, 6, 1, 187>>,
        iolist_to_binary(?C:encode_service(#{destination => IP, protocol => tcp, port => 443}))
    ).

%% Figure 10: the hostname is length-prefixed with a varint.
service_hostname_test() ->
    ?assertEqual(
        <<1, 11, "db.internal", 6, 16#15, 16#38>>,
        iolist_to_binary(
            ?C:encode_service(#{destination => <<"db.internal">>, protocol => tcp, port => 5432})
        )
    ).

services() ->
    [
        #{destination => local, protocol => tcp, port => 22},
        #{destination => {10, 0, 0, 5}, protocol => udp, port => 53},
        #{destination => {16#fd00, 0, 0, 0, 0, 0, 0, 1}, protocol => tcp, port => 8443},
        #{destination => <<"db.internal">>, protocol => tcp, port => 5432}
    ].

round_trip_test() ->
    Caps = [
        {available_services, services()},
        {available_services, []},
        {connection_request, 0, hd(services())},
        {connection_request, (1 bsl 62) - 1, lists:last(services())},
        {connection_request_declined, 12345}
    ],
    lists:foreach(
        fun(Cap) ->
            Bin = ?C:encode(Cap),
            {ok, {Type, Value, <<>>}} = masque_capsule:decode(Bin),
            ?assertEqual({ok, Cap}, ?C:decode(?C:type(Type), Value))
        end,
        Caps
    ).

%% Figure 11: type, length, request id, service.
connection_request_bytes_test() ->
    Bin = ?C:encode({connection_request, 1, #{destination => local, protocol => tcp, port => 80}}),
    ?assertEqual(<<16#80, 16#52, 16#43, 16#a1, 5, 1, 0, 6, 0, 80>>, Bin).

%% Figure 12.
declined_bytes_test() ->
    ?assertEqual(
        <<16#80, 16#52, 16#43, 16#a2, 2, 16#40, 64>>, ?C:encode({connection_request_declined, 64})
    ).

codes_test() ->
    ?assertEqual(available_services, ?C:type(?MASQUE_CAPSULE_AVAILABLE_SERVICES)),
    ?assertEqual(connection_request, ?C:type(?MASQUE_CAPSULE_CONNECTION_REQUEST)),
    ?assertEqual(connection_request_declined, ?C:type(?MASQUE_CAPSULE_CONNECTION_REQUEST_DECLINED)),
    ?assertEqual(unknown, ?C:type(0)),
    %% None is a GREASE value (RFC 9297 section 5.4).
    [
        ?assertNotEqual(0, (T - 16#29) rem 16#1f)
     || T <- [
            ?MASQUE_CAPSULE_AVAILABLE_SERVICES,
            ?MASQUE_CAPSULE_CONNECTION_REQUEST,
            ?MASQUE_CAPSULE_CONNECTION_REQUEST_DECLINED
        ]
    ].

%% Section 4.4 and 5.1: malformed fields are an error.
malformed_test() ->
    Bad = [
        {available_services, <<9, 6, 0, 22>>},
        {available_services, <<4, 10, 0, 0>>},
        {available_services, <<0, 7, 0, 22>>},
        {available_services, <<1, 0, 6, 0, 22>>},
        {available_services, <<1, 5, "a b c", 6, 0, 22>>},
        {available_services, <<1, 20, "short", 6, 0, 22>>},
        {connection_request, <<1, 0, 6, 0, 22, 99>>},
        {connection_request, <<1>>},
        {connection_request, <<>>},
        {connection_request_declined, <<>>},
        {connection_request_declined, <<1, 2>>}
    ],
    [?assertEqual({error, malformed}, ?C:decode(T, V)) || {T, V} <- Bad].

%% Section 4.1 templates.
listen_template_test() ->
    {ok, T} = masque_uri_reverse:parse_listen_template(?MASQUE_DEFAULT_LISTEN_URI_TEMPLATE),
    Cases = [
        {local, '*'},
        {'*', tcp},
        {{wildcard, <<"example.com">>}, udp},
        {<<"svc.example.com">>, tcp},
        {{10, 0, 0, 1}, '*'},
        {{4, {10, 0, 0, 0}, 8}, tcp},
        {{6, {16#2001, 16#db8, 0, 0, 0, 0, 0, 0}, 32}, udp}
    ],
    lists:foreach(
        fun({Target, Proto}) ->
            Path = masque_uri_reverse:expand_listen(T, #{target => Target, ipproto => Proto}),
            ?assertEqual(
                {ok, #{target => Target, ipproto => Proto}},
                masque_uri_reverse:match_listen(T, Path)
            )
        end,
        Cases
    ),
    ?assertEqual(
        {ok, #{target => local, ipproto => '*'}},
        masque_uri_reverse:match_listen(T, <<"/.well-known/masque/listen/./*/">>)
    ),
    ?assertEqual(
        {error, bad_ipproto},
        masque_uri_reverse:match_listen(T, <<"/.well-known/masque/listen/./1/">>)
    ),
    ?assertEqual(
        {error, bad_target},
        masque_uri_reverse:match_listen(T, <<"/.well-known/masque/listen/10.0.0.1%2F7/6/">>)
    ).

%% A template without the variables means any target and protocol.
listen_template_without_vars_test() ->
    {ok, T} = masque_uri_reverse:parse_listen_template(<<"/masque?user=bob">>),
    ?assertEqual(
        {ok, #{target => '*', ipproto => '*'}},
        masque_uri_reverse:match_listen(T, <<"/masque?user=bob">>)
    ).

listen_template_rejects_other_vars_test() ->
    ?assertEqual(
        {error, bad_template},
        masque_uri_reverse:parse_listen_template(<<"/l/{target_host}/{target_port}/">>)
    ).

%% Section 5.2.
accept_template_test() ->
    {ok, T} = masque_uri_reverse:parse_accept_template(?MASQUE_DEFAULT_ACCEPT_URI_TEMPLATE),
    Path = masque_uri_reverse:expand_accept(T, 4611686018427387903),
    ?assertEqual(<<"/.well-known/masque/accept/4611686018427387903/">>, Path),
    ?assertEqual({ok, 4611686018427387903}, masque_uri_reverse:match_accept(T, Path)),
    ?assertEqual(
        {error, bad_request_id},
        masque_uri_reverse:match_accept(T, <<"/.well-known/masque/accept/x1/">>)
    ),
    ?assertEqual({error, no_match}, masque_uri_reverse:match_accept(T, <<"/other/">>)),
    {ok, Q} = masque_uri_reverse:parse_accept_template(<<"/masque/accept{?request_id}">>),
    ?assertEqual(
        {ok, 7}, masque_uri_reverse:match_accept(Q, masque_uri_reverse:expand_accept(Q, 7))
    ).

accept_template_requires_request_id_test() ->
    ?assertEqual({error, bad_template}, masque_uri_reverse:parse_accept_template(<<"/accept/">>)),
    ?assertEqual({error, bad_template}, masque_uri_reverse:parse_accept_template(<<"/a/{id}/">>)).
