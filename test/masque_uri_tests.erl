-module(masque_uri_tests).

-include_lib("eunit/include/eunit.hrl").

-define(TPL, <<"/.well-known/masque/udp/{target_host}/{target_port}/">>).

expand_ipv4_test() ->
    ?assertEqual(
        <<"/.well-known/masque/udp/192.0.2.6/443/">>,
        masque_uri:expand(
            ?TPL,
            #{
                target_host => <<"192.0.2.6">>,
                target_port => 443
            }
        )
    ).

expand_ipv6_test() ->
    %% Colons are not unreserved → percent-encoded.
    ?assertEqual(
        <<"/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/">>,
        masque_uri:expand(
            ?TPL,
            #{
                target_host => <<"2001:db8::1">>,
                target_port => 443
            }
        )
    ).

expand_hostname_test() ->
    ?assertEqual(
        <<"/.well-known/masque/udp/example.com/4433/">>,
        masque_uri:expand(
            ?TPL,
            #{
                target_host => "example.com",
                target_port => 4433
            }
        )
    ).

match_happy_test() ->
    {ok, Vars} = masque_uri:match(
        ?TPL,
        <<"/.well-known/masque/udp/192.0.2.6/443/">>
    ),
    ?assertEqual(<<"192.0.2.6">>, maps:get(target_host, Vars)),
    ?assertEqual(443, maps:get(target_port, Vars)).

match_ipv6_pct_decoded_test() ->
    {ok, Vars} = masque_uri:match(
        ?TPL,
        <<"/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/">>
    ),
    ?assertEqual(<<"2001:db8::1">>, maps:get(target_host, Vars)),
    ?assertEqual(443, maps:get(target_port, Vars)).

match_wrong_prefix_test() ->
    ?assertEqual(
        {error, no_match},
        masque_uri:match(?TPL, <<"/wrong/path/192.0.2.6/443/">>)
    ).

match_missing_trailing_slash_test() ->
    ?assertEqual(
        {error, no_match},
        masque_uri:match(
            ?TPL,
            <<"/.well-known/masque/udp/192.0.2.6/443">>
        )
    ).

match_bad_port_test() ->
    ?assertEqual(
        {error, bad_port},
        masque_uri:match(
            ?TPL,
            <<"/.well-known/masque/udp/192.0.2.6/99999/">>
        )
    ).

match_empty_host_test() ->
    ?assertEqual(
        {error, no_match},
        masque_uri:match(
            ?TPL,
            <<"/.well-known/masque/udp//443/">>
        )
    ).

match_zero_port_test() ->
    ?assertEqual(
        {error, bad_port},
        masque_uri:match(
            ?TPL,
            <<"/.well-known/masque/udp/192.0.2.6/0/">>
        )
    ).

absolute_template_strips_to_path_test() ->
    AbsTpl = <<
        "https://proxy.example/.well-known/masque/udp/"
        "{target_host}/{target_port}/"
    >>,
    ?assertEqual(
        <<"/.well-known/masque/udp/192.0.2.6/443/">>,
        masque_uri:expand(
            AbsTpl,
            #{
                target_host => <<"192.0.2.6">>,
                target_port => 443
            }
        )
    ),
    {ok, Vars} = masque_uri:match(
        AbsTpl,
        <<"/.well-known/masque/udp/192.0.2.6/443/">>
    ),
    ?assertEqual(<<"192.0.2.6">>, maps:get(target_host, Vars)).

valid_host_accepts_ipv4_ipv6_and_hostname_test() ->
    ?assert(masque_uri:valid_host(<<"192.0.2.6">>)),
    ?assert(masque_uri:valid_host(<<"example.com">>)),
    ?assert(masque_uri:valid_host(<<"a-b.c0">>)),
    ?assert(masque_uri:valid_host(<<"2001:db8::1">>)).

valid_host_rejects_zone_id_and_bad_labels_test() ->
    ?assertNot(masque_uri:valid_host(<<>>)),
    ?assertNot(masque_uri:valid_host(<<"fe80::1%eth0">>)),
    ?assertNot(masque_uri:valid_host(<<"-bad.example">>)),
    ?assertNot(masque_uri:valid_host(<<"bad-.example">>)),
    ?assertNot(masque_uri:valid_host(<<"spaces in.host">>)).

match_rejects_bad_host_shape_test() ->
    Tpl = ?TPL,
    ?assertEqual(
        {error, bad_host},
        masque_uri:match(
            Tpl,
            <<"/.well-known/masque/udp/-bad/443/">>
        )
    ).

roundtrip_test_() ->
    Cases = [
        {<<"192.0.2.6">>, 443},
        {<<"example.com">>, 1},
        {<<"example.com">>, 65535},
        {<<"2001:db8::1">>, 8080}
    ],
    [
        ?_test(begin
            Path = masque_uri:expand(
                ?TPL,
                #{target_host => H, target_port => P}
            ),
            {ok, Vars} = masque_uri:match(?TPL, Path),
            ?assertEqual(H, maps:get(target_host, Vars)),
            ?assertEqual(P, maps:get(target_port, Vars))
        end)
     || {H, P} <- Cases
    ].

%%====================================================================
%% Strict template, host and port parsing
%%====================================================================

template_rejects_adjacent_vars_test() ->
    ?assertEqual(
        {error, bad_template},
        masque_uri_template:parse_pattern(<<"/x/{target_host}{target_port}/">>)
    ).

template_rejects_var_before_query_test() ->
    ?assertEqual(
        {error, bad_template},
        masque_uri_template:parse_pattern(<<"/x/{target_host}{?target_port}">>)
    ).

template_rejects_query_not_last_test() ->
    ?assertEqual(
        {error, bad_template},
        masque_uri_template:parse_pattern(<<"/x{?target_host}/y">>)
    ).

query_template_requires_exact_path_test() ->
    {ok, T} = masque_uri_template:parse_pattern(<<"/masque{?target_host,target_port}">>),
    ?assertMatch(
        {ok, #{target_host := <<"a">>, target_port := <<"1">>}},
        masque_uri_template:match(T, <<"/masque?target_host=a&target_port=1">>)
    ),
    ?assertEqual(
        {error, no_match},
        masque_uri_template:match(T, <<"/masque/extra?target_host=a&target_port=1">>)
    ).

valid_host_rejects_zone_id_test() ->
    ?assertNot(masque_uri:valid_host(<<"fe80::1%eth0">>)),
    ?assert(masque_uri:valid_host(<<"fe80::1">>)).

valid_host_rejects_non_dotted_quad_test() ->
    [
        ?assertNot(masque_uri:valid_host(H))
     || H <- [<<"1">>, <<"127.1">>, <<"0x7f.0.0.1">>, <<"010.0.0.1">>, <<"1.2.3.04">>]
    ],
    ?assert(masque_uri:valid_host(<<"127.0.0.1">>)),
    ?assert(masque_uri:valid_host(<<"host1.example">>)).

match_rejects_non_canonical_port_test() ->
    [
        ?assertEqual(
            {error, bad_port},
            masque_uri:match(?TPL, <<"/.well-known/masque/udp/192.0.2.6/", P/binary, "/">>)
        )
     || P <- [<<"0443">>, <<"%2B443">>, <<"-1">>, <<"0">>]
    ].
