-module(masque_uri_tests).

-include_lib("eunit/include/eunit.hrl").

-define(TPL, <<"/.well-known/masque/udp/{target_host}/{target_port}/">>).

expand_ipv4_test() ->
    ?assertEqual(<<"/.well-known/masque/udp/192.0.2.6/443/">>,
                 masque_uri:expand(?TPL,
                                   #{target_host => <<"192.0.2.6">>,
                                     target_port => 443})).

expand_ipv6_test() ->
    %% Colons are not unreserved → percent-encoded.
    ?assertEqual(<<"/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/">>,
                 masque_uri:expand(?TPL,
                                   #{target_host => <<"2001:db8::1">>,
                                     target_port => 443})).

expand_hostname_test() ->
    ?assertEqual(<<"/.well-known/masque/udp/example.com/4433/">>,
                 masque_uri:expand(?TPL,
                                   #{target_host => "example.com",
                                     target_port => 4433})).

match_happy_test() ->
    {ok, Vars} = masque_uri:match(?TPL,
                                  <<"/.well-known/masque/udp/192.0.2.6/443/">>),
    ?assertEqual(<<"192.0.2.6">>, maps:get(target_host, Vars)),
    ?assertEqual(443, maps:get(target_port, Vars)).

match_ipv6_pct_decoded_test() ->
    {ok, Vars} = masque_uri:match(
                    ?TPL,
                    <<"/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/">>),
    ?assertEqual(<<"2001:db8::1">>, maps:get(target_host, Vars)),
    ?assertEqual(443, maps:get(target_port, Vars)).

match_wrong_prefix_test() ->
    ?assertEqual({error, no_match},
                 masque_uri:match(?TPL, <<"/wrong/path/192.0.2.6/443/">>)).

match_missing_trailing_slash_test() ->
    ?assertEqual({error, no_match},
                 masque_uri:match(?TPL,
                                  <<"/.well-known/masque/udp/192.0.2.6/443">>)).

match_bad_port_test() ->
    ?assertEqual({error, bad_port},
                 masque_uri:match(?TPL,
                                  <<"/.well-known/masque/udp/192.0.2.6/99999/">>)).

match_empty_host_test() ->
    ?assertEqual({error, no_match},
                 masque_uri:match(?TPL,
                                  <<"/.well-known/masque/udp//443/">>)).

match_zero_port_test() ->
    ?assertEqual({error, bad_port},
                 masque_uri:match(?TPL,
                                  <<"/.well-known/masque/udp/192.0.2.6/0/">>)).

roundtrip_test_() ->
    Cases = [
        {<<"192.0.2.6">>, 443},
        {<<"example.com">>, 1},
        {<<"example.com">>, 65535},
        {<<"2001:db8::1">>, 8080}
    ],
    [?_test(begin
        Path = masque_uri:expand(?TPL,
                                 #{target_host => H, target_port => P}),
        {ok, Vars} = masque_uri:match(?TPL, Path),
        ?assertEqual(H, maps:get(target_host, Vars)),
        ?assertEqual(P, maps:get(target_port, Vars))
    end) || {H, P} <- Cases].
