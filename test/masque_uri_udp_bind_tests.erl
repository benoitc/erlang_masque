-module(masque_uri_udp_bind_tests).

-include_lib("eunit/include/eunit.hrl").
-include("masque_udp_bind.hrl").

-define(TPL,
        <<"https://proxy.example:4443"
          "/.well-known/masque/udp/{target_host}/{target_port}/">>).

%%====================================================================
%% URI matching: scoped vs unscoped
%%====================================================================

match_scoped_test() ->
    Path = <<"/.well-known/masque/udp/192.0.2.6/443/">>,
    ?assertEqual({ok, #{target_host => <<"192.0.2.6">>,
                        target_port => 443,
                        bind        => scoped}},
                 masque_uri_udp_bind:match(?TPL, Path)).

match_unscoped_pct_encoded_test() ->
    %% draft-11: when target_host and target_port are both `*' (or
    %% percent-encoded), the bind is unscoped.
    Path = <<"/.well-known/masque/udp/%2A/%2A/">>,
    ?assertEqual({ok, #{target_host => '*',
                        target_port => '*',
                        bind        => unscoped}},
                 masque_uri_udp_bind:match(?TPL, Path)).

match_unscoped_literal_star_test() ->
    Path = <<"/.well-known/masque/udp/*/*/">>,
    ?assertEqual({ok, #{target_host => '*',
                        target_port => '*',
                        bind        => unscoped}},
                 masque_uri_udp_bind:match(?TPL, Path)).

%% Mixing wildcard host with a real port is malformed (the draft only
%% allows both wildcards together).
match_partial_wildcard_host_only_test() ->
    Path = <<"/.well-known/masque/udp/*/443/">>,
    ?assertEqual({error, bad_host},
                 masque_uri_udp_bind:match(?TPL, Path)).

match_partial_wildcard_port_only_test() ->
    Path = <<"/.well-known/masque/udp/192.0.2.6/*/">>,
    ?assertEqual({error, bad_host},
                 masque_uri_udp_bind:match(?TPL, Path)).

match_wrong_path_test() ->
    ?assertEqual({error, no_match},
                 masque_uri_udp_bind:match(?TPL, <<"/wrong">>)).

match_bad_port_test() ->
    Path = <<"/.well-known/masque/udp/192.0.2.6/notanumber/">>,
    ?assertEqual({error, bad_port},
                 masque_uri_udp_bind:match(?TPL, Path)).

%%====================================================================
%% URI expansion: unscoped, scoped, raw vars
%%====================================================================

%% `expand/2' returns the path-and-query portion only, mirroring the
%% existing `masque_uri:expand/2'. The template engine preserves a
%% literal `*' on the wire (it is reserved-but-allowed in the
%% existing `masque_uri_template' codebase, used by CONNECT-IP);
%% callers that need the percent-encoded form supply it as
%% `<<"%2A">>' explicitly.
expand_unscoped_test() ->
    Got = masque_uri_udp_bind:expand(?TPL, unscoped),
    ?assertEqual(<<"/.well-known/masque/udp/*/*/">>, Got).

expand_scoped_test() ->
    Got = masque_uri_udp_bind:expand(?TPL, {<<"192.0.2.6">>, 443}),
    ?assertEqual(<<"/.well-known/masque/udp/192.0.2.6/443/">>, Got).

expand_with_raw_vars_test() ->
    Got = masque_uri_udp_bind:expand(
            ?TPL, #{target_host => <<"example.com">>,
                    target_port => 4433}),
    ?assertEqual(<<"/.well-known/masque/udp/example.com/4433/">>, Got).

%%====================================================================
%% classify/1 helper
%%====================================================================

classify_match_unscoped_test() ->
    Match = #{target_host => '*', target_port => '*',
              bind => unscoped},
    ?assertEqual(unscoped, masque_uri_udp_bind:classify(Match)).

classify_match_scoped_test() ->
    Match = #{target_host => <<"x">>, target_port => 1,
              bind => scoped},
    ?assertEqual(scoped, masque_uri_udp_bind:classify(Match)).

classify_target_unscoped_test() ->
    ?assertEqual(unscoped, masque_uri_udp_bind:classify(unscoped)).

classify_target_scoped_test() ->
    ?assertEqual(scoped,
                 masque_uri_udp_bind:classify({<<"x">>, 1})).

%%====================================================================
%% Connect-UDP-Bind header
%%====================================================================

bind_header_present_test() ->
    ?assertEqual(bind,
                 masque_uri_udp_bind:parse_bind_header(
                   [{<<"connect-udp-bind">>, <<"?1">>}])).

bind_header_present_mixed_case_test() ->
    %% Header lookup is case-insensitive.
    ?assertEqual(bind,
                 masque_uri_udp_bind:parse_bind_header(
                   [{<<"Connect-UDP-Bind">>, <<"?1">>}])).

bind_header_absent_test() ->
    ?assertEqual(absent,
                 masque_uri_udp_bind:parse_bind_header([])).

bind_header_false_is_absent_test() ->
    %% ?0 means "feature explicitly disabled" - same effect for our
    %% dispatch as absent.
    ?assertEqual(absent,
                 masque_uri_udp_bind:parse_bind_header(
                   [{<<"connect-udp-bind">>, <<"?0">>}])).

bind_header_invalid_value_test() ->
    %% Anything that is not ?0 or ?1 is an invalid Boolean and per
    %% draft-11 must be treated as absent. We surface `invalid' so
    %% callers can log it.
    ?assertEqual(invalid,
                 masque_uri_udp_bind:parse_bind_header(
                   [{<<"connect-udp-bind">>, <<"foo">>}])).

bind_header_strips_whitespace_test() ->
    ?assertEqual(bind,
                 masque_uri_udp_bind:parse_bind_header(
                   [{<<"connect-udp-bind">>, <<" ?1 ">>}])).

format_bind_header_test() ->
    ?assertEqual({<<"connect-udp-bind">>, <<"?1">>},
                 masque_uri_udp_bind:format_bind_header()).

%%====================================================================
%% Proxy-Public-Address: parse + format roundtrips
%%====================================================================

ppa_parse_v4_only_test() ->
    Headers = [{<<"proxy-public-address">>,
                <<"\"192.0.2.45:54321\"">>}],
    ?assertEqual({ok, [{{192,0,2,45}, 54321}]},
                 masque_uri_udp_bind:parse_proxy_public_address(Headers)).

ppa_parse_v6_only_test() ->
    Headers = [{<<"proxy-public-address">>,
                <<"\"[2001:db8::1234]:54321\"">>}],
    ?assertEqual({ok, [{{16#2001,16#0DB8,0,0,0,0,0,16#1234}, 54321}]},
                 masque_uri_udp_bind:parse_proxy_public_address(Headers)).

ppa_parse_dual_stack_test() ->
    Headers = [{<<"proxy-public-address">>,
                <<"\"192.0.2.45:54321\", \"[2001:db8::1234]:54321\"">>}],
    ?assertEqual({ok, [{{192,0,2,45}, 54321},
                       {{16#2001,16#0DB8,0,0,0,0,0,16#1234}, 54321}]},
                 masque_uri_udp_bind:parse_proxy_public_address(Headers)).

ppa_parse_absent_test() ->
    ?assertEqual({error, absent},
                 masque_uri_udp_bind:parse_proxy_public_address([])).

ppa_parse_empty_value_test() ->
    Headers = [{<<"proxy-public-address">>, <<"">>}],
    ?assertEqual({error, empty},
                 masque_uri_udp_bind:parse_proxy_public_address(Headers)).

ppa_parse_malformed_unquoted_test() ->
    Headers = [{<<"proxy-public-address">>,
                <<"192.0.2.45:54321">>}],
    ?assertEqual({error, malformed},
                 masque_uri_udp_bind:parse_proxy_public_address(Headers)).

ppa_parse_malformed_bad_ip_test() ->
    Headers = [{<<"proxy-public-address">>,
                <<"\"not-an-ip:54321\"">>}],
    ?assertEqual({error, malformed},
                 masque_uri_udp_bind:parse_proxy_public_address(Headers)).

ppa_parse_malformed_bad_port_test() ->
    Headers = [{<<"proxy-public-address">>,
                <<"\"192.0.2.45:0\"">>}],
    ?assertEqual({error, malformed},
                 masque_uri_udp_bind:parse_proxy_public_address(Headers)).

ppa_format_dual_stack_test() ->
    Got = masque_uri_udp_bind:format_proxy_public_address(
            [{{192,0,2,45}, 54321},
             {{16#2001,16#0DB8,0,0,0,0,0,16#1234}, 54321}]),
    ?assertEqual(<<"\"192.0.2.45:54321\", "
                   "\"[2001:db8::1234]:54321\"">>, Got).

ppa_format_empty_rejected_test() ->
    ?assertError(empty_proxy_public_address,
                 masque_uri_udp_bind:format_proxy_public_address([])).

%% Format then parse: roundtrip.
ppa_roundtrip_v4_test() ->
    Pair = {{192,0,2,1}, 4433},
    Bin = masque_uri_udp_bind:format_proxy_public_address([Pair]),
    ?assertEqual({ok, [Pair]},
                 masque_uri_udp_bind:parse_proxy_public_address(
                   [{<<"proxy-public-address">>, Bin}])).

ppa_roundtrip_v6_test() ->
    Pair = {{16#2001,16#0DB8,0,0,0,0,0,1}, 5060},
    Bin = masque_uri_udp_bind:format_proxy_public_address([Pair]),
    ?assertEqual({ok, [Pair]},
                 masque_uri_udp_bind:parse_proxy_public_address(
                   [{<<"proxy-public-address">>, Bin}])).
