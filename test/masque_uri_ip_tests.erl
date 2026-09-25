-module(masque_uri_ip_tests).

-include_lib("eunit/include/eunit.hrl").

-define(ABS_PATH_TPL,
    <<"https://proxy.example:4443/.well-known/masque/ip/{target}/{ipproto}/">>
).
-define(ABS_QUERY_TPL,
    <<"https://proxy.example:4443/masque{?target,ipproto}">>
).
-define(SERVER_PATH_TPL,
    <<"/.well-known/masque/ip/{target}/{ipproto}/">>
).

%%====================================================================
%% Template parsing — client side is absolute-only
%%====================================================================

client_accepts_absolute_path_form_test() ->
    ?assertMatch({ok, _}, masque_uri_ip:parse_client_template(?ABS_PATH_TPL)).

client_accepts_absolute_query_form_test() ->
    ?assertMatch({ok, _}, masque_uri_ip:parse_client_template(?ABS_QUERY_TPL)).

client_rejects_path_only_test() ->
    ?assertEqual(
        {error, absolute_uri_required},
        masque_uri_ip:parse_client_template(?SERVER_PATH_TPL)
    ).

client_rejects_missing_scheme_test() ->
    ?assertEqual(
        {error, absolute_uri_required},
        masque_uri_ip:parse_client_template(
            <<"proxy.example/.well-known/masque/ip/{target}/{ipproto}/">>
        )
    ).

server_accepts_path_only_test() ->
    ?assertMatch({ok, _}, masque_uri_ip:parse_server_template(?SERVER_PATH_TPL)).

server_accepts_absolute_test() ->
    ?assertMatch({ok, _}, masque_uri_ip:parse_server_template(?ABS_PATH_TPL)).

%%====================================================================
%% Target parsing
%%====================================================================

parse_target_wildcard_test() ->
    ?assertEqual({ok, '*'}, masque_uri_ip:parse_target(<<"*">>)).

parse_target_v4_literal_test() ->
    ?assertEqual(
        {ok, {192, 0, 2, 1}},
        masque_uri_ip:parse_target(<<"192.0.2.1">>)
    ).

parse_target_v6_literal_test() ->
    ?assertEqual(
        {ok, {16#2001, 16#DB8, 0, 0, 0, 0, 0, 1}},
        masque_uri_ip:parse_target(<<"2001:db8::1">>)
    ).

parse_target_v4_prefix_test() ->
    ?assertEqual(
        {ok, {4, {10, 0, 0, 0}, 24}},
        masque_uri_ip:parse_target(<<"10.0.0.0/24">>)
    ).

parse_target_v6_prefix_test() ->
    ?assertEqual(
        {ok, {6, {16#2001, 16#DB8, 0, 0, 0, 0, 0, 0}, 32}},
        masque_uri_ip:parse_target(<<"2001:db8::/32">>)
    ).

parse_target_prefix_out_of_range_v4_test() ->
    ?assertEqual(
        {error, bad_target},
        masque_uri_ip:parse_target(<<"10.0.0.0/33">>)
    ).

%% RFC 9484 §3 / §4.6: prefix targets must be canonical (host bits zero).
parse_target_non_canonical_prefix_v4_test() ->
    ?assertEqual(
        {error, bad_target},
        masque_uri_ip:parse_target(<<"10.0.0.5/24">>)
    ).

parse_target_non_canonical_prefix_v6_test() ->
    ?assertEqual(
        {error, bad_target},
        masque_uri_ip:parse_target(<<"2001:db8::1/64">>)
    ).

parse_target_hostname_test() ->
    ?assertEqual(
        {ok, <<"example.com">>},
        masque_uri_ip:parse_target(<<"example.com">>)
    ).

parse_target_invalid_test() ->
    ?assertEqual(
        {error, bad_target},
        masque_uri_ip:parse_target(<<"not valid">>)
    ).

%%====================================================================
%% ipproto parsing
%%====================================================================

parse_ipproto_wildcard_test() ->
    ?assertEqual({ok, '*'}, masque_uri_ip:parse_ipproto(<<"*">>)).

parse_ipproto_integer_test() ->
    ?assertEqual({ok, 17}, masque_uri_ip:parse_ipproto(<<"17">>)).

parse_ipproto_zero_test() ->
    ?assertEqual({ok, 0}, masque_uri_ip:parse_ipproto(<<"0">>)).

parse_ipproto_max_test() ->
    ?assertEqual({ok, 255}, masque_uri_ip:parse_ipproto(<<"255">>)).

parse_ipproto_out_of_range_test() ->
    ?assertEqual(
        {error, bad_ipproto},
        masque_uri_ip:parse_ipproto(<<"256">>)
    ).

parse_ipproto_not_int_test() ->
    ?assertEqual(
        {error, bad_ipproto},
        masque_uri_ip:parse_ipproto(<<"abc">>)
    ).

%%====================================================================
%% Expand + match round-trips (path form)
%%====================================================================

expand_wildcard_path_test() ->
    {ok, T} = masque_uri_ip:parse_client_template(?ABS_PATH_TPL),
    ?assertEqual(
        <<"https://proxy.example:4443/.well-known/masque/ip/*/*/">>,
        masque_uri_ip:expand(T, #{target => '*', ipproto => '*'})
    ).

expand_v4_literal_path_test() ->
    {ok, T} = masque_uri_ip:parse_client_template(?ABS_PATH_TPL),
    ?assertEqual(
        <<"https://proxy.example:4443/.well-known/masque/ip/192.0.2.1/17/">>,
        masque_uri_ip:expand(
            T,
            #{target => {192, 0, 2, 1}, ipproto => 17}
        )
    ).

expand_v4_prefix_escapes_slash_test() ->
    {ok, T} = masque_uri_ip:parse_client_template(?ABS_PATH_TPL),
    ?assertEqual(
        <<"https://proxy.example:4443/.well-known/masque/ip/10.0.0.0%2F24/0/">>,
        masque_uri_ip:expand(
            T,
            #{target => {4, {10, 0, 0, 0}, 24}, ipproto => 0}
        )
    ).

expand_v6_literal_escapes_colons_test() ->
    {ok, T} = masque_uri_ip:parse_client_template(?ABS_PATH_TPL),
    ?assertEqual(
        <<"https://proxy.example:4443/.well-known/masque/ip/2001%3Adb8%3A%3A1/17/">>,
        masque_uri_ip:expand(
            T,
            #{target => {16#2001, 16#DB8, 0, 0, 0, 0, 0, 1}, ipproto => 17}
        )
    ).

match_wildcard_test() ->
    {ok, T} = masque_uri_ip:parse_server_template(?SERVER_PATH_TPL),
    ?assertEqual(
        {ok, #{target => '*', ipproto => '*'}},
        masque_uri_ip:match(
            T,
            <<"/.well-known/masque/ip/*/*/">>
        )
    ).

match_v4_literal_test() ->
    {ok, T} = masque_uri_ip:parse_server_template(?SERVER_PATH_TPL),
    ?assertEqual(
        {ok, #{target => {192, 0, 2, 1}, ipproto => 17}},
        masque_uri_ip:match(
            T,
            <<"/.well-known/masque/ip/192.0.2.1/17/">>
        )
    ).

match_v4_prefix_pct_decoded_test() ->
    {ok, T} = masque_uri_ip:parse_server_template(?SERVER_PATH_TPL),
    ?assertEqual(
        {ok, #{target => {4, {10, 0, 0, 0}, 24}, ipproto => 0}},
        masque_uri_ip:match(
            T,
            <<"/.well-known/masque/ip/10.0.0.0%2F24/0/">>
        )
    ).

match_v6_literal_pct_decoded_test() ->
    {ok, T} = masque_uri_ip:parse_server_template(?SERVER_PATH_TPL),
    ?assertEqual(
        {ok, #{target => {16#2001, 16#DB8, 0, 0, 0, 0, 0, 1}, ipproto => 17}},
        masque_uri_ip:match(
            T,
            <<"/.well-known/masque/ip/2001%3Adb8%3A%3A1/17/">>
        )
    ).

match_wrong_prefix_test() ->
    {ok, T} = masque_uri_ip:parse_server_template(?SERVER_PATH_TPL),
    ?assertEqual(
        {error, no_match},
        masque_uri_ip:match(T, <<"/wrong/prefix/192.0.2.1/17/">>)
    ).

match_bad_ipproto_test() ->
    {ok, T} = masque_uri_ip:parse_server_template(?SERVER_PATH_TPL),
    ?assertEqual(
        {error, bad_ipproto},
        masque_uri_ip:match(
            T,
            <<"/.well-known/masque/ip/192.0.2.1/999/">>
        )
    ).

%%====================================================================
%% Expand + match round-trips (query form)
%%====================================================================

expand_query_form_test() ->
    {ok, T} = masque_uri_ip:parse_client_template(?ABS_QUERY_TPL),
    ?assertEqual(
        <<"https://proxy.example:4443/masque?target=*&ipproto=*">>,
        masque_uri_ip:expand(T, #{target => '*', ipproto => '*'})
    ).

match_query_form_test() ->
    {ok, T} = masque_uri_ip:parse_server_template(
        <<"/masque{?target,ipproto}">>
    ),
    ?assertEqual(
        {ok, #{target => {192, 0, 2, 1}, ipproto => 6}},
        masque_uri_ip:match(
            T,
            <<"/masque?target=192.0.2.1&ipproto=6">>
        )
    ).

match_query_form_missing_var_test() ->
    {ok, T} = masque_uri_ip:parse_server_template(
        <<"/masque{?target,ipproto}">>
    ),
    ?assertEqual(
        {error, no_match},
        masque_uri_ip:match(T, <<"/masque?target=192.0.2.1">>)
    ).

%% RFC 9484 §3: target and ipproto are optional template variables.
%% Omitting them yields a wildcard scope.

match_template_omits_target_and_ipproto_test() ->
    {ok, T} = masque_uri_ip:parse_server_template(<<"/masque">>),
    ?assertEqual(
        {ok, #{target => '*', ipproto => '*'}},
        masque_uri_ip:match(T, <<"/masque">>)
    ).

match_template_omits_ipproto_only_test() ->
    {ok, T} = masque_uri_ip:parse_server_template(
        <<"/masque/{target}/">>
    ),
    ?assertEqual(
        {ok, #{target => {192, 0, 2, 1}, ipproto => '*'}},
        masque_uri_ip:match(T, <<"/masque/192.0.2.1/">>)
    ).

match_template_omits_target_only_test() ->
    {ok, T} = masque_uri_ip:parse_server_template(
        <<"/masque/{ipproto}/">>
    ),
    ?assertEqual(
        {ok, #{target => '*', ipproto => 17}},
        masque_uri_ip:match(T, <<"/masque/17/">>)
    ).

%% RFC 6570 Level 3+ operators are not in MASQUE's profile.
template_rejects_reserved_operator_test() ->
    ?assertEqual(
        {error, bad_template},
        masque_uri_ip:parse_server_template(
            <<"/masque/{+target}/{ipproto}/">>
        )
    ).

template_rejects_fragment_operator_test() ->
    ?assertEqual(
        {error, bad_template},
        masque_uri_ip:parse_server_template(
            <<"/masque/{#target}/{ipproto}/">>
        )
    ).

template_rejects_explode_modifier_test() ->
    ?assertEqual(
        {error, bad_template},
        masque_uri_ip:parse_server_template(
            <<"/masque/{target*}/{ipproto}/">>
        )
    ).

template_rejects_prefix_modifier_test() ->
    ?assertEqual(
        {error, bad_template},
        masque_uri_ip:parse_server_template(
            <<"/masque/{target:4}/{ipproto}/">>
        )
    ).

template_rejects_non_ascii_test() ->
    ?assertEqual(
        {error, bad_template},
        masque_uri_ip:parse_server_template(
            <<"/masque/{target}/", 16#C3, 16#A9, "/{ipproto}/">>
        )
    ).

%% Regression: untrusted query keys must not enter the atom table.
match_query_form_unknown_keys_no_atoms_test() ->
    {ok, T} = masque_uri_ip:parse_server_template(
        <<"/masque{?target,ipproto}">>
    ),
    Before = erlang:system_info(atom_count),
    Path = build_query_path(2000),
    %% Required keys are absent so this must fail to match, but parsing
    %% the unknown keys must not allocate atoms.
    ?assertEqual({error, no_match}, masque_uri_ip:match(T, Path)),
    After = erlang:system_info(atom_count),
    ?assert(After - Before < 50).

build_query_path(N) ->
    Pairs = [
        iolist_to_binary(["k", integer_to_binary(I), "=v"])
     || I <- lists:seq(1, N)
    ],
    iolist_to_binary([
        <<"/masque?">>,
        lists:join(<<"&">>, Pairs)
    ]).

%%====================================================================
%% Strict template, target and ipproto parsing
%%====================================================================

template_rejects_unknown_variable_test() ->
    ?assertEqual(
        {error, bad_template},
        masque_uri_ip:parse_server_template(<<"/masque/{target_host}/{ipproto}/">>)
    ).

parse_target_rejects_zone_id_test() ->
    ?assertEqual({error, bad_target}, masque_uri_ip:parse_target(<<"fe80::1%eth0">>)).

parse_target_rejects_non_dotted_quad_test() ->
    [
        ?assertEqual({error, bad_target}, masque_uri_ip:parse_target(T))
     || T <- [<<"1">>, <<"127.1">>, <<"0x7f.0.0.1">>, <<"010.0.0.1">>, <<"127.1/8">>]
    ].

parse_ipproto_strict_digits_test() ->
    [
        ?assertEqual({error, bad_ipproto}, masque_uri_ip:parse_ipproto(P))
     || P <- [<<"06">>, <<"+6">>, <<"-0">>, <<" 6">>, <<"256">>]
    ],
    ?assertEqual({ok, 0}, masque_uri_ip:parse_ipproto(<<"0">>)),
    ?assertEqual({ok, 17}, masque_uri_ip:parse_ipproto(<<"17">>)).
