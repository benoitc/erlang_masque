%%% @doc Unit tests for `masque:connect/3' input validation at the
%%% facade boundary. Focuses on opts that can inject / corrupt the
%%% wire if accepted verbatim.
-module(masque_facade_tests).

-include_lib("eunit/include/eunit.hrl").

proxy_authorization_with_cr_rejected_test() ->
    ?assertEqual(
        {error, {invalid_opts, proxy_authorization_contains_crlf}},
        masque:connect(
            <<"https://127.0.0.1:1">>,
            {<<"host">>, 80},
            #{
                protocol => tcp,
                proxy_authorization =>
                    <<"Basic abc\r\nInjected: y">>
            }
        )
    ).

proxy_authorization_with_lf_rejected_test() ->
    ?assertEqual(
        {error, {invalid_opts, proxy_authorization_contains_crlf}},
        masque:connect(
            <<"https://127.0.0.1:1">>,
            {<<"host">>, 80},
            #{
                protocol => tcp,
                proxy_authorization => <<"Basic abc\nX: 1">>
            }
        )
    ).

proxy_authorization_non_binary_rejected_test() ->
    ?assertEqual(
        {error, {invalid_opts, proxy_authorization_must_be_binary}},
        masque:connect(
            <<"https://127.0.0.1:1">>,
            {<<"host">>, 80},
            #{
                protocol => tcp,
                proxy_authorization => "not-a-binary"
            }
        )
    ).

proxy_authorization_clean_value_passes_validation_test() ->
    %% The clean value passes validation. Connect fails later on the
    %% actual TCP/TLS dial because 127.0.0.1:1 has nothing listening;
    %% we only care that the rejection did NOT come from validation.
    Result = masque:connect(
        <<"https://127.0.0.1:1">>,
        {<<"host">>, 80},
        #{
            protocol => tcp,
            transports => [h1],
            timeout => 200,
            proxy_authorization =>
                <<"Basic dXNlcjpwYXNz">>
        }
    ),
    ?assertMatch({error, _}, Result),
    {error, Reason} = Result,
    ?assertNotMatch({invalid_opts, _}, Reason).

unknown_transport_returns_error_test() ->
    ?assertEqual(
        {error, {invalid_opts, {transports, [foo]}}},
        masque:connect(<<"https://127.0.0.1:1">>, {<<"host">>, 80}, #{transports => [foo]})
    ),
    ?assertEqual(
        {error, {invalid_opts, {transports, h3}}},
        masque:connect(<<"https://127.0.0.1:1">>, {<<"host">>, 80}, #{transports => h3})
    ),
    ?assertEqual(
        {error, {invalid_opts, {transports, [h3, bar]}}},
        masque:bind_connect(<<"https://127.0.0.1:1">>, unscoped, #{transports => [h3, bar]})
    ).
