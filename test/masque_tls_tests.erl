%%% @doc Unit tests for `masque_tls:client_opts/2'.
%%%
%%% Covers the safe-by-default surface: verify_peer, cacerts, hostname
%%% check, ALPN, SNI (omitted for IP literals), and caller override
%%% precedence.
-module(masque_tls_tests).

-include_lib("eunit/include/eunit.hrl").

default_verify_is_peer_test() ->
    Opts = masque_tls:client_opts(<<"proxy.example">>, #{}),
    ?assertEqual(verify_peer, proplists:get_value(verify, Opts)).

default_includes_cacerts_test() ->
    Opts = masque_tls:client_opts(<<"proxy.example">>, #{}),
    %% public_key:cacerts_get/0 may legitimately return [] in some
    %% CI images; the key must be present regardless.
    ?assert(proplists:is_defined(cacerts, Opts)).

default_alpn_is_http1_1_test() ->
    Opts = masque_tls:client_opts(<<"proxy.example">>, #{}),
    ?assertEqual(
        [<<"http/1.1">>],
        proplists:get_value(alpn_advertised_protocols, Opts)
    ).

default_hostname_check_present_test() ->
    Opts = masque_tls:client_opts(<<"proxy.example">>, #{}),
    ?assert(proplists:is_defined(customize_hostname_check, Opts)).

sni_for_hostname_test() ->
    Opts = masque_tls:client_opts(<<"proxy.example">>, #{}),
    ?assertEqual(
        "proxy.example",
        proplists:get_value(server_name_indication, Opts)
    ).

sni_omitted_for_ipv4_literal_test() ->
    Opts = masque_tls:client_opts(<<"127.0.0.1">>, #{}),
    ?assertEqual(
        undefined,
        proplists:get_value(server_name_indication, Opts)
    ).

sni_omitted_for_ipv6_literal_test() ->
    Opts = masque_tls:client_opts(<<"::1">>, #{}),
    ?assertEqual(
        undefined,
        proplists:get_value(server_name_indication, Opts)
    ).

caller_verify_none_wins_test() ->
    Opts = masque_tls:client_opts(
        <<"proxy.example">>,
        #{verify => verify_none}
    ),
    ?assertEqual(verify_none, proplists:get_value(verify, Opts)).

caller_ssl_opts_override_test() ->
    Opts = masque_tls:client_opts(
        <<"proxy.example">>,
        #{
            ssl_opts => [
                {verify, verify_none},
                {cacerts, []}
            ]
        }
    ),
    ?assertEqual(verify_none, proplists:get_value(verify, Opts)),
    ?assertEqual([], proplists:get_value(cacerts, Opts)).

accepts_list_host_test() ->
    %% `h1_client:connect/3' accepts either a binary or a string.
    Opts = masque_tls:client_opts("proxy.example", #{}),
    ?assertEqual(
        "proxy.example",
        proplists:get_value(server_name_indication, Opts)
    ).
