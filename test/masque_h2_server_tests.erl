%%% @doc Unit tests for the HTTP/2 Extended CONNECT validator.
%%%
%%% h2 0.10.2 delivers `:authority' and `:scheme' to the handler. The
%%% validator reads both from the request headers; it no longer falls
%%% back to the `host' header or a hard-coded `https' scheme, and it
%%% rejects a request that is missing either pseudo-header.
-module(masque_h2_server_tests).

-include_lib("eunit/include/eunit.hrl").
-include("masque.hrl").
-include("masque_ip.hrl").

-define(UDP_TPL, ?MASQUE_DEFAULT_URI_TEMPLATE).
-define(TCP_TPL, ?MASQUE_DEFAULT_TCP_URI_TEMPLATE).
-define(IP_TPL, ?MASQUE_DEFAULT_IP_URI_PATH_PATTERN).

-define(UDP_PATH, <<"/.well-known/masque/udp/192.0.2.6/443/">>).
-define(IP_PATH, <<"/.well-known/masque/ip/192.0.2.1/17/">>).

validate(Headers) ->
    masque_h2_server:validate(
        <<"CONNECT">>,
        ?UDP_PATH,
        Headers,
        ?UDP_TPL,
        ?TCP_TPL,
        ?IP_TPL,
        false
    ).

%%====================================================================
%% CONNECT-UDP: pseudo-headers are read straight from the headers
%%====================================================================

udp_reads_authority_and_scheme_test() ->
    Headers = [
        {<<":protocol">>, ?MASQUE_CONNECT_UDP_PROTOCOL},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"proxy.example:443">>}
    ],
    {ok, Req} = validate(Headers),
    ?assertEqual(<<"proxy.example:443">>, maps:get(authority, Req)),
    ?assertEqual(<<"https">>, maps:get(scheme, Req)),
    ?assertEqual(udp, maps:get(protocol, Req)).

%% The scheme is taken from the header, not hard-coded to `https'.
udp_scheme_follows_header_test() ->
    Headers = [
        {<<":protocol">>, ?MASQUE_CONNECT_UDP_PROTOCOL},
        {<<":scheme">>, <<"http">>},
        {<<":authority">>, <<"proxy.example:443">>}
    ],
    {ok, Req} = validate(Headers),
    ?assertEqual(<<"http">>, maps:get(scheme, Req)).

%% The `host' header is no longer a fallback for a missing `:authority'.
udp_no_host_fallback_test() ->
    Headers = [
        {<<":protocol">>, ?MASQUE_CONNECT_UDP_PROTOCOL},
        {<<":scheme">>, <<"https">>},
        {<<"host">>, <<"proxy.example:443">>}
    ],
    ?assertEqual({error, bad_path}, validate(Headers)).

udp_missing_scheme_rejected_test() ->
    Headers = [
        {<<":protocol">>, ?MASQUE_CONNECT_UDP_PROTOCOL},
        {<<":authority">>, <<"proxy.example:443">>}
    ],
    ?assertEqual({error, bad_path}, validate(Headers)).

udp_missing_authority_rejected_test() ->
    Headers = [
        {<<":protocol">>, ?MASQUE_CONNECT_UDP_PROTOCOL},
        {<<":scheme">>, <<"https">>}
    ],
    ?assertEqual({error, bad_path}, validate(Headers)).

%%====================================================================
%% CONNECT-IP: same rules on the IP matcher
%%====================================================================

ip_reads_authority_and_scheme_test() ->
    Headers = [
        {<<":protocol">>, ?MASQUE_CONNECT_IP_PROTOCOL},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"proxy.example:443">>}
    ],
    {ok, Req} = masque_h2_server:validate(
        <<"CONNECT">>,
        ?IP_PATH,
        Headers,
        ?UDP_TPL,
        ?TCP_TPL,
        ?IP_TPL,
        false
    ),
    ?assertEqual(<<"proxy.example:443">>, maps:get(authority, Req)),
    ?assertEqual(<<"https">>, maps:get(scheme, Req)),
    ?assertEqual(ip, maps:get(protocol, Req)).

ip_no_host_fallback_test() ->
    Headers = [
        {<<":protocol">>, ?MASQUE_CONNECT_IP_PROTOCOL},
        {<<":scheme">>, <<"https">>},
        {<<"host">>, <<"proxy.example:443">>}
    ],
    ?assertEqual(
        {error, bad_path},
        masque_h2_server:validate(
            <<"CONNECT">>,
            ?IP_PATH,
            Headers,
            ?UDP_TPL,
            ?TCP_TPL,
            ?IP_TPL,
            false
        )
    ).

%%====================================================================
%% CONNECT-UDP with Connect-UDP-Bind: same strict pseudo-header rules
%%====================================================================

udp_bind_reads_authority_and_scheme_test() ->
    Headers = [
        {<<":protocol">>, ?MASQUE_CONNECT_UDP_PROTOCOL},
        {<<"connect-udp-bind">>, <<"?1">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"proxy.example:443">>}
    ],
    {ok, Req} = masque_h2_server:validate(
        <<"CONNECT">>,
        <<"/.well-known/masque/udp/*/*/">>,
        Headers,
        ?UDP_TPL,
        ?TCP_TPL,
        ?IP_TPL,
        true
    ),
    ?assertEqual(<<"proxy.example:443">>, maps:get(authority, Req)),
    ?assertEqual(<<"https">>, maps:get(scheme, Req)),
    ?assertEqual(udp_bind, maps:get(protocol, Req)).

udp_bind_no_host_fallback_test() ->
    Headers = [
        {<<":protocol">>, ?MASQUE_CONNECT_UDP_PROTOCOL},
        {<<"connect-udp-bind">>, <<"?1">>},
        {<<":scheme">>, <<"https">>},
        {<<"host">>, <<"proxy.example:443">>}
    ],
    ?assertEqual(
        {error, bad_path},
        masque_h2_server:validate(
            <<"CONNECT">>,
            <<"/.well-known/masque/udp/*/*/">>,
            Headers,
            ?UDP_TPL,
            ?TCP_TPL,
            ?IP_TPL,
            true
        )
    ).
