%%% @doc Compliance tests for Connect-UDP-Bind
%%% (draft-ietf-masque-connect-udp-listen-11). End-to-end coverage
%%% over h3: a real listener with `accept_bind => true', a real
%%% `masque:bind_connect/3' client, an echo upstream peer.
-module(masque_udp_bind_compliance_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([suite/0, all/0,
         init_per_suite/1, end_per_suite/1,
         init_per_testcase/2, end_per_testcase/2]).

-export([handshake_unscoped_completes/1,
         handshake_response_carries_required_headers/1,
         bind_disabled_rejects/1]).

suite() -> [{timetrap, {seconds, 30}}].

all() ->
    [handshake_unscoped_completes,
     handshake_response_carries_required_headers,
     bind_disabled_rejects].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    {ok, _} = application:ensure_all_started(masque),
    case masque_test_helpers:generate_certs() of
        {ok, Certs} -> [{certs, Certs} | Config];
        {error, R}  -> {skip, {cert_generation_failed, R}}
    end.

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(certs, Config)),
    ok.

init_per_testcase(bind_disabled_rejects, Config) ->
    Certs = ?config(certs, Config),
    %% accept_bind defaults to false; a bind handshake should fail.
    ServerCtx = maps:merge(Certs, #{handler => masque_echo_handler}),
    {ok, Server} = masque_test_helpers:start_masque_server(ServerCtx),
    [{server, Server} | Config];
init_per_testcase(_Case, Config) ->
    Certs = ?config(certs, Config),
    %% bind_address goes into handler_opts so the bind handler picks
    %% it up; the listener-level keys are bind_handler / accept_bind.
    ServerCtx = maps:merge(Certs, #{
        handler      => masque_echo_handler,
        accept_bind  => true,
        handler_opts => #{bind_address => {127,0,0,1},
                          allow_loopback => true}
    }),
    {ok, Server} = masque_test_helpers:start_masque_server(ServerCtx),
    [{server, Server} | Config].

end_per_testcase(_Case, Config) ->
    case ?config(server, Config) of
        undefined -> ok;
        Server    -> masque_test_helpers:stop_masque_server(Server)
    end,
    ok.

%%====================================================================
%% Cases
%%====================================================================

handshake_unscoped_completes(Config) ->
    Server = ?config(server, Config),
    Url = server_url(Server),
    case masque:bind_connect(Url, unscoped,
                              #{transports => [h3],
                                verify => verify_none,
                                timeout => 5000}) of
        {ok, Sess} ->
            ?assert(is_pid(Sess)),
            ok = masque:close(Sess);
        {error, Reason} ->
            ct:fail({bind_handshake_failed, Reason})
    end.

handshake_response_carries_required_headers(Config) ->
    Server = ?config(server, Config),
    Url = server_url(Server),
    {ok, Sess} = masque:bind_connect(Url, unscoped,
                                      #{transports => [h3],
                                        verify => verify_none,
                                        timeout => 5000}),
    {ok, Addrs} = masque:proxy_public_address(Sess),
    ?assertNotEqual([], Addrs),
    [{Addr, _Port} | _] = Addrs,
    %% The default handler binds to 127.0.0.1 in our setup.
    ?assertEqual({127,0,0,1}, Addr),
    ok = masque:close(Sess).

bind_disabled_rejects(Config) ->
    Server = ?config(server, Config),
    Url = server_url(Server),
    %% accept_bind => false: the listener treats Connect-UDP-Bind: ?1
    %% as absent and the URI matcher rejects `*' as a host.
    Result = masque:bind_connect(Url, unscoped,
                                  #{transports => [h3],
                                    verify => verify_none,
                                    timeout => 5000}),
    ?assertMatch({error, _}, Result).

server_url(#{port := Port}) ->
    iolist_to_binary(io_lib:format("https://127.0.0.1:~p", [Port])).
