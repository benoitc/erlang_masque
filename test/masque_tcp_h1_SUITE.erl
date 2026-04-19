%%% @doc End-to-end tests for classic CONNECT-TCP over HTTP/1.1
%%% (RFC 9110 §9.3.6).
%%%
%%% Drives `masque:connect/3' with `transports => [h1]' and
%%% `protocol => tcp' against `masque:start_listener_h1/2'. A toy TCP
%%% echo server stands in for the tunnel target; the handler under
%%% test is the production `masque_tcp_proxy_handler', keeping the
%%% coverage path identical to the h2 / h3 CONNECT-TCP flow on the
%%% server side.
-module(masque_tcp_h1_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1,
         init_per_testcase/2, end_per_testcase/2]).

-export([echo_bytes/1,
         ipv6_authority/1,
         allow_denies/1,
         allow_private_false_rejects_loopback/1,
         proxy_authorization_header_roundtrip/1,
         non_2xx_surfaces_on_client/1,
         target_fin_closes_tunnel/1]).

all() ->
    [echo_bytes,
     ipv6_authority,
     allow_denies,
     allow_private_false_rejects_loopback,
     proxy_authorization_header_roundtrip,
     non_2xx_surfaces_on_client,
     target_fin_closes_tunnel].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Ctx} = masque_test_helpers:generate_certs(),
    [{ctx, Ctx} | Config].

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(ctx, Config)),
    ok.

init_per_testcase(Case, Config) ->
    Ctx = ?config(ctx, Config),
    {EchoPid, EchoPort, EchoAcceptor} =
        start_echo_server(Case),
    Listener = list_to_atom(
                 "tcp_h1_" ++ atom_to_list(Case) ++ "_" ++
                 integer_to_list(erlang:unique_integer([positive]))),
    Opts = listener_opts(Case, Ctx, EchoPort),
    Parent = self(),
    Keeper = erlang:spawn(fun() -> keeper_loop(Parent, Listener, Opts) end),
    Port = receive
        {Keeper, started, P} -> P
    after 5000 ->
        ct:fail(keeper_start_timeout)
    end,
    [{listener, Listener}, {port, Port}, {keeper, Keeper},
     {echo_pid, EchoPid}, {echo_port, EchoPort},
     {echo_acceptor, EchoAcceptor} | Config].

end_per_testcase(_Case, Config) ->
    ?config(keeper, Config) ! stop,
    case ?config(echo_pid, Config) of
        Pid when is_pid(Pid) -> exit(Pid, shutdown);
        _ -> ok
    end,
    ok.

%%====================================================================
%% Listener / echo setup
%%====================================================================

keeper_loop(Parent, Name, Opts) ->
    case masque:start_listener_h1(Name, Opts) of
        {ok, Ref} ->
            Parent ! {self(), started, h1:server_port(Ref)},
            keeper_wait(Name);
        {error, Reason} ->
            Parent ! {self(), start_failed, Reason}
    end.

keeper_wait(Name) ->
    receive
        stop -> _ = masque:stop_listener_h1(Name), ok;
        _    -> keeper_wait(Name)
    end.

listener_opts(allow_denies, Ctx, _EchoPort) ->
    (base_listener(Ctx))#{
        allow => fun(_) -> false end
    };
listener_opts(allow_private_false_rejects_loopback, Ctx, _EchoPort) ->
    (base_listener(Ctx))#{
        allow_private => false
    };
listener_opts(_Case, Ctx, _EchoPort) ->
    (base_listener(Ctx))#{
        allow_private => true
    }.

base_listener(Ctx) ->
    #{port => 0,
      cert => maps:get(cert_file, Ctx),
      key  => maps:get(key_file, Ctx)}.

%% Start a loopback TCP echo server. For `target_fin_closes_tunnel'
%% the server closes the socket after a single echo so the client
%% observes the tunnel teardown. For all other cases the server
%% echoes forever.
start_echo_server(target_fin_closes_tunnel) ->
    start_echo_server_impl(single_echo);
start_echo_server(_) ->
    start_echo_server_impl(forever).

start_echo_server_impl(Mode) ->
    Parent = self(),
    {Pid, _} = spawn_monitor(fun() ->
        {ok, LSock} = gen_tcp:listen(0, [binary, {active, false},
                                          {reuseaddr, true}]),
        {ok, Port} = inet:port(LSock),
        Parent ! {echo_ready, self(), Port},
        accept_loop(LSock, Mode)
    end),
    Port = receive
        {echo_ready, Pid, P} -> P
    after 2000 ->
        ct:fail(echo_start_timeout)
    end,
    {Pid, Port, Pid}.

accept_loop(LSock, Mode) ->
    case gen_tcp:accept(LSock, 5000) of
        {ok, Sock} ->
            _ = spawn(fun() -> echo_one(Sock, Mode) end),
            accept_loop(LSock, Mode);
        {error, timeout} ->
            accept_loop(LSock, Mode);
        {error, _} ->
            ok
    end.

echo_one(Sock, single_echo) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, Bin} ->
            _ = gen_tcp:send(Sock, Bin),
            _ = gen_tcp:close(Sock);
        _ ->
            _ = gen_tcp:close(Sock)
    end;
echo_one(Sock, forever) ->
    case gen_tcp:recv(Sock, 0, 60000) of
        {ok, Bin} ->
            _ = gen_tcp:send(Sock, Bin),
            echo_one(Sock, forever);
        _ ->
            _ = gen_tcp:close(Sock)
    end.

%%====================================================================
%% Cases
%%====================================================================

echo_bytes(Config) ->
    Port = ?config(port, Config),
    EchoPort = ?config(echo_port, Config),
    {ok, Sess} = do_connect(Port, {<<"127.0.0.1">>, EchoPort}, #{}),
    ok = masque:send(Sess, <<"hello">>),
    receive
        {masque_data, Sess, <<"hello">>} -> ok
    after 2000 -> ct:fail(no_echo)
    end,
    ok = masque:close(Sess).

ipv6_authority(Config) ->
    %% Spin up a fresh echo bound to `::1' so we can exercise IPv6
    %% authority on the wire. Skip gracefully if the runtime box has
    %% no IPv6 loopback.
    case gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true},
                             inet6, {ip, {0,0,0,0,0,0,0,1}}]) of
        {ok, LSock} ->
            {ok, V6Port} = inet:port(LSock),
            LSock1 = LSock,
            _ = spawn(fun() -> accept_loop(LSock1, forever) end),
            Port = ?config(port, Config),
            {ok, Sess} = do_connect(Port, {<<"::1">>, V6Port}, #{}),
            ok = masque:send(Sess, <<"ipv6">>),
            receive
                {masque_data, Sess, <<"ipv6">>} -> ok
            after 2000 -> ct:fail(no_ipv6_echo)
            end,
            ok = masque:close(Sess),
            _ = gen_tcp:close(LSock);
        {error, eafnosupport} ->
            {skip, "IPv6 loopback not available"};
        {error, Reason} ->
            {skip, io_lib:format("IPv6 listen failed: ~p", [Reason])}
    end.

allow_denies(Config) ->
    Port = ?config(port, Config),
    EchoPort = ?config(echo_port, Config),
    %% allow_listener rejects everything via allow/1 -> returns 403.
    ?assertMatch({error, {handshake_rejected, 403, _}},
                 do_connect(Port, {<<"127.0.0.1">>, EchoPort}, #{})).

allow_private_false_rejects_loopback(Config) ->
    Port = ?config(port, Config),
    EchoPort = ?config(echo_port, Config),
    %% With allow_private => false the proxy handler classifies
    %% 127.0.0.1 as non-public during resolve and 502-rejects.
    ?assertMatch({error, {handshake_rejected, Code, _}}
                   when Code =:= 502 orelse Code =:= 403,
                 do_connect(Port, {<<"127.0.0.1">>, EchoPort}, #{})).

proxy_authorization_header_roundtrip(Config) ->
    Port = ?config(port, Config),
    EchoPort = ?config(echo_port, Config),
    {ok, Sess} = do_connect(Port, {<<"127.0.0.1">>, EchoPort},
                             #{proxy_authorization =>
                                  <<"Basic dXNlcjpwYXNz">>}),
    %% The header is forwarded as-is on the CONNECT request; the
    %% tunnel still establishes (our proxy has no auth requirement,
    %% so a valid-looking header is simply ignored).
    ok = masque:send(Sess, <<"authed">>),
    receive {masque_data, Sess, <<"authed">>} -> ok
    after 2000 -> ct:fail(no_echo_after_auth)
    end,
    ok = masque:close(Sess).

non_2xx_surfaces_on_client(Config) ->
    Port = ?config(port, Config),
    %% Point at an impossible target; the proxy handler returns 502
    %% from accept/init resolution. The client should surface the
    %% status code rather than hang.
    case do_connect(Port, {<<"203.0.113.1">>, 7}, #{}) of
        {error, {handshake_rejected, Code, _}} when Code >= 400 ->
            ok;
        Other ->
            ct:fail({expected_non_2xx, Other})
    end.

target_fin_closes_tunnel(Config) ->
    Port = ?config(port, Config),
    EchoPort = ?config(echo_port, Config),
    {ok, Sess} = do_connect(Port, {<<"127.0.0.1">>, EchoPort}, #{}),
    MRef = erlang:monitor(process, Sess),
    ok = masque:send(Sess, <<"bye">>),
    %% target echoes once then closes; our client owner should see
    %% the bytes then a close notification.
    receive {masque_data, Sess, <<"bye">>} -> ok
    after 2000 -> ct:fail(no_echo_before_close)
    end,
    receive
        {masque_closed, Sess, _Reason} -> ok;
        {'DOWN', MRef, process, Sess, _} -> ok
    after 3000 ->
        ct:fail(tunnel_did_not_close_on_target_fin)
    end.

%%====================================================================
%% Internal
%%====================================================================

do_connect(Port, Target, Extra) ->
    ProxyURI = iolist_to_binary(
                 ["https://127.0.0.1:", integer_to_list(Port)]),
    Opts = maps:merge(
             #{transports => [h1],
               protocol   => tcp,
               timeout    => 5000,
               owner      => self(),
               verify     => verify_none,
               ssl_opts   => [{verify, verify_none}]},
             Extra),
    masque:connect(ProxyURI, Target, Opts).
