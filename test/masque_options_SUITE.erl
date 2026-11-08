%%% @doc Listener and client options passed through to QUIC and TLS:
%%% `quic_opts' on h3 listeners and clients, `ssl_opts' on h2 and h1
%%% listeners, and session tickets. Each case checks the option takes
%%% effect, not only that it is accepted.
-module(masque_options_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([suite/0, all/0, init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    h3_sni_callback_without_cert/1,
    h3_missing_cert_refused/1,
    h3_listener_quic_opts_override/1,
    h3_client_quic_opts_override/1,
    h3_more_streams_per_connection/1,
    h3_pool_learns_proxy_stream_limit/1,
    h3_session_ticket/1,
    h3_client_certificate/1,
    h3_client_without_certificate_refused/1,
    h3_pool_keeps_quic_opts_apart/1,
    h3_pool_restart_ends_its_owners/1,
    h3_pool_checkout_keeps_caller_timeout/1,
    h3_tcp_send_ready_after_full_queue/1,
    h2_sni_fun/1,
    h1_sni_fun/1,
    h1_handshake_timeout/1,
    h2_client_certificate/1,
    h2_client_without_certificate_refused/1
]).
-export([accept/1, init/2, handle_data/2, terminate/2]).

-define(TUNNELS, 150).

suite() -> [{timetrap, {minutes, 2}}].

all() ->
    [
        h3_sni_callback_without_cert,
        h3_missing_cert_refused,
        h3_listener_quic_opts_override,
        h3_client_quic_opts_override,
        h3_more_streams_per_connection,
        h3_pool_learns_proxy_stream_limit,
        h3_session_ticket,
        h3_client_certificate,
        h3_client_without_certificate_refused,
        h3_pool_keeps_quic_opts_apart,
        h3_pool_restart_ends_its_owners,
        h3_pool_checkout_keeps_caller_timeout,
        h3_tcp_send_ready_after_full_queue,
        h2_sni_fun,
        h1_sni_fun,
        h1_handshake_timeout,
        h2_client_certificate,
        h2_client_without_certificate_refused
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Certs} = masque_test_helpers:generate_certs(),
    {Echo, EchoPort} = start_tcp_echo(),
    [{certs, Certs}, {echo, Echo}, {echo_port, EchoPort} | Config].

end_per_suite(Config) ->
    exit(?config(echo, Config), kill),
    masque_test_helpers:cleanup_certs(?config(certs, Config)),
    ok.

init_per_testcase(_Case, Config) ->
    [{name, list_to_atom("opts_" ++ integer_to_list(erlang:unique_integer([positive])))} | Config].

end_per_testcase(Case, Config) ->
    Name = ?config(name, Config),
    _ =
        case atom_to_list(Case) of
            "h2_" ++ _ -> masque:stop_listener_h2(Name);
            "h1_" ++ _ -> masque:stop_listener_h1(Name);
            _ -> masque:stop_listener(Name)
        end,
    ok.

%%====================================================================
%% h3 listener
%%====================================================================

%% The certificate comes from the callback, for the name the client asked.
h3_sni_callback_without_cert(Config) ->
    #{cert := Cert, key := Key} = ?config(certs, Config),
    Self = self(),
    Sni = fun(Name) ->
        Self ! {sni, Name},
        {ok, #{cert => Cert, key => Key}}
    end,
    Port = start_h3(Config, #{quic_opts => #{sni_callback => Sni}}, without_cert),
    Sess = connect(<<"localhost">>, Port, Config, #{}),
    ok = echo(Sess),
    receive
        {sni, Name} -> ?assertEqual(<<"localhost">>, Name)
    after 1000 -> ct:fail(sni_callback_not_called)
    end,
    masque:close(Sess).

h3_missing_cert_refused(Config) ->
    ?assertEqual(
        {error, {missing_option, cert}},
        masque:start_listener(?config(name, Config), #{port => 0})
    ).

%% A short idle timeout with no keepalive on the listener closes a quiet
%% tunnel, which masque's own defaults would keep open.
h3_listener_quic_opts_override(Config) ->
    Port = start_h3(Config, #{
        quic_opts => #{idle_timeout => 1500, keep_alive_interval => disabled}
    }),
    Sess = connect(<<"127.0.0.1">>, Port, Config, #{quic_opts => #{keep_alive_interval => disabled}}),
    ok = echo(Sess),
    await_closed(Sess, 10000).

h3_client_quic_opts_override(Config) ->
    Port = start_h3(Config, #{quic_opts => #{keep_alive_interval => disabled}}),
    Sess = connect(<<"127.0.0.1">>, Port, Config, #{
        quic_opts => #{idle_timeout => 1500, keep_alive_interval => disabled}
    }),
    ok = echo(Sess),
    await_closed(Sess, 10000).

%% QUIC's default of 100 concurrent streams no longer caps a connection.
h3_more_streams_per_connection(Config) ->
    Port = start_h3(Config, #{
        max_tunnels_per_connection => 0,
        quic_opts => #{max_streams_bidi => 1000}
    }),
    Opts = #{
        protocol => tcp,
        upstream_pool => true,
        upstream_pool_opts => #{max_streams => 1000}
    },
    Sessions = [connect(<<"127.0.0.1">>, Port, Config, Opts) || _ <- lists:seq(1, ?TUNNELS)],
    [ok = echo(S) || S <- Sessions],
    ?assertEqual(1, length(server_connections())),
    [masque:close(S) || S <- Sessions],
    ok.

%% A proxy that allows fewer streams than the pool expects (10, not 100):
%% every tunnel still connects, the pool opening more connections.
h3_pool_learns_proxy_stream_limit(Config) ->
    Port = start_h3(Config, #{
        max_tunnels_per_connection => 0,
        quic_opts => #{max_streams_bidi => 10}
    }),
    Opts = #{protocol => tcp, upstream_pool => true},
    Sessions = [connect(<<"127.0.0.1">>, Port, Config, Opts) || _ <- lists:seq(1, 30)],
    [ok = echo(S) || S <- Sessions],
    ?assert(length(server_connections()) >= 3),
    [masque:close(S) || S <- Sessions],
    ok.

%% The client hands the ticket to its owner, and a new connection can
%% use it.
h3_session_ticket(Config) ->
    Port = start_h3(Config, #{}),
    Sess = connect(<<"localhost">>, Port, Config, #{}),
    ok = echo(Sess),
    Ticket =
        receive
            {masque_session_ticket, Sess, T} -> T
        after 5000 -> ct:fail(no_session_ticket)
        end,
    masque:close(Sess),
    Again = connect(<<"localhost">>, Port, Config, #{quic_opts => #{session_ticket => Ticket}}),
    ok = echo(Again),
    masque:close(Again).

%% Mutual TLS: the listener asks for a client certificate, and the
%% handler sees it as `peer_cert'.
h3_client_certificate(Config) ->
    #{cert := Cert, key := Key} = ?config(certs, Config),
    Port = start_h3(Config, #{
        tcp_handler => ?MODULE,
        handler_opts => #{report_to => self()},
        %% The proxy needs trust anchors to check the client's certificate;
        %% the test certificate is self-signed, so it is its own.
        quic_opts => #{require_client_cert => true, cacerts => [Cert]}
    }),
    Sess = connect(<<"127.0.0.1">>, Port, Config, #{
        quic_opts => #{cert => Cert, key => Key}
    }),
    receive
        {peer_cert, PeerCert} -> ?assertEqual(Cert, PeerCert)
    after 5000 -> ct:fail(no_peer_cert)
    end,
    masque:close(Sess).

%% A listener that requires client certificates refuses a client without
%% one, and the handler never runs.
h3_client_without_certificate_refused(Config) ->
    #{cert := Cert} = ?config(certs, Config),
    Port = start_h3(Config, #{
        tcp_handler => ?MODULE,
        handler_opts => #{report_to => self()},
        quic_opts => #{require_client_cert => true, cacerts => [Cert]}
    }),
    Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
    ?assertMatch(
        {error, _},
        masque:connect(Uri, {<<"127.0.0.1">>, ?config(echo_port, Config)}, #{
            protocol => tcp, transports => [h3], verify => verify_none, timeout => 5000
        })
    ),
    receive
        {peer_cert, _} -> ct:fail(handler_ran)
    after 0 -> ok
    end.

%% Connections with different QUIC options are never shared.
h3_pool_keeps_quic_opts_apart(Config) ->
    Port = start_h3(Config, #{}),
    Pooled = #{protocol => tcp, upstream_pool => true},
    A = connect(<<"127.0.0.1">>, Port, Config, Pooled),
    B = connect(<<"127.0.0.1">>, Port, Config, Pooled#{quic_opts => #{idle_timeout => 60000}}),
    ok = echo(A),
    ok = echo(B),
    ?assertEqual(2, length(server_connections())),
    masque:close(A),
    masque:close(B).

upstream_owners() ->
    [
        P
     || P <- processes(),
        {dictionary, D} <- [process_info(P, dictionary)],
        {_, {masque_upstream_owner, _, _}} <- [lists:keyfind('$initial_call', 1, D)]
    ].

%% A caller that joins a dial already in flight gives up after its own
%% timeout, not the pool's 60 s: here the "proxy" never answers.
h3_pool_checkout_keeps_caller_timeout(_Config) ->
    {ok, Silent} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Silent),
    Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
    Opts = #{protocol => tcp, upstream_pool => true, transports => [h3], verify => verify_none},
    Self = self(),
    _ = spawn(fun() ->
        Self ! {first, masque:connect(Uri, {<<"127.0.0.1">>, 9}, Opts#{timeout => 8000})}
    end),
    timer:sleep(200),
    T0 = erlang:monotonic_time(millisecond),
    ?assertMatch({error, _}, masque:connect(Uri, {<<"127.0.0.1">>, 9}, Opts#{timeout => 1000})),
    Elapsed = erlang:monotonic_time(millisecond) - T0,
    ct:pal("second caller gave up after ~p ms", [Elapsed]),
    ?assert(Elapsed < 3000),
    receive
        {first, _} -> ok
    after 15000 -> ct:fail(first_caller_stuck)
    end,
    gen_udp:close(Silent).

%% A CONNECT-TCP send refused because the h3 send queue is full is
%% followed by `masque_send_ready' once the queue drains, so the owner
%% knows when to send again instead of polling.
h3_tcp_send_ready_after_full_queue(Config) ->
    {ok, L} = gen_tcp:listen(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}, {recbuf, 4096}]),
    {ok, TPort} = inet:port(L),
    Target = spawn(fun() ->
        {ok, Sock} = gen_tcp:accept(L, 10000),
        receive
            go -> ok
        end,
        drain_tcp(Sock)
    end),
    ok = gen_tcp:controlling_process(L, Target),
    Port = start_h3(Config, #{}),
    Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
    {ok, Sess} = masque:connect(Uri, {<<"127.0.0.1">>, TPort}, #{
        protocol => tcp, transports => [h3], verify => verify_none, timeout => 5000
    }),
    Chunk = binary:copy(<<"q">>, 65536),
    ok = fill_until_full(Sess, Chunk, 4000),
    Target ! go,
    receive
        {masque_send_ready, Sess} -> ok
    after 10000 -> ct:fail(no_send_ready)
    end,
    ?assertEqual(ok, masque:send(Sess, <<"more">>)),
    masque:close(Sess),
    exit(Target, kill).

fill_until_full(_Sess, _Chunk, 0) ->
    ct:fail(send_queue_never_full);
fill_until_full(Sess, Chunk, N) ->
    case masque:send(Sess, Chunk) of
        ok -> fill_until_full(Sess, Chunk, N - 1);
        {error, send_queue_full} -> ok
    end.

drain_tcp(Sock) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, _} -> drain_tcp(Sock);
        {error, _} -> ok
    end.

%% A pool that dies and restarts no longer knows the connections it
%% opened: they end with it, and the tunnels on them are told.
h3_pool_restart_ends_its_owners(Config) ->
    Port = start_h3(Config, #{}),
    Earlier = upstream_owners(),
    Sess = connect(<<"127.0.0.1">>, Port, Config, #{protocol => tcp, upstream_pool => true}),
    ok = echo(Sess),
    %% Owners left by earlier cases are still on their idle timer.
    [Owner] = upstream_owners() -- Earlier,
    MRef = erlang:monitor(process, Owner),
    exit(whereis(masque_upstream_pool), kill),
    receive
        {'DOWN', MRef, process, Owner, _} -> ok
    after 5000 -> ct:fail(owner_outlived_pool)
    end,
    receive
        {masque_closed, Sess, _} -> ok
    after 5000 -> ct:fail(tunnel_not_told)
    end.

%%====================================================================
%% h2 and h1 listeners
%%====================================================================

h2_sni_fun(Config) -> sni_fun(Config, h2).
h1_sni_fun(Config) -> sni_fun(Config, h1).

sni_fun(Config, Transport) ->
    #{cert_file := Cert, key_file := Key} = ?config(certs, Config),
    Self = self(),
    Opts = #{
        port => 0,
        cert => Cert,
        key => Key,
        handler_opts => #{allow_private => true, allow_self => true},
        ssl_opts => [
            {sni_fun, fun(Name) ->
                Self ! {sni, Name},
                []
            end}
        ]
    },
    Port =
        case Transport of
            h2 ->
                {ok, {_, _, P}} = masque:start_listener_h2(?config(name, Config), Opts),
                P;
            h1 ->
                {ok, Ref} = masque:start_listener_h1(?config(name, Config), Opts),
                h1:server_port(Ref)
        end,
    Sess = connect(<<"localhost">>, Port, Config, #{transports => [Transport]}),
    ok = echo(Sess),
    receive
        {sni, Name} -> ?assertEqual("localhost", Name)
    after 1000 -> ct:fail(sni_fun_not_called)
    end,
    masque:close(Sess).

%%====================================================================
%% Handler reporting `peer_cert'
%%====================================================================

accept(#{peer_cert := Cert, handler_opts := #{report_to := Pid}}) ->
    Pid ! {peer_cert, Cert},
    accept;
accept(#{handler_opts := #{report_to := Pid}}) ->
    Pid ! {peer_cert, none},
    accept.

init(Req, Opts) -> masque_tcp_proxy_handler:init(Req, Opts).
handle_data(Data, State) -> masque_tcp_proxy_handler:handle_data(Data, State).
terminate(Reason, State) -> masque_tcp_proxy_handler:terminate(Reason, State).

%%====================================================================
%% Helpers
%%====================================================================

start_h3(Config, Extra) ->
    start_h3(Config, Extra, with_cert).

start_h3(Config, Extra, CertMode) ->
    #{cert := Cert, key := Key} = ?config(certs, Config),
    Base0 = #{port => 0, handler_opts => #{allow_private => true, allow_self => true}},
    Base =
        case CertMode of
            with_cert -> Base0#{cert => Cert, key => Key};
            without_cert -> Base0
        end,
    Opts = maps:merge(Base, Extra),
    Opts1 =
        case Extra of
            #{handler_opts := H} ->
                Opts#{handler_opts => maps:merge(maps:get(handler_opts, Base), H)};
            _ ->
                Opts
        end,
    {ok, _} = masque:start_listener(?config(name, Config), Opts1),
    {ok, Port} = quic:get_server_port(?config(name, Config)),
    Port.

connect(Host, Port, Config, Opts) ->
    Uri = iolist_to_binary(["https://", Host, ":", integer_to_list(Port)]),
    Defaults = #{protocol => tcp, transports => [h3], verify => verify_none, timeout => 5000},
    {ok, Sess} = masque:connect(
        Uri, {<<"127.0.0.1">>, ?config(echo_port, Config)}, maps:merge(Defaults, Opts)
    ),
    Sess.

echo(Sess) ->
    Msg = integer_to_binary(erlang:unique_integer([positive])),
    ok = masque:send(Sess, Msg),
    recv(Sess, Msg, <<>>).

recv(_Sess, Msg, Acc) when byte_size(Acc) >= byte_size(Msg) ->
    ?assertEqual(Msg, Acc),
    ok;
recv(Sess, Msg, Acc) ->
    receive
        {masque_data, Sess, Bin} -> recv(Sess, Msg, <<Acc/binary, Bin/binary>>);
        {masque_closed, Sess, Reason} -> ct:fail({closed, Reason})
    after 5000 -> ct:fail(no_echo)
    end.

await_closed(Sess, Ms) ->
    receive
        {masque_closed, Sess, Reason} -> ct:log("closed ~p", [Reason])
    after Ms -> ct:fail(quiet_tunnel_not_closed)
    end.

server_connections() ->
    lists:usort([
        element(2, sys:get_state(P))
     || P <- processes(),
        {dictionary, D} <- [process_info(P, dictionary)],
        {_, {masque_tcp_server_session, init, 1}} <- [lists:keyfind('$initial_call', 1, D)]
    ]).

start_tcp_echo() ->
    {ok, Listen} = gen_tcp:listen(0, [
        binary, {active, false}, {ip, {127, 0, 0, 1}}, {reuseaddr, true}, {backlog, 256}
    ]),
    {ok, Port} = inet:port(Listen),
    Pid = spawn(fun() -> accept_loop(Listen) end),
    ok = gen_tcp:controlling_process(Listen, Pid),
    {Pid, Port}.

accept_loop(Listen) ->
    {ok, Sock} = gen_tcp:accept(Listen),
    Pid = spawn(fun() ->
        receive
            go -> echo_loop(Sock)
        end
    end),
    _ = gen_tcp:controlling_process(Sock, Pid),
    Pid ! go,
    accept_loop(Listen).

echo_loop(Sock) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, Bin} ->
            _ = gen_tcp:send(Sock, Bin),
            echo_loop(Sock);
        {error, _} ->
            gen_tcp:close(Sock)
    end.

%% h1's own limits before the upgrade reach h1: a short handshake timeout
%% closes a client that never sends its TLS hello.
h1_handshake_timeout(Config) ->
    #{cert_file := Cert, key_file := Key} = ?config(certs, Config),
    {ok, Ref} = masque:start_listener_h1(?config(name, Config), #{
        port => 0, cert => Cert, key => Key, handshake_timeout => 300
    }),
    {ok, Sock} = gen_tcp:connect({127, 0, 0, 1}, h1:server_port(Ref), [binary, {active, false}]),
    ?assertEqual({error, closed}, gen_tcp:recv(Sock, 0, 3000)),
    gen_tcp:close(Sock).

%% h2 mutual TLS: the listener asks for client certificates through
%% `ssl_opts', and the handler sees the client's as `peer_cert'.
h2_client_certificate(Config) ->
    #{cert := ClientCert, cert_file := CF, key_file := KF, root := Chain} = client_cert(),
    Port = start_h2_mtls(Config, Chain),
    Sess = connect(<<"127.0.0.1">>, Port, Config, #{
        transports => [h2], ssl_opts => [{certfile, CF}, {keyfile, KF}]
    }),
    receive
        {peer_cert, PeerCert} -> ?assertEqual(ClientCert, PeerCert)
    after 5000 -> ct:fail(no_peer_cert)
    end,
    masque:close(Sess).

h2_client_without_certificate_refused(Config) ->
    #{root := Chain} = client_cert(),
    Port = start_h2_mtls(Config, Chain),
    Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
    ?assertMatch(
        {error, _},
        masque:connect(Uri, {<<"127.0.0.1">>, ?config(echo_port, Config)}, #{
            protocol => tcp, transports => [h2], verify => verify_none, timeout => 5000
        })
    ),
    receive
        {peer_cert, _} -> ct:fail(handler_ran)
    after 0 -> ok
    end.

start_h2_mtls(Config, ClientChain) ->
    #{cert_file := CertFile, key_file := KeyFile} = ?config(certs, Config),
    {ok, {_, _, Port}} = masque:start_listener_h2(?config(name, Config), #{
        port => 0,
        cert => CertFile,
        key => KeyFile,
        tcp_handler => ?MODULE,
        handler_opts => #{report_to => self(), allow_private => true, allow_self => true},
        ssl_opts => [{verify, verify_peer}, {cacerts, ClientChain}, {fail_if_no_peer_cert, true}]
    }),
    Port.

%% A client certificate for client auth, signed by a test CA the
%% listener trusts.
client_cert() ->
    Dir = filename:join(
        "/tmp", "masque_client_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    F = fun(Name) -> filename:join(Dir, Name) end,
    ok = file:write_file(
        F("ext.cnf"), <<"extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\n">>
    ),
    Run = fun(Fmt, Args) ->
        _ = os:cmd(lists:flatten(io_lib:format(Fmt, Args)) ++ " 2>/dev/null")
    end,
    Run(
        "openssl req -x509 -newkey rsa:2048 -nodes -keyout ~s -out ~s -days 1 -subj '/CN=test-ca'",
        [
            F("ca.key"), F("ca.pem")
        ]
    ),
    Run("openssl req -newkey rsa:2048 -nodes -keyout ~s -out ~s -subj '/CN=client'", [
        F("client.key"), F("client.csr")
    ]),
    Run(
        "openssl x509 -req -in ~s -CA ~s -CAkey ~s -CAcreateserial -out ~s -days 1 -extfile ~s",
        [F("client.csr"), F("ca.pem"), F("ca.key"), F("client.pem"), F("ext.cnf")]
    ),
    Der = fun(File) ->
        {ok, Pem} = file:read_file(File),
        [{'Certificate', D, _} | _] = public_key:pem_decode(Pem),
        D
    end,
    #{
        cert => Der(F("client.pem")),
        cert_file => F("client.pem"),
        key_file => F("client.key"),
        root => [Der(F("ca.pem"))]
    }.
