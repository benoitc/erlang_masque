%%% @doc Session lifecycle tests: server and client sessions end when
%%% the underlying connection or stream goes away.
%%%
%%% Server-side session pids are captured through
%%% `masque_report_handler', whose `init/2' reports `self()' to the
%%% test process.
-module(masque_lifecycle_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    suite/0,
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([
    h3_client_close_stops_server_session/1,
    h2_client_close_stops_server_session/1,
    h3_server_close_notifies_client/1,
    h2_server_close_notifies_client/1,
    h3_goaway_keeps_processed_tunnel/1
]).

-define(TPL, <<"/.well-known/masque/udp/{target_host}/{target_port}/">>).

%%====================================================================
%% CT callbacks
%%====================================================================

suite() -> [{timetrap, {seconds, 30}}].

all() ->
    [
        h3_client_close_stops_server_session,
        h2_client_close_stops_server_session,
        h3_server_close_notifies_client,
        h2_server_close_notifies_client,
        h3_goaway_keeps_processed_tunnel
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    {ok, _} = application:ensure_all_started(masque),
    case masque_test_helpers:generate_certs() of
        {ok, Certs} -> [{certs, Certs} | Config];
        {error, R} -> {skip, {cert_generation_failed, R}}
    end.

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(certs, Config)).

init_per_testcase(Case, Config) ->
    Certs = ?config(certs, Config),
    Extra = extra_opts(Case),
    HOpts = maps:merge(
        #{report_to => self()},
        maps:get(handler_opts, Extra, #{})
    ),
    Opts = maps:merge(
        #{handler => masque_report_handler},
        Extra#{handler_opts => HOpts}
    ),
    {ok, H3} = masque_test_helpers:start_masque_server(maps:merge(Certs, Opts)),
    {ok, H2} = start_h2_server(Certs, Opts),
    [{h3, H3}, {h2, H2} | Config].

end_per_testcase(_Case, Config) ->
    _ =
        (try
            masque_test_helpers:stop_masque_server(?config(h3, Config))
        catch
            _:_ -> ok
        end),
    _ =
        (try
            h2:stop_server(maps:get(h2_ref, ?config(h2, Config)))
        catch
            _:_ -> ok
        end),
    ok.

extra_opts(_Case) ->
    #{}.

%%====================================================================
%% Connection close
%%====================================================================

h3_client_close_stops_server_session(Config) ->
    {Conn, _Sid} = h3_open_udp(Config),
    Pid = await_session(),
    MRef = erlang:monitor(process, Pid),
    ok = quic_h3:close(Conn),
    await_down(MRef, Pid).

h2_client_close_stops_server_session(Config) ->
    Baseline = session_count(masque_h2_session_sup),
    {Conn, _Sid} = h2_open_udp(Config),
    Pid = await_session(),
    ?assertEqual(Baseline + 1, session_count(masque_h2_session_sup)),
    MRef = erlang:monitor(process, Pid),
    ok = h2:close(Conn),
    await_down(MRef, Pid),
    ok = wait_count(masque_h2_session_sup, Baseline, 50).

h3_server_close_notifies_client(Config) ->
    Sess = connect(Config, h3),
    Pid = await_session(),
    ServerConn = element(2, sys:get_state(Pid)),
    _ = quic_h3:close(ServerConn),
    await_closed(Sess).

h2_server_close_notifies_client(Config) ->
    Sess = connect(Config, h2),
    Pid = await_session(),
    ServerConn = element(2, sys:get_state(Pid)),
    _ = h2:close(ServerConn),
    await_closed(Sess).

%% A GOAWAY whose id is above the tunnel's stream leaves it running;
%% one that covers the stream ends it with `goaway'. The events are
%% injected: quic_h3 2.0.0 leaves calls such as `send_datagram'
%% unanswered once it has received a real GOAWAY.
h3_goaway_keeps_processed_tunnel(Config) ->
    Sess = connect(Config, h3),
    _ = await_session(),
    Sess ! {quic_h3, self(), {goaway, 1 bsl 40}},
    ok = masque:send(Sess, <<"still here">>),
    receive
        {masque_data, Sess, <<"still here">>} -> ok
    after 5000 -> ct:fail(no_echo_after_goaway)
    end,
    Sess ! {quic_h3, self(), {goaway, 0}},
    receive
        {masque_closed, Sess, goaway} -> ok
    after 5000 -> ct:fail(no_goaway_close)
    end.

%%====================================================================
%% Helpers
%%====================================================================

start_h2_server(#{cert_file := CertFile, key_file := KeyFile}, Opts) ->
    Name = list_to_atom(
        "h2_lifecycle_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),
    {ok, {_, _, Port} = Ref} = masque_h2_server:start_listener(
        Name,
        Opts#{port => 0, cert => CertFile, key => KeyFile}
    ),
    {ok, #{name => Name, port => Port, h2_ref => Ref}}.

connect(Config, Transport) ->
    Server =
        case Transport of
            h3 -> ?config(h3, Config);
            h2 -> ?config(h2, Config)
        end,
    ProxyURI = iolist_to_binary(
        ["https://localhost:", integer_to_list(maps:get(port, Server))]
    ),
    {ok, Sess} = masque:connect(
        ProxyURI,
        {<<"192.0.2.6">>, 443},
        #{verify => verify_none, transports => [Transport]}
    ),
    Sess.

h3_open_udp(Config) ->
    {ok, Conn} = masque_test_helpers:h3_client_connect(
        maps:get(port, ?config(h3, Config)), #{}
    ),
    {ok, Sid} = quic_h3:request(Conn, udp_headers(), #{end_stream => false}),
    {ok, 200, _} = masque_test_helpers:h3_await_response(Sid, 5000),
    {Conn, Sid}.

h2_open_udp(Config) ->
    {ok, Conn} = h2:connect(
        "localhost",
        maps:get(port, ?config(h2, Config)),
        #{transport => ssl, verify => verify_none, sync => true}
    ),
    {ok, Sid} = h2:request(Conn, udp_headers(), #{protocol => <<"connect-udp">>}),
    receive
        {h2, Conn, {response, Sid, 200, _}} -> ok
    after 5000 -> ct:fail(no_h2_response)
    end,
    {Conn, Sid}.

udp_headers() ->
    [
        {<<":method">>, <<"CONNECT">>},
        {<<":protocol">>, <<"connect-udp">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"localhost">>},
        {<<":path">>,
            masque_uri:expand(?TPL, #{
                target_host => <<"192.0.2.6">>, target_port => 443
            })},
        {<<"capsule-protocol">>, <<"?1">>}
    ].

await_session() ->
    receive
        {masque_session, Pid} -> Pid
    after 5000 -> ct:fail(no_server_session)
    end.

await_down(MRef, Pid) ->
    receive
        {'DOWN', MRef, process, Pid, _} -> ok
    after 5000 -> ct:fail({session_still_alive, Pid})
    end.

await_closed(Sess) ->
    receive
        {masque_closed, Sess, _Reason} -> ok
    after 5000 -> ct:fail(no_masque_closed)
    end.

session_count(Sup) ->
    proplists:get_value(active, supervisor:count_children(Sup)).

wait_count(Sup, Expected, 0) ->
    ct:fail({session_count, Sup, session_count(Sup), Expected});
wait_count(Sup, Expected, N) ->
    case session_count(Sup) of
        Expected ->
            ok;
        _ ->
            timer:sleep(100),
            wait_count(Sup, Expected, N - 1)
    end.
