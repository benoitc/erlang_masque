%% A misbehaving proxy, seen from the client: fake proxies that accept a
%% tunnel and then stop reading, flood the client with requests, or send
%% interim responses. The client must end or bound what it holds, and
%% tell its owner.
-module(masque_hostile_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    h1_udp_stalled_proxy_ends_session/1,
    h1_ip_stalled_proxy_ends_session/1,
    h1_udp_bind_stalled_proxy_ends_session/1,
    h3_interim_response_skipped/1,
    h2_interim_response_skipped/1
]).

suite() -> [{timetrap, {seconds, 60}}].

all() ->
    [
        h1_udp_stalled_proxy_ends_session,
        h1_ip_stalled_proxy_ends_session,
        h1_udp_bind_stalled_proxy_ends_session,
        h3_interim_response_skipped,
        h2_interim_response_skipped
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Certs} = masque_test_helpers:generate_certs(),
    [{certs, Certs} | Config].

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(certs, Config)),
    ok.

%% Blocked writes give up after one second instead of thirty.
init_per_testcase(_Case, Config) ->
    application:set_env(masque, stream_send_timeout_ms, 1000),
    Config.

end_per_testcase(_Case, _Config) ->
    application:unset_env(masque, stream_send_timeout_ms),
    ok.

%%====================================================================
%% h1: a proxy that answers 101 and never reads again
%%====================================================================

h1_udp_stalled_proxy_ends_session(Config) ->
    stalled(Config, <<"connect-udp">>, [], fun(Uri) ->
        masque:connect(Uri, {<<"192.0.2.6">>, 443}, opts())
    end).

h1_ip_stalled_proxy_ends_session(Config) ->
    stalled(Config, <<"connect-ip">>, [], fun(Uri) ->
        masque:connect(Uri, {'*', '*'}, (opts())#{protocol => ip})
    end).

h1_udp_bind_stalled_proxy_ends_session(Config) ->
    stalled(
        Config,
        <<"connect-udp">>,
        [
            <<"connect-udp-bind: ?1\r\n">>,
            <<"proxy-public-address: \"127.0.0.1:4000\"\r\n">>
        ],
        fun(Uri) -> masque:bind_connect(Uri, unscoped, opts()) end
    ).

opts() -> #{verify => verify_none, transports => [h1], timeout => 5000}.

stalled(Config, Token, Extra, Connect) ->
    {Port, Proxy} = stalled_proxy(Config, Token, Extra),
    {ok, Sess} = Connect(iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)])),
    MRef = erlang:monitor(process, Sess),
    %% Write until the proxy's receive window and both socket buffers
    %% are full; the next write blocks, gives up after the timeout and
    %% ends the session.
    Writer = spawn_link(fun() -> write_until_error(Sess, binary:copy(<<"x">>, 16384)) end),
    receive
        {masque_closed, Sess, _Reason} -> ok
    after 30000 -> ct:fail(session_still_open)
    end,
    receive
        {'DOWN', MRef, process, Sess, _} -> ok
    after 5000 -> ct:fail(session_process_alive)
    end,
    unlink(Writer),
    exit(Writer, kill),
    exit(Proxy, kill).

write_until_error(Sess, Chunk) ->
    try masque:send_capsule(Sess, 16#3ff, Chunk) of
        ok -> write_until_error(Sess, Chunk);
        _ -> ok
    catch
        exit:_ -> ok
    end.

%% A TLS listener that reads one request, answers 101 for `Token' and
%% then never reads again, with a small receive buffer.
stalled_proxy(Config, Token, Extra) ->
    #{cert_file := Cert, key_file := Key} = ?config(certs, Config),
    {ok, L} = ssl:listen(0, [
        binary,
        {active, false},
        {certfile, Cert},
        {keyfile, Key},
        {alpn_preferred_protocols, [<<"http/1.1">>]},
        {recbuf, 4096},
        {reuseaddr, true}
    ]),
    {ok, {_, Port}} = ssl:sockname(L),
    Parent = self(),
    Pid = spawn(fun() ->
        {ok, T} = ssl:transport_accept(L, 10000),
        {ok, S} = ssl:handshake(T, 10000),
        {ok, _Req} = ssl:recv(S, 0, 10000),
        ok = ssl:send(S, [
            <<"HTTP/1.1 101 Switching Protocols\r\n">>,
            <<"Upgrade: ">>,
            Token,
            <<"\r\nConnection: Upgrade\r\nCapsule-Protocol: ?1\r\n">>,
            Extra,
            <<"\r\n">>
        ]),
        Parent ! {proxy_up, self()},
        receive
            stop -> ok
        end
    end),
    ok = ssl:controlling_process(L, Pid),
    {Port, Pid}.

%%====================================================================
%% h3 and h2: a 103 Early Hints before the 200
%%====================================================================

%% Interim responses come before the final one and are skipped, for
%% every tunnel type, as they already were for CONNECT-TCP.
h3_interim_response_skipped(Config) ->
    #{cert := Cert, key := Key} = ?config(certs, Config),
    Name = h3_interim_proxy,
    {ok, _} = quic_h3:start_server(Name, 0, #{
        cert => Cert,
        key => Key,
        settings => #{enable_connect_protocol => 1, h3_datagram => 1},
        quic_opts => #{alpn => [<<"h3">>], max_datagram_frame_size => 65535},
        handler => fun(Conn, Sid, _Method, _Path, _Headers) ->
            ok = quic_h3:send_response(Conn, Sid, 103, [{<<"link">>, <<"</x>">>}]),
            ok = quic_h3:send_response(Conn, Sid, 200, [{<<"capsule-protocol">>, <<"?1">>}])
        end
    }),
    {ok, Port} = quic:get_server_port(Name),
    try
        interim_cases(Port, h3)
    after
        quic_h3:stop_server(Name)
    end.

h2_interim_response_skipped(Config) ->
    #{cert_file := Cert, key_file := Key} = ?config(certs, Config),
    Self = self(),
    Keeper = spawn(fun() ->
        {ok, {_, _, P}} = h2:start_server(h2_interim_proxy, 0, #{
            cert => Cert,
            key => Key,
            enable_connect_protocol => true,
            settings => #{enable_connect_protocol => 1},
            handler => fun(Conn, Sid, _Method, _Path, _Headers) ->
                ok = h2:send_response(Conn, Sid, 103, [{<<"link">>, <<"</x>">>}]),
                ok = h2:send_response(Conn, Sid, 200, [{<<"capsule-protocol">>, <<"?1">>}]),
                receive
                    stop -> ok
                after 10000 -> ok
                end
            end
        }),
        Self ! {port, P},
        receive
            stop -> ok
        end
    end),
    Port =
        receive
            {port, P} -> P
        end,
    try
        interim_cases(Port, h2)
    after
        Keeper ! stop
    end.

interim_cases(Port, T) ->
    Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
    O = #{verify => verify_none, transports => [T], timeout => 5000},
    {ok, Udp} = masque:connect(Uri, {<<"192.0.2.6">>, 443}, O),
    ok = masque:close(Udp),
    {ok, Ip} = masque:connect(Uri, {'*', '*'}, O#{protocol => ip}),
    ok = masque:close(Ip),
    ok.
