%%% @doc End-to-end tests for the MASQUE CONNECT-UDP stack over
%%% HTTP/1.1.
%%%
%%% Drives `masque:connect/3' with `transports => [h1]' and the real
%%% `masque:start_listener_h1/2' listener on loopback TLS. The server
%%% spawns `masque_h1_server_session' per accepted tunnel, which
%%% dispatches into the standard `masque_handler' callbacks (we use
%%% `masque_echo_handler' to bounce datagrams back).
-module(masque_h1_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1,
         init_per_testcase/2, end_per_testcase/2]).

-export([echo_datagram/1,
         large_datagram_roundtrip/1,
         multiple_datagrams/1,
         graceful_stop/1,
         owner_message_shape/1,
         handshake_rejected_wrong_method/1,
         handshake_rejected_no_capsule_protocol/1,
         handshake_rejected_wrong_upgrade/1,
         drain_flag_rejects_new_tunnels/1,
         connect_via_masque_facade/1,
         one_tunnel_per_connection/1]).

all() ->
    [echo_datagram,
     large_datagram_roundtrip,
     multiple_datagrams,
     graceful_stop,
     owner_message_shape,
     handshake_rejected_wrong_method,
     handshake_rejected_no_capsule_protocol,
     handshake_rejected_wrong_upgrade,
     drain_flag_rejects_new_tunnels,
     connect_via_masque_facade,
     one_tunnel_per_connection].

groups() -> [].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Certs} = masque_test_helpers:generate_certs(),
    Name = list_to_atom("masque_h1_suite_" ++
                        integer_to_list(erlang:unique_integer([positive]))),
    %% `ssl:listen' ties the listen socket to the calling process; in
    %% Common Test that process exits between `init_per_suite' and the
    %% first test case. Host the server inside a dedicated keeper so
    %% the listen socket outlives suite setup.
    Parent = self(),
    Keeper = erlang:spawn(fun() -> keeper_loop(Parent, Name, Certs) end),
    receive
        {Keeper, started, Ref, Port} ->
            [{certs, Certs}, {server_ref, Ref}, {server_name, Name},
             {keeper, Keeper}, {port, Port} | Config];
        {Keeper, start_failed, Reason} ->
            ct:fail({h1_listener_start_failed, Reason})
    after 5000 ->
        ct:fail(keeper_start_timeout)
    end.

end_per_suite(Config) ->
    Keeper = ?config(keeper, Config),
    Keeper ! stop,
    _ = masque_test_helpers:cleanup_certs(?config(certs, Config)),
    ok.

keeper_loop(Parent, Name, Certs) ->
    Opts = #{
        port => 0,
        cert => maps:get(cert_file, Certs),
        key  => maps:get(key_file, Certs),
        handler => masque_echo_handler
    },
    case masque:start_listener_h1(Name, Opts) of
        {ok, Ref} ->
            Port = h1:server_port(Ref),
            Parent ! {self(), started, Ref, Port},
            keeper_wait(Name);
        {error, Reason} ->
            Parent ! {self(), start_failed, Reason}
    end.

keeper_wait(Name) ->
    receive
        stop ->
            _ = masque:stop_listener_h1(Name),
            ok;
        _ ->
            keeper_wait(Name)
    end.

init_per_testcase(_TC, Config) -> Config.

end_per_testcase(drain_flag_rejects_new_tunnels, Config) ->
    %% Always clear drain so leaky state does not infect later tests.
    _ = masque:undrain_listener(?config(server_name, Config)),
    ok;
end_per_testcase(_TC, _Config) -> ok.

%%====================================================================
%% Happy-path cases
%%====================================================================

echo_datagram(Config) ->
    {ok, Sess} = connect(Config),
    ok = masque:send(Sess, <<"ping">>),
    receive
        {masque_data, Sess, <<"ping">>} -> ok
    after 2000 ->
        ct:fail("did not receive echoed datagram")
    end,
    ok = masque:close(Sess).

large_datagram_roundtrip(Config) ->
    {ok, Sess} = connect(Config),
    Payload = crypto:strong_rand_bytes(32000),
    ok = masque:send(Sess, Payload),
    receive
        {masque_data, Sess, Got} ->
            ?assertEqual(Payload, Got)
    after 3000 ->
        ct:fail("did not receive large datagram")
    end,
    ok = masque:close(Sess).

multiple_datagrams(Config) ->
    {ok, Sess} = connect(Config),
    N = 16,
    Payloads = [ integer_to_binary(I) || I <- lists:seq(1, N) ],
    lists:foreach(fun(P) ->
        ok = masque:send(Sess, P)
    end, Payloads),
    Got = collect(Sess, N, []),
    ?assertEqual(lists:sort(Payloads), lists:sort(Got)),
    ok = masque:close(Sess).

graceful_stop(Config) ->
    {ok, Sess} = connect(Config),
    MRef = erlang:monitor(process, Sess),
    ok = masque:close(Sess),
    receive
        {'DOWN', MRef, process, Sess, _Reason} -> ok
    after 2000 ->
        ct:fail(session_did_not_exit)
    end.

owner_message_shape(Config) ->
    {ok, Sess} = connect(Config),
    ok = masque:send(Sess, <<"shape">>),
    receive
        {masque_data, S, <<"shape">>} when S =:= Sess -> ok
    after 2000 ->
        ct:fail("owner message did not match expected shape")
    end,
    ok = masque:close(Sess).

connect_via_masque_facade(Config) ->
    {ok, Sess} = connect(Config),
    ok = masque:send(Sess, <<"facade">>),
    receive
        {masque_data, Sess, <<"facade">>} -> ok
    after 2000 ->
        ct:fail(no_echo_via_facade)
    end,
    ok = masque:close(Sess).

%%====================================================================
%% Rejection cases
%%====================================================================

handshake_rejected_wrong_method(Config) ->
    %% Bypass the client session and talk to the server directly with
    %% a POST request; expect 405.
    Port = ?config(port, Config),
    ?assertMatch(405, direct_request(Port, <<"POST">>,
                                      <<"/">>,
                                      [{<<"host">>, <<"localhost">>},
                                       {<<"content-length">>, <<"0">>}])).

handshake_rejected_no_capsule_protocol(Config) ->
    Port = ?config(port, Config),
    %% GET + Upgrade: connect-udp but NO Capsule-Protocol header -> 501.
    ?assertMatch(501, direct_request(Port, <<"GET">>,
                                      <<"/.well-known/masque/udp/127.0.0.1/5353/">>,
                                      [{<<"host">>, <<"localhost">>},
                                       {<<"connection">>, <<"Upgrade">>},
                                       {<<"upgrade">>, <<"connect-udp">>}])).

handshake_rejected_wrong_upgrade(Config) ->
    Port = ?config(port, Config),
    %% GET + Upgrade: websocket -> 501 (not an RFC 9298 protocol).
    ?assertMatch(501, direct_request(Port, <<"GET">>,
                                      <<"/.well-known/masque/udp/127.0.0.1/5353/">>,
                                      [{<<"host">>, <<"localhost">>},
                                       {<<"connection">>, <<"Upgrade">>},
                                       {<<"upgrade">>, <<"websocket">>},
                                       {<<"capsule-protocol">>, <<"?1">>}])).

drain_flag_rejects_new_tunnels(Config) ->
    Name = ?config(server_name, Config),
    ok = masque:drain_listener(Name),
    Port = ?config(port, Config),
    ?assertMatch(503, direct_request(Port, <<"GET">>,
                                      <<"/.well-known/masque/udp/127.0.0.1/5353/">>,
                                      [{<<"host">>, <<"localhost">>},
                                       {<<"connection">>, <<"Upgrade">>},
                                       {<<"upgrade">>, <<"connect-udp">>},
                                       {<<"capsule-protocol">>, <<"?1">>}])),
    ok = masque:undrain_listener(Name).

one_tunnel_per_connection(Config) ->
    %% h1 inherently caps at one tunnel per TCP/TLS connection. Once
    %% the first Upgrade succeeds the server shuts the h1 state
    %% machine down (`socket_handed_off = true'), so any attempt to
    %% piggy-back a second request on the same socket must fail. Open
    %% two independent sessions and confirm BOTH succeed (each uses
    %% its own connection).
    {ok, Sess1} = connect(Config),
    {ok, Sess2} = connect(Config),
    ok = masque:send(Sess1, <<"a">>),
    ok = masque:send(Sess2, <<"b">>),
    A = recv_one(Sess1),
    B = recv_one(Sess2),
    ?assertEqual(<<"a">>, A),
    ?assertEqual(<<"b">>, B),
    ok = masque:close(Sess1),
    ok = masque:close(Sess2).

%%====================================================================
%% Helpers
%%====================================================================

connect(Config) ->
    Port = ?config(port, Config),
    ProxyURI = iolist_to_binary(
                 ["https://127.0.0.1:", integer_to_list(Port)]),
    Target = {<<"127.0.0.1">>, 5353},
    Opts = #{
        transports => [h1],
        protocol => udp,
        timeout => 5000,
        owner => self(),
        verify => verify_none,
        ssl_opts => [{verify, verify_none}]
    },
    case masque:connect(ProxyURI, Target, Opts) of
        {ok, Sess} -> {ok, Sess};
        Other      -> ct:fail({connect_failed, Other})
    end.

recv_one(Sess) ->
    receive
        {masque_data, Sess, Bin} -> Bin
    after 2000 ->
        ct:fail({no_data_for, Sess})
    end.

collect(_Sess, 0, Acc) ->
    Acc;
collect(Sess, N, Acc) ->
    receive
        {masque_data, Sess, Bin} ->
            collect(Sess, N - 1, [Bin | Acc])
    after 3000 ->
        ct:fail({timeout_waiting_for, N, more_echoes})
    end.

%% Send a raw HTTP/1.1 request on a one-shot TLS connection and return
%% the response status code. Used by the rejection cases to assert the
%% server writes the expected status without going through the h1
%% state machine or the masque client.
direct_request(Port, Method, Path, Headers) ->
    {ok, Sock} = ssl:connect("127.0.0.1", Port,
        [binary, {active, false},
         {verify, verify_none},
         {alpn_advertised_protocols, [<<"http/1.1">>]}], 5000),
    HdrLines = [[N, <<": ">>, V, <<"\r\n">>] || {N, V} <- Headers],
    Req = iolist_to_binary([Method, <<" ">>, Path, <<" HTTP/1.1\r\n">>,
                             HdrLines, <<"\r\n">>]),
    ok = ssl:send(Sock, Req),
    {ok, Resp} = ssl:recv(Sock, 0, 3000),
    _ = ssl:close(Sock),
    [StatusLine | _] = binary:split(Resp, <<"\r\n">>),
    [_Ver, CodeBin | _] = binary:split(StatusLine, <<" ">>, [global, trim_all]),
    binary_to_integer(CodeBin).
