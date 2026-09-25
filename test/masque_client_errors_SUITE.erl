%%% @doc Client-side failure paths.
%%%
%%% TLS verification of the proxy certificate on every transport: the
%%% listeners use a self-signed certificate, so a client with the
%%% default options must refuse it, and a client that trusts the
%%% certificate through `cacerts' must accept it.
%%%
%%% Failed handshakes (refused port, bad certificate, silent proxy)
%%% return `{error, _}' from `masque:connect/3' instead of raising, for
%%% every transport and tunnel protocol.
-module(masque_client_errors_SUITE).

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
    default_opts_reject_self_signed_h3/1,
    default_opts_reject_self_signed_h2/1,
    default_opts_reject_self_signed_h1/1,
    default_opts_reject_self_signed_tcp_h2/1,
    default_opts_reject_self_signed_bind_h3/1,
    default_opts_reject_self_signed_bind_h2/1,
    default_opts_reject_self_signed_bind_h1/1,
    trusted_cacerts_accepted_h3/1,
    trusted_cacerts_accepted_h2/1,
    trusted_cacerts_accepted_h1/1,
    refused_port_returns_error/1,
    silent_proxy_times_out/1,
    no_session_left_after_failure/1,
    bind_h1_bad_responses_rejected/1
]).

-define(TARGET, {<<"192.0.2.6">>, 443}).

%%====================================================================
%% CT callbacks
%%====================================================================

suite() -> [{timetrap, {seconds, 30}}].

all() ->
    [
        default_opts_reject_self_signed_h3,
        default_opts_reject_self_signed_h2,
        default_opts_reject_self_signed_h1,
        default_opts_reject_self_signed_tcp_h2,
        default_opts_reject_self_signed_bind_h3,
        default_opts_reject_self_signed_bind_h2,
        default_opts_reject_self_signed_bind_h1,
        trusted_cacerts_accepted_h3,
        trusted_cacerts_accepted_h2,
        trusted_cacerts_accepted_h1,
        refused_port_returns_error,
        silent_proxy_times_out,
        no_session_left_after_failure,
        bind_h1_bad_responses_rejected
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    {ok, _} = application:ensure_all_started(masque),
    case masque_test_helpers:generate_certs() of
        {ok, Certs} -> [{certs, Certs}, {ca, generate_ca_signed(Certs)} | Config];
        {error, R} -> {skip, {cert_generation_failed, R}}
    end.

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(certs, Config)).

%% The h2 and h1 listen sockets belong to the process that opens
%% them, so every case starts its own listeners.
init_per_testcase(Case, Config) ->
    Certs = certs_for(Case, Config),
    #{cert_file := CertFile, key_file := KeyFile} = Certs,
    Opts = #{
        handler => masque_echo_handler,
        handler_opts => #{allow_private => true}
    },
    {ok, H3} = masque_test_helpers:start_masque_server(maps:merge(Certs, Opts)),
    H2Name = unique_name("errors_h2"),
    {ok, {_, _, H2Port}} = masque_h2_server:start_listener(
        H2Name,
        Opts#{port => 0, cert => CertFile, key => KeyFile}
    ),
    H1Name = unique_name("errors_h1"),
    {ok, H1Ref} = masque:start_listener_h1(
        H1Name,
        Opts#{port => 0, cert => CertFile, key => KeyFile}
    ),
    [
        {h3, H3},
        {h2_name, H2Name},
        {h1_name, H1Name},
        {ports, #{
            h3 => maps:get(port, H3),
            h2 => H2Port,
            h1 => h1:server_port(H1Ref)
        }}
        | Config
    ].

end_per_testcase(_Case, Config) ->
    _ = catch_all(fun() ->
        masque_test_helpers:stop_masque_server(?config(h3, Config))
    end),
    _ = catch_all(fun() -> masque:stop_listener_h2(?config(h2_name, Config)) end),
    _ = catch_all(fun() -> masque:stop_listener_h1(?config(h1_name, Config)) end),
    ok.

%%====================================================================
%% Cases
%%====================================================================

default_opts_reject_self_signed_h3(Config) ->
    assert_rejected(connect(Config, h3, #{})).

default_opts_reject_self_signed_h2(Config) ->
    assert_rejected(connect(Config, h2, #{})).

default_opts_reject_self_signed_h1(Config) ->
    assert_rejected(connect(Config, h1, #{})).

default_opts_reject_self_signed_tcp_h2(Config) ->
    assert_rejected(connect(Config, h2, #{protocol => tcp})).

default_opts_reject_self_signed_bind_h3(Config) ->
    assert_rejected(bind_connect(Config, h3)).

default_opts_reject_self_signed_bind_h2(Config) ->
    assert_rejected(bind_connect(Config, h2)).

default_opts_reject_self_signed_bind_h1(Config) ->
    assert_rejected(bind_connect(Config, h1)).

trusted_cacerts_accepted_h3(Config) ->
    assert_accepted(connect(Config, h3, trusted(Config))).

trusted_cacerts_accepted_h2(Config) ->
    assert_accepted(connect(Config, h2, trusted(Config))).

trusted_cacerts_accepted_h1(Config) ->
    assert_accepted(connect(Config, h1, trusted(Config))).

refused_port_returns_error(_Config) ->
    Port = closed_port(),
    URI = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
    [
        ?assertMatch(
            {error, _},
            dial(URI, Transport, Protocol, #{timeout => 1000}),
            {Transport, Protocol}
        )
     || Transport <- [h3, h2, h1], Protocol <- [udp, tcp, ip, udp_bind]
    ],
    assert_no_close_messages().

%% A proxy that accepts the TCP connection (or swallows QUIC packets)
%% and never answers: the dial fails with an error once the handshake
%% timeout passes.
silent_proxy_times_out(_Config) ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, TcpPort} = inet:port(LSock),
    Acceptor = spawn(fun() -> accept_and_hold(LSock, []) end),
    ok = gen_tcp:controlling_process(LSock, Acceptor),
    {ok, Udp} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}]),
    {ok, UdpPort} = inet:port(Udp),
    try
        [
            begin
                Port =
                    case Transport of
                        h3 -> UdpPort;
                        _ -> TcpPort
                    end,
                URI = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
                T0 = erlang:monotonic_time(millisecond),
                Result = dial(URI, Transport, Protocol, #{timeout => 1000}),
                Elapsed = erlang:monotonic_time(millisecond) - T0,
                ?assertMatch({error, _}, Result, {Transport, Protocol}),
                ?assert(Elapsed < 4000)
            end
         || Transport <- [h3, h2, h1], Protocol <- [udp, tcp, ip, udp_bind]
        ]
    after
        exit(Acceptor, kill),
        gen_udp:close(Udp)
    end,
    assert_no_close_messages().

%% A failed dial leaves no client session process behind.
no_session_left_after_failure(Config) ->
    Before = erlang:processes(),
    [
        _ = dial(proxy_uri(Config, T), T, udp, #{})
     || T <- [h3, h2, h1]
    ],
    timer:sleep(200),
    Sessions = [
        P
     || P <- erlang:processes() -- Before,
        is_client_session(P)
    ],
    ?assertEqual([], Sessions).

%% The udp-bind h1 client checks the 101 it gets back: a non-numeric
%% status, a 101 without the Upgrade / Connection pair, an oversized
%% head and a head trickled past the deadline are all errors.
bind_h1_bad_responses_rejected(Config) ->
    Cases = [
        {<<"HTTP/1.1 1x1 Switching\r\n\r\n">>, bad_status_line},
        {<<"HTTP/1.1 101 Switching Protocols\r\nupgrade: connect-udp\r\n\r\n">>,
            bad_upgrade_response},
        {
            <<"HTTP/1.1 101 Switching Protocols\r\nx: ", (binary:copy(<<"a">>, 70000))/binary>>,
            headers_too_large
        },
        {trickle, handshake_timeout}
    ],
    [
        begin
            Port = start_fake_h1_proxy(Config, Reply),
            URI = iolist_to_binary(["https://localhost:", integer_to_list(Port)]),
            ?assertEqual(
                {error, Expected},
                dial(URI, h1, udp_bind, #{verify => verify_none, timeout => 1000})
            )
        end
     || {Reply, Expected} <- Cases
    ].

%%====================================================================
%% Helpers
%%====================================================================

%% One-shot TLS server: reads the request head and answers with
%% `Reply', or with one byte of a valid head every 300 ms for `trickle'.
start_fake_h1_proxy(Config, Reply) ->
    #{cert_file := CertFile, key_file := KeyFile} = ?config(certs, Config),
    Parent = self(),
    spawn(fun() ->
        {ok, LSock} = ssl:listen(0, [
            binary,
            {active, false},
            {reuseaddr, true},
            {certfile, CertFile},
            {keyfile, KeyFile}
        ]),
        {ok, {_, Port}} = ssl:sockname(LSock),
        Parent ! {fake_proxy, Port},
        {ok, T} = ssl:transport_accept(LSock, 5000),
        {ok, Sock} = ssl:handshake(T, 5000),
        {ok, _Req} = ssl:recv(Sock, 0, 5000),
        case Reply of
            trickle ->
                [
                    begin
                        _ = ssl:send(Sock, <<C>>),
                        timer:sleep(300)
                    end
                 || <<C>> <= <<"HTTP/1.1 101 Switching Protocols\r\n\r\n">>
                ];
            _ ->
                ssl:send(Sock, Reply)
        end,
        timer:sleep(1000),
        ssl:close(Sock)
    end),
    receive
        {fake_proxy, Port} -> Port
    after 5000 -> ct:fail(fake_proxy_start)
    end.

dial(URI, Transport, udp_bind, Extra) ->
    catch_all(fun() ->
        masque:bind_connect(URI, unscoped, Extra#{transports => [Transport]})
    end);
dial(URI, Transport, Protocol, Extra) ->
    Target =
        case Protocol of
            ip -> {'*', '*'};
            _ -> ?TARGET
        end,
    Opts = Extra#{transports => [Transport], protocol => Protocol},
    catch_all(fun() -> masque:connect(URI, Target, Opts) end).

closed_port() ->
    {ok, L} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(L),
    ok = gen_tcp:close(L),
    Port.

accept_and_hold(LSock, Held) ->
    case gen_tcp:accept(LSock) of
        {ok, Sock} -> accept_and_hold(LSock, [Sock | Held]);
        {error, _} -> ok
    end.

assert_no_close_messages() ->
    receive
        {masque_closed, _, _} = Msg -> ct:fail({stray_message, Msg})
    after 200 -> ok
    end.

is_client_session(Pid) ->
    case erlang:process_info(Pid, dictionary) of
        {dictionary, Dict} ->
            case proplists:get_value('$initial_call', Dict) of
                {Mod, init, 1} ->
                    lists:prefix("masque_", atom_to_list(Mod)) andalso
                        string:find(atom_to_list(Mod), "client_session") =/= nomatch;
                _ ->
                    false
            end;
        undefined ->
            false
    end.

trusted(Config) ->
    #{cacerts => [maps:get(ca_cert, ?config(ca, Config))]}.

%% OTP's ssl refuses a self-signed leaf even when it is listed in
%% `cacerts', so the trusted cases use a leaf signed by a test CA.
certs_for(Case, Config) ->
    case atom_to_list(Case) of
        "trusted_" ++ _ -> ?config(ca, Config);
        _ -> ?config(certs, Config)
    end.

generate_ca_signed(#{tmp_dir := Dir}) ->
    F = fun(Name) -> filename:join(Dir, Name) end,
    Cmds = [
        io_lib:format(
            "openssl req -x509 -newkey rsa:2048 -nodes -days 1 "
            "-keyout ~s -out ~s -subj '/CN=masque test ca' "
            "-addext 'basicConstraints=critical,CA:TRUE' "
            "-addext 'keyUsage=critical,keyCertSign'",
            [F("ca_key.pem"), F("ca.pem")]
        ),
        io_lib:format(
            "openssl req -newkey rsa:2048 -nodes -keyout ~s -out ~s "
            "-subj '/CN=localhost'",
            [F("leaf_key.pem"), F("leaf.csr")]
        ),
        io_lib:format(
            "printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\\n' > ~s && "
            "openssl x509 -req -in ~s -CA ~s -CAkey ~s -CAcreateserial "
            "-days 1 -out ~s -extfile ~s",
            [
                F("leaf.ext"),
                F("leaf.csr"),
                F("ca.pem"),
                F("ca_key.pem"),
                F("leaf.pem"),
                F("leaf.ext")
            ]
        )
    ],
    [os:cmd(lists:flatten(C) ++ " 2>/dev/null") || C <- Cmds],
    {ok, CaPem} = file:read_file(F("ca.pem")),
    {ok, LeafPem} = file:read_file(F("leaf.pem")),
    {ok, KeyPem} = file:read_file(F("leaf_key.pem")),
    [{'Certificate', CaDer, _}] = public_key:pem_decode(CaPem),
    [{'Certificate', LeafDer, _}] = public_key:pem_decode(LeafPem),
    #{
        ca_cert => CaDer,
        cert => LeafDer,
        key => masque_test_helpers:decode_key(KeyPem),
        cert_file => F("leaf.pem"),
        key_file => F("leaf_key.pem")
    }.

proxy_uri(Config, Transport) ->
    Port = maps:get(Transport, ?config(ports, Config)),
    iolist_to_binary(["https://localhost:", integer_to_list(Port)]).

connect(Config, Transport, Extra) ->
    Opts = maps:merge(#{transports => [Transport], timeout => 3000}, Extra),
    catch_all(fun() ->
        masque:connect(proxy_uri(Config, Transport), ?TARGET, Opts)
    end).

bind_connect(Config, Transport) ->
    catch_all(fun() ->
        masque:bind_connect(
            proxy_uri(Config, Transport),
            unscoped,
            #{transports => [Transport], timeout => 3000}
        )
    end).

catch_all(Fun) ->
    try
        Fun()
    catch
        Class:Reason -> {caught, Class, Reason}
    end.

assert_rejected({ok, Sess}) ->
    _ = masque:close(Sess),
    ct:fail(self_signed_certificate_accepted);
assert_rejected({error, _} = Err) ->
    %% The listener is up, so the failure must come from TLS rather
    %% than from a refused connection.
    ?assertEqual(nomatch, string:find(io_lib:format("~0p", [Err]), "econnrefused"));
assert_rejected(Other) ->
    ct:fail({expected_error, Other}).

assert_accepted({ok, Sess}) ->
    ok = masque:close(Sess);
assert_accepted(Other) ->
    ct:fail({trusted_certificate_rejected, Other}).

unique_name(Prefix) ->
    list_to_atom(
        Prefix ++ "_" ++ integer_to_list(erlang:unique_integer([positive]))
    ).
