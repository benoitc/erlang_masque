%%% @doc Client-side failure paths: TLS verification of the proxy
%%% certificate on every transport.
%%%
%%% The listeners use a self-signed certificate, so a client with the
%%% default options must refuse it, and a client that trusts the
%%% certificate through `cacerts' must accept it.
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
    trusted_cacerts_accepted_h1/1
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
        trusted_cacerts_accepted_h1
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

%%====================================================================
%% Helpers
%%====================================================================

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
assert_rejected(Other) ->
    %% The listener is up, so the failure must come from TLS rather
    %% than from a refused connection.
    ?assertEqual(nomatch, string:find(io_lib:format("~0p", [Other]), "econnrefused")).

assert_accepted({ok, Sess}) ->
    ok = masque:close(Sess);
assert_accepted(Other) ->
    ct:fail({trusted_certificate_rejected, Other}).

unique_name(Prefix) ->
    list_to_atom(
        Prefix ++ "_" ++ integer_to_list(erlang:unique_integer([positive]))
    ).
