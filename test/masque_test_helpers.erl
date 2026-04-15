%%% @doc Common test helpers for masque suites.
%%%
%%% Generates a self-signed certificate in a tmp dir, starts
%%% `quic_h3' servers and clients, and exposes small utilities for
%%% driving the handshake directly through `quic_h3:request/3'.
-module(masque_test_helpers).

-export([
    generate_certs/0,
    cleanup_certs/1,
    start_masque_server/1,
    stop_masque_server/1,
    h3_client_connect/2,
    h3_await_response/2
]).

-include_lib("common_test/include/ct.hrl").

%%====================================================================
%% Certificates
%%====================================================================

generate_certs() ->
    TmpDir = filename:join(
        ["/tmp",
         "masque_test_" ++ integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    CertFile = filename:join(TmpDir, "cert.pem"),
    KeyFile = filename:join(TmpDir, "key.pem"),
    Cmd = lists:flatten(io_lib:format(
        "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
        "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null",
        [KeyFile, CertFile])),
    os:cmd(Cmd),
    case {filelib:is_file(CertFile), filelib:is_file(KeyFile)} of
        {true, true} ->
            {ok, CertPem} = file:read_file(CertFile),
            {ok, KeyPem}  = file:read_file(KeyFile),
            [{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),
            KeyDer = decode_key(KeyPem),
            {ok, #{tmp_dir => TmpDir, cert => CertDer, key => KeyDer}};
        _ ->
            os:cmd("rm -rf " ++ TmpDir),
            {error, cert_generation_failed}
    end.

cleanup_certs(#{tmp_dir := TmpDir}) ->
    os:cmd("rm -rf " ++ TmpDir),
    ok.

decode_key(KeyPem) ->
    case public_key:pem_decode(KeyPem) of
        [{'RSAPrivateKey', Der, not_encrypted}]    -> public_key:der_decode('RSAPrivateKey', Der);
        [{'ECPrivateKey', Der, not_encrypted}]     -> public_key:der_decode('ECPrivateKey', Der);
        [{'PrivateKeyInfo', Der, not_encrypted}]   -> public_key:der_decode('PrivateKeyInfo', Der);
        [{_Type, Der, not_encrypted}]              -> Der
    end.

%%====================================================================
%% Server lifecycle
%%====================================================================

start_masque_server(#{cert := Cert, key := Key} = Ctx) ->
    Name = list_to_atom("masque_test_" ++
                        integer_to_list(erlang:unique_integer([positive]))),
    Extra = maps:without([cert, key, tmp_dir], Ctx),
    Opts = maps:merge(
        #{port => 0, cert => Cert, key => Key},
        Extra),
    {ok, _} = masque_server:start_listener(Name, Opts),
    {ok, Port} = quic:get_server_port(Name),
    {ok, #{name => Name, port => Port}}.

stop_masque_server(#{name := Name}) ->
    masque_server:stop_listener(Name).

%%====================================================================
%% Client helpers (raw quic_h3, for driving the handshake in tests)
%%====================================================================

h3_client_connect(Port, Opts0) ->
    Opts = maps:merge(
        #{
            verify => false,
            sync => true,
            alpn => [<<"h3">>],
            settings => #{enable_connect_protocol => 1, h3_datagram => 1},
            h3_datagram_enabled => true,
            max_datagram_frame_size => 65535
        },
        Opts0),
    quic_h3:connect("127.0.0.1", Port, Opts).

%% Wait for the server to produce a response on StreamId; returns
%% `{ok, Status, Headers}' or `{error, timeout}'.
h3_await_response(StreamId, Timeout) ->
    receive
        {quic_h3, _Conn, {response, StreamId, Status, Headers}} ->
            {ok, Status, Headers}
    after Timeout ->
        {error, timeout}
    end.
