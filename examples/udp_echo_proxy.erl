%%% @doc Example - a minimal MASQUE (RFC 9298) UDP proxy.
%%%
%%% Starts a listener on `Port' with a self-signed certificate, using
%%% the built-in `masque_udp_proxy_handler' to relay every CONNECT-UDP
%%% tunnel to its requested target.
%%%
%%% Run from the project root:
%%%
%%%   rebar3 shell
%%%   1> c("examples/udp_echo_proxy").
%%%   2> {ok, _} = udp_echo_proxy:start(4433).
%%%
%%% Stop with `udp_echo_proxy:stop().'.
-module(udp_echo_proxy).

-export([start/0, start/1, stop/0]).

-define(LISTENER, udp_echo_proxy).

start() ->
    start(4433).

start(Port) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, TmpDir, Cert, Key} = ephemeral_cert(),
    persistent_term:put({?MODULE, tmp_dir}, TmpDir),
    Opts = #{
        port     => Port,
        cert     => Cert,
        key      => Key,
        handler  => masque_udp_proxy_handler
    },
    masque:start_listener(?LISTENER, Opts).

stop() ->
    _ = masque:stop_listener(?LISTENER),
    case persistent_term:get({?MODULE, tmp_dir}, undefined) of
        undefined -> ok;
        Dir       -> os:cmd("rm -rf " ++ Dir)
    end,
    persistent_term:erase({?MODULE, tmp_dir}),
    ok.

%% Generate a throwaway self-signed cert using `openssl' - good enough
%% for local testing; bring your own for anything else.
ephemeral_cert() ->
    Dir = filename:join(
        "/tmp", "masque_echo_proxy_" ++
            integer_to_list(erlang:unique_integer([positive]))),
    ok = filelib:ensure_dir(filename:join(Dir, ".keep")),
    CertFile = filename:join(Dir, "cert.pem"),
    KeyFile  = filename:join(Dir, "key.pem"),
    Cmd = lists:flatten(io_lib:format(
        "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
        "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null",
        [KeyFile, CertFile])),
    os:cmd(Cmd),
    {ok, CertPem} = file:read_file(CertFile),
    {ok, KeyPem}  = file:read_file(KeyFile),
    [{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),
    [{KeyType, KeyDerRaw, not_encrypted}] = public_key:pem_decode(KeyPem),
    KeyDer = public_key:der_decode(KeyType, KeyDerRaw),
    {ok, Dir, CertDer, KeyDer}.
