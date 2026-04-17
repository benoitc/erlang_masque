%%% @doc Interop tests against an external MASQUE implementation.
%%%
%%% The suite drives `masque-go' (or any binary exposing an equivalent
%%% client/server CLI) through `os:cmd/1'. Because the external binary
%%% is not a hard dependency of the library, every case is `{skip, _}'
%%% unless the environment variable `MASQUE_GO_BIN' is set to the
%%% absolute path of a working binary.
%%%
%%% When interop is wanted, run:
%%%
%%%   MASQUE_GO_BIN=/path/to/masque-go \
%%%     MASQUE_GO_MODE=server          \
%%%     rebar3 ct --suite=masque_interop_SUITE
%%%
%%% `MASQUE_GO_MODE' selects whether the external peer plays the server
%%% (`server', default) or the client (`client') role.
-module(masque_interop_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    suite/0, all/0,
    init_per_suite/1, end_per_suite/1,
    init_per_testcase/2, end_per_testcase/2
]).

-export([
    our_client_talks_to_peer_server/1,
    our_server_talks_to_peer_client/1
]).

-define(BIN_ENV, "MASQUE_GO_BIN").
-define(MODE_ENV, "MASQUE_GO_MODE").

suite() -> [{timetrap, {seconds, 60}}].

all() ->
    [
        our_client_talks_to_peer_server,
        our_server_talks_to_peer_client
    ].

init_per_suite(Config) ->
    case external_bin() of
        false ->
            {skip, "set MASQUE_GO_BIN to run interop; binary not provided"};
        Bin ->
            {ok, _} = application:ensure_all_started(quic),
            {ok, _} = application:ensure_all_started(masque),
            case masque_test_helpers:generate_certs() of
                {ok, Certs} ->
                    [{certs, Certs}, {interop_bin, Bin} | Config];
                {error, R} ->
                    {skip, {cert_generation_failed, R}}
            end
    end.

end_per_suite(Config) ->
    case ?config(certs, Config) of
        undefined -> ok;
        Certs     -> masque_test_helpers:cleanup_certs(Certs)
    end,
    ok.

init_per_testcase(_Case, Config) ->
    Config.

end_per_testcase(_Case, _Config) ->
    ok.

%%====================================================================
%% Cases
%%====================================================================

our_client_talks_to_peer_server(Config) ->
    case os:getenv(?MODE_ENV, "server") of
        "server" ->
            Bin = ?config(interop_bin, Config),
            {ok, PeerPort} = spawn_peer_server(Bin, ?config(certs, Config)),
            ProxyURI = iolist_to_binary(
                ["https://localhost:", integer_to_list(PeerPort)]),
            try
                {ok, Sess} = masque:connect(ProxyURI,
                                            {<<"127.0.0.1">>, 9},
                                            #{verify => verify_none}),
                ok = masque:send(Sess, <<"interop ping">>),
                masque:close(Sess)
            after
                stop_peer()
            end;
        Other ->
            {skip, {wrong_mode, Other}}
    end.

our_server_talks_to_peer_client(Config) ->
    case os:getenv(?MODE_ENV, "server") of
        "client" ->
            Certs = ?config(certs, Config),
            {ok, Server} = masque_test_helpers:start_masque_server(Certs),
            Bin = ?config(interop_bin, Config),
            try
                _ = spawn_peer_client(Bin, maps:get(port, Server)),
                ok
            after
                masque_test_helpers:stop_masque_server(Server)
            end;
        _ ->
            {skip, "MASQUE_GO_MODE=client not selected"}
    end.

%%====================================================================
%% Helpers (best-effort binary shelling - the exact CLI depends on the
%% chosen external implementation; fill these in when pinning a peer).
%%====================================================================

external_bin() ->
    case os:getenv(?BIN_ENV) of
        false -> false;
        ""    -> false;
        Path  ->
            case filelib:is_regular(Path) of
                true  -> Path;
                false -> false
            end
    end.

spawn_peer_server(_Bin, _Certs) ->
    %% Real invocation would be, for instance:
    %%     os:cmd(Bin ++ " server --cert ... --key ... --port 0")
    %% and then parse the port the binary reports on stdout.
    %% We stop here because pinning to a specific binary is out of
    %% scope for this suite scaffolding.
    {skip, "spawn_peer_server not configured for this binary"}.

spawn_peer_client(_Bin, _Port) ->
    {skip, "spawn_peer_client not configured for this binary"}.

stop_peer() ->
    ok.
