%%% @doc Supervisor for HTTP/2 MASQUE server sessions.
%%%
%%% Each accepted CONNECT-UDP tunnel spawns one
%%% `masque_h2_server_session' child here. Sessions are `temporary'
%%% (not restarted on crash - the tunnel is gone and the client will
%%% reconnect). The supervisor is started once as part of the
%%% `masque_sup' tree and lives for the application's lifetime.
-module(masque_h2_session_sup).
-behaviour(supervisor).

-export([start_link/0, start_session/1]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-spec start_session(map()) -> {ok, pid()} | {error, term()}.
start_session(Args) ->
    supervisor:start_child(?MODULE, [Args]).

init([]) ->
    ChildSpec = #{
        id       => masque_h2_server_session,
        start    => {masque_h2_server_session, start_link, []},
        restart  => temporary,
        shutdown => 5000,
        type     => worker
    },
    {ok, {#{strategy => simple_one_for_one,
            intensity => 10, period => 10}, [ChildSpec]}}.
