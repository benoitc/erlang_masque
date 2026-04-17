%%% @doc Supervisor for HTTP/2 MASQUE server sessions.
%%%
%%% Each accepted tunnel spawns one child here. UDP tunnels use
%%% `masque_h2_server_session'; TCP tunnels use
%%% `masque_tcp_server_session'. Two `simple_one_for_one'
%%% supervisors run under `masque_sup', one per protocol.
%%% Sessions are `temporary' (not restarted on crash).
-module(masque_h2_session_sup).
-behaviour(supervisor).

-export([start_link/0, start_link_tcp/0, start_session/1]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, udp).

start_link_tcp() ->
    supervisor:start_link({local, masque_h2_tcp_session_sup}, ?MODULE, tcp).

-spec start_session(map()) -> {ok, pid()} | {error, term()}.
start_session(#{protocol := tcp} = Args) ->
    supervisor:start_child(masque_h2_tcp_session_sup, [Args]);
start_session(Args) ->
    supervisor:start_child(?MODULE, [Args]).

init(udp) ->
    ChildSpec = #{
        id       => masque_h2_server_session,
        start    => {masque_h2_server_session, start_link, []},
        restart  => temporary,
        shutdown => 5000,
        type     => worker
    },
    {ok, {#{strategy => simple_one_for_one,
            intensity => 10, period => 10}, [ChildSpec]}};
init(tcp) ->
    ChildSpec = #{
        id       => masque_tcp_server_session,
        start    => {masque_tcp_server_session, start_link, []},
        restart  => temporary,
        shutdown => 5000,
        type     => worker
    },
    {ok, {#{strategy => simple_one_for_one,
            intensity => 10, period => 10}, [ChildSpec]}}.
