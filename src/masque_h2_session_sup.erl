%%% Supervisor for HTTP/2 MASQUE server sessions.
%%%
%%% Each accepted tunnel spawns one child here. UDP tunnels use
%%% `masque_h2_server_session`; TCP tunnels use
%%% `masque_tcp_server_session`; CONNECT-IP tunnels use
%%% `masque_ip_server_session`. One `simple_one_for_one` supervisor
%%% per protocol runs under `masque_sup`. Sessions are `temporary`
%%% (not restarted on crash).
-module(masque_h2_session_sup).
-moduledoc false.
-behaviour(supervisor).

-export([
    start_link/0,
    start_link_tcp/0,
    start_link_ip/0,
    start_link_udp_bind/0,
    start_session/1
]).
-export([init/1]).

-spec start_link() -> supervisor:startlink_ret().
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, udp).

-spec start_link_tcp() -> supervisor:startlink_ret().
start_link_tcp() ->
    supervisor:start_link({local, masque_h2_tcp_session_sup}, ?MODULE, tcp).

-spec start_link_ip() -> supervisor:startlink_ret().
start_link_ip() ->
    supervisor:start_link({local, masque_h2_ip_session_sup}, ?MODULE, ip).

-spec start_link_udp_bind() -> supervisor:startlink_ret().
start_link_udp_bind() ->
    supervisor:start_link(
        {local, masque_h2_udp_bind_session_sup},
        ?MODULE,
        udp_bind
    ).

-spec start_session(map()) -> {ok, pid()} | {error, term()}.
start_session(#{protocol := tcp} = Args) ->
    supervisor:start_child(masque_h2_tcp_session_sup, [Args]);
start_session(#{protocol := ip} = Args) ->
    supervisor:start_child(masque_h2_ip_session_sup, [Args]);
start_session(#{protocol := udp_bind} = Args) ->
    supervisor:start_child(masque_h2_udp_bind_session_sup, [Args]);
start_session(Args) ->
    supervisor:start_child(?MODULE, [Args]).

-spec init(udp | tcp | ip | udp_bind) ->
    {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(udp) -> {ok, spec(masque_h2_server_session)};
init(tcp) -> {ok, spec(masque_tcp_server_session)};
init(ip) -> {ok, spec(masque_ip_server_session)};
init(udp_bind) -> {ok, spec(masque_udp_bind_server_session)}.

spec(Mod) ->
    ChildSpec = #{
        id => Mod,
        start => {Mod, start_link, []},
        restart => temporary,
        shutdown => 5000,
        type => worker
    },
    {
        #{
            strategy => simple_one_for_one,
            intensity => 10,
            period => 10
        },
        [ChildSpec]
    }.
