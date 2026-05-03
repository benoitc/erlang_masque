%%% @doc Supervisor for HTTP/1.1 MASQUE server sessions.
%%%
%%% One `simple_one_for_one' supervisor per protocol, sibling of
%%% `masque_h2_session_sup'. For now only the UDP branch is populated;
%%% IP and TCP variants are added by later implementation steps.
%%% Sessions are `temporary' (not restarted on crash).
-module(masque_h1_session_sup).
-behaviour(supervisor).

-export([start_link/0, start_link_ip/0, start_link_tcp/0,
         start_link_udp_bind/0,
         start_session/1]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, udp).

start_link_ip() ->
    supervisor:start_link({local, masque_h1_ip_session_sup}, ?MODULE, ip).

start_link_tcp() ->
    supervisor:start_link({local, masque_h1_tcp_session_sup}, ?MODULE, tcp).

start_link_udp_bind() ->
    supervisor:start_link({local, masque_h1_udp_bind_session_sup},
                          ?MODULE, udp_bind).

-spec start_session(map()) -> {ok, pid()} | {error, term()}.
start_session(#{protocol := ip} = Args) ->
    supervisor:start_child(masque_h1_ip_session_sup, [Args]);
start_session(#{protocol := tcp} = Args) ->
    supervisor:start_child(masque_h1_tcp_session_sup, [Args]);
start_session(#{protocol := udp_bind} = Args) ->
    supervisor:start_child(masque_h1_udp_bind_session_sup, [Args]);
start_session(Args) ->
    supervisor:start_child(?MODULE, [Args]).

init(udp)      -> {ok, spec(masque_h1_server_session)};
init(ip)       -> {ok, spec(masque_ip_h1_server_session)};
init(tcp)      -> {ok, spec(masque_tcp_h1_server_session)};
init(udp_bind) -> {ok, spec(masque_udp_bind_h1_server_session)}.

spec(Mod) ->
    ChildSpec = #{
        id       => Mod,
        start    => {Mod, start_link, []},
        restart  => temporary,
        shutdown => 5000,
        type     => worker
    },
    {#{strategy => simple_one_for_one,
       intensity => 10, period => 10}, [ChildSpec]}.
