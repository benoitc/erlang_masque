%%% Top-level supervisor for the `masque` application.
%%%
%%% Starts the h2 and h1 session supervisors (one per protocol), the
%%% upstream pool and the CONNECT-IP address registry, and owns the
%%% ETS table that counts h2 tunnels per connection. Listeners and
%%% client sessions are not children. See
%%% docs/1-understand/architecture.md.
-module(masque_sup).
-moduledoc false.
-behaviour(supervisor).

-export([start_link/0, init/1]).

-spec start_link() -> supervisor:startlink_ret().
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    %% ETS table for h2 per-connection tunnel counting.
    _ = ets:new(
        masque_h2_tunnel_counts,
        [set, public, named_table, {write_concurrency, true}]
    ),
    SupFlags = #{
        strategy => one_for_one,
        intensity => 10,
        period => 10
    },
    Children = [
        #{
            id => masque_h2_session_sup,
            start => {masque_h2_session_sup, start_link, []},
            type => supervisor
        },
        #{
            id => masque_h2_tcp_session_sup,
            start => {masque_h2_session_sup, start_link_tcp, []},
            type => supervisor
        },
        #{
            id => masque_h2_ip_session_sup,
            start => {masque_h2_session_sup, start_link_ip, []},
            type => supervisor
        },
        #{
            id => masque_h2_udp_bind_session_sup,
            start => {masque_h2_session_sup, start_link_udp_bind, []},
            type => supervisor
        },
        #{
            id => masque_h1_udp_bind_session_sup,
            start => {masque_h1_session_sup, start_link_udp_bind, []},
            type => supervisor
        },
        #{
            id => masque_h1_session_sup,
            start => {masque_h1_session_sup, start_link, []},
            type => supervisor
        },
        #{
            id => masque_h1_ip_session_sup,
            start => {masque_h1_session_sup, start_link_ip, []},
            type => supervisor
        },
        #{
            id => masque_h1_tcp_session_sup,
            start => {masque_h1_session_sup, start_link_tcp, []},
            type => supervisor
        },
        #{
            id => masque_upstream_pool,
            start => {masque_upstream_pool, start_link, []},
            type => worker
        },
        #{
            id => masque_ip_session_registry,
            start => {masque_ip_session_registry, start_link, []},
            type => worker
        }
    ],
    {ok, {SupFlags, Children}}.
