%%% @doc Top-level supervisor for the `masque' application.
%%%
%%% Listeners and client sessions are attached dynamically as children
%%% from later steps; the initial tree is empty on purpose.
-module(masque_sup).
-behaviour(supervisor).

-export([start_link/0, init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    %% ETS table for H2 per-connection tunnel counting (Step 4).
    _ = ets:new(masque_h2_tunnel_counts,
                [set, public, named_table, {write_concurrency, true}]),
    SupFlags = #{strategy => one_for_one,
                 intensity => 10,
                 period => 10},
    Children = [
        #{id    => masque_h2_session_sup,
          start => {masque_h2_session_sup, start_link, []},
          type  => supervisor},
        #{id    => masque_h2_tcp_session_sup,
          start => {masque_h2_session_sup, start_link_tcp, []},
          type  => supervisor},
        #{id    => masque_h2_ip_session_sup,
          start => {masque_h2_session_sup, start_link_ip, []},
          type  => supervisor},
        #{id    => masque_h1_session_sup,
          start => {masque_h1_session_sup, start_link, []},
          type  => supervisor},
        #{id    => masque_h1_ip_session_sup,
          start => {masque_h1_session_sup, start_link_ip, []},
          type  => supervisor},
        #{id    => masque_h1_tcp_session_sup,
          start => {masque_h1_session_sup, start_link_tcp, []},
          type  => supervisor},
        #{id    => masque_upstream_pool,
          start => {masque_upstream_pool, start_link, []},
          type  => worker}
    ],
    {ok, {SupFlags, Children}}.
