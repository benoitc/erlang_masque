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
    SupFlags = #{strategy => one_for_one,
                 intensity => 10,
                 period => 10},
    {ok, {SupFlags, []}}.
