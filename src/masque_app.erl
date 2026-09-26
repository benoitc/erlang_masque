%%% @doc Application callback module for the `masque' library.
-module(masque_app).
-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    {ok, Pid} = masque_sup:start_link(),
    masque_metrics:setup(),
    _ = masque_chain_handler:init_node_token(),
    {ok, Pid}.

stop(_State) ->
    ok.
