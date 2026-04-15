%%% @doc Application callback module for the `masque' library.
-module(masque_app).
-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    masque_sup:start_link().

stop(_State) ->
    ok.
