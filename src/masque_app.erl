%%% Application callback module for the `masque` library.
-module(masque_app).
-moduledoc false.
-behaviour(application).

-export([start/2, stop/1]).

-spec start(application:start_type(), term()) -> {ok, pid()} | {error, term()}.
start(_StartType, _StartArgs) ->
    {ok, Pid} = masque_sup:start_link(),
    masque_metrics:setup(),
    _ = masque_chain_handler:init_node_token(),
    {ok, Pid}.

-spec stop(term()) -> ok.
stop(_State) ->
    ok.
