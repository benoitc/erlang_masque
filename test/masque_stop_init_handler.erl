%%% @doc Test fixture - a MASQUE handler that always refuses in
%%% `init/2'. Used to prove that an `{stop, _}' from the handler
%%% reaches the client as a 502 reject rather than as "101 then
%%% immediate close". Exercised by the correctness track CT cases
%%% for the h1 server session ordering fix.
-module(masque_stop_init_handler).
-behaviour(masque_handler).

-export([accept/1, init/2, terminate/2]).

accept(_Req) -> accept.

init(_Req, _Opts) ->
    {stop, handler_refused}.

terminate(_Reason, _State) -> ok.
