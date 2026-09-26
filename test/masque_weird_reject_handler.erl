%%% @doc Test fixture - rejects every request with a reason
%%% `masque_errors' does not know.
-module(masque_weird_reject_handler).
-behaviour(masque_handler).

-export([accept/1]).

accept(_Req) ->
    {reject, weird}.
