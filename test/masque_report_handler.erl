%%% @doc Test fixture - echo handler that reports its session pid.
%%%
%%% `init/2' sends `{masque_session, self()}' to the pid under
%%% `report_to' in the handler opts, so a suite can monitor the
%%% server-side session process. Packets and capsules are echoed.
-module(masque_report_handler).
-behaviour(masque_handler).

-export([accept/1, init/2, handle_packet/2, handle_capsule/3, handle_data/2]).

accept(_Req) ->
    accept.

init(_Req, Opts) ->
    case maps:find(report_to, Opts) of
        {ok, Pid} -> Pid ! {masque_session, self()};
        error -> ok
    end,
    {ok, Opts}.

handle_packet(Data, State) ->
    {ok, State, [{send, Data}]}.

handle_capsule(Type, Value, State) ->
    {ok, State, [{send_capsule, Type, Value}]}.

handle_data(Data, State) ->
    {ok, State, [{send_data, Data}]}.
