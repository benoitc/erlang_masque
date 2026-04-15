%%% @doc Test fixture - bounces every UDP packet back to the sender.
%%%
%%% Used by `masque_compliance_SUITE' to exercise the datagram path
%%% without needing a real UDP target.
-module(masque_echo_handler).
-behaviour(masque_handler).

-export([accept/1, init/2, handle_packet/2, handle_capsule/3, terminate/2]).

accept(_Req) ->
    accept.

init(_Req, _Opts) ->
    {ok, undefined}.

handle_packet(Data, State) ->
    {ok, State, [{send_packet, Data}]}.

handle_capsule(Type, Value, State) ->
    {ok, State, [{send_capsule, Type, Value}]}.

terminate(_Reason, _State) ->
    ok.
