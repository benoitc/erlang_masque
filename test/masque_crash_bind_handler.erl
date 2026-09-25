%%% @doc Test fixture - the default udp-bind handler, except that
%%% capsule type `16#ff01' makes `handle_capsule/3' crash.
-module(masque_crash_bind_handler).

-export([init/2, handle_bind_packet/3, handle_info/2, handle_capsule/3, terminate/2]).

init(Req, Opts) ->
    masque_udp_bind_proxy_handler:init(Req, Opts).

handle_bind_packet(Peer, Payload, State) ->
    masque_udp_bind_proxy_handler:handle_bind_packet(Peer, Payload, State).

handle_info(Msg, State) ->
    masque_udp_bind_proxy_handler:handle_info(Msg, State).

handle_capsule(16#ff01, _Value, _State) ->
    error(boom);
handle_capsule(_Type, _Value, State) ->
    {ok, State}.

terminate(Reason, State) ->
    masque_udp_bind_proxy_handler:terminate(Reason, State).
