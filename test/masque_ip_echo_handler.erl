%%% @doc Test handler for CONNECT-IP: echoes every inbound IP packet
%%% back to the client on arrival. Used by masque_ip_h3_SUITE and
%%% masque_ip_h2_SUITE.
-module(masque_ip_echo_handler).
-behaviour(masque_handler).

-export([accept/1, init/2, handle_ip_packet/2,
         handle_address_request/2, terminate/2]).

accept(_Req) -> accept.

init(_Req, Opts) ->
    %% If the test registered `ping' in Opts, notify on every callback.
    ping(Opts, {init, self()}),
    {ok, Opts}.

handle_ip_packet(Packet, Opts) ->
    ping(Opts, {ip_packet, byte_size(Packet)}),
    {ok, Opts, [{send_ip_packet, Packet}]}.

handle_address_request(Requests, Opts) ->
    ping(Opts, {addr_req, length(Requests)}),
    Entries = masque_ip:reject_requests(Requests),
    {ok, Opts, [{assign, Entries}]}.

terminate(_Reason, _State) -> ok.

ping(#{ping := Pid}, Msg) when is_pid(Pid) ->
    Pid ! {echo_handler, Msg};
ping(_, _) ->
    ok.
