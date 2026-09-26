%%% @doc Test fixture - CONNECT-IP handler that sends an unprompted
%%% `ADDRESS_ASSIGN' (`request_id = 0') on tunnel start.
%%%
%%% The built-in `masque_ip_proxy_handler' only emits assignments in
%%% response to a client `ADDRESS_REQUEST', so the chain handler's
%%% unprompted-forwarding path has no real upstream to exercise.
%%% This fixture gives the chain CT suite one.
%%%
%%% With `assign_on_init => true' in `handler_opts' the assignment is
%%% an init action instead, so it goes out right after the 2xx.
-module(masque_ip_unprompted_handler).
-behaviour(masque_handler).

-export([accept/1, init/2, handle_ip_packet/2, terminate/2]).

-include("masque_ip.hrl").

accept(_Req) -> accept.

init(_Req, #{assign_on_init := true}) ->
    {ok, #{sent => true}, [{assign, [assignment()]}]};
init(_Req, _Opts) ->
    %% Cannot send the unprompted ADDRESS_ASSIGN in init: for h3 the
    %% session stream is not claimed yet, and pending-action delivery
    %% on init races with the incoming-from-egress path. Defer until
    %% the first client packet arrives; the handler has a fully open
    %% stream by then.
    {ok, #{sent => false}}.

handle_ip_packet(Pkt, #{sent := false} = S) ->
    {ok, S#{sent := true}, [
        {assign, [assignment()]},
        {send_ip_packet, Pkt}
    ]};
handle_ip_packet(Pkt, S) ->
    {ok, S, [{send_ip_packet, Pkt}]}.

terminate(_Reason, _State) -> ok.

assignment() ->
    #ip_assignment{
        request_id = 0,
        version = 4,
        address = {10, 77, 0, 1},
        prefix_len = 32
    }.
