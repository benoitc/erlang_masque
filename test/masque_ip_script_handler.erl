%%% @doc Test fixture - CONNECT-IP handler driven by the test case.
%%%
%%% `handler_opts':
%%% - `report => Pid' gets `{script, init, SessionPid}' and one
%%%   `{script, Event, Arg}' per control capsule from the client
%%%   (`address_request', `address_assign', `route_advertisement'),
%%%   plus `{script, info, Msg}' for other session messages.
%%% - `on_request => answer_first | reject_all | none' (default
%%%   `reject_all'): how an ADDRESS_REQUEST is answered. `answer_first'
%%%   assigns 10.99.0.1 to the first entry only, `none' answers nothing.
%%%
%%% Send `{script_actions, Actions}' to the session pid to make the
%%% handler return `Actions', so a test can put any capsule on the wire.
%%% IP packets are echoed back.
-module(masque_ip_script_handler).
-behaviour(masque_handler).

-export([
    accept/1,
    init/2,
    handle_ip_packet/2,
    handle_address_request/2,
    handle_address_assign/2,
    handle_route_advertisement/2,
    handle_info/2,
    terminate/2
]).

-include("masque_ip.hrl").

accept(_Req) -> accept.

init(_Req, Opts) ->
    report(Opts, init, self()),
    {ok, Opts}.

handle_ip_packet(Packet, Opts) ->
    {ok, Opts, [{send_ip_packet, Packet}]}.

handle_address_request(Requests, Opts) ->
    report(Opts, address_request, Requests),
    case maps:get(on_request, Opts, reject_all) of
        none ->
            {ok, Opts};
        answer_first ->
            [#ip_prefix_request{request_id = Id} | _] = Requests,
            Entry = #ip_assignment{
                request_id = Id, version = 4, address = {10, 99, 0, 1}, prefix_len = 32
            },
            {ok, Opts, [{assign, [Entry]}]};
        reject_all ->
            {ok, Opts, [{assign, masque_ip:reject_requests(Requests)}]}
    end.

handle_address_assign(Entries, Opts) ->
    report(Opts, address_assign, Entries),
    {ok, Opts}.

handle_route_advertisement(Routes, Opts) ->
    report(Opts, route_advertisement, Routes),
    {ok, Opts}.

handle_info({script_actions, Actions}, Opts) ->
    {ok, Opts, Actions};
handle_info(Msg, Opts) ->
    report(Opts, info, Msg),
    {ok, Opts}.

terminate(_Reason, _Opts) -> ok.

report(#{report := Pid}, Event, Arg) when is_pid(Pid) ->
    Pid ! {script, Event, Arg},
    ok;
report(_, _, _) ->
    ok.
