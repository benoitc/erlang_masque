%%% @doc Test fixture - echo handler that reports its session pid.
%%%
%%% `init/2' sends `{masque_session, self()}' to the pid under
%%% `report_to' in the handler opts, so a suite can monitor the
%%% server-side session process. Packets, capsules and TCP bytes are
%%% echoed, except capsule type `16#ff00', which closes the session,
%%% and `16#ff01', which makes `handle_capsule/3' crash.
%%% With `early_data => Bin' the session also queues a message, before
%%% the stream is finalized, that makes the handler send `Bin' as a
%%% datagram. With `init_delay => Ms' `init/2' sleeps after reporting;
%%% `delay_ports => #{Port => Ms}' does the same for one target port.
%%% `init_actions => Actions' are returned from `init/2'.
-module(masque_report_handler).
-behaviour(masque_handler).

-export([accept/1, init/2, handle_packet/2, handle_capsule/3, handle_data/2, handle_info/2]).

accept(_Req) ->
    accept.

init(Req, Opts) ->
    case maps:find(report_to, Opts) of
        {ok, Pid} ->
            Pid ! {masque_session, self()},
            Pid ! {masque_req, maps:without([handler_opts], Req)};
        error ->
            ok
    end,
    case maps:find(early_data, Opts) of
        {ok, Bin} -> self() ! {masque_test_early_data, Bin};
        error -> ok
    end,
    timer:sleep(maps:get(init_delay, Opts, 0)),
    Port = maps:get(target_port, Req, undefined),
    timer:sleep(maps:get(Port, maps:get(delay_ports, Opts, #{}), 0)),
    {ok, Opts, maps:get(init_actions, Opts, [])}.

handle_packet(Data, State) ->
    {ok, State, [{send, Data}]}.

handle_capsule(16#ff00, _Value, State) ->
    {ok, State, [close_session]};
handle_capsule(16#ff01, _Value, _State) ->
    error(boom);
handle_capsule(Type, Value, State) ->
    {ok, State, [{send_capsule, Type, Value}]}.

handle_data(Data, State) ->
    {ok, State, [{send_data, Data}]}.

handle_info({masque_test_early_data, Bin}, State) ->
    {ok, State, [{send, Bin}]};
handle_info(_Msg, State) ->
    {ok, State}.
