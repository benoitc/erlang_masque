%%% @doc Test fixture - the default udp-bind handler, except that
%%% capsule type `16#ff01' makes `handle_capsule/3' crash. With
%%% `early_assign => {IP, Port}' the session also queues a message,
%%% before the stream is finalized, that makes the handler open a
%%% compression context for that peer. With `response_headers => none'
%%% the handler returns no headers (no `Proxy-Public-Address'), with
%%% `address_only' only `Proxy-Public-Address'; either way its
%%% `terminate/2' then reports `{bind_handler_terminated, Reason}' to
%%% `report_to'. Capsule `16#ff02' (value: one id byte) makes it close
%%% that context and then try to open one to 127.0.0.1:9; `16#ff03'
%%% (value: a 16-bit port) makes it open one to 127.0.0.1 on that port.
-module(masque_crash_bind_handler).

-export([init/2, handle_bind_packet/3, handle_info/2, handle_capsule/3, terminate/2]).

init(Req, Opts) ->
    case maps:find(early_assign, Opts) of
        {ok, Peer} -> self() ! {masque_test_early_assign, Peer};
        error -> ok
    end,
    case masque_udp_bind_proxy_handler:init(Req, Opts) of
        {ok, State, [{response_headers, Headers}]} ->
            case maps:get(response_headers, Opts, all) of
                all ->
                    {ok, State, [{response_headers, Headers}]};
                Which ->
                    put(masque_test_report_to, maps:get(report_to, Opts, undefined)),
                    {ok, State, [{response_headers, keep(Which, Headers)}]}
            end;
        Other ->
            Other
    end.

keep(none, _Headers) ->
    [];
keep(address_only, Headers) ->
    [H || {<<"proxy-public-address">>, _} = H <- Headers].

handle_bind_packet(Peer, Payload, State) ->
    masque_udp_bind_proxy_handler:handle_bind_packet(Peer, Payload, State).

handle_info({masque_test_early_assign, Peer}, State) ->
    {ok, State, [{compression_assign, Peer}]};
handle_info(Msg, State) ->
    masque_udp_bind_proxy_handler:handle_info(Msg, State).

handle_capsule(16#ff01, _Value, _State) ->
    error(boom);
%% Close context `Id', then try to open a compressed context.
handle_capsule(16#ff02, <<Id>>, State) ->
    {ok, State, [{compression_close, Id}, {compression_assign, {{127, 0, 0, 1}, 9}}]};
%% Open a compressed context to 127.0.0.1:`Port'.
handle_capsule(16#ff03, <<Port:16>>, State) ->
    {ok, State, [{compression_assign, {{127, 0, 0, 1}, Port}}]};
handle_capsule(_Type, _Value, State) ->
    {ok, State}.

terminate(Reason, State) ->
    case get(masque_test_report_to) of
        Pid when is_pid(Pid) -> Pid ! {bind_handler_terminated, Reason};
        _ -> ok
    end,
    masque_udp_bind_proxy_handler:terminate(Reason, State).
