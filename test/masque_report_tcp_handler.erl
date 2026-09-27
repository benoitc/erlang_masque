%%% @doc Test fixture - `masque_tcp_proxy_handler' that reports its
%%% session pid.
%%%
%%% `init/2' sends `{masque_session, self()}' to the pid under
%%% `report_to' in the handler opts, then delegates every callback to
%%% the built-in TCP proxy handler. With `early_data => Bin' the
%%% session also queues a message, before the stream is finalized,
%%% that makes the handler send `Bin' to the client. With
%%% `data_delay => Ms' every `handle_data/2' first sleeps, like a
%%% target that stops reading.
-module(masque_report_tcp_handler).
-behaviour(masque_handler).

-export([accept/1, init/2, handle_data/2, handle_eof/1, handle_info/2, terminate/2]).

-define(H, masque_tcp_proxy_handler).

accept(Req) -> ?H:accept(Req).

init(Req, Opts) ->
    case maps:find(report_to, Opts) of
        {ok, Pid} -> Pid ! {masque_session, self()};
        error -> ok
    end,
    case maps:find(early_data, Opts) of
        {ok, Bin} -> self() ! {masque_test_early_data, Bin};
        error -> ok
    end,
    put(masque_test_data_delay, maps:get(data_delay, Opts, 0)),
    ?H:init(Req, Opts).

handle_data(Data, State) ->
    timer:sleep(get(masque_test_data_delay)),
    ?H:handle_data(Data, State).

handle_eof(State) -> ?H:handle_eof(State).

handle_info({masque_test_early_data, Bin}, State) -> {ok, State, [{send_data, Bin}]};
handle_info(Msg, State) -> ?H:handle_info(Msg, State).

terminate(Reason, State) -> ?H:terminate(Reason, State).
