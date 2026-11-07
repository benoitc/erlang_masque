-module(masque_reverse_accept_handler).
-moduledoc false.

%%% Server side of a reverse connect accept stream carrying TCP
%%% (draft-rosomakho-masque-reverse-connect-01 section 5.3).
%%%
%%% The listener runs it in a CONNECT-TCP session in capsule framing, so
%%% the stream gets that session's blocking writes, half-close, aborts and
%%% flow control. The handler takes its request from the registry and
%%% relays the stream to the process that asked for the connection:
%%%
%%% - `{masque_data, Stream, Bytes}' for each chunk, whose credit comes
%%%   back only through `masque:consumed(Stream, N)';
%%% - `{masque_closed, Stream, peer_fin}' when the client finished
%%%   sending, then `{masque_closed, Stream, Reason}' when the stream ends,
%%%   unless the requester closed it.
%%%
%%% The requester writes with `masque:send/2', which returns once the
%%% bytes are on the stream.

-behaviour(masque_handler).

-export([init/2, handle_data/2, handle_eof/1, handle_info/2, handle_call/3, terminate/2]).

-record(st, {
    id :: non_neg_integer(),
    control :: pid(),
    requester :: pid(),
    mref :: reference(),
    write_closed = false :: boolean(),
    %% The client finished sending.
    eof = false :: boolean(),
    %% The requester called `masque:close/1': it needs no notice.
    closed_by_owner = false :: boolean()
}).

init(#{reverse_id := Id}, _HOpts) ->
    case masque_reverse_registry:take(Id) of
        {ok, #{requester := Requester, control := Control}} ->
            MRef = erlang:monitor(process, Requester),
            %% Handled once the 2xx is out: the control session then hands
            %% the stream to the requester, which may write at once.
            self() ! masque_reverse_opened,
            {ok, #st{id = Id, control = Control, requester = Requester, mref = MRef}};
        error ->
            {stop, {reject, unknown_request}}
    end;
init(_Req, _HOpts) ->
    {stop, {reject, unknown_request}}.

handle_data(Bytes, #st{requester = R} = S) ->
    R ! {masque_data, self(), Bytes},
    {ok, S, [hold_credit]}.

handle_eof(#st{requester = R} = S) ->
    R ! {masque_closed, self(), peer_fin},
    case S#st.write_closed of
        true -> {stop, normal, S};
        false -> {ok, S#st{eof = true}}
    end.

handle_info(masque_reverse_opened, #st{control = C, id = Id} = S) ->
    C ! {masque_reverse_accepted, Id, self()},
    {ok, S};
handle_info({'DOWN', MRef, process, _, _}, #st{mref = MRef} = S) ->
    {stop, requester_gone, S#st{closed_by_owner = true}};
handle_info(_Msg, S) ->
    {ok, S}.

handle_call({send, _Data}, _From, #st{write_closed = true} = S) ->
    {reply, {error, write_closed}, S};
handle_call({send, Data}, _From, S) ->
    {reply, ok, S, [{send_data, Data}]};
handle_call(shutdown_write, _From, #st{write_closed = true} = S) ->
    {reply, ok, S};
%% Both sides done: the stream ends.
handle_call(shutdown_write, _From, #st{eof = true} = S) ->
    {reply, ok, S#st{write_closed = true}, [{send_data, <<>>, true}, close_session]};
handle_call(shutdown_write, _From, S) ->
    {reply, ok, S#st{write_closed = true}, [{send_data, <<>>, true}]};
handle_call({consumed, N}, _From, S) when is_integer(N), N >= 0 ->
    {reply, ok, S, [{release_credit, N}]};
handle_call(stop, _From, S) ->
    {reply, ok, S#st{closed_by_owner = true}, [close_session]};
handle_call(info, _From, #st{id = Id, requester = R} = S) ->
    {reply, #{protocol => tcp, request_id => Id, requester => R}, S};
handle_call(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

terminate(_Reason, #st{closed_by_owner = true}) ->
    ok;
terminate(Reason, #st{requester = R}) ->
    R ! {masque_closed, self(), Reason},
    ok;
terminate(_Reason, _S) ->
    ok.
