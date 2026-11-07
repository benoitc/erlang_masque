-module(masque_reverse_accept_udp_handler).
-moduledoc false.

%%% Server side of a reverse connect accept stream carrying UDP
%%% (draft-rosomakho-masque-reverse-connect-01 section 5.3).
%%%
%%% The listener runs it in a CONNECT-UDP session: datagrams travel as
%%% HTTP Datagrams (QUIC datagrams on h3, DATAGRAM capsules on h2 and
%%% h1). Each one reaches the process that asked for the connection as
%%% `{masque_data, Stream, Payload}'; it sends with `masque:send/2'. UDP
%%% has no flow control: datagrams too large for the path are dropped,
%%% as on any CONNECT-UDP tunnel, and `masque:consumed/2' does nothing.

-behaviour(masque_handler).

-export([init/2, handle_packet/2, handle_info/2, handle_call/3, terminate/2]).

-record(st, {
    id :: non_neg_integer(),
    control :: pid(),
    requester :: pid(),
    mref :: reference(),
    closed_by_owner = false :: boolean()
}).

init(#{reverse_id := Id}, _HOpts) ->
    case masque_reverse_registry:take(Id) of
        {ok, #{requester := Requester, control := Control}} ->
            MRef = erlang:monitor(process, Requester),
            %% Handled once the 2xx is out (see the TCP accept handler).
            self() ! masque_reverse_opened,
            {ok, #st{id = Id, control = Control, requester = Requester, mref = MRef}};
        error ->
            {stop, {reject, unknown_request}}
    end;
init(_Req, _HOpts) ->
    {stop, {reject, unknown_request}}.

handle_packet(Payload, #st{requester = R} = S) ->
    R ! {masque_data, self(), Payload},
    {ok, S}.

handle_info(masque_reverse_opened, #st{control = C, id = Id} = S) ->
    C ! {masque_reverse_accepted, Id, self()},
    {ok, S};
handle_info({'DOWN', MRef, process, _, _}, #st{mref = MRef} = S) ->
    {stop, requester_gone, S#st{closed_by_owner = true}};
handle_info(_Msg, S) ->
    {ok, S}.

handle_call({send, Payload}, _From, S) ->
    {reply, ok, S, [{send, Payload}]};
handle_call({consumed, _N}, _From, S) ->
    {reply, ok, S};
handle_call(shutdown_write, _From, S) ->
    {reply, {error, not_supported}, S};
handle_call(stop, _From, S) ->
    {reply, ok, S#st{closed_by_owner = true}, [close_session]};
handle_call(info, _From, #st{id = Id, requester = R} = S) ->
    {reply, #{protocol => udp, request_id => Id, requester => R}, S};
handle_call(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

terminate(_Reason, #st{closed_by_owner = true}) ->
    ok;
terminate(Reason, #st{requester = R}) ->
    R ! {masque_closed, self(), Reason},
    ok;
terminate(_Reason, _S) ->
    ok.
