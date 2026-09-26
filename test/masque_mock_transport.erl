%%% @doc Test fixture - a stand-in for `h2' / `quic_h3' that the
%%% upstream-owner unit tests drive instead of a real transport.
%%%
%%% The mock is a gen_server. `start/1' spawns one and returns a pid
%%% that tests hand to `masque_upstream_owner:start_link/1' as
%%% `conn'. The owner's `transport_mod' key points at this module;
%%% every call the owner would make against `h2' / `quic_h3' lands
%%% here and is recorded for later assertions.
%%%
%%% Per-call overrides are supported via `configure/2' so tests can
%%% steer behaviour (return stream ids, fail the next request, etc.)
%%% without a forest of options.
-module(masque_mock_transport).
-behaviour(gen_server).

-export([start/0, start/1, stop/1]).
-export([configure/2, calls/1, simulate/2]).

%% Transport API (owner calls these - must match the h2 / quic_h3
%% shape the owner relies on).
-export([connect/3]).
-export([
    request/3,
    set_stream_handler/3,
    unset_stream_handler/2,
    cancel/2,
    close/1,
    get_peer_settings/1
]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-record(state, {
    next_stream_id :: non_neg_integer(),
    peer_settings :: map(),
    request_result :: {ok, non_neg_integer()} | {error, term()} | auto,
    set_handler_result :: ok | {ok, [term()]} | {error, term()},
    handlers :: #{non_neg_integer() => pid()},
    calls = [] :: [term()]
}).

%%====================================================================
%% Control API
%%====================================================================

start() -> start(#{}).

start(Opts) ->
    gen_server:start(?MODULE, Opts, []).

stop(Pid) ->
    gen_server:stop(Pid).

%% @doc Merge `Overrides' into the mock's behaviour. Supported keys:
%%   `peer_settings'     - map returned by `get_peer_settings/1'
%%   `request_result'    - `{ok, StreamId} | {error, _}' for the
%%                         next `request/3' call, or `auto' to use
%%                         the internal counter.
%%   `set_handler_result' - return value for `set_stream_handler/3'.
configure(Pid, Overrides) ->
    gen_server:call(Pid, {configure, Overrides}).

%% @doc Return the list of `{Fun, Args}' tuples the owner called on
%% this mock, in arrival order.
calls(Pid) ->
    gen_server:call(Pid, calls).

%% @doc Push a transport-level event into the owner's mailbox as if
%% the real transport had delivered it. The owner pid receives the
%% message. Used by tests to simulate `{quic_h3, Conn, {datagram,
%% Sid, Bin}}', `{h2, Conn, {stream_reset, Sid, Err}}', `{h2, Conn,
%% closed}', etc.
simulate(_MockPid, {send_to_owner, OwnerPid, Msg}) ->
    OwnerPid ! Msg,
    ok;
simulate(MockPid, {send_to_stream, StreamId, Msg}) ->
    gen_server:call(MockPid, {deliver_to_stream, StreamId, Msg}).

%%====================================================================
%% Transport surface the owner calls
%%====================================================================

%% `connect/3' is consulted by the self-dial path. Unit tests set a
%% `connect_result' shared env (persistent_term) so multiple calls
%% stay predictable without plumbing a server handle through.
%%
%% Supported values:
%%   `auto'                    - spawn a fresh mock as the conn.
%%   `{ok, Pid}'               - return Pid as the conn.
%%   `{error, Reason}'         - fail.
%%   `{delay, Ms, Inner}'      - sleep Ms, optionally notify a pid,
%%                               then use Inner (same shape as above).
%%                               If `{delay, Ms, {notify, NotifyPid,
%%                               Inner}}` the sleep completes then
%%                               sends `{mock_connected, self()}' to
%%                               NotifyPid before returning Inner.
%%   `{raise, Class, Reason}'  - raise instead of returning.
connect(_Host, _Port, _Opts) ->
    resolve_connect(persistent_term:get({?MODULE, connect_result}, auto)).

resolve_connect(auto) ->
    start();
resolve_connect({delay, Ms, Inner}) ->
    timer:sleep(Ms),
    resolve_connect(Inner);
resolve_connect({notify, NotifyPid, Inner}) ->
    NotifyPid ! {mock_connected, self()},
    resolve_connect(Inner);
resolve_connect({raise, Class, Reason}) ->
    erlang:raise(Class, Reason, []);
resolve_connect({ok, _} = R) ->
    R;
resolve_connect({error, _} = E) ->
    E.

request(MockPid, Headers, Opts) ->
    gen_server:call(MockPid, {request, Headers, Opts}).

set_stream_handler(MockPid, StreamId, HandlerPid) ->
    gen_server:call(MockPid, {set_stream_handler, StreamId, HandlerPid}).

unset_stream_handler(MockPid, StreamId) ->
    gen_server:call(MockPid, {unset_stream_handler, StreamId}).

cancel(MockPid, StreamId) ->
    gen_server:call(MockPid, {cancel, StreamId}).

close(MockPid) ->
    gen_server:call(MockPid, close).

get_peer_settings(MockPid) ->
    gen_server:call(MockPid, get_peer_settings).

%%====================================================================
%% gen_server
%%====================================================================

init(Opts) ->
    {ok, #state{
        next_stream_id = maps:get(start_stream_id, Opts, 1),
        peer_settings = maps:get(peer_settings, Opts, #{}),
        request_result = maps:get(request_result, Opts, auto),
        set_handler_result = maps:get(set_handler_result, Opts, ok),
        handlers = #{}
    }}.

handle_call({configure, Overrides}, _From, S) ->
    S1 = lists:foldl(fun apply_override/2, S, maps:to_list(Overrides)),
    {reply, ok, S1};
handle_call(calls, _From, #state{calls = Calls} = S) ->
    {reply, lists:reverse(Calls), S};
handle_call({deliver_to_stream, StreamId, Msg}, _From, S) ->
    case maps:find(StreamId, S#state.handlers) of
        {ok, Pid} ->
            Pid ! Msg,
            {reply, ok, S};
        error ->
            {reply, {error, no_handler}, S}
    end;
handle_call({request, Headers, Opts}, _From, S) ->
    S1 = record({request, [Headers, Opts]}, S),
    {Reply, S2} =
        case S1#state.request_result of
            auto ->
                Id = S1#state.next_stream_id,
                {{ok, Id}, S1#state{next_stream_id = Id + 4}};
            {ok, _Id} = R ->
                {R, S1};
            {error, _} = R ->
                {R, S1}
        end,
    {reply, Reply, S2};
handle_call({set_stream_handler, StreamId, HandlerPid}, _From, S) ->
    S1 = record({set_stream_handler, [StreamId, HandlerPid]}, S),
    case S1#state.set_handler_result of
        ok ->
            {reply, ok, S1#state{
                handlers = maps:put(
                    StreamId,
                    HandlerPid,
                    S1#state.handlers
                )
            }};
        {ok, _} = R ->
            {reply, R, S1#state{
                handlers = maps:put(
                    StreamId,
                    HandlerPid,
                    S1#state.handlers
                )
            }};
        {error, _} = Err ->
            {reply, Err, S1}
    end;
handle_call({unset_stream_handler, StreamId}, _From, S) ->
    S1 = record({unset_stream_handler, [StreamId]}, S),
    {reply, ok, S1#state{handlers = maps:remove(StreamId, S1#state.handlers)}};
handle_call({cancel, StreamId}, _From, S) ->
    {reply, ok, record({cancel, [StreamId]}, S)};
handle_call(close, _From, S) ->
    {reply, ok, record({close, []}, S)};
handle_call(get_peer_settings, _From, S) ->
    {reply, S#state.peer_settings, record({get_peer_settings, []}, S)};
handle_call(_, _From, S) ->
    {reply, {error, unknown}, S}.

handle_cast(_, S) -> {noreply, S}.

handle_info(_, S) -> {noreply, S}.

terminate(_, _) -> ok.

code_change(_, S, _) -> {ok, S}.

%%====================================================================
%% Internal
%%====================================================================

apply_override({peer_settings, V}, S) -> S#state{peer_settings = V};
apply_override({request_result, V}, S) -> S#state{request_result = V};
apply_override({set_handler_result, V}, S) -> S#state{set_handler_result = V};
apply_override({start_stream_id, V}, S) -> S#state{next_stream_id = V};
apply_override({_, _}, S) -> S.

record(Call, #state{calls = Calls} = S) ->
    S#state{calls = [Call | Calls]}.
