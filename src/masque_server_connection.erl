%%% @doc Per-H3-connection owner + router for MASQUE tunnels.
%%%
%%% The listener's `connection_handler` hook spawns one of these
%%% gen_servers per accepted H3 connection and hands its pid to
%%% `quic_h3' as the connection's `owner'. That makes it the single
%%% receiver of all owner-addressed events (datagrams, stream-data
%%% for non-claimed streams, etc.), which we then route to the
%%% per-tunnel session process keyed by `StreamId'.
-module(masque_server_connection).
-behaviour(gen_server).

-export([
    start_link/1,
    start_link/2,
    start_session/2,
    cancel_pending/2,
    register_session/3,
    unregister_session/2,
    lookup_session/2,
    session_module/1
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
    %% StreamId -> SessionPid
    sessions = #{} :: #{non_neg_integer() => pid()},
    %% MonitorRef -> StreamId (for cleanup on session death)
    monitors = #{} :: #{reference() => non_neg_integer()},
    %% StreamId -> {CallerFrom, Stage, [BufferedMsg]}
    %% Streams being set up asynchronously; messages buffered here.
    %% Stage is the init worker pid, then `{finalizing, Session, MRef}'
    %% once the session is up and sending its 2xx.
    pending = #{} :: #{
        non_neg_integer() =>
            {gen_server:from(), pid() | {finalizing, pid(), reference()}, [term()]}
    },
    %% 0 = unlimited
    max_tunnels = 0 :: non_neg_integer(),
    %% Monitors on the QUIC connection (from `connection_handler') and
    %% the H3 connection (from `connected'). Either going down ends
    %% the router so its sessions are told the connection is gone.
    conn_mons = [] :: [reference()]
}).

%%====================================================================
%% API
%%====================================================================

-spec start_link(non_neg_integer()) -> {ok, pid()} | ignore | {error, term()}.
start_link(MaxTunnels) ->
    gen_server:start_link(?MODULE, [MaxTunnels], []).

%% @doc Start a router that also monitors `QuicConn', the QUIC
%% connection the listener accepted, and stops when it goes down.
-spec start_link(non_neg_integer(), pid()) ->
    {ok, pid()} | ignore | {error, term()}.
start_link(MaxTunnels, QuicConn) ->
    gen_server:start_link(?MODULE, [MaxTunnels, QuicConn], []).

%% @doc Start a session process and register it. The router spawns the
%% session asynchronously so it stays responsive for datagram routing.
%% The caller blocks until the session init completes.
-spec start_session(pid(), map()) -> {ok, pid()} | {error, term()}.
start_session(RouterPid, SessionArgs) ->
    gen_server:call(RouterPid, {start_session, SessionArgs}, 30000).

%% @doc Cancel a pending session that timed out.
-spec cancel_pending(pid(), non_neg_integer()) ->
    ok | {error, already_activated}.
cancel_pending(RouterPid, StreamId) ->
    gen_server:call(RouterPid, {cancel_pending, StreamId}).

%% @doc Register `SessionPid` as the owner of `StreamId`'s datagrams.
-spec register_session(pid(), non_neg_integer(), pid()) -> ok.
register_session(RouterPid, StreamId, SessionPid) ->
    gen_server:call(RouterPid, {register, StreamId, SessionPid}).

-spec unregister_session(pid(), non_neg_integer()) -> ok.
unregister_session(RouterPid, StreamId) ->
    gen_server:cast(RouterPid, {unregister, StreamId}).

-spec lookup_session(pid(), non_neg_integer()) -> {ok, pid()} | error.
lookup_session(RouterPid, StreamId) ->
    gen_server:call(RouterPid, {lookup, StreamId}).

%% @doc Return the session module for the given args.
-spec session_module(map()) -> module().
session_module(#{protocol := tcp}) -> masque_tcp_server_session;
session_module(#{protocol := ip}) -> masque_ip_server_session;
session_module(#{protocol := udp_bind}) -> masque_udp_bind_server_session;
session_module(_) -> masque_server_session.

%%====================================================================
%% gen_server
%%====================================================================

init([MaxTunnels]) ->
    process_flag(trap_exit, true),
    {ok, #state{max_tunnels = MaxTunnels}};
init([MaxTunnels, QuicConn]) ->
    process_flag(trap_exit, true),
    MRef = erlang:monitor(process, QuicConn),
    {ok, #state{max_tunnels = MaxTunnels, conn_mons = [MRef]}}.

handle_call({start_session, Args}, From, S) ->
    Active = maps:size(S#state.sessions) + maps:size(S#state.pending),
    case S#state.max_tunnels > 0 andalso Active >= S#state.max_tunnels of
        true ->
            {reply, {error, too_many_tunnels}, S};
        false ->
            #{stream_id := StreamId} = Args,
            Mod = session_module(Args),
            Self = self(),
            WorkerPid = spawn_link(fun() ->
                Self !
                    {session_init_done, StreamId, gen_server:start(Mod, Args, [{timeout, 30000}])}
            end),
            erlang:monitor(process, WorkerPid),
            {noreply, S#state{
                pending = maps:put(
                    StreamId, {From, WorkerPid, []}, S#state.pending
                )
            }}
    end;
handle_call({cancel_pending, StreamId}, _From, S) ->
    case maps:find(StreamId, S#state.pending) of
        {ok, {_, {finalizing, _, _}, _}} ->
            %% The 2xx may already be on the wire: too late to reject.
            {reply, {error, already_activated}, S};
        {ok, _} ->
            {reply, ok, S#state{pending = maps:remove(StreamId, S#state.pending)}};
        error ->
            case maps:is_key(StreamId, S#state.sessions) of
                true -> {reply, {error, already_activated}, S};
                false -> {reply, ok, S}
            end
    end;
handle_call({register, StreamId, SessionPid}, _From, S) ->
    MRef = erlang:monitor(process, SessionPid),
    {reply, ok, S#state{
        sessions = maps:put(StreamId, SessionPid, S#state.sessions),
        monitors = maps:put(MRef, StreamId, S#state.monitors)
    }};
handle_call({lookup, StreamId}, _From, S) ->
    {reply, maps:find(StreamId, S#state.sessions), S};
handle_call(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

handle_cast({unregister, StreamId}, S) ->
    {noreply, drop_stream(StreamId, S)};
handle_cast(connection_closed, S) ->
    {stop, connection_closed, S};
handle_cast(_Msg, S) ->
    {noreply, S}.

%% Session init completed successfully. Finalize is asynchronous so a
%% slow `send_response' does not stall datagram routing: the session
%% answers with `{masque_finalized, StreamId, Pid, Result}'.
handle_info({session_init_done, StreamId, {ok, Pid}}, S) ->
    case maps:find(StreamId, S#state.pending) of
        {ok, {From, _WorkerPid, Buf}} ->
            link(Pid),
            MRef = erlang:monitor(process, Pid),
            gen_server:cast(Pid, {finalize, self()}),
            {noreply, S#state{
                pending = maps:put(
                    StreamId,
                    {From, {finalizing, Pid, MRef}, Buf},
                    S#state.pending
                )
            }};
        error ->
            %% Cancelled (caller timed out)
            try
                gen_server:stop(Pid, cancelled, 5000)
            catch
                _:_ -> ok
            end,
            {noreply, S}
    end;
handle_info({masque_finalized, StreamId, Pid, Result}, S) ->
    case maps:take(StreamId, S#state.pending) of
        {{From, {finalizing, Pid, MRef}, Buf}, Pending2} when Result =:= ok ->
            _ = [Pid ! Msg || Msg <- lists:reverse(Buf)],
            gen_server:reply(From, {ok, Pid}),
            {noreply, S#state{
                sessions = maps:put(StreamId, Pid, S#state.sessions),
                monitors = maps:put(MRef, StreamId, S#state.monitors),
                pending = Pending2
            }};
        {{From, {finalizing, Pid, MRef}, _Buf}, Pending2} ->
            %% The session stops itself; the stream is unusable.
            unlink(Pid),
            erlang:demonitor(MRef, [flush]),
            gen_server:reply(From, {error, stream_dead}),
            {noreply, S#state{pending = Pending2}};
        _ ->
            {noreply, S}
    end;
handle_info({session_init_done, StreamId, {error, Reason}}, S) ->
    case maps:take(StreamId, S#state.pending) of
        {{From, _WorkerPid, _Buf}, Pending2} ->
            gen_server:reply(From, {error, Reason}),
            {noreply, S#state{pending = Pending2}};
        error ->
            {noreply, S}
    end;
%% Linked worker EXIT - cleanup handled via monitor DOWN.
handle_info({'EXIT', _Pid, _Reason}, S) ->
    {noreply, S};
%% Forward HTTP/3 datagrams to the registered session or buffer
%% for pending sessions.
handle_info({quic_h3, _Conn, {datagram, StreamId, Payload}}, S) ->
    route_to_session(
        StreamId,
        {masque_datagram_in, StreamId, Payload},
        S
    );
%% Stream-level data for capsule framing.
handle_info({quic_h3, _Conn, {data, StreamId, Data, Fin}}, S) ->
    route_to_session(
        StreamId,
        {masque_stream_data, StreamId, Data, Fin},
        S
    );
handle_info({quic_h3, _Conn, {stream_reset, StreamId, ErrorCode}}, S) ->
    _ =
        case maps:find(StreamId, S#state.sessions) of
            {ok, Pid} -> Pid ! {masque_stream_reset, StreamId, ErrorCode};
            error -> ok
        end,
    {noreply, drop_stream(StreamId, S)};
%% The H3 connection is up: watch it so a crash (no `closed' event)
%% still ends the router.
handle_info({quic_h3, Conn, connected}, #state{conn_mons = Mons} = S) ->
    MRef = erlang:monitor(process, Conn),
    {noreply, S#state{conn_mons = [MRef | Mons]}};
handle_info({quic_h3, _Conn, {closed, _Reason}}, S) ->
    {stop, normal, S};
handle_info({'DOWN', MRef, process, DownPid, Reason}, S) ->
    case lists:member(MRef, S#state.conn_mons) of
        true -> {stop, normal, S};
        false -> handle_down(MRef, DownPid, Reason, S)
    end;
handle_info(_Msg, S) ->
    {noreply, S}.

handle_down(MRef, DownPid, Reason, S) ->
    case maps:take(MRef, S#state.monitors) of
        {StreamId, Monitors2} ->
            %% Session died
            {noreply, S#state{
                sessions = maps:remove(StreamId, S#state.sessions),
                monitors = Monitors2
            }};
        error ->
            %% Worker or finalizing session died - clean up pending entry
            case find_pending_by_worker(DownPid, S#state.pending) of
                {StreamId, {From, {finalizing, _, _}, _}} ->
                    %% The session died while finalizing, possibly
                    %% after its 2xx.
                    gen_server:reply(From, {error, stream_dead}),
                    {noreply, S#state{
                        pending = maps:remove(StreamId, S#state.pending)
                    }};
                {StreamId, {From, _Worker, _}} when Reason =/= normal ->
                    gen_server:reply(From, {error, {worker_crash, Reason}}),
                    {noreply, S#state{
                        pending = maps:remove(StreamId, S#state.pending)
                    }};
                _ ->
                    {noreply, S}
            end
    end.

terminate(_Reason, #state{sessions = Sessions, pending = Pending}) ->
    maps:foreach(
        fun(_StreamId, Pid) ->
            gen_server:cast(Pid, connection_closed)
        end,
        Sessions
    ),
    %% Kill pending workers so their in-progress sessions get
    %% router DOWN and stop.
    maps:foreach(
        fun
            (_StreamId, {_From, {finalizing, Pid, _}, _Buf}) ->
                gen_server:cast(Pid, connection_closed);
            (_StreamId, {_From, WorkerPid, _Buf}) ->
                exit(WorkerPid, kill)
        end,
        Pending
    ),
    ok.

code_change(_OldVsn, S, _Extra) ->
    {ok, S}.

%%====================================================================
%% Internal
%%====================================================================

-define(MAX_PENDING_BUF, 100).

route_to_session(StreamId, Msg, S) ->
    case maps:find(StreamId, S#state.sessions) of
        {ok, Pid} ->
            Pid ! Msg,
            {noreply, S};
        error ->
            case maps:find(StreamId, S#state.pending) of
                {ok, {From, W, Buf}} when
                    length(Buf) < ?MAX_PENDING_BUF
                ->
                    {noreply, S#state{
                        pending = maps:put(
                            StreamId,
                            {From, W, [Msg | Buf]},
                            S#state.pending
                        )
                    }};
                {ok, _} ->
                    %% Buffer full, drop to prevent memory growth
                    {noreply, S};
                error ->
                    {noreply, S}
            end
    end.

find_pending_by_worker(WorkerPid, Pending) ->
    maps:fold(
        fun
            (StreamId, {_From, {finalizing, P, _}, _Buf} = Val, Acc) ->
                case P =:= WorkerPid of
                    true -> {StreamId, Val};
                    false -> Acc
                end;
            (StreamId, {_From, W, _Buf} = Val, Acc) ->
                case W =:= WorkerPid of
                    true -> {StreamId, Val};
                    false -> Acc
                end
        end,
        error,
        Pending
    ).

drop_stream(StreamId, S) ->
    Sessions2 = maps:remove(StreamId, S#state.sessions),
    Monitors2 = maps:filter(
        fun
            (MRef, Sid) when Sid =:= StreamId ->
                erlang:demonitor(MRef, [flush]),
                false;
            (_, _) ->
                true
        end,
        S#state.monitors
    ),
    Pending2 = drop_pending(StreamId, S#state.pending),
    S#state{
        sessions = Sessions2,
        monitors = Monitors2,
        pending = Pending2
    }.

%% A stream that goes away while its session is still starting answers
%% the waiting listener with `stream_dead' so it does not sit out the
%% `start_session' timeout. A session already started is released and
%% stopped; a worker still running is left to finish, and its session
%% is stopped when `session_init_done' finds no pending entry.
drop_pending(StreamId, Pending) ->
    case maps:take(StreamId, Pending) of
        {{From, {finalizing, Pid, MRef}, _Buf}, Pending2} ->
            erlang:demonitor(MRef, [flush]),
            unlink(Pid),
            gen_server:cast(Pid, connection_closed),
            gen_server:reply(From, {error, stream_dead}),
            Pending2;
        {{From, _WorkerPid, _Buf}, Pending2} ->
            gen_server:reply(From, {error, stream_dead}),
            Pending2;
        error ->
            Pending
    end.
