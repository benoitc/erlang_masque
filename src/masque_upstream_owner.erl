%%% @doc Per-connection owner for a pooled upstream transport conn.
%%%
%%% One `masque_upstream_owner' gen_server wraps exactly one h2 /
%%% quic_h3 client connection. It is the process that called
%%% `h2:connect/3' / `quic_h3:connect/3', so it is the process both
%%% transport libraries deliver connection-level events to (response
%%% headers, h3 datagrams, connection close, SETTINGS updates). The
%%% owner hands per-stream events off to the calling session via the
%%% transport library's `set_stream_handler/3,4' so `{h2, _, {data,
%%% _, _, _}}' / `{quic_h3, _, {data, _, _, _}}' messages flow to
%%% the session's mailbox directly. The owner only demuxes the
%%% things `set_stream_handler' does not cover: h3 datagrams (which
%%% the transport delivers to the connection owner), stream resets,
%%% and connection-close notifications.
%%%
%%% Lifecycle:
%%%
%%% <ul>
%%%  <li>Spawned by {@link masque_upstream_pool} via the pool dialer
%%%      process, which has just completed the handshake and owns
%%%      the conn. Ownership is transferred to this process on
%%%      start.</li>
%%%  <li>Sessions call `acquire_stream/4' to open a new tunnel on
%%%      the pooled conn; the owner issues the CONNECT request,
%%%      registers the session as the stream's handler, and returns
%%%      `{ok, StreamId, Conn}'.</li>
%%%  <li>Sessions call `release_stream/2' on normal or abnormal exit.
%%%      The owner also monitors every session so a crashed session
%%%      releases its slot automatically.</li>
%%%  <li>When the last stream releases, the owner arms an idle timer
%%%      (default 30 s, override via `idle_timeout_ms'). Expiry ->
%%%      close the conn and stop normally; the pool registry
%%%      observes the DOWN and drops its cache entry.</li>
%%% </ul>
%%%
%%% h1 does not use this module: h1 is 1-tunnel-per-socket, so the
%%% pool bypasses it and sessions keep owning their socket directly.
-module(masque_upstream_owner).
-behaviour(gen_server).

-export([start_link/1, stop/1]).
-export([start_for_pool/3]).
-export([acquire_stream/4, release_stream/2]).
-export([info/1]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-type start_args() :: #{
    transport := h2 | quic_h3,
    conn := pid(),
    %% Optional override for the module used to drive the conn. In
    %% production `h2` / `quic_h3' are both module names and tag
    %% atoms, so they double up; tests supply a mock module that
    %% implements the same contract.
    transport_mod => module(),
    %% Optional; passed back as-is by the registry for logging.
    fingerprint => term(),
    %% Idle window before the owner closes the conn and stops.
    idle_timeout_ms => non_neg_integer() | infinity,
    %% Upper bound on concurrent streams. Defaults: h2 reads the peer
    %% SETTINGS, h3 leaves it dynamic (ask the transport).
    max_streams => pos_integer() | dynamic
}.

-export_type([start_args/0]).

-record(ref, {
    session_pid :: pid(),
    monitor_ref :: reference()
}).

-record(state, {
    transport :: h2 | quic_h3,
    mod :: module(),
    conn :: pid(),
    conn_mon :: reference(),
    fingerprint :: term(),
    refs :: #{non_neg_integer() => #ref{}},
    max_streams :: pos_integer() | dynamic,
    idle_ms :: non_neg_integer() | infinity,
    idle_ref :: undefined | reference()
}).

%%====================================================================
%% API
%%====================================================================

-spec start_link(start_args()) -> {ok, pid()} | {error, term()}.
start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

%% @doc Spawn an owner that dials the upstream itself and becomes
%% the transport connection's owner.
%%
%% The spawned process blocks on the handshake in its init; the
%% transport's `Conn' pid is therefore parented to the owner (no
%% ownership transfer required, which matters for `quic_h3' where
%% the public API does not expose a `controlling_process/2'
%% equivalent). On success it sends `{dial_result, Tag, {ok, Self}}'
%% to `RegistryPid' and then enters the normal gen_server loop. On
%% failure it sends `{dial_result, Tag, {error, Reason}}' and exits
%% normally.
%%
%% `Opts' must contain `transport' (h2 | quic_h3), `host', `port',
%% and any transport-specific `connect_opts'. The optional
%% `transport_mod' points at a mock implementing the same surface
%% so unit tests can drive this path without a real TLS handshake.
-spec start_for_pool(pid(), term(), map()) -> pid().
start_for_pool(RegistryPid, Tag, Opts) ->
    proc_lib:spawn(fun() -> init_for_pool(RegistryPid, Tag, Opts) end).

-spec stop(pid()) -> ok.
stop(Owner) ->
    gen_server:call(Owner, stop, 5000).

%% @doc Open a new tunnel stream on this pooled conn. Issues the
%% CONNECT request synchronously and registers the session as the
%% stream's handler so subsequent stream-data events flow directly
%% to the session's mailbox. Returns the transport's conn pid too
%% so the session can issue its own outbound calls (send_data,
%% send_datagram, etc.).
-spec acquire_stream(pid(), [{binary(), binary()}], pid(), map()) ->
    {ok, non_neg_integer(), pid()} | {error, term()}.
acquire_stream(Owner, Headers, SessionPid, ReqOpts) ->
    gen_server:call(
        Owner,
        {acquire, Headers, SessionPid, ReqOpts},
        30000
    ).

%% @doc Release the stream previously acquired by this session.
%% Safe to call multiple times (second call is a no-op).
-spec release_stream(pid(), non_neg_integer()) -> ok.
release_stream(Owner, StreamId) ->
    gen_server:cast(Owner, {release, StreamId}).

%% @doc Diagnostic snapshot.
-spec info(pid()) -> map().
info(Owner) ->
    gen_server:call(Owner, info, 1000).

%%====================================================================
%% gen_server
%%====================================================================

init(#{transport := Transport, conn := Conn} = Args) ->
    process_flag(trap_exit, true),
    Mod = maps:get(transport_mod, Args, Transport),
    %% Monitor the conn so a dead transport takes the owner down;
    %% the registry's DOWN handler evicts the cache entry from there.
    MRef = erlang:monitor(process, Conn),
    IdleMs = maps:get(idle_timeout_ms, Args, 30000),
    MaxStreams = resolve_max_streams(
        Transport,
        Mod,
        Conn,
        maps:get(max_streams, Args, default)
    ),
    State0 = #state{
        transport = Transport,
        mod = Mod,
        conn = Conn,
        conn_mon = MRef,
        fingerprint = maps:get(fingerprint, Args, undefined),
        refs = #{},
        max_streams = MaxStreams,
        idle_ms = IdleMs,
        idle_ref = undefined
    },
    %% No refs yet; start the idle timer so a conn nobody ever uses
    %% does not sit open forever.
    {ok, arm_idle(State0)}.

handle_call(
    {acquire, Headers, SessionPid, ReqOpts},
    _From,
    #state{refs = Refs, max_streams = MS} = S
) ->
    case at_capacity(maps:size(Refs), MS) of
        true ->
            {reply, {error, stream_limit}, S};
        false ->
            case issue_request(S, Headers, ReqOpts) of
                {ok, StreamId} ->
                    case register_stream(StreamId, SessionPid, S) of
                        {ok, S1} ->
                            {reply, {ok, StreamId, S#state.conn}, cancel_idle(S1)};
                        {error, _} = Err ->
                            _ = cancel_transport_stream(S, StreamId),
                            {reply, Err, S}
                    end;
                {error, _} = Err ->
                    {reply, Err, S}
            end
    end;
handle_call(info, _From, S) ->
    {reply,
        #{
            transport => S#state.transport,
            conn => S#state.conn,
            refs => maps:size(S#state.refs),
            max_streams => S#state.max_streams,
            idle_ms => S#state.idle_ms,
            fingerprint => S#state.fingerprint
        },
        S};
handle_call(stop, _From, S) ->
    {stop, normal, ok, S};
handle_call(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

handle_cast({release, StreamId}, S) ->
    {noreply, drop_stream(StreamId, S)};
handle_cast(_Msg, S) ->
    {noreply, S}.

%% Response headers land on the connection owner with the stream
%% id; route to the session that owns that stream.
handle_info(
    {quic_h3, _Conn, {response, StreamId, _, _} = Evt},
    #state{transport = quic_h3} = S
) ->
    _ = route({quic_h3, S#state.conn, Evt}, StreamId, S),
    {noreply, S};
handle_info(
    {h2, _Conn, {response, StreamId, _, _} = Evt},
    #state{transport = h2} = S
) ->
    _ = route({h2, S#state.conn, Evt}, StreamId, S),
    {noreply, S};
%% Stream data (h2 or h3) that was buffered before the handler was
%% set can arrive as a message when `drain_buffer => false'.
handle_info(
    {quic_h3, _Conn, {data, StreamId, _, _} = Evt},
    #state{transport = quic_h3} = S
) ->
    _ = route({quic_h3, S#state.conn, Evt}, StreamId, S),
    {noreply, S};
handle_info(
    {h2, _Conn, {data, StreamId, _, _} = Evt},
    #state{transport = h2} = S
) ->
    _ = route({h2, S#state.conn, Evt}, StreamId, S),
    {noreply, S};
%% h3 datagrams arrive at the connection owner (this process) with
%% the stream id in the tag; route them to the matching session.
handle_info(
    {quic_h3, _Conn, {datagram, StreamId, _Payload} = Evt},
    #state{transport = quic_h3} = S
) ->
    _ = route({quic_h3, S#state.conn, Evt}, StreamId, S),
    {noreply, S};
%% Stream resets are delivered to the connection owner on both h2
%% and quic_h3; forward to the affected session and drop the slot.
handle_info(
    {quic_h3, _Conn, {stream_reset, StreamId, _} = Evt} = _Msg,
    #state{transport = quic_h3} = S
) ->
    _ = route({quic_h3, S#state.conn, Evt}, StreamId, S),
    {noreply, drop_stream(StreamId, S)};
handle_info(
    {h2, _Conn, {stream_reset, StreamId, _} = Evt},
    #state{transport = h2} = S
) ->
    _ = route({h2, S#state.conn, Evt}, StreamId, S),
    {noreply, drop_stream(StreamId, S)};
%% Connection-closed: fan out to every registered session so they
%% can surface `peer_closed' cleanly, then stop so the registry
%% evicts this owner.
handle_info(
    {h2, _Conn, {closed, _Reason}} = Evt,
    #state{transport = h2} = S
) ->
    broadcast(Evt, S),
    {stop, normal, S};
handle_info(
    {quic_h3, _Conn, {closed, _Reason}} = Evt,
    #state{transport = quic_h3} = S
) ->
    broadcast(Evt, S),
    {stop, normal, S};
%% quic_h3 reports GOAWAY to the connection owner only; each session
%% decides from its own stream id whether it is affected. (h2 already
%% tells every stream handler.)
handle_info(
    {quic_h3, _Conn, {goaway, _Id}} = Evt,
    #state{transport = quic_h3} = S
) ->
    broadcast(Evt, S),
    {noreply, S};
%% The monitored conn died without a graceful close - same outcome.
handle_info(
    {'DOWN', Ref, process, _Pid, Reason},
    #state{conn_mon = Ref} = S
) ->
    broadcast({tagged_closed(S), S#state.conn, {closed, Reason}}, S),
    {stop, normal, S};
%% A registered session died. Release its slot.
handle_info({'DOWN', Ref, process, Pid, _Reason}, S) ->
    {noreply, release_by_monitor(Ref, Pid, S)};
%% Idle-timer expiry: no active streams for idle_ms; close the conn
%% and stop.
handle_info(
    {timeout, Ref, idle},
    #state{idle_ref = Ref} = S
) ->
    _ = close_transport(S),
    {stop, normal, S};
%% Late / stale timer.
handle_info({timeout, _Ref, idle}, S) ->
    {noreply, S};
handle_info(_Msg, S) ->
    {noreply, S}.

terminate(_Reason, S) ->
    _ = close_transport(S),
    ok.

code_change(_OldVsn, S, _Extra) ->
    {ok, S}.

%%====================================================================
%% Internal
%%====================================================================

at_capacity(_N, dynamic) -> false;
at_capacity(N, Max) when is_integer(Max) -> N >= Max.

resolve_max_streams(h2, Mod, Conn, default) ->
    try Mod:get_peer_settings(Conn) of
        Map when is_map(Map) ->
            %% RFC 9113 §6.5.2: default is 100 when absent or 0.
            %% erlang_h2 may also surface `unlimited'; treat as dynamic.
            case maps:get(max_concurrent_streams, Map, 100) of
                0 -> 100;
                unlimited -> dynamic;
                N when is_integer(N), N > 0 -> N;
                _ -> 100
            end;
        _ ->
            100
    catch
        _:_ ->
            100
    end;
resolve_max_streams(quic_h3, _Mod, _Conn, default) ->
    dynamic;
resolve_max_streams(_, _Mod, _Conn, Explicit) when
    is_integer(Explicit), Explicit > 0
->
    Explicit;
resolve_max_streams(_, _Mod, _Conn, dynamic) ->
    dynamic.

issue_request(#state{mod = Mod, conn = Conn}, Headers, Opts) ->
    Mod:request(Conn, Headers, Opts).

cancel_transport_stream(#state{mod = Mod, conn = Conn}, StreamId) ->
    try
        Mod:cancel(Conn, StreamId)
    catch
        _:_ -> ok
    end.

register_stream(
    StreamId,
    SessionPid,
    #state{mod = Mod, conn = Conn, refs = Refs} = S
) ->
    %% `drain_buffer => false' tells the transport to re-emit any
    %% chunks that arrived before registration as `{data, _, _, _}'
    %% messages to the handler. Keeps the session's `handle_info'
    %% clauses the only decode path.
    Result =
        case erlang:function_exported(Mod, set_stream_handler, 4) of
            true ->
                Mod:set_stream_handler(
                    Conn,
                    StreamId,
                    SessionPid,
                    #{drain_buffer => false}
                );
            false ->
                Mod:set_stream_handler(Conn, StreamId, SessionPid)
        end,
    case Result of
        R when R =:= ok; element(1, R) =:= ok ->
            MonRef = erlang:monitor(process, SessionPid),
            {ok, S#state{
                refs = maps:put(
                    StreamId,
                    #ref{
                        session_pid = SessionPid,
                        monitor_ref = MonRef
                    },
                    Refs
                )
            }};
        {error, _} = Err ->
            Err
    end.

drop_stream(StreamId, #state{refs = Refs} = S) ->
    case maps:take(StreamId, Refs) of
        {#ref{monitor_ref = MRef}, Refs1} ->
            _ = erlang:demonitor(MRef, [flush]),
            _ = unset_stream_handler(S, StreamId),
            _ = cancel_transport_stream(S, StreamId),
            maybe_arm_idle(S#state{refs = Refs1});
        error ->
            S
    end.

unset_stream_handler(#state{mod = Mod, conn = Conn}, StreamId) ->
    try
        Mod:unset_stream_handler(Conn, StreamId)
    catch
        _:_ -> ok
    end.

release_by_monitor(MRef, _Pid, #state{refs = Refs} = S) ->
    Entries = maps:to_list(Refs),
    case
        lists:keyfind(
            MRef,
            2,
            [{Sid, R#ref.monitor_ref} || {Sid, R} <- Entries]
        )
    of
        {StreamId, MRef} ->
            drop_stream(StreamId, S);
        false ->
            S
    end.

%% Route a transport event to the session registered for the given
%% stream id. Inner payload shape varies: `{datagram, Sid, Data}',
%% `{stream_reset, Sid, _}', `{response, Sid, _, _}', `{data, Sid,
%% _, _}'. Stream-data typically bypasses the owner via
%% `set_stream_handler/3', but arrives here when buffered chunks are
%% re-emitted with `drain_buffer => false'.
route(Msg, StreamId, #state{refs = Refs}) ->
    case maps:find(StreamId, Refs) of
        {ok, #ref{session_pid = Pid}} -> Pid ! Msg;
        error -> ok
    end.

broadcast(Msg, #state{refs = Refs}) ->
    maps:foreach(
        fun(_Sid, #ref{session_pid = Pid}) -> Pid ! Msg end, Refs
    ).

tagged_closed(#state{transport = h2}) -> h2;
tagged_closed(#state{transport = quic_h3}) -> quic_h3.

close_transport(#state{mod = Mod, conn = Conn}) ->
    try
        Mod:close(Conn)
    catch
        _:_ -> ok
    end.

arm_idle(#state{idle_ms = infinity} = S) ->
    S;
arm_idle(#state{idle_ms = 0} = S) ->
    S;
arm_idle(#state{idle_ref = Old, idle_ms = Ms} = S) ->
    case Old of
        undefined ->
            ok;
        _ ->
            _ = erlang:cancel_timer(Old),
            ok
    end,
    Ref = erlang:start_timer(Ms, self(), idle),
    S#state{idle_ref = Ref}.

cancel_idle(#state{idle_ref = undefined} = S) ->
    S;
cancel_idle(#state{idle_ref = Ref} = S) ->
    _ = erlang:cancel_timer(Ref),
    S#state{idle_ref = undefined}.

maybe_arm_idle(#state{refs = Refs} = S) when map_size(Refs) =:= 0 ->
    arm_idle(S);
maybe_arm_idle(S) ->
    S.

%%====================================================================
%% Self-dialing entry point (used by masque_upstream_pool)
%%====================================================================

init_for_pool(RegistryPid, Tag, Opts) ->
    process_flag(trap_exit, true),
    Transport = maps:get(transport, Opts),
    Mod = maps:get(transport_mod, Opts, Transport),
    case do_dial(Transport, Mod, Opts) of
        {ok, Conn} ->
            Args = Opts#{
                conn => Conn,
                transport => Transport,
                transport_mod => Mod,
                fingerprint => Tag
            },
            {ok, State} = init(Args),
            RegistryPid ! {dial_result, Tag, {ok, self()}},
            gen_server:enter_loop(?MODULE, [], State);
        {error, Reason} ->
            RegistryPid ! {dial_result, Tag, {error, Reason}}
    end.

do_dial(h2, Mod, Opts) ->
    Host = maps:get(host, Opts),
    Port = maps:get(port, Opts),
    ConnOpts = maps:get(connect_opts, Opts, #{}),
    case Mod:connect(Host, Port, ConnOpts#{sync => true}) of
        {ok, Conn} -> {ok, Conn};
        {error, _} = E -> E
    end;
do_dial(quic_h3, Mod, Opts) ->
    Host = maps:get(host, Opts),
    Port = maps:get(port, Opts),
    ConnOpts0 = maps:get(connect_opts, Opts, #{}),
    %% Pooled h3 conns are always opened datagram-capable so the
    %% same conn can carry CONNECT-UDP / -IP / -TCP tunnels.
    ConnOpts = ConnOpts0#{
        sync => true,
        h3_datagram_enabled => true,
        settings =>
            maps:merge(
                #{
                    enable_connect_protocol => 1,
                    h3_datagram => 1
                },
                maps:get(settings, ConnOpts0, #{})
            )
    },
    case Mod:connect(Host, Port, ConnOpts) of
        {ok, Conn} -> {ok, Conn};
        {error, _} = E -> E
    end.
