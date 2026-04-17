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

-export([start_link/0,
         start_session/2,
         register_session/3,
         unregister_session/2,
         lookup_session/2]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(state, {
    %% StreamId -> SessionPid
    sessions = #{} :: #{non_neg_integer() => pid()},
    %% MonitorRef -> StreamId (for cleanup on session death)
    monitors = #{} :: #{reference() => non_neg_integer()}
}).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link(?MODULE, [], []).

%% @doc Spawn a session process linked to this router (so the
%% session outlives the short-lived handler fun) and register it.
start_session(RouterPid, SessionArgs) ->
    gen_server:call(RouterPid, {start_session, SessionArgs}).

%% @doc Register `SessionPid` as the owner of `StreamId`'s datagrams.
register_session(RouterPid, StreamId, SessionPid) ->
    gen_server:call(RouterPid, {register, StreamId, SessionPid}).

unregister_session(RouterPid, StreamId) ->
    gen_server:cast(RouterPid, {unregister, StreamId}).

lookup_session(RouterPid, StreamId) ->
    gen_server:call(RouterPid, {lookup, StreamId}).

%%====================================================================
%% gen_server
%%====================================================================

init([]) ->
    process_flag(trap_exit, true),
    {ok, #state{}}.

handle_call({start_session, Args}, _From, S) ->
    #{stream_id := StreamId} = Args,
    Mod = session_module(Args),
    case Mod:start_link(Args) of
        {ok, Pid} ->
            MRef = erlang:monitor(process, Pid),
            {reply, {ok, Pid},
             S#state{sessions = maps:put(StreamId, Pid, S#state.sessions),
                     monitors = maps:put(MRef, StreamId, S#state.monitors)}};
        Err ->
            {reply, Err, S}
    end;
handle_call({register, StreamId, SessionPid}, _From, S) ->
    MRef = erlang:monitor(process, SessionPid),
    {reply, ok,
     S#state{sessions  = maps:put(StreamId, SessionPid, S#state.sessions),
             monitors  = maps:put(MRef, StreamId, S#state.monitors)}};
handle_call({lookup, StreamId}, _From, S) ->
    {reply, maps:find(StreamId, S#state.sessions), S};
handle_call(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

handle_cast({unregister, StreamId}, S) ->
    {noreply, drop_stream(StreamId, S)};
handle_cast(_Msg, S) ->
    {noreply, S}.

%% Forward HTTP/3 datagrams to the registered session. The quarter-
%% stream-id has already been stripped by `quic_h3'; we still carry
%% the original `StreamId' in the message so routing is straightforward.
handle_info({quic_h3, _Conn, {datagram, StreamId, Payload}}, S) ->
    _ = case maps:find(StreamId, S#state.sessions) of
            {ok, Pid} -> Pid ! {masque_datagram_in, StreamId, Payload};
            error     -> ok
        end,
    {noreply, S};
%% Stream-level data can arrive for capsule framing. Route if we have
%% a session; drop otherwise. The session handles capsule framing.
handle_info({quic_h3, _Conn, {data, StreamId, Data, Fin}}, S) ->
    _ = case maps:find(StreamId, S#state.sessions) of
            {ok, Pid} -> Pid ! {masque_stream_data, StreamId, Data, Fin};
            error     -> ok
        end,
    {noreply, S};
handle_info({quic_h3, _Conn, {stream_reset, StreamId, ErrorCode}}, S) ->
    _ = case maps:find(StreamId, S#state.sessions) of
            {ok, Pid} -> Pid ! {masque_stream_reset, StreamId, ErrorCode};
            error     -> ok
        end,
    {noreply, drop_stream(StreamId, S)};
handle_info({'DOWN', MRef, process, _Pid, _Reason}, S) ->
    case maps:take(MRef, S#state.monitors) of
        {StreamId, Monitors2} ->
            {noreply, S#state{
                sessions = maps:remove(StreamId, S#state.sessions),
                monitors = Monitors2}};
        error ->
            {noreply, S}
    end;
handle_info(_Msg, S) ->
    {noreply, S}.

terminate(_Reason, _S) ->
    ok.

code_change(_OldVsn, S, _Extra) ->
    {ok, S}.

%%====================================================================
%% Internal
%%====================================================================

session_module(#{protocol := tcp}) -> masque_tcp_server_session;
session_module(_)                  -> masque_server_session.

drop_stream(StreamId, S) ->
    Sessions2 = maps:remove(StreamId, S#state.sessions),
    Monitors2 = maps:filter(
        fun(MRef, Sid) when Sid =:= StreamId ->
                erlang:demonitor(MRef, [flush]),
                false;
           (_, _) -> true
        end, S#state.monitors),
    S#state{sessions = Sessions2, monitors = Monitors2}.
