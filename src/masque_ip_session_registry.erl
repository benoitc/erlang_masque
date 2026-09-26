%%% Cross-session address registry for CONNECT-IP.
%%%
%%% Stores `{Version, StartAddr, EndAddr, Prefix} -> {SessionPid,
%%% ContextId}` assignments so an out-of-band consumer (e.g. a TUN
%%% device owner) can answer "which session serves destination X?"
%%% without reaching into per-session state.
%%%
%%% Storage is a single ETS `ordered_set` keyed by
%%% `{Version, StartIntAddr}`. Lookup does interval inclusion: find
%%% the entry with the largest start address `=<` the probe and
%%% verify the end address `>=` the probe. Because registrations are
%%% rejected when their range overlaps an existing entry, at most one
%%% interval can cover any given address.
%%%
%%% The gen_server itself is only on the write path (register /
%%% release / monitor handling). Lookups go directly through ETS so
%%% read traffic does not serialise on the server.
%%%
%%% All write APIs are tolerant of the registry not being started -
%%% they become no-ops when `whereis(?MODULE) =:= undefined`. This
%%% keeps test environments that don't boot the application from
%%% needing extra setup, and keeps the proxy handler simple (it
%%% always calls `register/5` / `release/3` without a feature flag).
-module(masque_ip_session_registry).
-moduledoc false.
-behaviour(gen_server).

-export([start_link/0]).
-export([register/5, release/3, release/4, release_pid/1, lookup/1, all/0]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-define(TABLE, ?MODULE).

-record(state, {monitors = #{} :: #{reference() => [tuple()]}}).

%%====================================================================
%% Public API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% Register a host address or prefix as served by `SessionPid`.
%% Returns `{error, conflict}` if the proposed range overlaps any
%% existing registration, including an exact repeat; otherwise `ok`.
-spec register(
    4 | 6,
    inet:ip4_address() | inet:ip6_address(),
    non_neg_integer(),
    pid(),
    non_neg_integer()
) -> ok | {error, conflict}.
register(V, Addr, Pfx, Pid, ContextId) when
    (V =:= 4 orelse V =:= 6),
    is_integer(Pfx),
    is_pid(Pid),
    is_integer(ContextId)
->
    case whereis(?MODULE) of
        undefined ->
            ok;
        _Server ->
            gen_server:call(
                ?MODULE,
                {register, V, Addr, Pfx, Pid, ContextId}
            )
    end.

%% Release a range registered by the calling process. Same as
%% `release(V, Addr, Pfx, self())`.
-spec release(
    4 | 6,
    inet:ip4_address() | inet:ip6_address(),
    non_neg_integer()
) -> ok.
release(V, Addr, Pfx) when V =:= 4; V =:= 6 ->
    release(V, Addr, Pfx, self()).

%% Release a range registered by `Pid`. No-op if the range was
%% not registered or belongs to another pid, so a session can never
%% drop an entry another session now owns.
-spec release(
    4 | 6,
    inet:ip4_address() | inet:ip6_address(),
    non_neg_integer(),
    pid()
) -> ok.
release(V, Addr, Pfx, Pid) when (V =:= 4 orelse V =:= 6), is_pid(Pid) ->
    case whereis(?MODULE) of
        undefined -> ok;
        _Server -> gen_server:call(?MODULE, {release, V, Addr, Pfx, Pid})
    end.

%% Release every range owned by `Pid`. Used by the registry's
%% own `'DOWN'` handler; exposed for tests and explicit cleanup.
-spec release_pid(pid()) -> ok.
release_pid(Pid) when is_pid(Pid) ->
    case whereis(?MODULE) of
        undefined -> ok;
        _Server -> gen_server:call(?MODULE, {release_pid, Pid})
    end.

%% Look up the session serving `IP`. Reads ETS directly.
-spec lookup(inet:ip_address()) ->
    {ok, pid(), non_neg_integer()} | not_found.
lookup(IP) ->
    try
        case normalise(IP) of
            {V, Int} -> lookup_int(V, Int);
            error -> not_found
        end
    catch
        %% table absent
        error:badarg -> not_found
    end.

%% Snapshot of every registration. Intended for diagnostics.
-spec all() ->
    [{4 | 6, non_neg_integer(), non_neg_integer(), non_neg_integer(), pid(), non_neg_integer()}].
all() ->
    try
        [
            {V, Start, End, Pfx, Pid, Ctx}
         || {{V, Start}, End, Pfx, Pid, Ctx, _MRef} <- ets:tab2list(?TABLE)
        ]
    catch
        error:badarg -> []
    end.

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    _ = ets:new(
        ?TABLE,
        [
            ordered_set,
            named_table,
            public,
            {read_concurrency, true},
            {write_concurrency, true}
        ]
    ),
    {ok, #state{}}.

handle_call({register, V, Addr, Pfx, Pid, Ctx}, _From, S) ->
    case to_int(V, Addr) of
        error ->
            {reply, {error, bad_address}, S};
        Start ->
            End = range_end(Start, V, Pfx),
            Key = {V, Start},
            case overlap_check(V, Start, End) of
                ok ->
                    MRef = erlang:monitor(process, Pid),
                    true = ets:insert(
                        ?TABLE,
                        {Key, End, Pfx, Pid, Ctx, MRef}
                    ),
                    Mon = maps:get(MRef, S#state.monitors, []),
                    Mons = (S#state.monitors)#{
                        MRef => [{V, Start, Pfx} | Mon]
                    },
                    {reply, ok, S#state{monitors = Mons}};
                conflict ->
                    {reply, {error, conflict}, S}
            end
    end;
handle_call({release, V, Addr, Pfx, Pid}, _From, S) ->
    case to_int(V, Addr) of
        error ->
            {reply, ok, S};
        Start ->
            S2 = release_key({V, Start}, Pfx, Pid, S),
            {reply, ok, S2}
    end;
handle_call({release_pid, Pid}, _From, S) ->
    S2 = release_by_pid(Pid, S),
    {reply, ok, S2};
handle_call(_Other, _From, S) ->
    {reply, {error, bad_call}, S}.

handle_cast(_Msg, S) -> {noreply, S}.

handle_info(
    {'DOWN', MRef, process, _Pid, _Reason},
    #state{monitors = Mons} = S
) ->
    case maps:take(MRef, Mons) of
        {Ranges, Mons1} ->
            lists:foreach(
                fun({V, Start, _Pfx}) ->
                    _ = ets:delete(?TABLE, {V, Start}),
                    masque_metrics:ip_release_inc()
                end,
                Ranges
            ),
            {noreply, S#state{monitors = Mons1}};
        error ->
            {noreply, S}
    end;
handle_info(_Other, S) ->
    {noreply, S}.

terminate(_Reason, _S) -> ok.

code_change(_OldVsn, S, _Extra) -> {ok, S}.

%%====================================================================
%% Internal
%%====================================================================

normalise({_, _, _, _} = A) -> {4, to_int(4, A)};
normalise({_, _, _, _, _, _, _, _} = A) -> {6, to_int(6, A)};
normalise(_) -> error.

to_int(4, {A, B, C, D}) when
    A >= 0,
    A =< 255,
    B >= 0,
    B =< 255,
    C >= 0,
    C =< 255,
    D >= 0,
    D =< 255
->
    (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D;
to_int(6, {A, B, C, D, E, F, G, H}) ->
    (A bsl 112) bor (B bsl 96) bor (C bsl 80) bor (D bsl 64) bor
        (E bsl 48) bor (F bsl 32) bor (G bsl 16) bor H;
to_int(_, _) ->
    error.

range_end(Start, 4, Pfx) when Pfx >= 0, Pfx =< 32 ->
    Start bor ((1 bsl (32 - Pfx)) - 1);
range_end(Start, 6, Pfx) when Pfx >= 0, Pfx =< 128 ->
    Start bor ((1 bsl (128 - Pfx)) - 1).

%% Check whether a proposed range conflicts with any existing entry.
%% Returns `ok' or `conflict'. An exact-key match is a conflict too,
%% whoever owns it, to keep the contract strict.
overlap_check(V, Start, End) ->
    Key = {V, Start},
    case ets:lookup(?TABLE, Key) of
        [{Key, _End, _Pfx, _Pid, _Ctx, _MRef}] ->
            conflict;
        [] ->
            case ets:prev(?TABLE, Key) of
                '$end_of_table' ->
                    overlap_check_next(V, Key, End);
                {V, _} = Prev ->
                    case ets:lookup(?TABLE, Prev) of
                        [{Prev, PrevEnd, _, _, _, _}] when PrevEnd >= Start ->
                            conflict;
                        _ ->
                            overlap_check_next(V, Key, End)
                    end;
                _OtherVer ->
                    overlap_check_next(V, Key, End)
            end
    end.

overlap_check_next(V, Key, End) ->
    case ets:next(?TABLE, Key) of
        '$end_of_table' -> ok;
        {V, NextStart} when NextStart =< End -> conflict;
        _ -> ok
    end.

lookup_int(V, Int) ->
    Probe = {V, Int + 1},
    case ets:prev(?TABLE, Probe) of
        '$end_of_table' ->
            not_found;
        {V, _} = Key ->
            case ets:lookup(?TABLE, Key) of
                [{Key, End, _Pfx, Pid, Ctx, _MRef}] when End >= Int ->
                    {ok, Pid, Ctx};
                _ ->
                    not_found
            end;
        _OtherVer ->
            not_found
    end.

release_key({V, Start} = Key, Pfx, Pid, #state{monitors = Mons} = S) ->
    case ets:lookup(?TABLE, Key) of
        [{Key, _End, Pfx, Pid, _Ctx, MRef}] ->
            true = ets:delete(?TABLE, Key),
            masque_metrics:ip_release_inc(),
            Mons1 =
                case maps:find(MRef, Mons) of
                    error ->
                        Mons;
                    {ok, Ranges} ->
                        Ranges1 = [R || R <- Ranges, R =/= {V, Start, Pfx}],
                        case Ranges1 of
                            [] ->
                                erlang:demonitor(MRef, [flush]),
                                maps:remove(MRef, Mons);
                            _ ->
                                Mons#{MRef => Ranges1}
                        end
                end,
            S#state{monitors = Mons1};
        _ ->
            S
    end.

release_by_pid(Pid, #state{monitors = Mons} = S) ->
    {Mons1, Released} = maps:fold(
        fun(MRef, Ranges, {Acc, Drop}) ->
            case ranges_for_pid(Pid, Ranges) of
                [] ->
                    {Acc#{MRef => Ranges}, Drop};
                MatchedAll when MatchedAll =:= Ranges ->
                    erlang:demonitor(MRef, [flush]),
                    {Acc, Drop ++ MatchedAll};
                _Some ->
                    {Acc#{MRef => Ranges}, Drop}
            end
        end,
        {#{}, []},
        Mons
    ),
    lists:foreach(
        fun({V, Start, _Pfx}) ->
            _ = ets:delete(?TABLE, {V, Start}),
            masque_metrics:ip_release_inc()
        end,
        Released
    ),
    S#state{monitors = Mons1}.

ranges_for_pid(Pid, Ranges) ->
    [
        R
     || R <- Ranges,
        {V, Start, _Pfx0} <- [R],
        case ets:lookup(?TABLE, {V, Start}) of
            [{_, _End, _Pfx1, P, _Ctx, _MRef}] when P =:= Pid -> true;
            _ -> false
        end
    ].
