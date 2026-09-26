%%% Registry for pooled upstream MASQUE connections.
%%%
%%% Callers ask for an owner that can open a MASQUE tunnel against
%%% the configured upstream proxy. The registry either returns a
%%% cached `masque_upstream_owner` pid that has spare stream
%%% capacity, or spawns a fresh one that self-dials and notifies the
%%% registry when it is ready. Single-flight: multiple callers for
%%% the same fingerprint while a dial is in progress all block on
%%% the same result.
%%%
%%% Fingerprints encode host + port + transport + a hash of
%%% connection-affecting opts (`verify`, `cacerts`, `ssl_opts`,
%%% `alpn`). Two callers with different trust or ALPN settings get
%%% different owners even if they target the same host:port.
%%%
%%% The registry itself never blocks on a handshake; the async
%%% spawn of the owner process handles that. A slow upstream only
%%% stalls callers on its own key. The registry monitors each owner
%%% from the moment it is spawned, so a dial that crashes fails its
%%% waiters instead of leaving the key stuck in the dialing state.
%%%
%%% Owners tell the registry when they reach or leave their stream
%%% limit. Checkout skips full owners and dials another connection
%%% for the same fingerprint when every cached owner is full.
%%%
%%% h1 is not handled here - the pool is opt-in for h2 / h3 only.
%%% Callers that want to pool an h1 upstream receive `{error,
%%% pool_unsupported_for_transport}` and should fall back to the
%%% direct per-tunnel path.
-module(masque_upstream_pool).
-moduledoc false.
-behaviour(gen_server).

-export([start_link/0]).
-export([checkout/2, close_all/0]).
-export([fingerprint/4]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-type fingerprint() :: {
    Host :: binary() | string(),
    Port :: inet:port_number(),
    Transport :: h2 | quic_h3,
    OptsHash :: binary()
}.

-export_type([fingerprint/0]).

-record(entry, {
    owner :: pid(),
    mon_ref :: reference(),
    full = false :: boolean()
}).

-record(dial, {
    owner :: pid(),
    mon_ref :: reference(),
    waiters = [] :: [gen_server:from()]
}).

-record(state, {
    cache = #{} :: #{fingerprint() => [#entry{}]},
    dialing = #{} :: #{fingerprint() => #dial{}},
    owner_ix = #{} :: #{reference() => fingerprint()}
}).

-define(CHECKOUT_TIMEOUT, 60000).

%%====================================================================
%% API
%%====================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% Get an owner for the given fingerprint. Opens a new one on
%% cache miss, blocks briefly on a concurrent dial for the same
%% fingerprint, returns `{error, _}` on dial failure.
%%
%% `Opts` carries everything the owner needs to dial: `host`, `port`,
%% `connect_opts`, optional `transport_mod` (for tests), plus any
%% owner-level tuning (`idle_timeout_ms`, `max_streams`). A dial
%% that does not finish within `checkout_timeout_ms` (default 60 s)
%% returns `{error, timeout}`.
-spec checkout(fingerprint(), map()) ->
    {ok, pid()} | {error, term()}.
checkout(FP, Opts) ->
    Timeout = maps:get(checkout_timeout_ms, Opts, ?CHECKOUT_TIMEOUT),
    try
        gen_server:call(?MODULE, {checkout, FP, Opts}, Timeout)
    catch
        exit:{Reason, {gen_server, call, _}} -> {error, Reason}
    end.

%% Tear down every pooled owner. Used on application shutdown
%% and in tests. Safe to call while callers are in flight - they
%% receive `{error, shutdown}`.
-spec close_all() -> ok.
close_all() ->
    gen_server:call(?MODULE, close_all, 10000).

%% Build a fingerprint from the host / port / transport and the
%% connection-affecting subset of `Opts`. Stable under re-ordering
%% of list-valued opts so two callers that pass `ssl_opts` in
%% different order still hash to the same key.
-spec fingerprint(
    binary() | string(),
    inet:port_number(),
    h2 | quic_h3,
    map()
) -> fingerprint().
fingerprint(Host, Port, Transport, Opts) when is_map(Opts) ->
    Canon = #{
        verify => maps:get(verify, Opts, verify_peer),
        cacerts => maps:get(cacerts, Opts, default),
        ssl_opts => canonical_ssl_opts(maps:get(ssl_opts, Opts, [])),
        alpn => maps:get(alpn, Opts, default)
    },
    Hash = crypto:hash(
        sha256,
        term_to_binary(
            Canon,
            [{minor_version, 2}]
        )
    ),
    {to_bin(Host), Port, Transport, Hash}.

%%====================================================================
%% gen_server
%%====================================================================

init([]) ->
    process_flag(trap_exit, true),
    {ok, #state{}}.

handle_call({checkout, FP, Opts}, From, S) ->
    case pick_owner(FP, S) of
        {ok, Owner} ->
            {reply, {ok, Owner}, S};
        none ->
            case maps:find(FP, S#state.dialing) of
                {ok, #dial{waiters = Waiters} = Dial} ->
                    %% A dial is already in flight for this FP; join
                    %% the queue. Caller will be replied to when the
                    %% dial completes.
                    {noreply, S#state{
                        dialing =
                            maps:put(
                                FP,
                                Dial#dial{waiters = [From | Waiters]},
                                S#state.dialing
                            )
                    }};
                error ->
                    %% Cold key, or every cached owner is full: spawn
                    %% a self-dialing owner. Registry never blocks on
                    %% the handshake; the monitor catches a dial that
                    %% dies without reporting.
                    Owner = masque_upstream_owner:start_for_pool(
                        self(), FP, Opts
                    ),
                    MRef = erlang:monitor(process, Owner),
                    Dial = #dial{owner = Owner, mon_ref = MRef, waiters = [From]},
                    {noreply, S#state{
                        dialing = maps:put(FP, Dial, S#state.dialing),
                        owner_ix = maps:put(MRef, FP, S#state.owner_ix)
                    }}
            end
    end;
handle_call(close_all, _From, S) ->
    reply_all_dialing({error, shutdown}, S),
    _ = [
        exit(E#entry.owner, shutdown)
     || {_FP, Entries} <- maps:to_list(S#state.cache),
        E <- Entries
    ],
    {reply, ok, #state{}};
handle_call(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

handle_cast(_, S) -> {noreply, S}.

handle_info({dial_result, FP, {ok, Owner}}, S) ->
    case maps:find(FP, S#state.dialing) of
        {ok, #dial{owner = Owner, mon_ref = MRef}} ->
            Entry = #entry{owner = Owner, mon_ref = MRef},
            S1 = S#state{
                cache = maps:update_with(
                    FP,
                    fun(L) -> L ++ [Entry] end,
                    [Entry],
                    S#state.cache
                )
            },
            {noreply, reply_dialing(FP, {ok, Owner}, S1)};
        _ ->
            %% Not the dial we are waiting for (e.g. after close_all).
            exit(Owner, shutdown),
            {noreply, S}
    end;
handle_info({dial_result, FP, {error, _} = Err}, S) ->
    case maps:find(FP, S#state.dialing) of
        {ok, #dial{mon_ref = MRef}} ->
            _ = erlang:demonitor(MRef, [flush]),
            S1 = S#state{owner_ix = maps:remove(MRef, S#state.owner_ix)},
            {noreply, reply_dialing(FP, Err, S1)};
        error ->
            {noreply, S}
    end;
handle_info({owner_capacity, Owner, Full}, S) ->
    {noreply, set_full(Owner, Full, S)};
handle_info({'DOWN', MRef, process, _Pid, Reason}, S) ->
    case maps:take(MRef, S#state.owner_ix) of
        {FP, Ix2} ->
            case maps:find(FP, S#state.dialing) of
                {ok, #dial{mon_ref = MRef}} ->
                    %% The owner died before reporting its dial.
                    S1 = S#state{owner_ix = Ix2},
                    {noreply, reply_dialing(FP, {error, {dial_failed, Reason}}, S1)};
                _ ->
                    {noreply, evict(FP, MRef, S#state{owner_ix = Ix2})}
            end;
        error ->
            {noreply, S}
    end;
handle_info(_, S) ->
    {noreply, S}.

terminate(_Reason, S) ->
    _ = [
        (try
            exit(E#entry.owner, shutdown)
        catch
            _:_ -> ok
        end)
     || {_FP, Entries} <- maps:to_list(S#state.cache),
        E <- Entries
    ],
    ok.

code_change(_, S, _) -> {ok, S}.

%%====================================================================
%% Internal
%%====================================================================

%% First cached owner that is alive and below its stream limit;
%% `none' makes the caller dial another connection.
pick_owner(FP, #state{cache = Cache}) ->
    Entries = maps:get(FP, Cache, []),
    case
        [
            O
         || #entry{owner = O, full = false} <- Entries,
            erlang:is_process_alive(O)
        ]
    of
        [O | _] -> {ok, O};
        [] -> none
    end.

evict(FP, MRef, S) ->
    Cache2 =
        case maps:find(FP, S#state.cache) of
            {ok, Entries} ->
                case [E || E <- Entries, E#entry.mon_ref =/= MRef] of
                    [] -> maps:remove(FP, S#state.cache);
                    Left -> maps:put(FP, Left, S#state.cache)
                end;
            error ->
                S#state.cache
        end,
    S#state{cache = Cache2}.

set_full(Owner, Full, #state{cache = Cache} = S) ->
    Cache2 = maps:map(
        fun(_FP, Entries) ->
            [
                case E of
                    #entry{owner = Owner} -> E#entry{full = Full};
                    _ -> E
                end
             || E <- Entries
            ]
        end,
        Cache
    ),
    S#state{cache = Cache2}.

reply_dialing(FP, Reply, S) ->
    case maps:take(FP, S#state.dialing) of
        {#dial{waiters = Waiters}, Dialing1} ->
            [gen_server:reply(From, Reply) || From <- lists:reverse(Waiters)],
            S#state{dialing = Dialing1};
        error ->
            S
    end.

reply_all_dialing(Reply, #state{dialing = D}) ->
    maps:foreach(
        fun(_FP, #dial{owner = Owner, mon_ref = MRef, waiters = Waiters}) ->
            _ = erlang:demonitor(MRef, [flush]),
            exit(Owner, shutdown),
            [gen_server:reply(From, Reply) || From <- Waiters]
        end,
        D
    ),
    ok.

canonical_ssl_opts(Opts) when is_list(Opts) ->
    lists:sort(Opts);
canonical_ssl_opts(Other) ->
    Other.

to_bin(B) when is_binary(B) -> B;
to_bin(L) when is_list(L) -> list_to_binary(L).
