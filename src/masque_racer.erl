%%% Transport race for MASQUE client connects.
%%%
%%% Apple's MASQUE clients (Private Relay, Network.framework) prefer
%%% HTTP/3 but fall back to HTTP/2 on networks that block QUIC. They
%%% don't wait for an h3 timeout - they give h3 a short head start
%%% and then race h2 in parallel, using whichever handshake finishes
%%% first. HTTP/1.1 over classic HTTPS follows the same idea as a
%%% tertiary rung for networks where h2 is also refused or ALPN is
%%% stripped.
%%%
%%% This module implements that logic for a single `masque:connect/3`
%%% call. The race loop runs in the caller's process and receives
%%% through an `erlang:alias/0` that is dropped before `race/4`
%%% returns, so late attempt reports never reach the caller's
%%% mailbox. Each attempt runs in a worker process that monitors the
%%% caller and gives up at the race deadline.
%%%
%%% Flow for `[T1, T2, T3]` (T3 optional):
%%% 1. Start `T1` immediately with a shadow owner.
%%% 2. After `prefer_timeout_ms` ms, start `T2` in parallel.
%%% 3. After another `h1_prefer_timeout_ms` ms (only if `T3` is
%%%    present), start `T3` in parallel.
%%% 4. First attempt to report `ok` on its `handshake_await` call
%%%    wins. Shadow owner is flipped to the real owner via
%%%    `gen_statem:call(Pid, {set_owner, RealOwner})`, losers are
%%%    stopped.
%%%
%%% Sessions are started with the race worker as owner and
%%% `defer_owner => true`: events they produce before `set_owner`
%%% (for example a CONNECT-IP ADDRESS_ASSIGN sent right after the 2xx)
%%% are held by the session and flushed in order to the real owner
%%% on `set_owner` (see `masque_client_owner`).
-module(masque_racer).
-moduledoc false.

-export([race/4, checkout_pool/2]).

-include("masque.hrl").

%% Workers outlive the race deadline by this much so a winner that
%% reports just before the deadline still sees the racer's verdict.
-define(WORKER_GRACE_MS, 1000).

%% The racing process and the alias it receives attempt reports on.
-type racer() :: {pid(), reference()}.

%% Race the listed transports and return the winning session.
-spec race([masque:transport()], masque:target(), map(), pid()) ->
    {ok, masque:session()} | {error, term()}.
race(Transports, Target, Opts, RealOwner) ->
    PreferMs = maps:get(prefer_timeout_ms, Opts, 250),
    H1PreferMs = maps:get(h1_prefer_timeout_ms, Opts, 500),
    Timeout = maps:get(timeout, Opts, 5000),
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    [Primary | Rest] = Transports,
    Alias = erlang:alias(),
    Racer = {self(), Alias},
    P1 = spawn_attempt(Racer, Primary, Target, Opts, Deadline),
    %% Arm the first head-start timer only when there's more to spawn.
    NextTRef =
        case Rest of
            [] -> undefined;
            _ -> erlang:send_after(PreferMs, self(), {Alias, start_next_attempt})
        end,
    S = #{
        real_owner => RealOwner,
        attempts => #{P1 => {Primary, undefined}},
        pending => Rest,
        next_timer => NextTRef,
        head_starts => head_start_queue(Rest, H1PreferMs),
        target => Target,
        opts => Opts,
        deadline => Deadline,
        racer => Racer,
        last_error => undefined
    },
    try
        loop(S)
    after
        _ = erlang:unalias(Alias),
        flush(Alias)
    end.

%%====================================================================
%% Internal
%%====================================================================

%% The delay between attempt N and attempt N+1. The first head-start
%% (primary -> secondary) is already armed with `prefer_timeout_ms'; this
%% queue holds subsequent delays. For `[h3, h2, h1]' that is
%% `[h1_prefer_timeout_ms]'. Longer transport lists would extend here.
head_start_queue([], _H1PreferMs) ->
    [];
head_start_queue([_Secondary | Rest], H1PreferMs) ->
    %% Only entry today: the delay before the tertiary (typically h1)
    %% attempt. Any further transports inherit the same cadence.
    [H1PreferMs || _ <- Rest].

loop(#{racer := {_, Alias}} = S) ->
    receive
        {Alias, {attempt_ready, AttemptPid, Transport, SessionPid}} ->
            handle_attempt_ready(AttemptPid, Transport, SessionPid, S);
        {Alias, {attempt_failed, AttemptPid, Transport, Reason}} ->
            handle_attempt_failed(AttemptPid, Transport, Reason, S);
        {Alias, start_next_attempt} ->
            handle_start_next(S)
    after remaining(maps:get(deadline, S)) ->
        cleanup_all(S),
        {error, {race_timeout, maps:get(last_error, S)}}
    end.

%% Drop reports that reached the alias before it was deactivated.
flush(Alias) ->
    receive
        {Alias, _} -> flush(Alias)
    after 0 -> ok
    end.

remaining(Deadline) ->
    max(0, Deadline - erlang:monotonic_time(millisecond)).

handle_attempt_ready(Pid, Transport, Sess, S) ->
    RealOwner = maps:get(real_owner, S),
    case transfer_owner(Transport, Sess, RealOwner) of
        ok ->
            _ = notify_result(Pid, win, S),
            cleanup_others(Pid, S),
            {ok, Sess};
        {error, Reason} ->
            %% The winner died between `attempt_ready' and
            %% `set_owner'. Tell its worker to stop the session and
            %% keep racing what's still running or pending.
            _ = notify_result(Pid, lose, S),
            _ =
                (try
                    exit(Sess, kill)
                catch
                    _:_ -> ok
                end),
            handle_attempt_failed(Pid, Transport, Reason, S)
    end.

handle_attempt_failed(Pid, _Transport, Reason, S) ->
    S1 = S#{last_error := Reason},
    Attempts = maps:get(attempts, S1),
    case maps:is_key(Pid, Attempts) of
        true ->
            Attempts2 = maps:remove(Pid, Attempts),
            S2 = S1#{attempts := Attempts2},
            case maps:size(Attempts2) of
                0 ->
                    %% All current attempts failed. Keep waiting if
                    %% there is still a pending attempt (its head-start
                    %% timer hasn't fired yet); otherwise give up.
                    case maps:get(pending, S2) of
                        [] ->
                            cleanup_all(S2),
                            {error, Reason};
                        _ ->
                            loop(S2)
                    end;
                _ ->
                    loop(S2)
            end;
        false ->
            loop(S1)
    end.

handle_start_next(#{pending := []} = S) ->
    loop(S);
handle_start_next(
    #{
        pending := [T | Rest],
        head_starts := HeadStarts,
        attempts := Attempts,
        target := Target,
        opts := Opts,
        deadline := Deadline,
        racer := {_, Alias} = Racer
    } = S
) ->
    P = spawn_attempt(Racer, T, Target, Opts, Deadline),
    {NextTRef, HeadStarts1} =
        case {Rest, HeadStarts} of
            {[], _} ->
                {undefined, []};
            {_, []} ->
                {undefined, []};
            {_, [Delay | RestDelays]} ->
                {erlang:send_after(Delay, self(), {Alias, start_next_attempt}), RestDelays}
        end,
    loop(S#{
        attempts := maps:put(P, {T, undefined}, Attempts),
        pending := Rest,
        head_starts := HeadStarts1,
        next_timer := NextTRef
    }).

%% Spawn a worker that performs one transport attempt and reports the
%% outcome to the racer alias. The session is owned by the worker
%% until the racer transfers it; the worker stops the session when it
%% loses, when the caller goes away, or at the race deadline.
-spec spawn_attempt(racer(), masque:transport(), masque:target(), map(), integer()) -> pid().
spawn_attempt(Racer, Transport, Target, Opts, Deadline) ->
    spawn(fun() -> attempt(Racer, Transport, Target, Opts, Deadline) end).

-spec attempt(racer(), masque:transport(), masque:target(), map(), integer()) -> ok.
attempt({RacerPid, _} = Racer, Transport, Target, Opts, Deadline) ->
    RRef = erlang:monitor(process, RacerPid),
    Mod = resolve_mod(Transport, Opts),
    case maybe_inject_pool_owner(Transport, Opts) of
        {error, Reason} ->
            report(Racer, {attempt_failed, self(), Transport, Reason});
        {ok, Opts1} ->
            start_attempt(Racer, RRef, Deadline, Transport, Target, Opts1, Mod)
    end.

start_attempt(Racer, RRef, Deadline, Transport, Target, Opts, Mod) ->
    SessOpts = Opts#{transport => Transport, defer_owner => true},
    case Mod:start(Target, SessOpts, self()) of
        {ok, Pid} ->
            ReqId = gen_statem:send_request(Pid, handshake_await),
            case await_handshake(ReqId, Racer, RRef, Deadline) of
                ok ->
                    report(Racer, {attempt_ready, self(), Transport, Pid}),
                    case await_result(Racer, RRef, Deadline) of
                        win -> ok;
                        lose -> stop_session(Mod, Pid)
                    end;
                lose ->
                    stop_session(Mod, Pid);
                {error, Reason} ->
                    kill_session(Pid),
                    report(Racer, {attempt_failed, self(), Transport, Reason})
            end;
        {error, Reason} ->
            report(Racer, {attempt_failed, self(), Transport, Reason})
    end.

%% Wait for the session's `handshake_await' reply. The racer can end
%% the attempt early with `lose' (another transport won or the race
%% gave up) and the attempt ends on its own when the caller dies.
await_handshake(ReqId, {_, Alias} = Racer, RRef, Deadline) ->
    receive
        {Alias, lose} ->
            lose;
        {'DOWN', RRef, process, _, _} ->
            lose;
        Msg ->
            case gen_statem:check_response(Msg, ReqId) of
                {reply, Reply} -> Reply;
                {error, {Reason, _}} -> {error, Reason};
                no_reply -> await_handshake(ReqId, Racer, RRef, Deadline)
            end
    after remaining(Deadline) + ?WORKER_GRACE_MS ->
        {error, handshake_timeout}
    end.

await_result({_, Alias}, RRef, Deadline) ->
    receive
        {Alias, win} -> win;
        {Alias, lose} -> lose;
        {'DOWN', RRef, process, _, _} -> lose
    after remaining(Deadline) + ?WORKER_GRACE_MS ->
        lose
    end.

report({_, Alias}, Event) ->
    Alias ! {Alias, Event},
    ok.

stop_session(Mod, Pid) ->
    try
        _ = Mod:stop(Pid),
        ok
    catch
        _:_ -> kill_session(Pid)
    end.

kill_session(Pid) ->
    exit(Pid, kill),
    ok.

%% If `upstream_pool => true' and the transport supports pooling
%% (h2, h3), check out a shared owner from the pool. h1 bypasses
%% the pool (1-tunnel-per-socket).
maybe_inject_pool_owner(_Transport, #{protocol := udp_bind} = Opts) ->
    %% udp-bind is never pooled: each bind needs its own connection.
    {ok, Opts};
maybe_inject_pool_owner(Transport, #{upstream_pool := true} = Opts) when
    Transport =:= h2; Transport =:= h3
->
    checkout_pool(Transport, Opts);
maybe_inject_pool_owner(_Transport, Opts) ->
    {ok, Opts}.

%% Exposed to `masque:connect/3' so the single-transport path can
%% honour `upstream_pool => true' without going through the racer.
-spec checkout_pool(masque:transport(), map()) ->
    {ok, map()} | {error, term()}.
checkout_pool(Transport, Opts) when Transport =:= h2; Transport =:= h3 ->
    case pool_fingerprint(Transport, Opts) of
        {ok, FP, PoolOpts} ->
            case masque_upstream_pool:checkout(FP, PoolOpts) of
                {ok, Owner} -> {ok, Opts#{pool_owner => Owner}};
                {error, _} = Err -> Err
            end;
        {error, _} = Err ->
            Err
    end.

pool_fingerprint(Transport, Opts) ->
    case maps:get(proxy, Opts, undefined) of
        {Host, Port} ->
            PoolTransport =
                case Transport of
                    h3 -> quic_h3;
                    h2 -> h2
                end,
            FP = masque_upstream_pool:fingerprint(
                Host, Port, PoolTransport, Opts
            ),
            PoolOpts = maps:merge(
                #{
                    transport => PoolTransport,
                    host => Host,
                    port => Port,
                    connect_opts => pool_connect_opts(Transport, Host, Opts)
                },
                maps:get(upstream_pool_opts, Opts, #{})
            ),
            {ok, FP, PoolOpts};
        _ ->
            {error, no_proxy}
    end.

pool_connect_opts(h3, _Host, Opts) ->
    Base = maps:with([verify, cacerts], Opts),
    Base#{
        quic_opts => #{
            alpn => maps:get(alpn, Opts, [<<"h3">>]),
            max_datagram_frame_size => 65535
        }
    };
pool_connect_opts(h2, Host, Opts) ->
    #{
        transport => ssl,
        ssl_opts => masque_tls:client_opts(Host, Opts, [<<"h2">>]),
        timeout => maps:get(timeout, Opts, 5000)
    }.

%% Test hook: allow eunit to inject fake session modules without
%% wiring real network transports.
resolve_mod(Transport, #{racer_transport_mods := Mods}) when is_map(Mods) ->
    case maps:find(Transport, Mods) of
        {ok, Mod} -> Mod;
        error -> transport_mod(Transport, #{})
    end;
resolve_mod(Transport, Opts) ->
    transport_mod(Transport, Opts).

transport_mod(h3, Opts) ->
    case maps:get(protocol, Opts, udp) of
        tcp -> masque_tcp_client_session;
        ip -> masque_ip_client_session;
        udp_bind -> masque_udp_bind_client_session;
        _ -> masque_client_session
    end;
transport_mod(h2, Opts) ->
    case maps:get(protocol, Opts, udp) of
        tcp -> masque_tcp_client_session;
        ip -> masque_ip_client_session;
        udp_bind -> masque_udp_bind_client_session;
        _ -> masque_h2_client_session
    end;
transport_mod(h1, Opts) ->
    %% h1 implements CONNECT-UDP, CONNECT-IP, classic CONNECT-TCP,
    %% and Connect-UDP-Bind.
    case maps:get(protocol, Opts, udp) of
        udp -> masque_h1_client_session;
        ip -> masque_ip_h1_client_session;
        tcp -> masque_tcp_h1_client_session;
        udp_bind -> masque_udp_bind_h1_client_session
    end.

%% The session is in its `open' state when the winner reports, so
%% `set_owner' is a trivial synchronous hop; a long timeout here only
%% hides real bugs. 500 ms is comfortably above any reasonable
%% scheduler hiccup on a healthy node. The call's reply goes through
%% its own alias, so a late reply after a timeout is dropped.
transfer_owner(_Transport, Pid, Owner) ->
    try gen_statem:call(Pid, {set_owner, Owner}, 500) of
        ok -> ok;
        Other -> {error, {owner_transfer_failed, Other}}
    catch
        exit:{Reason, {gen_statem, call, _}} -> {error, Reason};
        _:Reason -> {error, Reason}
    end.

notify_result(Pid, Tag, #{racer := {_, Alias}}) ->
    Pid ! {Alias, Tag}.

cleanup_others(WinnerPid, S) ->
    Losers = [
        P
     || P <- maps:keys(maps:get(attempts, S)),
        P =/= WinnerPid
    ],
    _ = [notify_result(P, lose, S) || P <- Losers],
    cancel_next_timer(S).

cleanup_all(S) ->
    _ = [notify_result(P, lose, S) || P <- maps:keys(maps:get(attempts, S))],
    cancel_next_timer(S).

cancel_next_timer(#{next_timer := undefined}) ->
    ok;
cancel_next_timer(#{next_timer := TRef}) ->
    _ = erlang:cancel_timer(TRef),
    ok.
