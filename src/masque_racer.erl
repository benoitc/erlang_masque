%%% @doc Transport race for MASQUE client connects.
%%%
%%% Apple's MASQUE clients (Private Relay, Network.framework) prefer
%%% HTTP/3 but fall back to HTTP/2 on networks that block QUIC. They
%%% don't wait for an h3 timeout - they give h3 a short head start
%%% and then race h2 in parallel, using whichever handshake finishes
%%% first. HTTP/1.1 over classic HTTPS follows the same idea as a
%%% tertiary rung for networks where h2 is also refused or ALPN is
%%% stripped.
%%%
%%% This module implements that logic for a single `masque:connect/3'
%%% call. It runs in the caller's process; no extra supervision.
%%%
%%% Flow for `[T1, T2, T3]' (T3 optional):
%%% <ol>
%%%  <li>Start `T1' immediately with a shadow owner.</li>
%%%  <li>After `prefer_timeout_ms' ms, start `T2' in parallel.</li>
%%%  <li>After another `h1_prefer_timeout_ms' ms (only if `T3' is
%%%      present), start `T3' in parallel.</li>
%%%  <li>First attempt to report `ok' on its `handshake_await' call
%%%      wins. Shadow owner is flipped to the real owner via
%%%      `gen_statem:call(Pid, {set_owner, RealOwner})', losers are
%%%      killed.</li>
%%% </ol>
%%%
%%% Note: the session modules already deliver to the owner set on
%%% start. To avoid a racey burst of messages going to the caller
%%% from losing attempts, each session is started with the racer as
%%% owner; on win we transfer owner via a session call. Since the
%%% race completes before any datagrams are sent (sessions only
%%% reach `open' on 2xx / 101), the owner swap happens on a quiet
%%% mailbox.
-module(masque_racer).

-export([race/4]).

-include("masque.hrl").


%% @doc Race the listed transports and return the winning session.
-spec race([masque:transport()], masque:target(), map(), pid()) ->
    {ok, masque:session()} | {error, term()}.
race(Transports, Target, Opts, RealOwner) ->
    PreferMs = maps:get(prefer_timeout_ms, Opts, 250),
    H1PreferMs = maps:get(h1_prefer_timeout_ms, Opts, 500),
    Timeout = maps:get(timeout, Opts, 5000),
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    [Primary | Rest] = Transports,
    Racer = self(),
    P1 = spawn_attempt(Racer, Primary, Target, Opts),
    %% Arm the first head-start timer only when there's more to spawn.
    NextTRef = case Rest of
        [] -> undefined;
        _  -> erlang:send_after(PreferMs, self(), start_next_attempt)
    end,
    loop(#{
        real_owner        => RealOwner,
        attempts          => #{P1 => {Primary, undefined}},
        pending           => Rest,
        next_timer        => NextTRef,
        head_starts       => head_start_queue(Rest, H1PreferMs),
        target            => Target,
        opts              => Opts,
        deadline          => Deadline,
        racer             => Racer,
        last_error        => undefined
    }).

%%====================================================================
%% Internal
%%====================================================================

%% The delay between attempt N and attempt N+1. The first head-start
%% (primary -> secondary) is already armed with `prefer_timeout_ms'; this
%% queue holds subsequent delays. For `[h3, h2, h1]' that is
%% `[h1_prefer_timeout_ms]'. Longer transport lists would extend here.
head_start_queue([], _H1PreferMs) -> [];
head_start_queue([_Secondary | Rest], H1PreferMs) ->
    %% Only entry today: the delay before the tertiary (typically h1)
    %% attempt. Any further transports inherit the same cadence.
    [H1PreferMs || _ <- Rest].

loop(S) ->
    Now = erlang:monotonic_time(millisecond),
    RemainingMs = max(0, maps:get(deadline, S) - Now),
    receive
        {attempt_ready, AttemptPid, Transport, SessionPid} ->
            handle_attempt_ready(AttemptPid, Transport, SessionPid, S);
        {attempt_failed, AttemptPid, Transport, Reason} ->
            handle_attempt_failed(AttemptPid, Transport, Reason, S);
        start_next_attempt ->
            handle_start_next(S)
    after RemainingMs ->
        cleanup_all(S),
        {error, {race_timeout, maps:get(last_error, S)}}
    end.

handle_attempt_ready(Pid, Transport, Sess, S) ->
    RealOwner = maps:get(real_owner, S),
    case transfer_owner(Transport, Sess, RealOwner) of
        ok ->
            _ = notify_result(Pid, win),
            cleanup_others(Pid, S),
            {ok, Sess};
        {error, Reason} ->
            %% Session is dead (killed by transfer_owner).
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
                        [] -> cleanup_all(S2), {error, Reason};
                        _  -> loop(S2)
                    end;
                _ ->
                    loop(S2)
            end;
        false ->
            loop(S1)
    end.

handle_start_next(#{pending := []} = S) ->
    loop(S);
handle_start_next(#{pending := [T | Rest],
                    head_starts := HeadStarts,
                    attempts := Attempts,
                    target := Target,
                    opts := Opts,
                    racer := Racer} = S) ->
    P = spawn_attempt(Racer, T, Target, Opts),
    {NextTRef, HeadStarts1} = case {Rest, HeadStarts} of
        {[], _} -> {undefined, []};
        {_, []} -> {undefined, []};
        {_, [Delay | RestDelays]} ->
            {erlang:send_after(Delay, self(), start_next_attempt), RestDelays}
    end,
    loop(S#{attempts   := maps:put(P, {T, undefined}, Attempts),
            pending    := Rest,
            head_starts := HeadStarts1,
            next_timer := NextTRef}).

%% Spawn a worker that performs one transport attempt and reports the
%% outcome to the racer. The session is owned by the worker; on loss
%% we kill the worker which in turn kills the session.
-spec spawn_attempt(pid(), masque:transport(), masque:target(), map()) -> pid().
spawn_attempt(Racer, Transport, Target, Opts) ->
    spawn(fun() -> attempt(Racer, Transport, Target, Opts) end).

-spec attempt(pid(), masque:transport(), masque:target(), map()) -> ok.
attempt(Racer, Transport, Target, Opts) ->
    Mod = resolve_mod(Transport, Opts),
    case Mod:start(Target, Opts#{transport => Transport}, self()) of
        {ok, Pid} ->
            MRef = erlang:monitor(process, Pid),
            T = maps:get(timeout, Opts, 5000),
            Result = try gen_statem:call(Pid, handshake_await, T + 1000)
                     catch exit:_ -> {error, session_died}
                     end,
            erlang:demonitor(MRef, [flush]),
            case Result of
                ok ->
                    Racer ! {attempt_ready, self(), Transport, Pid},
                    receive
                        win  -> ok;
                        lose -> _ = catch Mod:stop(Pid), ok
                    end;
                {error, Reason} ->
                    catch exit(Pid, kill),
                    Racer ! {attempt_failed, self(), Transport, Reason},
                    ok
            end;
        {error, Reason} ->
            Racer ! {attempt_failed, self(), Transport, Reason},
            ok
    end.

%% Test hook: allow eunit to inject fake session modules without
%% wiring real network transports.
resolve_mod(Transport, #{racer_transport_mods := Mods}) when is_map(Mods) ->
    case maps:find(Transport, Mods) of
        {ok, Mod} -> Mod;
        error     -> transport_mod(Transport, #{})
    end;
resolve_mod(Transport, Opts) ->
    transport_mod(Transport, Opts).

transport_mod(h3, Opts) ->
    case maps:get(protocol, Opts, udp) of
        tcp -> masque_tcp_client_session;
        ip  -> masque_ip_client_session;
        _   -> masque_client_session
    end;
transport_mod(h2, Opts) ->
    case maps:get(protocol, Opts, udp) of
        tcp -> masque_tcp_client_session;
        ip  -> masque_ip_client_session;
        _   -> masque_h2_client_session
    end;
transport_mod(h1, Opts) ->
    %% h1 implements CONNECT-UDP, CONNECT-IP, and classic CONNECT-TCP.
    case maps:get(protocol, Opts, udp) of
        udp -> masque_h1_client_session;
        ip  -> masque_ip_h1_client_session;
        tcp -> masque_tcp_h1_client_session
    end.

transfer_owner(_Transport, Pid, Owner) ->
    case (catch gen_statem:call(Pid, {set_owner, Owner}, 2000)) of
        ok -> ok;
        _  ->
            catch exit(Pid, kill),
            {error, owner_transfer_failed}
    end.

notify_result(Pid, Tag) ->
    Pid ! Tag.

cleanup_others(WinnerPid, S) ->
    Losers = [P || P <- maps:keys(maps:get(attempts, S)),
                   P =/= WinnerPid],
    [notify_result(P, lose) || P <- Losers],
    cancel_next_timer(S).

cleanup_all(S) ->
    [notify_result(P, lose) || P <- maps:keys(maps:get(attempts, S))],
    cancel_next_timer(S).

cancel_next_timer(#{next_timer := undefined}) -> ok;
cancel_next_timer(#{next_timer := TRef}) ->
    _ = erlang:cancel_timer(TRef),
    ok.
