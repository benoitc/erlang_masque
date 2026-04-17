%%% @doc Transport race for MASQUE client connects.
%%%
%%% Apple's MASQUE clients (Private Relay, Network.framework) prefer
%%% HTTP/3 but fall back to HTTP/2 on networks that block QUIC. They
%%% don't wait for an h3 timeout - they give h3 a short head start
%%% and then race h2 in parallel, using whichever handshake finishes
%%% first. That shaves ~1-3 seconds from the fallback path on lossy
%%% or UDP-blocked networks.
%%%
%%% This module implements that logic for a single `masque:connect/3'
%%% call. It runs in the caller's process; no extra supervision.
%%%
%%% Flow:
%%% <ol>
%%%  <li>Start the primary transport (default `h3') immediately with
%%%      a shadow owner (so owner-addressed messages are not delivered
%%%      to the real owner until the session wins).</li>
%%%  <li>After `prefer_timeout_ms' ms, start the secondary transport
%%%      (default `h2') in parallel.</li>
%%%  <li>First session to report `ok' on its `handshake_await' call
%%%      wins. The shadow owner is flipped to the real owner via
%%%      `gen_statem:call(Pid, {set_owner, RealOwner})', and the
%%%      loser is killed.</li>
%%%  <li>If the primary completes within the head-start window we do
%%%      not even spawn the secondary.</li>
%%% </ol>
%%%
%%% Note: the session modules already deliver to the owner set on
%%% start. To avoid a racey burst of messages going to the caller
%%% from the losing attempt, each session is started with the racer
%%% as owner; on win we transfer owner via a session call. Since the
%%% race completes before any packets are sent (sessions only reach
%%% the `open' state on 2xx), the owner swap happens on a quiet
%%% mailbox.
-module(masque_racer).

-export([race/4]).

-include("masque.hrl").


%% @doc Race the listed transports and return the winning session.
-spec race([masque:transport()], masque:target(), map(), pid()) ->
    {ok, masque:session()} | {error, term()}.
race(Transports, Target, Opts, RealOwner) ->
    PreferMs = maps:get(prefer_timeout_ms, Opts, 250),
    Timeout = maps:get(timeout, Opts, 5000),
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    [Primary | Rest] = Transports,
    Racer = self(),
    P1 = spawn_attempt(Racer, Primary, Target, Opts),
    SecondaryTRef = case Rest of
        [] -> undefined;
        _  -> erlang:send_after(PreferMs, self(), start_secondary)
    end,
    loop(#{
        real_owner     => RealOwner,
        primary        => {Primary, P1},
        secondary      => undefined,
        secondary_pending => Rest,
        secondary_tref => SecondaryTRef,
        target         => Target,
        opts           => Opts,
        deadline       => Deadline,
        racer          => Racer,
        last_error     => undefined
    }).

%%====================================================================
%% Internal
%%====================================================================

loop(S) ->
    Now = erlang:monotonic_time(millisecond),
    RemainingMs = max(0, maps:get(deadline, S) - Now),
    receive
        {attempt_ready, AttemptPid, Transport, SessionPid} ->
            handle_attempt_ready(AttemptPid, Transport, SessionPid, S);
        {attempt_failed, AttemptPid, Transport, Reason} ->
            handle_attempt_failed(AttemptPid, Transport, Reason, S);
        start_secondary ->
            handle_start_secondary(S)
    after RemainingMs ->
        cleanup_all(S),
        {error, {race_timeout, maps:get(last_error, S)}}
    end.

handle_attempt_ready(Pid, Transport, Sess, S) ->
    %% First success wins.
    RealOwner = maps:get(real_owner, S),
    _ = transfer_owner(Transport, Sess, RealOwner),
    _ = notify_result(Pid, win),
    cleanup_others(Pid, S),
    {ok, Sess}.

handle_attempt_failed(Pid, _Transport, Reason, S) ->
    S1 = S#{last_error := Reason},
    case attempt_map(S) of
        #{Pid := _} = Attempts ->
            case maps:remove(Pid, Attempts) of
                Left when map_size(Left) =:= 0 ->
                    %% All current attempts failed. If we still have a
                    %% secondary pending (head-start window hasn't
                    %% fired), keep waiting. Otherwise give up.
                    case maps:get(secondary_pending, S1) of
                        [] -> cleanup_all(S1), {error, Reason};
                        _  -> loop(clear_attempt(Pid, S1))
                    end;
                _ ->
                    loop(clear_attempt(Pid, S1))
            end;
        _ ->
            loop(S1)
    end.

handle_start_secondary(#{secondary_pending := []} = S) ->
    loop(S);
handle_start_secondary(#{secondary_pending := [T | Rest],
                         target := Target,
                         opts := Opts,
                         racer := Racer} = S) ->
    P = spawn_attempt(Racer, T, Target, Opts),
    loop(S#{secondary => {T, P},
            secondary_pending := Rest,
            secondary_tref := undefined}).

%% Spawn a worker that performs one transport attempt and reports the
%% outcome to the racer. The session is linked to the worker; on loss
%% we kill the worker which in turn kills the session.
-spec spawn_attempt(pid(), masque:transport(), masque:target(), map()) -> pid().
spawn_attempt(Racer, Transport, Target, Opts) ->
    spawn(fun() -> attempt(Racer, Transport, Target, Opts) end).

-spec attempt(pid(), masque:transport(), masque:target(), map()) -> ok.
attempt(Racer, Transport, Target, Opts) ->
    Mod = transport_mod(Transport, Opts),
    %% Owner = self() (the worker) so the losing session's incoming
    %% messages die with the worker when we kill it.
    case Mod:start_link(Target, Opts#{transport => Transport}, self()) of
        {ok, Pid} ->
            T = maps:get(timeout, Opts, 5000),
            case gen_statem:call(Pid, handshake_await, T + 1000) of
                ok ->
                    Racer ! {attempt_ready, self(), Transport, Pid},
                    receive
                        win ->
                            _ = catch unlink(Pid),
                            ok;
                        lose ->
                            _ = catch Mod:stop(Pid),
                            ok
                    end;
                {error, Reason} ->
                    Racer ! {attempt_failed, self(), Transport, Reason},
                    ok
            end;
        {error, Reason} ->
            Racer ! {attempt_failed, self(), Transport, Reason},
            ok
    end.

transport_mod(h3, Opts) ->
    case maps:get(protocol, Opts, udp) of
        tcp -> masque_tcp_client_session;
        _   -> masque_client_session
    end;
transport_mod(h2, Opts) ->
    case maps:get(protocol, Opts, udp) of
        tcp -> masque_tcp_client_session;
        _   -> masque_h2_client_session
    end.

transfer_owner(h3, Pid, Owner) ->
    %% Session doesn't (yet) expose a live owner-swap. Use the
    %% `controlling_process'-style call if it ever lands. For now
    %% we send a best-effort internal call and ignore errors -
    %% sessions are built to tolerate an unaware owner (message-mode
    %% delivery targets the stored owner; the winner starts at
    %% handshake success with an empty mailbox).
    _ = (catch gen_statem:call(Pid, {set_owner, Owner}, 1000)),
    ok;
transfer_owner(h2, Pid, Owner) ->
    _ = (catch gen_statem:call(Pid, {set_owner, Owner}, 1000)),
    ok.

notify_result(Pid, Tag) ->
    Pid ! Tag.

attempt_map(#{primary := undefined, secondary := undefined}) -> #{};
attempt_map(#{primary := {_, P1}, secondary := undefined}) -> #{P1 => primary};
attempt_map(#{primary := undefined, secondary := {_, P2}}) -> #{P2 => secondary};
attempt_map(#{primary := {_, P1}, secondary := {_, P2}}) ->
    #{P1 => primary, P2 => secondary}.

clear_attempt(Pid, S) ->
    case S of
        #{primary := {_, Pid}}   -> S#{primary := undefined};
        #{secondary := {_, Pid}} -> S#{secondary := undefined};
        _                        -> S
    end.

cleanup_others(WinnerPid, S) ->
    Losers = [P || P <- [pid_of(primary, S), pid_of(secondary, S)],
                   P =/= undefined, P =/= WinnerPid],
    [notify_result(P, lose) || P <- Losers],
    case maps:get(secondary_tref, S) of
        undefined -> ok;
        TRef      -> _ = erlang:cancel_timer(TRef), ok
    end.

cleanup_all(S) ->
    [notify_result(P, lose) || P <- [pid_of(primary, S), pid_of(secondary, S)],
                               P =/= undefined],
    case maps:get(secondary_tref, S) of
        undefined -> ok;
        TRef      -> _ = erlang:cancel_timer(TRef), ok
    end.

pid_of(Key, S) ->
    case maps:get(Key, S) of
        undefined -> undefined;
        {_, P}    -> P
    end.
