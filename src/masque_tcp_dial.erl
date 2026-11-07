-module(masque_tcp_dial).
-moduledoc false.

%%% Happy Eyeballs for the CONNECT-TCP proxy (RFC 8305, which
%%% draft-ietf-httpbis-connect-tcp-18 section 4.1 recommends when a
%%% target resolves to both address families).
%%%
%%% Addresses are tried in RFC 8305 order (families interleaved, IPv6
%%% first), a new attempt every `?ATTEMPT_DELAY_MS' or as soon as the
%%% previous one fails. The first connection wins; the others are closed
%%% before any payload is sent on them. Each attempt runs in its own
%%% process with the socket passive, so no target bytes are lost when the
%%% winner's socket moves to the caller.

-export([order/1, connect/4]).

-define(ATTEMPT_DELAY_MS, 250).
%% How long the winner's handover may take.
-define(HANDOVER_MS, 5000).

%% RFC 8305 section 4: interleave the families, starting with IPv6.
-spec order([inet:ip_address()]) -> [inet:ip_address()].
order(IPs) ->
    {V6, V4} = lists:partition(fun(IP) -> tuple_size(IP) =:= 8 end, IPs),
    interleave(V6, V4).

interleave([], B) -> B;
interleave(A, []) -> A;
interleave([A | As], [B | Bs]) -> [A, B | interleave(As, Bs)].

%% Connect to the first address that answers. `OptsFun(IP)' gives the
%% socket options for an address; `{active, false}' is forced and the
%% caller sets its own mode on the returned socket. The caller becomes
%% the socket's controlling process.
-spec connect(
    [inet:ip_address()], inet:port_number(), fun((inet:ip_address()) -> list()), timeout()
) ->
    {ok, gen_tcp:socket()} | {error, term()}.
connect([IP], Port, OptsFun, Timeout) ->
    gen_tcp:connect(IP, Port, passive(OptsFun(IP)), Timeout);
connect(IPs, Port, OptsFun, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    Alias = erlang:alias(),
    try
        race(IPs, #{}, undefined, Alias, Port, OptsFun, Deadline)
    after
        erlang:unalias(Alias)
    end.

passive(Opts) ->
    [{active, false} | proplists:delete(active, Opts)].

%% `Live' maps attempt pids to monitor refs; `LastErr' is the latest
%% failure, returned when every attempt failed.
race(Pending, Live, LastErr, Alias, Port, OptsFun, Deadline) ->
    Live1 =
        case {Pending, map_size(Live)} of
            {[IP | _], 0} -> start(IP, Alias, Port, OptsFun, Deadline, Live);
            _ -> Live
        end,
    Pending1 =
        case Live1 =:= Live of
            true -> Pending;
            false -> tl(Pending)
        end,
    case {Pending1, map_size(Live1)} of
        {[], 0} ->
            {error, LastErr};
        _ ->
            Wait =
                case Pending1 of
                    [] -> remaining(Deadline);
                    _ -> min(?ATTEMPT_DELAY_MS, remaining(Deadline))
                end,
            receive
                {Alias, Pid, connected} when is_map_key(Pid, Live1) ->
                    win(Pid, Live1);
                {Alias, Pid, {failed, Reason}} when is_map_key(Pid, Live1) ->
                    erlang:demonitor(maps:get(Pid, Live1), [flush]),
                    race(Pending1, maps:remove(Pid, Live1), Reason, Alias, Port, OptsFun, Deadline);
                {'DOWN', Ref, process, Pid, Reason} when map_get(Pid, Live1) =:= Ref ->
                    race(Pending1, maps:remove(Pid, Live1), Reason, Alias, Port, OptsFun, Deadline)
            after Wait ->
                case {Pending1, remaining(Deadline)} of
                    {_, 0} ->
                        stop_all(Live1),
                        {error, timeout};
                    {[IP2 | Rest], _} ->
                        Live2 = start(IP2, Alias, Port, OptsFun, Deadline, Live1),
                        race(Rest, Live2, LastErr, Alias, Port, OptsFun, Deadline);
                    {[], _} ->
                        race([], Live1, LastErr, Alias, Port, OptsFun, Deadline)
                end
            end
    end.

start(IP, Alias, Port, OptsFun, Deadline, Live) ->
    Opts = passive(OptsFun(IP)),
    {Pid, Ref} = spawn_monitor(fun() -> attempt(IP, Port, Opts, Deadline, Alias) end),
    Live#{Pid => Ref}.

attempt(IP, Port, Opts, Deadline, Alias) ->
    case gen_tcp:connect(IP, Port, Opts, remaining(Deadline)) of
        {ok, Sock} ->
            Alias ! {Alias, self(), connected},
            %% A caller that is gone or picked another attempt never
            %% asks; the socket closes when this process ends.
            receive
                {take, Caller, Tag} ->
                    ok = gen_tcp:controlling_process(Sock, Caller),
                    Caller ! {Tag, Sock}
            after remaining(Deadline) + ?HANDOVER_MS ->
                gen_tcp:close(Sock)
            end;
        {error, Reason} ->
            Alias ! {Alias, self(), {failed, Reason}}
    end.

%% Take the winner's socket, then stop the others: their sockets close
%% with them, before carrying any payload.
win(Pid, Live) ->
    Tag = make_ref(),
    Pid ! {take, self(), Tag},
    Ref = maps:get(Pid, Live),
    Result =
        receive
            {Tag, Sock} -> {ok, Sock};
            {'DOWN', Ref, process, Pid, Reason} -> {error, Reason}
        after ?HANDOVER_MS ->
            exit(Pid, kill),
            {error, timeout}
        end,
    erlang:demonitor(Ref, [flush]),
    stop_all(maps:remove(Pid, Live)),
    Result.

stop_all(Live) ->
    maps:foreach(
        fun(Pid, Ref) ->
            exit(Pid, kill),
            erlang:demonitor(Ref, [flush])
        end,
        Live
    ).

remaining(Deadline) ->
    max(0, Deadline - erlang:monotonic_time(millisecond)).
