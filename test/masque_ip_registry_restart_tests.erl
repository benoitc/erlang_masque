%%% @doc The CONNECT-IP registry keeps its assignments across a restart
%%% when its table has another owner (`masque_sup' in the application).
-module(masque_ip_registry_restart_tests).

-include_lib("eunit/include/eunit.hrl").

-define(R, masque_ip_session_registry).

restart_keeps_assignments_test() ->
    case whereis(?R) of
        undefined -> run();
        _ -> ok
    end.

run() ->
    ok = masque_metrics:setup_ip_counters(),
    Self = self(),
    %% A stand-in for `masque_sup': owns the table.
    TableOwner = spawn(fun() ->
        ok = ?R:new_table(),
        Self ! table_ready,
        receive
            stop -> ok
        end
    end),
    receive
        table_ready -> ok
    end,
    Session = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    {ok, R1} = ?R:start_link(),
    unlink(R1),
    ok = ?R:register(4, {10, 9, 0, 1}, 32, Session, 0),
    exit(R1, kill),
    wait_down(R1),
    {ok, R2} = ?R:start_link(),
    unlink(R2),
    ?assertMatch({ok, Session, 0}, ?R:lookup({10, 9, 0, 1})),
    %% The restarted registry watches the session again.
    Session ! stop,
    wait_until(fun() -> ?R:lookup({10, 9, 0, 1}) =:= not_found end, 50),
    gen_server:stop(R2),
    TableOwner ! stop.

wait_down(Pid) ->
    MRef = erlang:monitor(process, Pid),
    receive
        {'DOWN', MRef, process, Pid, _} -> ok
    end.

wait_until(_F, 0) ->
    ?assert(false);
wait_until(F, N) ->
    case F() of
        true ->
            ok;
        false ->
            timer:sleep(20),
            wait_until(F, N - 1)
    end.
