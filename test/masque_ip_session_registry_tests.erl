-module(masque_ip_session_registry_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Module-level fixture: one registry instance shared across all
%% tests in this module so we don't race per-test start/stop with
%% other suites that boot the masque application.
%%====================================================================

registry_test_() ->
    {setup,
     fun setup/0,
     fun teardown/1,
     fun (_) ->
         [
            {"register and lookup host route",
             fun register_and_lookup_host/0},
            {"register prefix then lookup inside",
             fun register_prefix_then_lookup_inside/0},
            {"overlapping prefix rejected",
             fun overlapping_prefix_rejected/0},
            {"release clears lookup",
             fun release_clears_lookup/0},
            {"down pid releases entries",
             fun down_pid_releases_entries/0},
            {"ipv6 lookup",
             fun ipv6_lookup/0}
         ]
     end}.

setup() ->
    ok = masque_metrics:setup_ip_counters(),
    case whereis(masque_ip_session_registry) of
        undefined ->
            {ok, Pid} = masque_ip_session_registry:start_link(),
            unlink(Pid),
            Pid;
        _ ->
            undefined  %% pre-existing instance, leave it alone
    end.

teardown(undefined) -> ok;
teardown(Pid) when is_pid(Pid) ->
    %% gen_server:stop is synchronous and unregisters the name before
    %% returning, which is what we need to keep masque_upstream_pool_tests
    %% (which boots the whole masque application) happy.
    try gen_server:stop(masque_ip_session_registry, normal, 1000) catch _:_ -> ok end,
    case is_process_alive(Pid) of
        true ->
            exit(Pid, kill),
            ok;
        false -> ok
    end.

clear() ->
    _ = (try ets:delete_all_objects(masque_ip_session_registry) catch _:_ -> ok end),
    ok.

%%====================================================================
%% Cases
%%====================================================================

register_and_lookup_host() ->
    clear(),
    Owner = self(),
    ok = masque_ip_session_registry:register(
           4, {10,0,0,5}, 32, Owner, 0),
    ?assertEqual({ok, Owner, 0},
                 masque_ip_session_registry:lookup({10,0,0,5})).

register_prefix_then_lookup_inside() ->
    clear(),
    Owner = self(),
    ok = masque_ip_session_registry:register(
           4, {10,0,0,0}, 24, Owner, 0),
    ?assertMatch({ok, Owner, 0},
                 masque_ip_session_registry:lookup({10,0,0,1})),
    ?assertMatch({ok, Owner, 0},
                 masque_ip_session_registry:lookup({10,0,0,200})),
    ?assertEqual(not_found,
                 masque_ip_session_registry:lookup({10,0,1,1})).

overlapping_prefix_rejected() ->
    clear(),
    ok = masque_ip_session_registry:register(
           4, {10,0,0,0}, 24, self(), 0),
    ?assertEqual({error, conflict},
                 masque_ip_session_registry:register(
                   4, {10,0,0,5}, 32, self(), 0)),
    ?assertEqual({error, conflict},
                 masque_ip_session_registry:register(
                   4, {10,0,0,0}, 16, self(), 0)).

release_clears_lookup() ->
    clear(),
    ok = masque_ip_session_registry:register(
           4, {10,0,0,5}, 32, self(), 0),
    ok = masque_ip_session_registry:release(4, {10,0,0,5}, 32),
    ?assertEqual(not_found,
                 masque_ip_session_registry:lookup({10,0,0,5})).

down_pid_releases_entries() ->
    clear(),
    Self = self(),
    {Pid, MRef} = spawn_monitor(
        fun () ->
            ok = masque_ip_session_registry:register(
                   4, {10,0,1,0}, 24, self(), 0),
            Self ! registered,
            receive die -> ok end
        end),
    receive registered -> ok after 1000 -> ct:fail("never registered") end,
    Pid ! die,
    receive {'DOWN', MRef, process, Pid, _} -> ok
    after 1000 -> ct:fail("worker did not exit")
    end,
    %% The registry sees its own 'DOWN' message asynchronously.
    Until = erlang:monotonic_time(millisecond) + 500,
    wait_for(fun () ->
        not_found =:= masque_ip_session_registry:lookup({10,0,1,1})
    end, Until).

ipv6_lookup() ->
    clear(),
    Owner = self(),
    ok = masque_ip_session_registry:register(
           6, {16#2001,16#DB8,0,0,0,0,0,0}, 64, Owner, 0),
    ?assertMatch({ok, Owner, 0},
                 masque_ip_session_registry:lookup(
                   {16#2001,16#DB8,0,0,16#1234,0,0,1})).

wait_for(Pred, Until) ->
    case Pred() of
        true  -> ok;
        false ->
            case erlang:monotonic_time(millisecond) > Until of
                true  -> ?assert(Pred());
                false ->
                    timer:sleep(10),
                    wait_for(Pred, Until)
            end
    end.
