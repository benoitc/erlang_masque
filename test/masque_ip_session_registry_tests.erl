-module(masque_ip_session_registry_tests).

-include_lib("eunit/include/eunit.hrl").
-include("masque_ip.hrl").

%%====================================================================
%% Module-level fixture: one registry instance shared across all
%% tests in this module so we don't race per-test start/stop with
%% other suites that boot the masque application.
%%====================================================================

registry_test_() ->
    {setup, fun setup/0, fun teardown/1, fun(_) ->
        [
            {"register and lookup host route", fun register_and_lookup_host/0},
            {"register prefix then lookup inside", fun register_prefix_then_lookup_inside/0},
            {"overlapping prefix rejected", fun overlapping_prefix_rejected/0},
            {"release clears lookup", fun release_clears_lookup/0},
            {"down pid releases entries", fun down_pid_releases_entries/0},
            {"ipv6 lookup", fun ipv6_lookup/0},
            {"release ignores other pid's entry", fun release_other_pid_is_noop/0},
            {"shared pool gives distinct addresses", fun shared_pool_distinct_addresses/0}
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
            %% pre-existing instance, leave it alone
            undefined
    end.

teardown(undefined) ->
    ok;
teardown(Pid) when is_pid(Pid) ->
    %% gen_server:stop is synchronous and unregisters the name before
    %% returning, which is what we need to keep masque_upstream_pool_tests
    %% (which boots the whole masque application) happy.
    try
        gen_server:stop(masque_ip_session_registry, normal, 1000)
    catch
        _:_ -> ok
    end,
    case is_process_alive(Pid) of
        true ->
            exit(Pid, kill),
            ok;
        false ->
            ok
    end.

clear() ->
    _ =
        (try
            ets:delete_all_objects(masque_ip_session_registry)
        catch
            _:_ -> ok
        end),
    ok.

%%====================================================================
%% Cases
%%====================================================================

register_and_lookup_host() ->
    clear(),
    Owner = self(),
    ok = masque_ip_session_registry:register(
        4, {10, 0, 0, 5}, 32, Owner, 0
    ),
    ?assertEqual(
        {ok, Owner, 0},
        masque_ip_session_registry:lookup({10, 0, 0, 5})
    ).

register_prefix_then_lookup_inside() ->
    clear(),
    Owner = self(),
    ok = masque_ip_session_registry:register(
        4, {10, 0, 0, 0}, 24, Owner, 0
    ),
    ?assertMatch(
        {ok, Owner, 0},
        masque_ip_session_registry:lookup({10, 0, 0, 1})
    ),
    ?assertMatch(
        {ok, Owner, 0},
        masque_ip_session_registry:lookup({10, 0, 0, 200})
    ),
    ?assertEqual(
        not_found,
        masque_ip_session_registry:lookup({10, 0, 1, 1})
    ).

overlapping_prefix_rejected() ->
    clear(),
    ok = masque_ip_session_registry:register(
        4, {10, 0, 0, 0}, 24, self(), 0
    ),
    ?assertEqual(
        {error, conflict},
        masque_ip_session_registry:register(
            4, {10, 0, 0, 5}, 32, self(), 0
        )
    ),
    ?assertEqual(
        {error, conflict},
        masque_ip_session_registry:register(
            4, {10, 0, 0, 0}, 16, self(), 0
        )
    ).

release_clears_lookup() ->
    clear(),
    ok = masque_ip_session_registry:register(
        4, {10, 0, 0, 5}, 32, self(), 0
    ),
    ok = masque_ip_session_registry:release(4, {10, 0, 0, 5}, 32),
    ?assertEqual(
        not_found,
        masque_ip_session_registry:lookup({10, 0, 0, 5})
    ).

down_pid_releases_entries() ->
    clear(),
    Self = self(),
    {Pid, MRef} = spawn_monitor(
        fun() ->
            ok = masque_ip_session_registry:register(
                4, {10, 0, 1, 0}, 24, self(), 0
            ),
            Self ! registered,
            receive
                die -> ok
            end
        end
    ),
    receive
        registered -> ok
    after 1000 -> ct:fail("never registered")
    end,
    Pid ! die,
    receive
        {'DOWN', MRef, process, Pid, _} -> ok
    after 1000 -> ct:fail("worker did not exit")
    end,
    %% The registry sees its own 'DOWN' message asynchronously.
    Until = erlang:monotonic_time(millisecond) + 500,
    wait_for(
        fun() ->
            not_found =:= masque_ip_session_registry:lookup({10, 0, 1, 1})
        end,
        Until
    ).

ipv6_lookup() ->
    clear(),
    Owner = self(),
    ok = masque_ip_session_registry:register(
        6, {16#2001, 16#DB8, 0, 0, 0, 0, 0, 0}, 64, Owner, 0
    ),
    ?assertMatch(
        {ok, Owner, 0},
        masque_ip_session_registry:lookup(
            {16#2001, 16#DB8, 0, 0, 16#1234, 0, 0, 1}
        )
    ).

release_other_pid_is_noop() ->
    clear(),
    Owner = self(),
    ok = masque_ip_session_registry:register(
        4, {10, 0, 0, 9}, 32, Owner, 0
    ),
    Other = spawn(fun() -> ok end),
    ok = masque_ip_session_registry:release(4, {10, 0, 0, 9}, 32, Other),
    ?assertEqual(
        {ok, Owner, 0},
        masque_ip_session_registry:lookup({10, 0, 0, 9})
    ),
    %% release/3 releases on behalf of the caller.
    ok = masque_ip_session_registry:release(4, {10, 0, 0, 9}, 32),
    ?assertEqual(
        not_found,
        masque_ip_session_registry:lookup({10, 0, 0, 9})
    ).

%% Two proxy-handler sessions allocating from the same pool must not
%% hand out the same address, and ending one keeps the other routable.
shared_pool_distinct_addresses() ->
    clear(),
    Self = self(),
    Pool = {4, {10, 9, 0, 0}, 30},
    Start = fun() ->
        spawn(fun() -> handler_session(Self, Pool) end)
    end,
    A = Start(),
    AddrA = receive_assigned(A),
    B = Start(),
    AddrB = receive_assigned(B),
    ?assertNotEqual(AddrA, AddrB),
    ?assertMatch({ok, A, _}, masque_ip_session_registry:lookup(AddrA)),
    ?assertMatch({ok, B, _}, masque_ip_session_registry:lookup(AddrB)),
    A ! {stop, Self},
    receive
        {stopped, A} -> ok
    after 1000 -> ct:fail("session A did not stop")
    end,
    ?assertEqual(not_found, masque_ip_session_registry:lookup(AddrA)),
    ?assertMatch({ok, B, _}, masque_ip_session_registry:lookup(AddrB)),
    B ! {stop, Self},
    receive
        {stopped, B} -> ok
    after 1000 -> ct:fail("session B did not stop")
    end.

handler_session(Parent, Pool) ->
    Req = #{ip_target => '*', ip_ipproto => '*'},
    {ok, S0} = masque_ip_proxy_handler:init(Req, #{address_pool => Pool}),
    Reqs = [
        #ip_prefix_request{
            request_id = 1,
            version = 4,
            address = {0, 0, 0, 0},
            prefix_len = 32
        }
    ],
    {ok, S1, [{assign, [#ip_assignment{address = Addr}]}]} =
        masque_ip_proxy_handler:handle_address_request(Reqs, S0),
    Parent ! {assigned, self(), Addr},
    receive
        {stop, From} ->
            ok = masque_ip_proxy_handler:terminate(normal, S1),
            From ! {stopped, self()}
    end.

receive_assigned(Pid) ->
    receive
        {assigned, Pid, Addr} -> Addr
    after 1000 -> ct:fail("no address assigned")
    end.

wait_for(Pred, Until) ->
    case Pred() of
        true ->
            ok;
        false ->
            case erlang:monotonic_time(millisecond) > Until of
                true ->
                    ?assert(Pred());
                false ->
                    timer:sleep(10),
                    wait_for(Pred, Until)
            end
    end.
