%%% @doc Unit tests for `masque_upstream_pool'.
%%%
%%% The registry is exercised end-to-end against the mock transport
%%% so the self-dialing owner path and the single-flight coalescing
%%% are both under test. No real TLS handshakes are performed.
-module(masque_upstream_pool_tests).

-include_lib("eunit/include/eunit.hrl").

-define(M, masque_upstream_pool).
-define(MOCK, masque_mock_transport).

%%====================================================================
%% Fixture
%%====================================================================

-define(setup(F),
    {setup, fun setup/0, fun cleanup/1, F}
).

setup() ->
    %% Apps already started when eunit pulls in masque; the pool is
    %% a supervised child so it should be up.
    {ok, _} = application:ensure_all_started(masque),
    _ = persistent_term:put({?MOCK, connect_result}, auto),
    ok.

cleanup(_) ->
    _ = ?M:close_all(),
    _ = persistent_term:erase({?MOCK, connect_result}),
    ok.

%%====================================================================
%% Fingerprint
%%====================================================================

fingerprint_differs_on_verify_test() ->
    A = ?M:fingerprint(<<"host">>, 443, h2, #{verify => verify_peer}),
    B = ?M:fingerprint(<<"host">>, 443, h2, #{verify => verify_none}),
    ?assertNotEqual(A, B).

fingerprint_stable_under_ssl_opts_reorder_test() ->
    A = ?M:fingerprint(
        <<"host">>,
        443,
        h2,
        #{
            ssl_opts => [
                {verify, verify_peer},
                {cacerts, []}
            ]
        }
    ),
    B = ?M:fingerprint(
        <<"host">>,
        443,
        h2,
        #{
            ssl_opts => [
                {cacerts, []},
                {verify, verify_peer}
            ]
        }
    ),
    ?assertEqual(A, B).

fingerprint_ignores_per_tunnel_opts_test() ->
    A = ?M:fingerprint(<<"host">>, 443, h2, #{
        timeout => 1000,
        protocol => udp,
        owner => self()
    }),
    B = ?M:fingerprint(<<"host">>, 443, h2, #{
        timeout => 9000,
        protocol => tcp,
        owner => self()
    }),
    ?assertEqual(A, B).

fingerprint_differs_on_host_port_transport_test() ->
    A = ?M:fingerprint(<<"a">>, 443, h2, #{}),
    B = ?M:fingerprint(<<"b">>, 443, h2, #{}),
    C = ?M:fingerprint(<<"a">>, 8443, h2, #{}),
    D = ?M:fingerprint(<<"a">>, 443, quic_h3, #{}),
    ?assertNotEqual(A, B),
    ?assertNotEqual(A, C),
    ?assertNotEqual(A, D).

%%====================================================================
%% Checkout behaviour
%%====================================================================

checkout_opens_once_and_reuses_test_() ->
    ?setup(fun checkout_opens_once_and_reuses/0).

checkout_opens_once_and_reuses() ->
    FP = ?M:fingerprint(<<"reuse">>, 443, h2, #{}),
    {ok, O1} = ?M:checkout(FP, pool_opts(h2)),
    {ok, O2} = ?M:checkout(FP, pool_opts(h2)),
    ?assertEqual(O1, O2).

checkout_different_fp_opens_new_test_() ->
    ?setup(fun checkout_different_fp_opens_new/0).

checkout_different_fp_opens_new() ->
    FPA = ?M:fingerprint(<<"alpha">>, 443, h2, #{}),
    FPB = ?M:fingerprint(<<"beta">>, 443, h2, #{}),
    {ok, OA} = ?M:checkout(FPA, pool_opts(h2)),
    {ok, OB} = ?M:checkout(FPB, pool_opts(h2)),
    ?assertNotEqual(OA, OB).

checkout_different_verify_opens_new_test_() ->
    ?setup(fun checkout_different_verify_opens_new/0).

checkout_different_verify_opens_new() ->
    FPPeer = ?M:fingerprint(<<"host">>, 443, h2, #{verify => verify_peer}),
    FPNone = ?M:fingerprint(<<"host">>, 443, h2, #{verify => verify_none}),
    {ok, OA} = ?M:checkout(FPPeer, pool_opts(h2)),
    {ok, OB} = ?M:checkout(FPNone, pool_opts(h2)),
    ?assertNotEqual(OA, OB).

%%====================================================================
%% Coalesced dial
%%====================================================================

checkout_coalesces_during_dial_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun checkout_coalesces_during_dial/0}.

checkout_coalesces_during_dial() ->
    %% Stage the mock's `connect' to sleep 150 ms and notify us so
    %% we can count the actual handshakes. Five concurrent checkouts
    %% for the same FP must all get the same owner and the mock
    %% must have been connected exactly once.
    Self = self(),
    persistent_term:put(
        {?MOCK, connect_result},
        {delay, 150, {notify, Self, auto}}
    ),
    FP = ?M:fingerprint(<<"coalesce">>, 443, h2, #{}),
    try
        Pids = [spawn_checkout(FP, pool_opts(h2)) || _ <- lists:seq(1, 5)],
        Owners = [recv_result(P, 3000) || P <- Pids],
        [First | Rest] = Owners,
        [?assertEqual(First, O) || O <- Rest],
        receive
        after 300 -> ok
        end,
        Count = length([x || {mock_connected, _} <- drain_mailbox()]),
        ?assertEqual(1, Count)
    after
        persistent_term:erase({?MOCK, connect_result})
    end.

%%====================================================================
%% Dial failure
%%====================================================================

dial_failure_replies_to_all_waiters_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun dial_failure_replies_to_all_waiters/0}.

dial_failure_replies_to_all_waiters() ->
    persistent_term:put({?MOCK, connect_result}, {error, econnrefused}),
    FP = ?M:fingerprint(<<"fail">>, 443, h2, #{}),
    try
        R = ?M:checkout(FP, pool_opts(h2)),
        ?assertMatch({error, econnrefused}, R)
    after
        persistent_term:erase({?MOCK, connect_result})
    end.

throwing_dial_does_not_poison_fingerprint_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun throwing_dial_does_not_poison_fingerprint/0}.

throwing_dial_does_not_poison_fingerprint() ->
    FP = ?M:fingerprint(<<"throw">>, 443, h2, #{}),
    persistent_term:put({?MOCK, connect_result}, {raise, throw, boom}),
    ?assertMatch({error, {dial_crashed, {throw, boom}}}, ?M:checkout(FP, pool_opts(h2))),
    persistent_term:put({?MOCK, connect_result}, {raise, error, badarg}),
    ?assertMatch({error, {dial_crashed, {error, badarg}}}, ?M:checkout(FP, pool_opts(h2))),
    persistent_term:put({?MOCK, connect_result}, auto),
    ?assertMatch({ok, _}, ?M:checkout(FP, pool_opts(h2))).

owner_killed_while_dialing_fails_waiters_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun owner_killed_while_dialing_fails_waiters/0}.

owner_killed_while_dialing_fails_waiters() ->
    Self = self(),
    persistent_term:put({?MOCK, connect_result}, {notify, Self, {delay, 5000, auto}}),
    FP = ?M:fingerprint(<<"killed">>, 443, h2, #{}),
    Pids = [spawn_checkout(FP, pool_opts(h2)) || _ <- lists:seq(1, 3)],
    Dialer =
        receive
            {mock_connected, P} -> P
        after 1000 -> error(no_dial)
        end,
    exit(Dialer, kill),
    [?assertEqual({error, {dial_failed, killed}}, recv_result(P, 1000)) || P <- Pids],
    persistent_term:put({?MOCK, connect_result}, auto),
    ?assertMatch({ok, _}, ?M:checkout(FP, pool_opts(h2))).

checkout_timeout_returns_error_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun checkout_timeout_returns_error/0}.

checkout_timeout_returns_error() ->
    persistent_term:put({?MOCK, connect_result}, {delay, 500, auto}),
    FP = ?M:fingerprint(<<"slow">>, 443, h2, #{}),
    Opts = (pool_opts(h2))#{checkout_timeout_ms => 50},
    ?assertEqual({error, timeout}, ?M:checkout(FP, Opts)).

%%====================================================================
%% Stream capacity
%%====================================================================

full_owner_triggers_second_owner_test_() ->
    ?setup(fun full_owner_triggers_second_owner/0).

full_owner_triggers_second_owner() ->
    FP = ?M:fingerprint(<<"full">>, 443, h2, #{}),
    Opts = (pool_opts(h2))#{max_streams => 1},
    {ok, O1} = ?M:checkout(FP, Opts),
    {ok, Sid, _} = masque_upstream_owner:acquire_stream(O1, [], self(), #{}),
    {ok, O2} = ?M:checkout(FP, Opts),
    ?assertNotEqual(O1, O2),
    %% Releasing the stream frees the first owner again.
    ok = masque_upstream_owner:release_stream(O1, Sid),
    _ = masque_upstream_owner:info(O1),
    timer:sleep(20),
    ?assertEqual({ok, O1}, ?M:checkout(FP, Opts)).

%%====================================================================
%% Owner death eviction
%%====================================================================

owner_death_evicts_entry_test_() ->
    ?setup(fun owner_death_evicts_entry/0).

owner_death_evicts_entry() ->
    FP = ?M:fingerprint(<<"evict">>, 443, h2, #{}),
    {ok, O1} = ?M:checkout(FP, pool_opts(h2)),
    MRef = erlang:monitor(process, O1),
    exit(O1, kill),
    receive
        {'DOWN', MRef, process, O1, _} -> ok
    after 1000 -> ct:fail(no_down)
    end,
    %% Give the registry a tick to handle its own monitor.
    timer:sleep(50),
    {ok, O2} = ?M:checkout(FP, pool_opts(h2)),
    ?assertNotEqual(O1, O2).

%%====================================================================
%% Registry responsiveness during a dial
%%====================================================================

registry_does_not_block_on_dial_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun registry_does_not_block_on_dial/0}.

registry_does_not_block_on_dial() ->
    %% Two different FPs both dial slowly (400 ms each). If the
    %% registry serialises dials across keys the total wall time is
    %% ~800 ms; the parallel-dial design should complete in ~400 ms.
    persistent_term:put(
        {?MOCK, connect_result},
        {delay, 400, auto}
    ),
    FPA = ?M:fingerprint(<<"slow-a">>, 443, h2, #{}),
    FPB = ?M:fingerprint(<<"slow-b">>, 443, h2, #{}),
    try
        T0 = erlang:monotonic_time(millisecond),
        APid = spawn_checkout(FPA, pool_opts(h2)),
        BPid = spawn_checkout(FPB, pool_opts(h2)),
        _ = recv_result(APid, 2000),
        _ = recv_result(BPid, 2000),
        Elapsed = erlang:monotonic_time(millisecond) - T0,
        %% 600 ms headroom above the 400 ms dial; serialised would
        %% land around 800 ms.
        ?assert(
            Elapsed < 600,
            io_lib:format(
                "parallel dials took ~p ms, expected < 600",
                [Elapsed]
            )
        )
    after
        persistent_term:erase({?MOCK, connect_result})
    end.

%%====================================================================
%% Helpers
%%====================================================================

pool_opts(Transport) ->
    #{
        transport => Transport,
        transport_mod => ?MOCK,
        host => <<"127.0.0.1">>,
        port => 1,
        connect_opts => #{},
        idle_timeout_ms => 30000
    }.

spawn_checkout(FP, Opts) ->
    Self = self(),
    erlang:spawn(fun() ->
        R = ?M:checkout(FP, Opts),
        Self ! {result, self(), R}
    end).

recv_result(Pid, Timeout) ->
    receive
        {result, Pid, {ok, Owner}} -> Owner;
        {result, Pid, Other} -> Other
    after Timeout ->
        ct:fail({no_result, Pid})
    end.

drain_mailbox() ->
    receive
        Msg -> [Msg | drain_mailbox()]
    after 0 -> []
    end.
