%%% @doc Unit tests for `masque_upstream_owner'.
%%%
%%% Drives the owner against `masque_mock_transport' so the tests
%%% never touch a real h2 / quic_h3 connection. Covers acquire +
%%% release, auto-release on session death, connection close
%%% propagation, stream-limit rejection, and idle-timeout eviction.
-module(masque_upstream_owner_tests).

-include_lib("eunit/include/eunit.hrl").

-define(M, masque_upstream_owner).
-define(MOCK, masque_mock_transport).

%%====================================================================
%% Basic lifecycle
%%====================================================================

start_stop_test() ->
    {Owner, Mock} = start_owner(h2),
    ok = ?M:stop(Owner),
    assert_dead(Owner),
    ?MOCK:stop(Mock).

info_reports_current_state_test() ->
    {Owner, Mock} = start_owner(h2),
    Info = ?M:info(Owner),
    ?assertMatch(#{transport := h2, refs := 0}, Info),
    ok = ?M:stop(Owner),
    ?MOCK:stop(Mock).

%%====================================================================
%% acquire_stream / release_stream
%%====================================================================

acquire_issues_request_and_registers_handler_test() ->
    {Owner, Mock} = start_owner(h2),
    Session = self(),
    {ok, StreamId, Conn} =
        ?M:acquire_stream(Owner, sample_headers(), Session, #{}),
    ?assertEqual(Mock, Conn),
    %% Mock recorded a `request' call + `set_stream_handler' for the
    %% stream id it just returned (plus a bootstrap `get_peer_settings').
    Calls = ?MOCK:calls(Mock),
    ?assert(
        lists:any(
            fun
                ({request, _}) -> true;
                (_) -> false
            end,
            Calls
        )
    ),
    ?assert(
        lists:any(
            fun
                ({set_stream_handler, [SId, Pid]}) ->
                    SId =:= StreamId andalso Pid =:= Session;
                (_) ->
                    false
            end,
            Calls
        )
    ),
    %% refs count is 1 after acquire.
    #{refs := 1} = ?M:info(Owner),
    ok = ?M:release_stream(Owner, StreamId),
    wait_refs_drop_to_zero(Owner, 500),
    ok = ?M:stop(Owner),
    ?MOCK:stop(Mock).

release_cancels_and_unregisters_test() ->
    {Owner, Mock} = start_owner(h2),
    {ok, StreamId, _} =
        ?M:acquire_stream(Owner, sample_headers(), self(), #{}),
    ok = ?M:release_stream(Owner, StreamId),
    wait_refs_drop_to_zero(Owner, 500),
    Calls = ?MOCK:calls(Mock),
    ?assert(
        lists:any(
            fun
                ({unset_stream_handler, [SId]}) -> SId =:= StreamId;
                (_) -> false
            end,
            Calls
        )
    ),
    ?assert(
        lists:any(
            fun
                ({cancel, [SId]}) -> SId =:= StreamId;
                (_) -> false
            end,
            Calls
        )
    ),
    ok = ?M:stop(Owner),
    ?MOCK:stop(Mock).

release_is_idempotent_test() ->
    {Owner, Mock} = start_owner(h2),
    {ok, StreamId, _} =
        ?M:acquire_stream(Owner, sample_headers(), self(), #{}),
    ok = ?M:release_stream(Owner, StreamId),
    ok = ?M:release_stream(Owner, StreamId),
    #{refs := 0} = ?M:info(Owner),
    ok = ?M:stop(Owner),
    ?MOCK:stop(Mock).

session_death_auto_releases_test() ->
    {Owner, Mock} = start_owner(h2),
    %% Spawn a session that acquires then dies.
    Self = self(),
    SessionPid = erlang:spawn(fun() ->
        Self !
            {acquired,
                ?M:acquire_stream(
                    Owner,
                    sample_headers(),
                    self(),
                    #{}
                )},
        receive
            die -> exit(boom)
        end
    end),
    {ok, StreamId, _Conn} =
        receive
            {acquired, R} -> R
        after 2000 -> ct:fail(no_reply)
        end,
    #{refs := 1} = ?M:info(Owner),
    SessionPid ! die,
    ok = wait_refs_drop_to_zero(Owner, 500),
    Calls = ?MOCK:calls(Mock),
    ?assert(
        lists:any(
            fun
                ({unset_stream_handler, [SId]}) -> SId =:= StreamId;
                (_) -> false
            end,
            Calls
        )
    ),
    ok = ?M:stop(Owner),
    ?MOCK:stop(Mock).

%%====================================================================
%% Stream limits
%%====================================================================

h2_reads_peer_settings_for_max_streams_test() ->
    {Owner, Mock} = start_owner(
        h2,
        #{peer_settings => #{max_concurrent_streams => 2}}
    ),
    ?assertMatch(#{max_streams := 2}, ?M:info(Owner)),
    ok = ?M:stop(Owner),
    ?MOCK:stop(Mock).

acquire_over_limit_rejects_test() ->
    {Owner, Mock} = start_owner(
        h2,
        #{peer_settings => #{max_concurrent_streams => 1}}
    ),
    {ok, _Sid, _} =
        ?M:acquire_stream(Owner, sample_headers(), self(), #{}),
    ?assertEqual(
        {error, stream_limit},
        ?M:acquire_stream(
            Owner,
            sample_headers(),
            self(),
            #{}
        )
    ),
    ok = ?M:stop(Owner),
    ?MOCK:stop(Mock).

h3_max_streams_defaults_to_100_test() ->
    {Owner, Mock} = start_owner(quic_h3),
    ?assertMatch(#{max_streams := 100}, ?M:info(Owner)),
    ok = ?M:stop(Owner),
    ?MOCK:stop(Mock).

%% A transport stream-limit error marks the owner full so the pool
%% stops handing it out.
transport_stream_limit_marks_owner_full_test() ->
    {Owner, Mock} = start_owner(quic_h3, #{
        pool => self(), request_result => {error, stream_limit}
    }),
    ?assertEqual(
        {error, stream_limit},
        ?M:acquire_stream(Owner, sample_headers(), self(), #{})
    ),
    receive
        {owner_capacity, Owner, true} -> ok
    after 1000 -> ?assert(false)
    end,
    ok = ?M:stop(Owner),
    ?MOCK:stop(Mock).

%%====================================================================
%% Connection close propagation
%%====================================================================

connection_closed_broadcasts_to_all_sessions_test() ->
    {Owner, Mock} = start_owner(h2),
    {ok, _S1, _} = ?M:acquire_stream(Owner, sample_headers(), self(), #{}),
    Self = self(),
    OtherSession = erlang:spawn(fun() ->
        Self ! {sub, self()},
        receive
            M -> Self ! {other_got, M}
        end
    end),
    receive
        {sub, OtherSession} -> ok
    after 500 -> ok
    end,
    {ok, _S2, _} =
        ?M:acquire_stream(Owner, sample_headers(), OtherSession, #{}),
    %% Simulate conn close: owner receives `{h2, Conn, {closed, Reason}}'
    ?MOCK:simulate(Mock, {send_to_owner, Owner, {h2, Mock, {closed, normal}}}),
    %% Our test process should see `{h2, _, {closed, _}}' and the spawned
    %% session should too.
    receive
        {h2, _, {closed, _}} -> ok
    after 1000 -> ct:fail(no_closed_to_self)
    end,
    receive
        {other_got, {h2, _, {closed, _}}} -> ok
    after 1000 -> ct:fail(no_closed_to_other)
    end,
    %% Owner should be stopping (normal).
    true = wait_dead(Owner, 1000),
    ?MOCK:stop(Mock).

conn_death_stops_owner_test() ->
    {Owner, Mock} = start_owner(h2),
    {ok, _, _} = ?M:acquire_stream(Owner, sample_headers(), self(), #{}),
    %% Kill the mock (the "conn") - owner monitors it.
    exit(Mock, kill),
    true = wait_dead(Owner, 1000),
    %% Our session received the closed notification.
    receive
        {h2, _, {closed, _}} -> ok
    after 1000 -> ct:fail(no_closed_on_conn_death)
    end.

%%====================================================================
%% Idle timeout
%%====================================================================

idle_timeout_stops_owner_when_refs_empty_test() ->
    {Owner, Mock} = start_owner(h2, #{idle_timeout_ms => 100}),
    %% No acquires; the initial idle timer fires and stops the owner.
    true = wait_dead(Owner, 500),
    ?MOCK:stop(Mock).

idle_timer_rearms_after_last_release_test() ->
    {Owner, Mock} = start_owner(h2, #{idle_timeout_ms => 100}),
    {ok, StreamId, _} =
        ?M:acquire_stream(Owner, sample_headers(), self(), #{}),
    timer:sleep(200),
    %% Still alive: the acquire cancelled the initial idle timer.
    ?assert(is_process_alive(Owner)),
    ok = ?M:release_stream(Owner, StreamId),
    true = wait_dead(Owner, 500),
    ?MOCK:stop(Mock).

%%====================================================================
%% h3 datagram demux
%%====================================================================

h3_datagram_routes_to_matching_session_test() ->
    {Owner, Mock} = start_owner(quic_h3),
    Self = self(),
    %% Two sessions, each acquires one stream.
    SessionA = erlang:spawn(
        fun() ->
            Self !
                {a_stream,
                    ?M:acquire_stream(
                        Owner,
                        sample_headers(),
                        self(),
                        #{}
                    )},
            receive
                {quic_h3, _, {datagram, Sid, P}} ->
                    Self ! {a_got, Sid, P}
            end
        end
    ),
    SessionB = erlang:spawn(
        fun() ->
            Self !
                {b_stream,
                    ?M:acquire_stream(
                        Owner,
                        sample_headers(),
                        self(),
                        #{}
                    )},
            receive
                {quic_h3, _, {datagram, Sid, P}} ->
                    Self ! {b_got, Sid, P}
            end
        end
    ),
    {ok, SidA, _} =
        receive
            {a_stream, R1} -> R1
        after 2000 ->
            ct:fail(no_a)
        end,
    {ok, SidB, _} =
        receive
            {b_stream, R2} -> R2
        after 2000 ->
            ct:fail(no_b)
        end,
    %% Simulate h3 delivering a datagram to the conn owner for each
    %% stream; the owner must route by stream_id.
    ?MOCK:simulate(Mock, {send_to_owner, Owner, {quic_h3, Mock, {datagram, SidA, <<"apkt">>}}}),
    ?MOCK:simulate(Mock, {send_to_owner, Owner, {quic_h3, Mock, {datagram, SidB, <<"bpkt">>}}}),
    receive
        {a_got, SidA, <<"apkt">>} -> ok
    after 1000 -> ct:fail(a_missed)
    end,
    receive
        {b_got, SidB, <<"bpkt">>} -> ok
    after 1000 -> ct:fail(b_missed)
    end,
    _ = SessionA,
    _ = SessionB,
    ok = ?M:stop(Owner),
    ?MOCK:stop(Mock).

%%====================================================================
%% Helpers
%%====================================================================

sample_headers() ->
    [
        {<<":method">>, <<"CONNECT">>},
        {<<":protocol">>, <<"connect-udp">>},
        {<<":path">>, <<"/.well-known/masque/udp/127.0.0.1/5353/">>}
    ].

start_owner(Transport) ->
    start_owner(Transport, #{}).

%% `Extra' may contain owner keys (`idle_timeout_ms', `max_streams',
%% `fingerprint') and mock-config keys (`peer_settings',
%% `request_result', `set_handler_result', `start_stream_id'). The
%% helper sorts them into the right place.
start_owner(Transport, Extra) ->
    MockKeys = [
        peer_settings,
        request_result,
        set_handler_result,
        start_stream_id
    ],
    MockOpts = maps:with(MockKeys, Extra),
    OwnerExtra = maps:without(MockKeys, Extra),
    {ok, Mock} = ?MOCK:start(MockOpts),
    Args = maps:merge(
        #{
            transport => Transport,
            transport_mod => ?MOCK,
            conn => Mock,
            idle_timeout_ms => 10000
        },
        OwnerExtra
    ),
    {ok, Owner} = ?M:start_link(Args),
    {Owner, Mock}.

assert_dead(Pid) ->
    true = wait_dead(Pid, 500).

wait_dead(Pid, Timeout) ->
    MRef = erlang:monitor(process, Pid),
    receive
        {'DOWN', MRef, process, Pid, _} -> true
    after Timeout -> false
    end.

wait_refs_drop_to_zero(_Owner, 0) ->
    ct:fail(refs_did_not_drop);
wait_refs_drop_to_zero(Owner, Remaining) ->
    case ?M:info(Owner) of
        #{refs := 0} ->
            ok;
        _ ->
            timer:sleep(10),
            wait_refs_drop_to_zero(Owner, Remaining - 10)
    end.
