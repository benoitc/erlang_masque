%%% @doc Unit tests for `masque_racer'.
%%%
%%% Swap out the real session modules for `masque_racer_fake_session'
%%% via the `racer_transport_mods' opts hook so the tests exercise
%%% attempt scheduling, winner selection, and failure handling
%%% without spinning up TLS listeners.
-module(masque_racer_tests).

-include_lib("eunit/include/eunit.hrl").

-define(FAKE, masque_racer_fake_session).

%%====================================================================
%% Winner selection
%%====================================================================

primary_wins_when_fast_enough_test() ->
    %% h3 resolves in 0 ms; h2 should never be spawned because the
    %% primary completes inside its 200 ms head-start window.
    Opts = base_opts(#{
        prefer_timeout_ms => 200,
        fake_by_transport => #{
            h3 => #{fake_result => ok, fake_delay_ms => 0},
            h2 => #{fake_result => ok, fake_delay_ms => 0}
        }
    }),
    {ok, Sess} = run([h3, h2], Opts),
    ok = ?FAKE:stop(Sess).

h2_wins_after_h3_fails_test() ->
    Opts = base_opts(#{
        fake_by_transport => #{
            h3 => #{fake_result => {error, econnrefused}},
            h2 => #{fake_result => ok}
        }
    }),
    {ok, Sess} = run([h3, h2], Opts),
    ok = ?FAKE:stop(Sess).

h1_wins_when_h3_and_h2_fail_test() ->
    Opts = base_opts(#{
        prefer_timeout_ms => 30,
        h1_prefer_timeout_ms => 30,
        timeout => 2000,
        fake_by_transport => #{
            h3 => #{fake_result => {error, no_quic}},
            h2 => #{fake_result => {error, alpn_mismatch}},
            h1 => #{fake_result => ok}
        }
    }),
    {ok, Sess} = run([h3, h2, h1], Opts),
    ok = ?FAKE:stop(Sess).

fastest_wins_in_three_way_test() ->
    %% All three succeed. Primary has a 300 ms head start; with every
    %% attempt taking ~10 ms the primary wins before the secondary or
    %% tertiary are even spawned.
    Opts = base_opts(#{
        prefer_timeout_ms => 300,
        h1_prefer_timeout_ms => 300,
        timeout => 3000,
        fake_by_transport => #{
            h3 => #{fake_result => ok, fake_delay_ms => 10},
            h2 => #{fake_result => ok, fake_delay_ms => 10},
            h1 => #{fake_result => ok, fake_delay_ms => 10}
        }
    }),
    {ok, Sess} = run([h3, h2, h1], Opts),
    ok = ?FAKE:stop(Sess).

%%====================================================================
%% Head-start scheduling
%%====================================================================

h1_not_spawned_when_h2_wins_inside_window_test() ->
    %% h3 fails immediately. h2 succeeds after 20 ms. h1 is 500 ms out
    %% so the race resolves long before the h1 timer fires.
    Start = erlang:monotonic_time(millisecond),
    Opts = base_opts(#{
        prefer_timeout_ms => 30,
        h1_prefer_timeout_ms => 500,
        timeout => 3000,
        fake_by_transport => #{
            h3 => #{fake_result => {error, no_quic}},
            h2 => #{fake_result => ok, fake_delay_ms => 20},
            h1 => #{fake_result => ok, fake_delay_ms => 0}
        }
    }),
    {ok, Sess} = run([h3, h2, h1], Opts),
    Elapsed = erlang:monotonic_time(millisecond) - Start,
    ?assert(Elapsed < 400),
    ok = ?FAKE:stop(Sess).

%%====================================================================
%% Failure surfacing
%%====================================================================

all_fail_returns_last_error_test() ->
    Opts = base_opts(#{
        timeout => 2000,
        prefer_timeout_ms => 10,
        h1_prefer_timeout_ms => 10,
        fake_by_transport => #{
            h3 => #{fake_result => {error, err_h3}},
            h2 => #{fake_result => {error, err_h2}},
            h1 => #{fake_result => {error, err_h1}}
        }
    }),
    %% All attempts fail. The racer returns `{error, Reason}' once
    %% every attempt has resolved (no `race_timeout' wrapper because
    %% the deadline is not hit).
    ?assertMatch({error, _}, run([h3, h2, h1], Opts)).

race_timeout_surfaces_when_deadline_hits_test() ->
    %% Every attempt sits forever (delay >> timeout). The racer hits
    %% its deadline and returns `{error, {race_timeout, _}}'.
    Opts = base_opts(#{
        timeout => 120,
        prefer_timeout_ms => 10,
        h1_prefer_timeout_ms => 10,
        fake_by_transport => #{
            h3 => #{fake_result => ok, fake_delay_ms => 5000},
            h2 => #{fake_result => ok, fake_delay_ms => 5000},
            h1 => #{fake_result => ok, fake_delay_ms => 5000}
        }
    }),
    ?assertMatch({error, {race_timeout, _}}, run([h3, h2, h1], Opts)).

%%====================================================================
%% Helpers
%%====================================================================

base_opts(Extra) ->
    Defaults = #{
        proxy => {<<"127.0.0.1">>, 0},
        owner => self()
    },
    maps:merge(Defaults, Extra).

run(Transports, Opts) ->
    Mods = #{h3 => ?FAKE, h2 => ?FAKE, h1 => ?FAKE},
    Opts1 = Opts#{racer_transport_mods => Mods},
    Target = {<<"target.test">>, 1234},
    masque_racer:race(Transports, Target, Opts1, maps:get(owner, Opts1)).
