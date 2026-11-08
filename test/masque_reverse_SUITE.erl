-module(masque_reverse_SUITE).

%% Reverse connect (draft-rosomakho-masque-reverse-connect-01) end to
%% end on h3, h2 and h1: a listener with `accept_listen', an agent that
%% opens a control channel and accepts, and the test process as the
%% edge that requests connections. This module is also the listen
%% handler.

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("masque_reverse.hrl").

-export([suite/0, all/0, groups/0]).
-export([init_per_suite/1, end_per_suite/1, init_per_group/2, end_per_group/2]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    echo/1,
    large_both_ways/1,
    half_close_from_edge/1,
    half_close_from_agent/1,
    agent_abort_reaches_edge/1,
    decline/1,
    request_timeout/1,
    unknown_id_is_404/1,
    foreign_accept_is_404/1,
    listen_needs_auth/1,
    control_end_fails_pending/1,
    connection_end_ends_streams/1,
    services_delivered/1,
    many_accepts/1,
    slow_edge_holds_agent/1,
    off_by_default/1,
    declined_for_unknown_id_aborts/1,
    udp_echo/1,
    udp_burst/1,
    orphan_accept_is_stopped/1,
    listen_close_ends_accepted_streams/1,
    accepts_wait_for_stream_limit/1,
    pending_requests_capped/1,
    dead_control_rows_dropped/1,
    udp_too_big_dropped/1
]).

%% listen_handler callbacks
-export([authenticate/1, init/2, handle_services/2, handle_info/2, terminate/2]).

-define(PROBE, masque_reverse_probe).
-define(TOKEN, <<"Bearer good">>).
-define(BIG, 16 * 1024 * 1024).
-define(LEAK_MS, 10000).

suite() -> [{timetrap, {minutes, 5}}].

all() -> [{group, h3}, {group, h2}, {group, h1}].

groups() ->
    Common = [
        echo,
        large_both_ways,
        half_close_from_edge,
        half_close_from_agent,
        agent_abort_reaches_edge,
        decline,
        request_timeout,
        unknown_id_is_404,
        foreign_accept_is_404,
        listen_needs_auth,
        control_end_fails_pending,
        services_delivered,
        many_accepts,
        slow_edge_holds_agent,
        off_by_default,
        udp_echo,
        udp_burst,
        orphan_accept_is_stopped,
        pending_requests_capped,
        dead_control_rows_dropped
    ],
    [
        {h3, [],
            Common ++
                [
                    connection_end_ends_streams,
                    listen_close_ends_accepted_streams,
                    accepts_wait_for_stream_limit,
                    declined_for_unknown_id_aborts,
                    udp_too_big_dropped
                ]},
        {h2, [],
            Common ++
                [
                    connection_end_ends_streams,
                    listen_close_ends_accepted_streams,
                    accepts_wait_for_stream_limit,
                    declined_for_unknown_id_aborts
                ]},
        {h1, [], Common}
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Certs} = masque_test_helpers:generate_certs(),
    [{certs, Certs} | Config].

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(certs, Config)).

init_per_group(T, Config) -> [{transport, T} | Config].

end_per_group(_T, _Config) -> ok.

init_per_testcase(Case, Config) ->
    true = register(?PROBE, self()),
    Opts0 =
        case Case of
            off_by_default -> #{};
            _ -> #{accept_listen => true, listen_handler => ?MODULE}
        end,
    Opts =
        case {Case, ?config(transport, Config)} of
            %% Three streams: the control channel and two accept streams.
            {accepts_wait_for_stream_limit, h3} ->
                Opts0#{quic_opts => #{max_streams_bidi => 3}};
            {accepts_wait_for_stream_limit, h2} ->
                Opts0#{settings => #{max_concurrent_streams => 3}};
            _ ->
                Opts0
        end,
    Server = start_server(?config(transport, Config), ?config(certs, Config), Opts),
    [{server, Server} | Config].

end_per_testcase(_Case, Config) ->
    try
        unregister(?PROBE)
    catch
        error:badarg -> ok
    end,
    Left =
        case ?config(tc_status, Config) of
            ok -> wait_no_sessions(?LEAK_MS);
            _ -> []
        end,
    stop_server(?config(transport, Config), ?config(server, Config)),
    case Left of
        [] -> ok;
        _ -> {fail, {sessions_left_behind, [{P, process_info(P, current_stacktrace)} || P <- Left]}}
    end.

%%====================================================================
%% listen_handler
%%====================================================================

authenticate(#{headers := Headers}) ->
    case lists:keyfind(<<"authorization">>, 1, Headers) of
        {_, ?TOKEN} -> {ok, <<"alice">>};
        {_, <<"Bearer other">>} -> {ok, <<"mallory">>};
        _ -> {reject, {other, 401}}
    end.

init(Identity, _Req) ->
    probe({control, self(), Identity}),
    {ok, Identity}.

handle_services(Services, S) ->
    probe({services, Services}),
    {ok, S}.

handle_info(_Msg, S) ->
    {ok, S}.

terminate(Reason, _S) ->
    probe({control_ended, self(), Reason}),
    ok.

%%====================================================================
%% Cases
%%====================================================================

service() -> #{destination => local, protocol => tcp, port => 22}.

echo(Config) ->
    {Agent, Control} = start_agent(Config, echo),
    {ok, Stream} = masque:request_connection(Control, service()),
    ok = masque:send(Stream, <<"hello">>),
    ?assertEqual(<<"hello">>, edge_recv(Stream, 5)),
    ok = masque:close(Stream),
    stop_agent(Agent).

%% 16 MB to the agent and back, with the edge returning credit as it
%% reads.
large_both_ways(Config) ->
    {Agent, Control} = start_agent(Config, echo),
    {ok, Stream} = masque:request_connection(Control, service()),
    Payload = crypto:strong_rand_bytes(?BIG),
    Self = self(),
    Writer = spawn_link(fun() -> Self ! {written, send_chunks(Stream, Payload)} end),
    Got = edge_recv(Stream, ?BIG),
    receive
        {written, ok} -> ok
    after 60000 -> ct:fail({writer_stuck, Writer})
    end,
    ?assertEqual(crypto:hash(sha256, Payload), crypto:hash(sha256, Got)),
    ok = masque:close(Stream),
    stop_agent(Agent).

%% The edge finishes sending; the agent sees FIN, answers and finishes.
half_close_from_edge(Config) ->
    {Agent, Control} = start_agent(Config, collect),
    {ok, Stream} = masque:request_connection(Control, service()),
    ok = masque:send(Stream, <<"abc">>),
    ok = masque:shutdown_write(Stream),
    receive
        {agent_collected, Bytes} -> ?assertEqual(<<"abc">>, Bytes)
    after 10000 -> ct:fail(agent_no_fin)
    end,
    ?assertEqual(<<"xyz">>, edge_recv(Stream, 3)),
    expect_closed(Stream, peer_fin),
    expect_closed(Stream, normal),
    stop_agent(Agent).

%% The agent finishes first; the edge can still send.
half_close_from_agent(Config) ->
    {Agent, Control} = start_agent(Config, greet_then_fin),
    {ok, Stream} = masque:request_connection(Control, service()),
    ?assertEqual(<<"hi">>, edge_recv(Stream, 2)),
    expect_closed(Stream, peer_fin),
    ok = masque:send(Stream, <<"late">>),
    ok = masque:shutdown_write(Stream),
    receive
        {agent_collected, Bytes} -> ?assertEqual(<<"late">>, Bytes)
    after 10000 -> ct:fail(agent_lost_bytes)
    end,
    expect_closed(Stream, normal),
    stop_agent(Agent).

%% An agent that drops its stream aborts it; the edge sees an abort,
%% not a clean end.
agent_abort_reaches_edge(Config) ->
    {Agent, Control} = start_agent(Config, abort),
    {ok, Stream} = masque:request_connection(Control, service()),
    receive
        {masque_closed, Stream, Reason} -> ?assertNotEqual(normal, Reason)
    after 10000 -> ct:fail(no_abort)
    end,
    stop_agent(Agent).

decline(Config) ->
    {Agent, Control} = start_agent(Config, decline),
    ?assertEqual({error, declined}, masque:request_connection(Control, service())),
    stop_agent(Agent).

%% No answer in time; an accept after that gets 404.
request_timeout(Config) ->
    {Agent, Control} = start_agent(Config, hold),
    ?assertEqual(
        {error, timeout}, masque:request_connection(Control, service(), #{timeout => 500})
    ),
    Agent ! accept_now,
    receive
        {agent_accept_result, Result} ->
            ?assertMatch({error, {handshake_rejected, 404, _}}, norm(Result))
    after 10000 -> ct:fail(no_late_accept)
    end,
    stop_agent(Agent).

%% An accept for an id the proxy never issued.
unknown_id_is_404(Config) ->
    ?assertEqual(404, raw_accept_status(Config, 123456789, ?TOKEN)).

%% h3 and h2: an accept on another connection; h1: an accept with
%% another identity. Either way the id stays pending for the real agent.
foreign_accept_is_404(Config) ->
    {Agent, Control} = start_agent(Config, hold),
    Self = self(),
    Requester = spawn_link(fun() ->
        Self ! {requested, masque:request_connection(Control, service())}
    end),
    Id =
        receive
            {agent_request, I} -> I
        after 10000 -> ct:fail(no_request)
        end,
    Token =
        case ?config(transport, Config) of
            h1 -> <<"Bearer other">>;
            _ -> ?TOKEN
        end,
    ?assertEqual(404, raw_accept_status(Config, Id, Token)),
    Agent ! accept_now,
    receive
        {requested, {ok, Stream}} -> ok = masque:close(Stream)
    after 10000 -> ct:fail({no_stream, Requester})
    end,
    stop_agent(Agent).

listen_needs_auth(Config) ->
    ?assertMatch(
        {error, {handshake_rejected, 401, _}},
        norm(
            masque:reverse_listen(
                proxy(Config), {local, '*'}, client_opts(Config, <<"Bearer bad">>)
            )
        )
    ).

%% Requests still waiting when the channel ends fail with `closed'.
control_end_fails_pending(Config) ->
    {Agent, Control} = start_agent(Config, hold),
    Self = self(),
    _ = spawn_link(fun() ->
        Self ! {requested, masque:request_connection(Control, service(), #{timeout => 30000})}
    end),
    receive
        {agent_request, _} -> ok
    after 10000 -> ct:fail(no_request)
    end,
    stop_agent(Agent),
    receive
        {requested, Result} -> ?assertEqual({error, closed}, Result)
    after 10000 -> ct:fail(pending_not_failed)
    end.

%% h3 and h2: the channel and its streams share a connection, so
%% closing the channel ends the streams.
connection_end_ends_streams(Config) ->
    {Agent, Control} = start_agent(Config, echo),
    {ok, Stream} = masque:request_connection(Control, service()),
    ok = masque:send(Stream, <<"x">>),
    <<"x">> = edge_recv(Stream, 1),
    stop_agent(Agent),
    receive
        {masque_closed, Stream, _} -> ok
    after 15000 -> ct:fail(stream_survived)
    end.

%% h3 and h2: the agent closing its control channel (the connection is
%% its own) ends every stream it accepted on it, with `masque_closed'
%% and without a crash.
listen_close_ends_accepted_streams(Config) ->
    {Agent, Control} = start_agent(Config, echo),
    {ok, Stream} = masque:request_connection(Control, service()),
    ok = masque:send(Stream, <<"x">>),
    <<"x">> = edge_recv(Stream, 1),
    Agent ! close_listen,
    receive
        {agent_listen_closed, Agent} -> ok
    after 5000 -> ct:fail(listen_not_closed)
    end,
    receive
        {agent_stream_closed, _S, _Reason} -> ok;
        {agent_streams_open, Left} -> ct:fail({accepted_streams_left, Left})
    after 15000 -> ct:fail(no_stream_end)
    end,
    receive
        {agent_streams_done, Agent} -> ok
    after 15000 -> ct:fail(agent_not_done)
    end.

%% h3 and h2: a proxy that allows only three streams (the control
%% channel and two accept streams). More requests at once still succeed:
%% the agent's accepts wait for a stream to free up instead of failing.
accepts_wait_for_stream_limit(Config) ->
    {Agent, Control} = start_agent(Config, concurrent),
    Self = self(),
    [
        spawn_link(fun() ->
            Result =
                case masque:request_connection(Control, service(), #{timeout => 20000}) of
                    {ok, Stream} ->
                        ok = masque:send(Stream, <<"x">>),
                        <<"x">> = edge_recv(Stream, 1),
                        timer:sleep(500),
                        ok = masque:close(Stream);
                    Other ->
                        Other
                end,
            Self ! {done, N, Result}
        end)
     || N <- lists:seq(1, 5)
    ],
    Results = [
        receive
            {done, N, R} -> R
        after 30000 -> ct:fail({request_stuck, N})
        end
     || N <- lists:seq(1, 5)
    ],
    ?assertEqual([ok, ok, ok, ok, ok], Results),
    stop_agent(Agent).

services_delivered(Config) ->
    {Agent, _Control} = start_agent(Config, echo),
    First = [
        #{destination => local, protocol => tcp, port => 22},
        #{destination => {10, 0, 0, 2}, protocol => udp, port => 53}
    ],
    Second = [#{destination => <<"db.internal">>, protocol => tcp, port => 5432}],
    Agent ! {advertise, First},
    receive
        {services, S1} -> ?assertEqual(First, S1)
    after 10000 -> ct:fail(no_services)
    end,
    Agent ! {advertise, Second},
    receive
        {services, S2} -> ?assertEqual(Second, S2)
    after 10000 -> ct:fail(no_services)
    end,
    stop_agent(Agent).

%% 500 connections, 50 at a time, on one control channel.
many_accepts(Config) ->
    %% One process per accept, as a real agent: an accept that waits for
    %% the proxy to return stream credit does not stop the echoes.
    {Agent, Control} = start_agent(Config, concurrent),
    Self = self(),
    Run = fun(N) ->
        {ok, S} = masque:request_connection(Control, service()),
        Msg = integer_to_binary(N),
        ok = masque:send(S, Msg),
        Msg = edge_recv(S, byte_size(Msg)),
        ok = masque:close(S),
        ok
    end,
    lists:foreach(
        fun(Batch) ->
            Pids = [spawn_link(fun() -> Self ! {done, self(), Run(N)} end) || N <- Batch],
            [
                receive
                    {done, P, ok} -> ok
                after 30000 -> ct:fail({stuck, P})
                end
             || P <- Pids
            ]
        end,
        batches(lists:seq(1, 500), 50)
    ),
    stop_agent(Agent).

%% The edge stops consuming: the agent cannot get far ahead, then
%% catches up once credit comes back.
slow_edge_holds_agent(Config) ->
    {Agent, Control} = start_agent(Config, flood),
    {ok, Stream} = masque:request_connection(Control, service()),
    timer:sleep(3000),
    Held = drain_unconsumed(Stream, 0),
    ct:log("received without returning credit: ~p bytes", [Held]),
    ?assert(Held < 8 * 1024 * 1024),
    ok = masque:consumed(Stream, Held),
    More = edge_recv(Stream, 1024 * 1024),
    ?assert(byte_size(More) >= 1024 * 1024),
    ok = masque:close(Stream),
    stop_agent(Agent).

%% Without `accept_listen' the listener does not know connect-listen.
off_by_default(Config) ->
    ?assertMatch(
        {error, {handshake_rejected, _, _}},
        norm(masque:reverse_listen(proxy(Config), {local, '*'}, client_opts(Config, ?TOKEN)))
    ).

%% Section 5.1: DECLINED for an id that is not outstanding aborts the
%% channel.
declined_for_unknown_id_aborts(Config) ->
    {Tag, Conn, Sid} = raw_listen(Config),
    Bad = masque_reverse_capsule:encode({connection_request_declined, 42}),
    ok = raw_send(Tag, Conn, Sid, Bad),
    receive
        {Tag, Conn, {stream_reset, Sid, _}} -> ok
    after 10000 -> ct:fail(not_aborted)
    end,
    raw_close(Tag, Conn).

udp_service() -> #{destination => local, protocol => udp, port => 53}.

%% A UDP service: each datagram comes back as it went.
%% An accept stream whose request is gone (declined or timed out
%% meanwhile) is stopped, so its own cleanup runs (h2 tunnel slot,
%% gauge, a reset for the stream); it used to be killed.
orphan_accept_is_stopped(Config) ->
    {Agent, Control} = start_agent(Config, hold),
    Self = self(),
    Stream = spawn(fun() ->
        receive
            {'$gen_cast', abandon} -> Self ! {stream_stopped, self()}
        after 5000 -> ok
        end
    end),
    Control ! {masque_reverse_accepted, 424242, Stream},
    receive
        {stream_stopped, Stream} -> ok
    after 5000 -> ct:fail(orphan_not_stopped)
    end,
    ?assert(is_process_alive(Control)),
    stop_agent(Agent).

%% An agent holds at most `max_pending_requests' unanswered requests;
%% the proxy's further requests are declined at once, so a proxy cannot
%% grow the agent's memory or its owner's mailbox.
pending_requests_capped(Config) ->
    {Agent, Control} = start_agent(Config, hold, #{max_pending_requests => 4}),
    Self = self(),
    [
        spawn_link(fun() ->
            Self ! {requested, masque:request_connection(Control, service(), #{timeout => 3000})}
        end)
     || _ <- lists:seq(1, 20)
    ],
    Results = [
        receive
            {requested, R} -> R
        after 10000 -> ct:fail(request_stuck)
        end
     || _ <- lists:seq(1, 20)
    ],
    ?assertEqual(16, length([R || {error, declined} = R <- Results])),
    ?assertEqual(4, length([R || {error, timeout} = R <- Results])),
    ?assertEqual(4, count_agent_requests(0)),
    stop_agent(Agent).

count_agent_requests(N) ->
    receive
        {agent_request, _} -> count_agent_requests(N + 1)
    after 0 -> N
    end.

%% Requests left behind by a control session that died without its
%% cleanup (killed) are dropped at the next accept, which gets 404.
dead_control_rows_dropped(Config) ->
    Dead = spawn(fun() -> ok end),
    MRef = erlang:monitor(process, Dead),
    receive
        {'DOWN', MRef, process, Dead, _} -> ok
    end,
    Id = masque_reverse_registry:register(#{
        control => Dead,
        conn => undefined,
        identity => <<"alice">>,
        requester => self(),
        service => service()
    }),
    ?assertEqual(404, raw_accept_status(Config, Id, ?TOKEN)),
    ?assertEqual(error, masque_reverse_registry:lookup(Id)).

udp_echo(Config) ->
    {Agent, Control} = start_agent(Config, echo),
    {ok, Stream} = masque:request_connection(Control, udp_service()),
    lists:foreach(
        fun(Size) ->
            D = crypto:strong_rand_bytes(Size),
            ok = masque:send(Stream, D),
            receive
                {masque_data, Stream, Got} -> ?assertEqual(D, Got)
            after 5000 -> ct:fail({no_echo, Size})
            end
        end,
        [1, 100, 1000, 1200]
    ),
    ok = masque:close(Stream),
    stop_agent(Agent).

%% A burst of datagrams; UDP may drop some, most come back.
udp_burst(Config) ->
    {Agent, Control} = start_agent(Config, echo),
    {ok, Stream} = masque:request_connection(Control, udp_service()),
    [ok = masque:send(Stream, <<N:32, 0:(996 * 8)>>) || N <- lists:seq(1, 200)],
    Got = count_datagrams(Stream, 0),
    ct:log("~p of 200 datagrams came back", [Got]),
    ?assert(Got >= 150),
    ok = masque:close(Stream),
    stop_agent(Agent).

%% h3: a datagram larger than the path carries is dropped, as on any
%% CONNECT-UDP tunnel; the next one gets through.
udp_too_big_dropped(Config) ->
    {Agent, Control} = start_agent(Config, echo),
    {ok, Stream} = masque:request_connection(Control, udp_service()),
    ok = masque:send(Stream, binary:copy(<<"b">>, 4000)),
    ok = masque:send(Stream, <<"small">>),
    receive
        {masque_data, Stream, Got} -> ?assertEqual(<<"small">>, Got)
    after 5000 -> ct:fail(no_echo)
    end,
    ok = masque:close(Stream),
    stop_agent(Agent).

count_datagrams(Stream, N) ->
    receive
        {masque_data, Stream, _} -> count_datagrams(Stream, N + 1)
    after 2000 -> N
    end.

%%====================================================================
%% Agent
%%====================================================================

%% The agent opens the channel and answers requests by `Mode'. Returns
%% its pid and the control session the edge uses.
start_agent(Config, Mode) ->
    start_agent(Config, Mode, #{}).

start_agent(Config, Mode, Extra) ->
    Self = self(),
    Agent = spawn_link(fun() ->
        {ok, Listen} = masque:reverse_listen(
            proxy(Config), {local, tcp}, maps:merge(client_opts(Config, ?TOKEN), Extra)
        ),
        Self ! {agent_up, self()},
        agent_loop(Listen, Mode, Self, #{})
    end),
    receive
        {agent_up, Agent} -> ok
    after 10000 -> ct:fail(agent_not_up)
    end,
    Control =
        receive
            {control, C, <<"alice">>} -> C
        after 10000 -> ct:fail(no_control)
        end,
    {Agent, Control}.

stop_agent(Agent) ->
    Agent ! stop,
    MRef = erlang:monitor(process, Agent),
    receive
        {'DOWN', MRef, _, _, _} -> ok
    after 10000 -> ct:fail(agent_stuck)
    end.

echo_stream(S) ->
    receive
        {masque_data, S, Bytes} ->
            ok = masque:send(S, Bytes),
            echo_stream(S);
        {masque_closed, S, _} ->
            ok
    end.

%% After `close_listen': report how each accepted stream ended, then stop.
agent_streams_closed(Test, []) ->
    unlink(Test),
    Test ! {agent_streams_done, self()};
agent_streams_closed(Test, Left) ->
    receive
        {masque_closed, S, Reason} ->
            Test ! {agent_stream_closed, S, Reason},
            agent_streams_closed(Test, lists:delete(S, Left));
        _ ->
            agent_streams_closed(Test, Left)
    after 10000 ->
        Test ! {agent_streams_open, Left}
    end.

agent_loop(Listen, Mode, Test, Streams) ->
    receive
        stop ->
            unlink(Test),
            _ = masque:close(Listen);
        {masque_connection_request, Listen, Id, _Service} ->
            agent_request(Listen, Mode, Test, Streams, Id);
        close_listen ->
            ok = masque:close(Listen),
            Test ! {agent_listen_closed, self()},
            agent_streams_closed(Test, maps:keys(maps:remove(held, Streams)));
        accept_now ->
            [Id | _] = maps:get(held, Streams, []),
            Result = masque:reverse_accept(Listen, Id, #{verify => verify_none}),
            Test ! {agent_accept_result, Result},
            case Result of
                {ok, S} -> agent_loop(Listen, Mode, Test, Streams#{S => <<>>});
                _ -> agent_loop(Listen, Mode, Test, Streams)
            end;
        {advertise, Services} ->
            ok = masque:advertise_services(Listen, Services),
            agent_loop(Listen, Mode, Test, Streams);
        {masque_data, S, Bytes} ->
            agent_data(Listen, Mode, Test, Streams, S, Bytes);
        {masque_closed, S, peer_fin} when Mode =:= collect; Mode =:= greet_then_fin ->
            Test ! {agent_collected, maps:get(S, Streams, <<>>)},
            case Mode of
                collect ->
                    ok = masque:send(S, <<"xyz">>),
                    ok = masque:shutdown_write(S);
                greet_then_fin ->
                    ok
            end,
            agent_loop(Listen, Mode, Test, Streams);
        {masque_closed, S, peer_fin} when Mode =:= echo ->
            %% The edge is done: so is the echo.
            _ = quiet(fun() -> masque:shutdown_write(S) end),
            agent_loop(Listen, Mode, Test, Streams);
        {masque_closed, _, _} ->
            agent_loop(Listen, Mode, Test, Streams);
        _ ->
            agent_loop(Listen, Mode, Test, Streams)
    end.

agent_request(Listen, decline, Test, Streams, Id) ->
    ok = masque:reverse_decline(Listen, Id),
    agent_loop(Listen, decline, Test, Streams);
%% Each request in its own process, as a real agent would: an accept
%% waiting for a free stream does not hold up the others.
agent_request(Listen, concurrent, Test, Streams, Id) ->
    _ = spawn_link(fun() ->
        {ok, S} = masque:reverse_accept(Listen, Id, #{verify => verify_none}),
        echo_stream(S)
    end),
    agent_loop(Listen, concurrent, Test, Streams);
agent_request(Listen, hold, Test, Streams, Id) ->
    Test ! {agent_request, Id},
    agent_loop(Listen, hold, Test, Streams#{held => [Id | maps:get(held, Streams, [])]});
agent_request(Listen, Mode, Test, Streams, Id) ->
    {ok, S} = masque:reverse_accept(Listen, Id, #{verify => verify_none}),
    case Mode of
        abort ->
            exit(S, kill),
            agent_loop(Listen, Mode, Test, Streams);
        greet_then_fin ->
            ok = masque:send(S, <<"hi">>),
            ok = masque:shutdown_write(S),
            agent_loop(Listen, Mode, Test, Streams#{S => <<>>});
        flood ->
            Flooder = spawn_link(fun() -> flood(S, binary:copy(<<"f">>, 64 * 1024)) end),
            agent_loop(Listen, Mode, Test, Streams#{flooder => Flooder});
        _ ->
            agent_loop(Listen, Mode, Test, Streams#{S => <<>>})
    end.

agent_data(Listen, echo, Test, Streams, S, Bytes) ->
    ok = send_chunks(S, Bytes),
    agent_loop(Listen, echo, Test, Streams);
agent_data(Listen, Mode, Test, Streams, S, Bytes) ->
    Acc = maps:get(S, Streams, <<>>),
    agent_loop(Listen, Mode, Test, Streams#{S => <<Acc/binary, Bytes/binary>>}).

%% The stream may have ended already.
quiet(Fun) ->
    try
        Fun()
    catch
        exit:_ -> ok
    end.

flood(S, Chunk) ->
    case masque:send(S, Chunk) of
        ok ->
            flood(S, Chunk);
        {error, Full} when Full =:= send_queue_full; Full =:= send_buffer_full ->
            timer:sleep(20),
            flood(S, Chunk);
        _ ->
            ok
    end.

%%====================================================================
%% Helpers
%%====================================================================

%% Edge side: read `Want' bytes, returning credit as they come.
edge_recv(Stream, Want) ->
    edge_recv(Stream, Want, []).

edge_recv(_Stream, Want, Acc) when Want =< 0 ->
    iolist_to_binary(lists:reverse(Acc));
edge_recv(Stream, Want, Acc) ->
    receive
        {masque_data, Stream, Bytes} ->
            ok = masque:consumed(Stream, byte_size(Bytes)),
            edge_recv(Stream, Want - byte_size(Bytes), [Bytes | Acc]);
        {masque_closed, Stream, Reason} ->
            ct:fail({closed, Reason, iolist_size(Acc)})
    after 30000 -> ct:fail({stalled, iolist_size(Acc), Want})
    end.

drain_unconsumed(Stream, N) ->
    receive
        {masque_data, Stream, Bytes} -> drain_unconsumed(Stream, N + byte_size(Bytes))
    after 1000 -> N
    end.

expect_closed(Stream, Reason) ->
    receive
        {masque_closed, Stream, R} -> ?assertEqual(Reason, R)
    after 10000 -> ct:fail({not_closed, Reason})
    end.

send_chunks(_S, <<>>) ->
    ok;
send_chunks(S, Bin) ->
    Size = min(16384, byte_size(Bin)),
    <<Chunk:Size/binary, Rest/binary>> = Bin,
    case masque:send(S, Chunk) of
        ok ->
            send_chunks(S, Rest);
        {error, Full} when Full =:= send_queue_full; Full =:= send_buffer_full ->
            timer:sleep(10),
            send_chunks(S, Bin);
        Err ->
            Err
    end.

batches([], _N) ->
    [];
batches(L, N) when length(L) =< N -> [L];
batches(L, N) ->
    {A, B} = lists:split(N, L),
    [A | batches(B, N)].

%% Rejections come back as 2- or 3-tuples depending on the transport.
norm({error, {handshake_rejected, Status}}) -> {error, {handshake_rejected, Status, <<>>}};
norm(Other) -> Other.

proxy(Config) ->
    #{port := Port} = ?config(server, Config),
    iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]).

client_opts(Config, Token) ->
    #{
        transports => [?config(transport, Config)],
        verify => verify_none,
        timeout => 5000,
        request_headers => [{<<"authorization">>, Token}]
    }.

probe(Msg) ->
    try
        ?PROBE ! Msg,
        ok
    catch
        error:badarg -> ok
    end.

%% A hand-built accept request, for the 404 cases.
raw_accept_status(Config, Id, Token) ->
    Path = iolist_to_binary(["/.well-known/masque/accept/", integer_to_list(Id), "/"]),
    case ?config(transport, Config) of
        h1 ->
            #{port := Port} = ?config(server, Config),
            {ok, Sock} = ssl:connect(
                "127.0.0.1",
                Port,
                [
                    binary,
                    {active, false},
                    {verify, verify_none},
                    {alpn_advertised_protocols, [<<"http/1.1">>]}
                ],
                5000
            ),
            ok = ssl:send(Sock, [
                <<"GET ">>,
                Path,
                <<" HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: connect-accept\r\n">>,
                <<"Capsule-Protocol: ?1\r\nAuthorization: ">>,
                Token,
                <<"\r\n\r\n">>
            ]),
            {ok, <<"HTTP/1.1 ", Code:3/binary, _/binary>>} = ssl:recv(Sock, 0, 5000),
            ssl:close(Sock),
            binary_to_integer(Code);
        T ->
            {Tag, Conn, Sid} = raw_request(Config, T, ?MASQUE_CONNECT_ACCEPT_PROTOCOL, Path, Token),
            Status =
                receive
                    {Tag, Conn, {response, Sid, St, _}} -> St
                after 5000 -> ct:fail(no_response)
                end,
            raw_close(Tag, Conn),
            Status
    end.

raw_listen(Config) ->
    Path = <<"/.well-known/masque/listen/./6/">>,
    {Tag, Conn, Sid} = raw_request(
        Config, ?config(transport, Config), ?MASQUE_CONNECT_LISTEN_PROTOCOL, Path, ?TOKEN
    ),
    receive
        {Tag, Conn, {response, Sid, 200, _}} -> ok
    after 5000 -> ct:fail(no_listen_response)
    end,
    {Tag, Conn, Sid}.

raw_request(Config, h3, Token, Path, Auth) ->
    #{port := Port} = ?config(server, Config),
    {ok, Conn} = masque_test_helpers:h3_client_connect(Port, #{}),
    Headers = [
        {<<":method">>, <<"CONNECT">>},
        {<<":protocol">>, Token},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"127.0.0.1">>},
        {<<":path">>, Path},
        {<<"capsule-protocol">>, <<"?1">>},
        {<<"authorization">>, Auth}
    ],
    {ok, Sid} = quic_h3:request(Conn, Headers, #{end_stream => false}),
    {quic_h3, Conn, Sid};
raw_request(Config, h2, Token, Path, Auth) ->
    #{port := Port} = ?config(server, Config),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{
        transport => ssl,
        ssl_opts => [{verify, verify_none}, {alpn_advertised_protocols, [<<"h2">>]}],
        sync => true,
        settings => #{enable_connect_protocol => 1}
    }),
    Headers = [
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"127.0.0.1">>},
        {<<":path">>, Path},
        {<<"capsule-protocol">>, <<"?1">>},
        {<<"authorization">>, Auth}
    ],
    {ok, Sid} = h2:request(Conn, Headers, #{protocol => Token}),
    {h2, Conn, Sid}.

raw_send(quic_h3, Conn, Sid, Bin) -> quic_h3:send_data(Conn, Sid, Bin, false);
raw_send(h2, Conn, Sid, Bin) -> h2:send_data(Conn, Sid, Bin, false).

raw_close(quic_h3, Conn) -> quic_h3:close(Conn);
raw_close(h2, Conn) -> h2:close(Conn).

%%====================================================================
%% Servers
%%====================================================================

start_server(h3, Certs, Opts) ->
    {ok, Srv} = masque_test_helpers:start_masque_server(maps:merge(Certs, Opts)),
    Srv;
start_server(h2, #{cert_file := Cert, key_file := Key}, Opts) ->
    Name = unique(h2),
    {ok, {_, _, Port}} = masque:start_listener_h2(Name, Opts#{port => 0, cert => Cert, key => Key}),
    #{name => Name, port => Port};
start_server(h1, #{cert_file := Cert, key_file := Key}, Opts) ->
    Name = unique(h1),
    {ok, Ref} = masque:start_listener_h1(Name, Opts#{port => 0, cert => Cert, key => Key}),
    #{name => Name, port => h1:server_port(Ref)}.

stop_server(h3, Srv) -> masque_test_helpers:stop_masque_server(Srv);
stop_server(h2, #{name := Name}) -> masque:stop_listener_h2(Name);
stop_server(h1, #{name := Name}) -> masque:stop_listener_h1(Name).

unique(Prefix) ->
    list_to_atom(
        "rev_" ++ atom_to_list(Prefix) ++ "_" ++ integer_to_list(erlang:unique_integer([positive]))
    ).

wait_no_sessions(Left) when Left =< 0 ->
    sessions();
wait_no_sessions(Left) ->
    case sessions() of
        [] ->
            [];
        _ ->
            timer:sleep(200),
            wait_no_sessions(Left - 200)
    end.

%% Server sessions and reverse connect client sessions still alive.
sessions() ->
    [
        P
     || P <- processes(),
        Mod <- initial_module(P),
        lists:suffix("server_session", atom_to_list(Mod)) orelse
            lists:prefix("masque_listen_", atom_to_list(Mod))
    ].

initial_module(P) ->
    case process_info(P, dictionary) of
        {dictionary, Dict} ->
            case lists:keyfind('$initial_call', 1, Dict) of
                {_, {Mod, init, 1}} -> [Mod];
                _ -> []
            end;
        _ ->
            []
    end.
