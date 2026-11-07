%%% @doc Load checks, run on demand: `MASQUE_LOAD=1 rebar3 ct --suite
%%% test/masque_load_SUITE'. Each case logs what it measured and fails
%%% only on a broken tunnel or leftover sessions, since throughput and
%%% loss depend on the machine.
-module(masque_load_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([suite/0, all/0, init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([h3_busy_udp_tunnels/1, h3_short_tunnels/1, h2_short_tunnels/1]).
-export([h3_reverse_short_streams/1, h2_reverse_short_streams/1]).
%% logger handler: counts error reports
-export([log/2]).

-define(UDP_TUNNELS, 20).
-define(UDP_DATAGRAMS, 5000).
-define(SHORT_TUNNELS, 2000).
-define(SHORT_PARALLEL, 50).

suite() -> [{timetrap, {minutes, 10}}].

all() ->
    [
        h3_busy_udp_tunnels,
        h3_short_tunnels,
        h2_short_tunnels,
        h3_reverse_short_streams,
        h2_reverse_short_streams
    ].

init_per_suite(Config) ->
    case os:getenv("MASQUE_LOAD") of
        "1" ->
            {ok, _} = application:ensure_all_started(masque),
            {ok, Certs} = masque_test_helpers:generate_certs(),
            {Udp, UdpPort} = start_udp_echo(),
            {Tcp, TcpPort} = start_tcp_echo(),
            [
                {certs, Certs},
                {udp, Udp},
                {udp_port, UdpPort},
                {tcp, Tcp},
                {tcp_port, TcpPort}
                | Config
            ];
        _ ->
            {skip, "set MASQUE_LOAD=1 to run"}
    end.

end_per_suite(Config) ->
    exit(?config(udp, Config), kill),
    exit(?config(tcp, Config), kill),
    masque_test_helpers:cleanup_certs(?config(certs, Config)),
    ok.

init_per_testcase(Case, Config0) ->
    Config = count_error_reports(Config0),
    start_listener(Case, Config).

start_listener(Case, Config) when Case =:= h2_short_tunnels; Case =:= h2_reverse_short_streams ->
    #{cert_file := Cert, key_file := Key} = ?config(certs, Config),
    Name = list_to_atom("load_h2_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, {_, _, Port}} = masque:start_listener_h2(Name, (listener_opts())#{
        port => 0, cert => Cert, key => Key
    }),
    [{stop, fun() -> masque:stop_listener_h2(Name) end}, {port, Port}, {transport, h2} | Config];
start_listener(_Case, Config) ->
    {ok, #{port := Port} = Srv} = masque_test_helpers:start_masque_server(
        maps:merge(?config(certs, Config), listener_opts())
    ),
    [
        {stop, fun() -> masque_test_helpers:stop_masque_server(Srv) end},
        {port, Port},
        {transport, h3}
        | Config
    ].

%% A finished tunnel is not a crash: no session may log an error report,
%% whatever the load.
end_per_testcase(_Case, Config) ->
    (?config(stop, Config))(),
    logger:remove_handler(masque_load_reports),
    Reports = counters:get(?config(reports, Config), 1),
    ct:pal("error reports: ~p", [Reports]),
    case Reports of
        0 -> ok;
        N -> {fail, {error_reports, N}}
    end.

listener_opts() ->
    #{
        handler_opts => #{allow_private => true, allow_self => true},
        accept_listen => true,
        listen_handler => masque_listen_test_handler
    }.

count_error_reports(Config) ->
    Counter = counters:new(1, []),
    ok = logger:add_handler(masque_load_reports, ?MODULE, #{
        level => error, config => #{counter => Counter}
    }),
    [{reports, Counter} | Config].

%% logger handler: one count per error-level event from this node.
log(#{level := Level}, #{config := #{counter := Counter}}) when
    Level =:= error; Level =:= critical; Level =:= alert; Level =:= emergency
->
    counters:add(Counter, 1, 1);
log(_Event, _Config) ->
    ok.

%%====================================================================
%% Cases
%%====================================================================

%% Many busy tunnels. The router may drop datagrams for a session that
%% falls behind, but tunnels must keep working.
h3_busy_udp_tunnels(Config) ->
    Before = masque_metrics:backlog_drop_count(),
    Target = {<<"127.0.0.1">>, ?config(udp_port, Config)},
    Parent = self(),
    Start = erlang:monotonic_time(millisecond),
    Pids = [
        spawn_link(fun() -> Parent ! {done, self(), busy_udp(Config, Target)} end)
     || _ <- lists:seq(1, ?UDP_TUNNELS)
    ],
    Counts = [
        receive
            {done, P, N} -> N
        after 300000 -> ct:fail(udp_tunnel_stuck)
        end
     || P <- Pids
    ],
    Ms = erlang:monotonic_time(millisecond) - Start,
    Sent = ?UDP_TUNNELS * ?UDP_DATAGRAMS,
    ct:pal(
        "~p datagrams sent, ~p echoed (~.1f%), router backlog drops ~p, ~p ms",
        [
            Sent,
            lists:sum(Counts),
            100 * lists:sum(Counts) / Sent,
            masque_metrics:backlog_drop_count() - Before,
            Ms
        ]
    ),
    ?assert(lists:min(Counts) > 0),
    await_no_sessions(30000).

busy_udp(Config, Target) ->
    Sess = connect(Config, Target, #{}),
    Payload = binary:copy(<<"p">>, 1024),
    %% QUIC refuses a datagram it has no congestion window for. UDP may
    %% drop, so that counts as loss, not a failure.
    Results = [masque:send(Sess, Payload) || _ <- lists:seq(1, ?UDP_DATAGRAMS)],
    [] = [R || R <- Results, R =/= ok, R =/= {error, congestion_limited}],
    N = count(Sess, 0),
    alive(Sess, 40),
    _ = masque:close(Sess),
    N.

count(Sess, N) ->
    receive
        {masque_data, Sess, _} -> count(Sess, N + 1);
        {masque_closed, Sess, Reason} -> ct:fail({closed, Reason, N})
    after 2000 -> N
    end.

alive(_Sess, 0) ->
    ct:fail(tunnel_dead_after_load);
alive(Sess, N) ->
    _ = masque:send(Sess, <<"still alive">>),
    receive
        {masque_data, Sess, <<"still alive">>} -> ok
    after 250 -> alive(Sess, N - 1)
    end.

h3_short_tunnels(Config) -> short_tunnels(Config).
h2_short_tunnels(Config) -> short_tunnels(Config).

%% Open, echo, close, thousands of times. Nothing may accumulate.
short_tunnels(Config) ->
    Processes = erlang:system_info(process_count),
    Ports = length(erlang:ports()),
    Start = erlang:monotonic_time(millisecond),
    Parent = self(),
    PerWorker = ?SHORT_TUNNELS div ?SHORT_PARALLEL,
    Pids = [
        spawn_link(fun() ->
            [short_tunnel(Config) || _ <- lists:seq(1, PerWorker)],
            Parent ! {done, self()}
        end)
     || _ <- lists:seq(1, ?SHORT_PARALLEL)
    ],
    [
        receive
            {done, P} -> ok
        after 300000 -> ct:fail(short_tunnels_stuck)
        end
     || P <- Pids
    ],
    Ms = erlang:monotonic_time(millisecond) - Start,
    await_no_sessions(30000),
    ct:pal(
        "~p tunnels in ~p ms; processes ~p -> ~p, ports ~p -> ~p",
        [
            ?SHORT_TUNNELS,
            Ms,
            Processes,
            erlang:system_info(process_count),
            Ports,
            length(erlang:ports())
        ]
    ),
    ?assert(erlang:system_info(process_count) < Processes + 200),
    ?assert(length(erlang:ports()) < Ports + 50).

short_tunnel(Config) ->
    Sess = connect(Config, {<<"127.0.0.1">>, ?config(tcp_port, Config)}, #{
        protocol => tcp, upstream_pool => true
    }),
    ok = masque:send(Sess, <<"x">>),
    receive
        {masque_data, Sess, <<"x">>} -> ok;
        {masque_closed, Sess, Reason} -> ct:fail({closed, Reason})
    after 10000 -> ct:fail(no_echo)
    end,
    _ = masque:close(Sess),
    ok.

%% Reverse connect: one agent, many short accept streams on its control
%% channel, 50 at a time. Nothing may accumulate on either side.
h3_reverse_short_streams(Config) -> reverse_short_streams(Config).
h2_reverse_short_streams(Config) -> reverse_short_streams(Config).

reverse_short_streams(Config) ->
    Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(?config(port, Config))]),
    Self = self(),
    Agent = spawn_link(fun() ->
        {ok, Listen} = masque:reverse_listen(Uri, {local, tcp}, #{
            transports => [?config(transport, Config)],
            verify => verify_none,
            request_headers => [{<<"x-identity">>, <<"load">>}]
        }),
        Self ! agent_up,
        reverse_agent(Listen)
    end),
    receive
        agent_up -> ok
    after 10000 -> ct:fail(agent_not_up)
    end,
    Control = wait_control(50),
    Processes = erlang:system_info(process_count),
    Service = #{destination => local, protocol => tcp, port => 7},
    Start = erlang:monotonic_time(millisecond),
    PerWorker = ?SHORT_TUNNELS div ?SHORT_PARALLEL,
    Pids = [
        spawn_link(fun() ->
            [reverse_stream(Control, Service) || _ <- lists:seq(1, PerWorker)],
            Self ! {done, self()}
        end)
     || _ <- lists:seq(1, ?SHORT_PARALLEL)
    ],
    [
        receive
            {done, P} -> ok
        after 300000 -> ct:fail(reverse_streams_stuck)
        end
     || P <- Pids
    ],
    Ms = erlang:monotonic_time(millisecond) - Start,
    ct:pal(
        "~p reverse connect streams in ~p ms; processes ~p -> ~p",
        [?SHORT_TUNNELS, Ms, Processes, erlang:system_info(process_count)]
    ),
    ?assert(erlang:system_info(process_count) < Processes + 200),
    unlink(Agent),
    Agent ! stop,
    await_no_sessions(30000).

reverse_stream(Control, Service) ->
    {ok, Stream} = masque:request_connection(Control, Service),
    ok = masque:send(Stream, <<"x">>),
    receive
        {masque_data, Stream, <<"x">>} -> ok = masque:consumed(Stream, 1);
        {masque_closed, Stream, Reason} -> ct:fail({closed, Reason})
    after 10000 -> ct:fail(no_echo)
    end,
    ok = masque:close(Stream).

%% The control session of the agent that just connected.
wait_control(0) ->
    ct:fail(no_control_session);
wait_control(N) ->
    case
        [
            P
         || P <- processes(),
            {dictionary, D} <- [process_info(P, dictionary)],
            {_, {masque_listen_server_session, init, 1}} <- [lists:keyfind('$initial_call', 1, D)]
        ]
    of
        [Control] ->
            Control;
        _ ->
            timer:sleep(100),
            wait_control(N - 1)
    end.

%% Accept every request and echo; finish each stream when the edge does.
reverse_agent(Listen) ->
    receive
        stop ->
            _ = masque:close(Listen);
        {masque_connection_request, Listen, Id, _} ->
            {ok, _} = masque:reverse_accept(Listen, Id, #{verify => verify_none}),
            reverse_agent(Listen);
        {masque_data, S, Bytes} ->
            _ = masque:send(S, Bytes),
            reverse_agent(Listen);
        {masque_closed, S, peer_fin} ->
            _ =
                try
                    masque:shutdown_write(S)
                catch
                    exit:_ -> ok
                end,
            reverse_agent(Listen);
        _ ->
            reverse_agent(Listen)
    end.

connect(Config, Target, Opts) ->
    Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(?config(port, Config))]),
    {ok, Sess} = masque:connect(Uri, Target, Opts#{
        transports => [?config(transport, Config)], verify => verify_none, timeout => 10000
    }),
    Sess.

await_no_sessions(Left) when Left =< 0 ->
    ct:fail(
        {sessions_left_behind, [
            {P,
                process_info(P, [
                    initial_call, current_stacktrace, message_queue_len, status, links, monitors
                ])}
         || P <- sessions()
        ]}
    );
await_no_sessions(Left) ->
    case sessions() of
        [] ->
            ok;
        _ ->
            timer:sleep(200),
            await_no_sessions(Left - 200)
    end.

sessions() ->
    [
        P
     || P <- processes(),
        {dictionary, Dict} <- [process_info(P, dictionary)],
        {_, {Mod, init, 1}} <- [lists:keyfind('$initial_call', 1, Dict)],
        lists:suffix("server_session", atom_to_list(Mod))
    ].

start_udp_echo() ->
    {ok, Sock} = gen_udp:open(0, [
        binary, {active, false}, {ip, {127, 0, 0, 1}}, {recbuf, 16 * 1024 * 1024}
    ]),
    {ok, Port} = inet:port(Sock),
    Pid = spawn(fun() -> udp_loop(Sock) end),
    ok = gen_udp:controlling_process(Sock, Pid),
    {Pid, Port}.

udp_loop(Sock) ->
    case gen_udp:recv(Sock, 0) of
        {ok, {IP, Port, Data}} ->
            _ = gen_udp:send(Sock, IP, Port, Data),
            udp_loop(Sock);
        {error, _} ->
            ok
    end.

start_tcp_echo() ->
    {ok, Listen} = gen_tcp:listen(0, [
        binary, {active, false}, {ip, {127, 0, 0, 1}}, {reuseaddr, true}, {backlog, 1024}
    ]),
    {ok, Port} = inet:port(Listen),
    Pid = spawn(fun() -> tcp_accept(Listen) end),
    ok = gen_tcp:controlling_process(Listen, Pid),
    {Pid, Port}.

tcp_accept(Listen) ->
    {ok, Sock} = gen_tcp:accept(Listen),
    Pid = spawn(fun() ->
        receive
            go -> tcp_loop(Sock)
        end
    end),
    _ = gen_tcp:controlling_process(Sock, Pid),
    Pid ! go,
    tcp_accept(Listen).

tcp_loop(Sock) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, Bin} ->
            _ = gen_tcp:send(Sock, Bin),
            tcp_loop(Sock);
        {error, _} ->
            gen_tcp:close(Sock)
    end.
