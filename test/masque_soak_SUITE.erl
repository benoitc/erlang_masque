%% Soak: tunnels opened and closed in rounds on h3, h2 and h1, owners that
%% die without closing, peers that hang up mid-handshake, and an idle
%% check. Nothing may grow from round to round (processes, ports, ETS
%% rows, memory), no session may outlive its owner, and nothing may burn
%% CPU once the proxy is idle. Every case fails if anything logs an error
%% report. Skipped unless MASQUE_LOAD=1.
-module(masque_soak_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, groups/0, suite/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_group/2, end_per_group/2]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([churn/1, owners_killed/1, abrupt_peers/1, idle_cpu/1]).
%% logger handler: counts error reports
-export([log/2]).

-define(ROUNDS, 6).
-define(PER_ROUND, 400).
-define(PARALLEL, 40).
-define(KILLED, 200).
-define(ABRUPT, 200).
%% Reductions a single process may use in 3 s while the proxy is idle.
%% A busy loop does hundreds of millions.
-define(IDLE_REDUCTIONS, 2000000).

suite() -> [{timetrap, {minutes, 15}}].

all() -> [{group, h3}, {group, h2}, {group, h1}].

groups() ->
    Cases = [churn, owners_killed, abrupt_peers, idle_cpu],
    [{h3, [sequence], Cases}, {h2, [sequence], Cases}, {h1, [sequence], Cases}].

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

init_per_group(Transport, Config) ->
    #{cert_file := CertFile, key_file := KeyFile} = Certs = ?config(certs, Config),
    Opts = #{handler_opts => #{allow_private => true, allow_self => true}},
    case Transport of
        h3 ->
            {ok, #{port := Port} = Srv} =
                masque_test_helpers:start_masque_server(maps:merge(Certs, Opts)),
            [
                {stop, fun() -> masque_test_helpers:stop_masque_server(Srv) end},
                {port, Port},
                {transport, h3}
                | Config
            ];
        _ ->
            Name = list_to_atom("soak_" ++ atom_to_list(Transport)),
            {Start, Stop} =
                case Transport of
                    h2 -> {start_listener_h2, stop_listener_h2};
                    h1 -> {start_listener_h1, stop_listener_h1}
                end,
            %% An h2 or h1 listener lives as long as the process that
            %% started it, and init_per_group's process exits.
            Parent = self(),
            Keeper = spawn(fun() ->
                {ok, {_, _, P}} = masque:Start(Name, Opts#{
                    port => 0, cert => CertFile, key => KeyFile
                }),
                Parent ! {listening, P},
                receive
                    stop -> masque:Stop(Name)
                end
            end),
            Port =
                receive
                    {listening, P} -> P
                after 10000 -> ct:fail(no_listener)
                end,
            [
                {stop, fun() -> Keeper ! stop end},
                {port, Port},
                {transport, Transport}
                | Config
            ]
    end.

end_per_group(_Group, Config) ->
    (?config(stop, Config))(),
    ok.

init_per_testcase(_Case, Config) ->
    Counter = counters:new(1, []),
    ok = logger:add_handler(masque_soak_reports, ?MODULE, #{
        level => error, config => #{counter => Counter}
    }),
    [{reports, Counter} | Config].

end_per_testcase(_Case, Config) ->
    logger:remove_handler(masque_soak_reports),
    case counters:get(?config(reports, Config), 1) of
        0 -> ok;
        N -> {fail, {error_reports, N}}
    end.

log(#{level := Level}, #{config := #{counter := Counter}}) when
    Level =:= error; Level =:= critical; Level =:= alert; Level =:= emergency
->
    counters:add(Counter, 1, 1);
log(_Event, _Config) ->
    ok.

%%====================================================================
%% Cases
%%====================================================================

%% Rounds of short UDP and TCP tunnels, half of them on a pooled
%% connection (h3 and h2). After the first round warms up, nothing may
%% grow from one round to the next.
churn(Config) ->
    Snaps = [round(Config, R) || R <- lists:seq(1, ?ROUNDS)],
    [_Warmup, Base | _] = Snaps,
    Last = lists:last(Snaps),
    ct:pal("first ~p~nlast  ~p~ngrown ~p", [
        maps:remove(tables, Base), maps:remove(tables, Last), grown(Base, Last)
    ]),
    ?assert(maps:get(procs, Last) - maps:get(procs, Base) < 30),
    ?assert(maps:get(ports, Last) - maps:get(ports, Base) < 10),
    ?assert(maps:get(ets_rows, Last) - maps:get(ets_rows, Base) < 50),
    ?assert(maps:get(ets_tables, Last) - maps:get(ets_tables, Base) < 3),
    ?assert(maps:get(tickets, Last) =< 10000),
    %% Memory is noisy; a leak of even 1 KiB per tunnel over four rounds
    %% would pass 1.6 MB, so 16 MB only catches real growth.
    ?assert(maps:get(memory, Last) - maps:get(memory, Base) < 16 * 1024 * 1024).

round(Config, R) ->
    Start = erlang:monotonic_time(millisecond),
    Per = ?PER_ROUND div ?PARALLEL,
    run_parallel(?PARALLEL, fun(W) ->
        [short_tunnel(Config, (W + I) rem 4) || I <- lists:seq(1, Per)]
    end),
    Ms = erlang:monotonic_time(millisecond) - Start,
    await_quiet(30000),
    Snap =
        case R =:= 2 orelse R =:= ?ROUNDS of
            true -> settle(snapshot(), 60);
            false -> snapshot()
        end,
    ct:pal("round ~p: ~p tunnels in ~p ms, ~p", [R, ?PER_ROUND, Ms, maps:remove(tables, Snap)]),
    Snap.

%% Kind 0/1: UDP/TCP on a connection of their own; 2/3: pooled.
short_tunnel(Config, Kind) ->
    Pool = Kind >= 2 andalso ?config(transport, Config) =/= h1,
    {Proto, Port} =
        case Kind rem 2 of
            0 -> {udp, ?config(udp_port, Config)};
            1 -> {tcp, ?config(tcp_port, Config)}
        end,
    Sess = connect(Config, {<<"127.0.0.1">>, Port}, #{protocol => Proto, upstream_pool => Pool}),
    ok = echo(Sess, Proto),
    _ = masque:close(Sess),
    ok.

%% Owners that die (killed, no close) with a tunnel open. Their client
%% sessions and the proxy's sessions must all go away.
owners_killed(Config) ->
    Before = settle(snapshot(), 60),
    Parent = self(),
    %% In batches: macOS caps a listen backlog at 128, and a burst of 200
    %% TLS connects would overflow it.
    Owners = lists:append([
        owner_batch(Config, Parent, lists:seq(B, min(B + 39, ?KILLED)))
     || B <- lists:seq(1, ?KILLED, 40)
    ]),
    ?assert(length(server_sessions()) >= ?KILLED),
    [exit(O, kill) || O <- Owners],
    await_quiet(30000),
    After = settle(snapshot(), 60),
    ct:pal("before ~p~nafter  ~p~ngrown ~p", [
        maps:remove(tables, Before), maps:remove(tables, After), grown(Before, After)
    ]),
    ?assert(maps:get(procs, After) - maps:get(procs, Before) < 30),
    ?assert(maps:get(ports, After) - maps:get(ports, Before) < 10).

owner_batch(Config, Parent, Seq) ->
    Owners = [
        spawn(fun() ->
            Proto = lists:nth(1 + I rem 2, [udp, tcp]),
            Port =
                case Proto of
                    udp -> ?config(udp_port, Config);
                    tcp -> ?config(tcp_port, Config)
                end,
            Sess = connect(Config, {<<"127.0.0.1">>, Port}, #{protocol => Proto}),
            ok = echo(Sess, Proto),
            Parent ! {up, self()},
            receive
                never -> ok
            end
        end)
     || I <- Seq
    ],
    [
        receive
            {up, O} -> ok
        after 30000 -> ct:fail(owner_not_up)
        end
     || O <- Owners
    ],
    Owners.

%% Peers that hang up at every stage: TCP connect then close, TLS
%% handshake then close, a request cut short (h2 and h1), and junk
%% datagrams (h3). The listener must keep nothing.
abrupt_peers(Config) ->
    Before = settle(snapshot(), 60),
    Port = ?config(port, Config),
    case ?config(transport, Config) of
        h3 ->
            {ok, S} = gen_udp:open(0, [binary]),
            [
                ok = gen_udp:send(S, {127, 0, 0, 1}, Port, junk(I))
             || I <- lists:seq(1, ?ABRUPT * 5)
            ],
            gen_udp:close(S);
        T ->
            Alpn =
                case T of
                    h2 -> [<<"h2">>];
                    h1 -> [<<"http/1.1">>]
                end,
            run_parallel(20, fun(_) ->
                [abrupt(Port, Alpn, T, I rem 3) || I <- lists:seq(1, ?ABRUPT div 20)]
            end)
    end,
    await_quiet(30000),
    After = settle(snapshot(), 60),
    ct:pal("before ~p~nafter  ~p~ngrown ~p", [
        maps:remove(tables, Before), maps:remove(tables, After), grown(Before, After)
    ]),
    ?assert(maps:get(procs, After) - maps:get(procs, Before) < 30),
    ?assert(maps:get(ports, After) - maps:get(ports, Before) < 10),
    %% The listener still serves.
    Sess = connect(Config, {<<"127.0.0.1">>, ?config(tcp_port, Config)}, #{protocol => tcp}),
    ok = echo(Sess, tcp),
    masque:close(Sess).

abrupt(Port, _Alpn, _T, 0) ->
    {ok, S} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}]),
    gen_tcp:close(S);
abrupt(Port, Alpn, _T, 1) ->
    case tls(Port, Alpn) of
        {ok, S} -> ssl:close(S);
        _ -> ok
    end;
abrupt(Port, Alpn, h1, 2) ->
    case tls(Port, Alpn) of
        {ok, S} ->
            _ = ssl:send(S, <<"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n">>),
            ssl:close(S);
        _ ->
            ok
    end;
abrupt(Port, Alpn, h2, 2) ->
    case tls(Port, Alpn) of
        {ok, S} ->
            %% Preface and an empty SETTINGS, then gone.
            _ = ssl:send(S, [<<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>, <<0:24, 4, 0, 0:32>>]),
            ssl:close(S);
        _ ->
            ok
    end.

tls(Port, Alpn) ->
    ssl:connect(
        {127, 0, 0, 1},
        Port,
        [
            binary, {active, false}, {verify, verify_none}, {alpn_advertised_protocols, Alpn}
        ],
        5000
    ).

junk(I) ->
    %% Long and short header shapes, random bodies.
    First = lists:nth(1 + I rem 3, [16#C0, 16#40, 16#00]),
    <<First, (crypto:strong_rand_bytes(20 + I rem 1300))/binary>>.

%% Once everything is closed, no process may keep working.
idle_cpu(_Config) ->
    await_quiet(30000),
    timer:sleep(1000),
    Self = self(),
    R0 = reductions(),
    timer:sleep(3000),
    R1 = reductions(),
    Busy = lists:reverse(
        lists:keysort(2, [
            {P, N - maps:get(P, R0, 0)}
         || {P, N} <- maps:to_list(R1), P =/= Self
        ])
    ),
    Top = lists:sublist(Busy, 5),
    ct:pal("busiest over 3 s: ~p", [
        [{P, N, info(P)} || {P, N} <- Top]
    ]),
    case [B || {_, N} = B <- Top, N > ?IDLE_REDUCTIONS] of
        [] -> ok;
        Hot -> ct:fail({busy_while_idle, [{P, N, info(P)} || {P, N} <- Hot]})
    end.

reductions() ->
    maps:from_list([
        {P, R}
     || P <- processes(), {reductions, R} <- [process_info(P, reductions)]
    ]).

info(P) ->
    case process_info(P, [current_function, message_queue_len, dictionary, initial_call]) of
        undefined ->
            gone;
        [{current_function, F}, {message_queue_len, Q}, {dictionary, D}, {initial_call, I}] ->
            Call =
                case lists:keyfind('$initial_call', 1, D) of
                    {_, MFA} -> MFA;
                    false -> I
                end,
            #{call => Call, current => F, queue => Q}
    end.

%%====================================================================
%% Helpers
%%====================================================================

run_parallel(N, Fun) ->
    Parent = self(),
    Pids = [
        spawn_link(fun() ->
            Fun(W),
            Parent ! {done, self()}
        end)
     || W <- lists:seq(1, N)
    ],
    [
        receive
            {done, P} -> ok
        after 300000 -> ct:fail(workers_stuck)
        end
     || P <- Pids
    ],
    ok.

connect(Config, Target, Opts) ->
    Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(?config(port, Config))]),
    {ok, Sess} = masque:connect(Uri, Target, Opts#{
        transports => [?config(transport, Config)], verify => verify_none, timeout => 10000
    }),
    Sess.

echo(Sess, Proto) ->
    Msg = integer_to_binary(erlang:unique_integer([positive])),
    echo(Sess, Proto, Msg, 20).

echo(_Sess, _Proto, _Msg, 0) ->
    ct:fail(no_echo);
echo(Sess, Proto, Msg, N) ->
    ok = masque:send(Sess, Msg),
    receive
        {masque_data, Sess, Msg} -> ok;
        {masque_closed, Sess, Reason} -> ct:fail({closed, Reason})
    after 500 ->
        case Proto of
            %% A datagram may be lost; send again.
            udp -> echo(Sess, Proto, Msg, N - 1);
            tcp -> ct:fail(no_echo)
        end
    end.

%% No proxy session, client session or racer left. Pooled upstream
%% owners stay until their idle timer, so they are left to the snapshot
%% comparison.
await_quiet(Left) when Left =< 0 ->
    ct:fail({left_behind, [{P, info(P)} || P <- server_sessions() ++ client_sessions()]});
await_quiet(Left) ->
    case server_sessions() ++ client_sessions() of
        [] ->
            ok;
        _ ->
            timer:sleep(200),
            await_quiet(Left - 200)
    end.

server_sessions() -> by_initial(fun(M) -> lists:suffix("server_session", M) end).

client_sessions() ->
    by_initial(fun(M) ->
        lists:suffix("client_session", M) orelse M =:= "masque_racer" orelse
            M =:= "masque_client_owner"
    end).

by_initial(Pred) ->
    [
        P
     || P <- processes(),
        {dictionary, D} <- [process_info(P, dictionary)],
        {_, {Mod, _, _}} <- [lists:keyfind('$initial_call', 1, D)],
        Pred(atom_to_list(Mod))
    ].

snapshot() ->
    [erlang:garbage_collect(P) || P <- processes()],
    Tables = ets:all(),
    #{
        procs => erlang:system_info(process_count),
        ports => length(erlang:ports()),
        ets_tables => length(Tables),
        %% quic keeps one resumption ticket per handshake for a day, capped
        %% at 10,000 per node: counted on their own.
        ets_rows => lists:sum([
            N
         || T <- Tables,
            ets:info(T, name) =/= quic_server_tickets,
            N <- [ets:info(T, size)],
            is_integer(N)
        ]),
        tickets => lists:sum([
            N
         || T <- Tables,
            ets:info(T, name) =:= quic_server_tickets,
            N <- [ets:info(T, size)],
            is_integer(N)
        ]),
        memory => erlang:memory(total),
        binary => erlang:memory(binary),
        tables => maps:from_list([
            {table_name(T), N}
         || T <- Tables, N <- [ets:info(T, size)], is_integer(N)
        ])
    }.

%% QUIC connections drain for a few round trips after the close and
%% pooled owners wait for their idle timer: wait until the counts stop
%% falling (at most N seconds).
settle(Prev, 0) ->
    Prev;
settle(Prev, N) ->
    timer:sleep(1000),
    Now = snapshot(),
    case
        maps:get(procs, Now) < maps:get(procs, Prev) orelse
            maps:get(ports, Now) < maps:get(ports, Prev)
    of
        true -> settle(Now, N - 1);
        false when N rem 5 =:= 0 -> Now;
        false -> settle(Now, N - 1)
    end.

table_name(T) ->
    case ets:info(T, name) of
        N when is_atom(N) -> {N, ets:info(T, owner)};
        _ -> T
    end.

grown(#{tables := A}, #{tables := B}) ->
    [{T, maps:get(T, A, 0), N} || {T, N} <- maps:to_list(B), N > maps:get(T, A, 0)].

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
