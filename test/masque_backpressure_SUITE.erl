%%% @doc Backpressure on the proxy-side sockets.
%%%
%%% A local TCP target bursts far more data than the handler's
%%% `active_n' window. Every byte must reach the client in order and
%%% the server session's mailbox must stay small, over h3, h2 and h1.
%%%
%%% On the client side, an owner that does not read holds the proxy
%%% back: its mailbox stays bounded instead of taking the whole burst.
-module(masque_backpressure_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    suite/0,
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([
    h3_tcp_burst_in_order/1,
    h2_tcp_burst_in_order/1,
    h1_tcp_burst_in_order/1,
    h3_slow_owner_bounded/1,
    h2_slow_owner_bounded/1,
    h1_slow_owner_bounded/1,
    h2_small_window_forwards/1
]).

%% The slow-owner burst, and the most of it the owner's mailbox may hold
%% while it does not read: `rx_backlog' chunks plus a stream window.
-define(SLOW_BYTES, 16 * 1024 * 1024).
-define(SLOW_MAX_MAILBOX_BYTES, 4 * 1024 * 1024).

-define(CHUNK, 16384).
-define(CHUNKS, 256).
-define(ACTIVE_N, 4).
%% `active_n' socket messages plus a margin for unrelated traffic.
-define(MAX_MAILBOX, 16).

suite() -> [{timetrap, {seconds, 60}}].

all() ->
    [
        h3_tcp_burst_in_order,
        h2_tcp_burst_in_order,
        h1_tcp_burst_in_order,
        h3_slow_owner_bounded,
        h2_slow_owner_bounded,
        h1_slow_owner_bounded,
        h2_small_window_forwards
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    {ok, _} = application:ensure_all_started(masque),
    case masque_test_helpers:generate_certs() of
        {ok, Certs} -> [{certs, Certs} | Config];
        {error, R} -> {skip, {cert_generation_failed, R}}
    end.

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(certs, Config)).

%% Listen sockets belong to the process that opens them, so each case
%% starts its own listener.
init_per_testcase(Case, Config) ->
    Certs = ?config(certs, Config),
    #{cert_file := CertFile, key_file := KeyFile} = Certs,
    Opts = #{
        tcp_handler => masque_report_tcp_handler,
        handler_opts => #{
            report_to => self(),
            allow_private => true,
            active_n => ?ACTIVE_N
        }
    },
    Name = list_to_atom(
        atom_to_list(Case) ++ "_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),
    Server =
        case transport_of(Case) of
            h3 ->
                {ok, S} = masque_test_helpers:start_masque_server(maps:merge(Certs, Opts)),
                S#{transport => h3};
            h2 ->
                %% A stream window smaller than one h2 frame.
                Settings =
                    case Case of
                        h2_small_window_forwards -> #{settings => #{initial_window_size => 4096}};
                        _ -> #{}
                    end,
                {ok, {_, _, Port}} = masque:start_listener_h2(
                    Name, maps:merge(Opts#{port => 0, cert => CertFile, key => KeyFile}, Settings)
                ),
                #{name => Name, port => Port, transport => h2};
            h1 ->
                {ok, Ref} = masque:start_listener_h1(
                    Name, Opts#{port => 0, cert => CertFile, key => KeyFile}
                ),
                #{name => Name, port => h1:server_port(Ref), transport => h1}
        end,
    [{server, Server} | Config].

end_per_testcase(_Case, Config) ->
    Server = ?config(server, Config),
    _ =
        (try
            case maps:get(transport, Server) of
                h3 -> masque_test_helpers:stop_masque_server(Server);
                h2 -> masque:stop_listener_h2(maps:get(name, Server));
                h1 -> masque:stop_listener_h1(maps:get(name, Server))
            end
        catch
            _:_ -> ok
        end),
    ok.

%%====================================================================
%% Cases
%%====================================================================

transport_of(Case) ->
    case atom_to_list(Case) of
        "h3_" ++ _ -> h3;
        "h2_" ++ _ -> h2;
        "h1_" ++ _ -> h1
    end.

h3_tcp_burst_in_order(Config) -> tcp_burst_in_order(Config).

h2_tcp_burst_in_order(Config) -> tcp_burst_in_order(Config).

h1_tcp_burst_in_order(Config) -> tcp_burst_in_order(Config).

tcp_burst_in_order(Config) ->
    #{port := Port, transport := Transport} = ?config(server, Config),
    Expected = payload(),
    {LSock, TPort} = start_burst_target(Expected),
    {ok, Sess} = masque:connect(
        iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
        {<<"127.0.0.1">>, TPort},
        #{verify => verify_none, transports => [Transport], protocol => tcp}
    ),
    SessionPid =
        receive
            {masque_session, P} -> P
        after 5000 -> ct:fail(no_server_session)
        end,
    Sampler = start_sampler(SessionPid),
    Received = recv_all(Sess, byte_size(Expected), []),
    Sampler ! {stop, self()},
    MaxQueue =
        receive
            {max_queue, M} -> M
        after 5000 -> ct:fail(no_sampler_result)
        end,
    _ = masque:close(Sess),
    gen_tcp:close(LSock),
    ?assertEqual(byte_size(Expected), byte_size(Received)),
    ?assert(Expected =:= Received),
    ct:log("max server session mailbox: ~p", [MaxQueue]),
    ?assert(MaxQueue =< ?MAX_MAILBOX).

h3_slow_owner_bounded(Config) -> slow_owner_bounded(Config).

h2_slow_owner_bounded(Config) -> slow_owner_bounded(Config).

h1_slow_owner_bounded(Config) -> slow_owner_bounded(Config).

%% The owner reads nothing while the target bursts: the session stops
%% reading from the proxy instead of filling the owner's mailbox. Once
%% the owner reads, every byte arrives in order.
slow_owner_bounded(Config) ->
    #{port := Port, transport := Transport} = ?config(server, Config),
    Expected = binary:copy(<<"0123456789abcdef">>, ?SLOW_BYTES div 16),
    {LSock, TPort} = start_burst_target(Expected),
    {ok, Sess} = masque:connect(
        iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
        {<<"127.0.0.1">>, TPort},
        #{verify => verify_none, transports => [Transport], protocol => tcp}
    ),
    timer:sleep(2000),
    {messages, Msgs} = process_info(self(), messages),
    Held = lists:sum([byte_size(B) || {masque_data, S, B} <- Msgs, S =:= Sess]),
    ct:log("~p: ~p bytes in ~p messages while not reading", [Transport, Held, length(Msgs)]),
    ?assert(Held > 0),
    ?assert(Held =< ?SLOW_MAX_MAILBOX_BYTES),
    Received = recv_all(Sess, byte_size(Expected), []),
    _ = masque:close(Sess),
    gen_tcp:close(LSock),
    ?assert(Expected =:= Received).

%% With a 4 KB stream window the proxy still returns credit: an 8 KB
%% write reaches the target in full.
h2_small_window_forwards(Config) ->
    #{port := Port} = ?config(server, Config),
    {ok, LSock} = gen_tcp:listen(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, TPort} = inet:port(LSock),
    Self = self(),
    Reader = spawn(fun() ->
        {ok, Sock} = gen_tcp:accept(LSock, 10000),
        {ok, Got} = gen_tcp:recv(Sock, 8192, 10000),
        Self ! {target_got, byte_size(Got)},
        _ = gen_tcp:recv(Sock, 0, 10000),
        gen_tcp:close(Sock)
    end),
    {ok, Sess} = masque:connect(
        iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
        {<<"127.0.0.1">>, TPort},
        #{verify => verify_none, transports => [h2], protocol => tcp}
    ),
    ok = send_all(Sess, binary:copy(<<7>>, 8192)),
    Got =
        receive
            {target_got, N} -> N
        after 10000 -> ct:fail(target_starved)
        end,
    _ = masque:close(Sess),
    exit(Reader, kill),
    gen_tcp:close(LSock),
    ?assertEqual(8192, Got).

%% An h2 send refused for a full buffer is sent again.
send_all(Sess, Bytes) ->
    case masque:send(Sess, Bytes) of
        ok ->
            ok;
        {error, send_buffer_full} ->
            timer:sleep(10),
            send_all(Sess, Bytes);
        Other ->
            Other
    end.

%%====================================================================
%% Helpers
%%====================================================================

payload() ->
    iolist_to_binary([
        binary:copy(<<(I rem 256)>>, ?CHUNK)
     || I <- lists:seq(1, ?CHUNKS)
    ]).

start_burst_target(Payload) ->
    {ok, LSock} = gen_tcp:listen(0, [
        binary, {active, false}, {ip, {127, 0, 0, 1}}, {reuseaddr, true}
    ]),
    {ok, TPort} = inet:port(LSock),
    Pid = spawn(fun() ->
        {ok, Sock} = gen_tcp:accept(LSock, 10000),
        ok = gen_tcp:send(Sock, Payload),
        %% Keep the connection open until the test is done reading.
        _ = gen_tcp:recv(Sock, 0, 30000),
        gen_tcp:close(Sock)
    end),
    ok = gen_tcp:controlling_process(LSock, Pid),
    {LSock, TPort}.

recv_all(_Sess, Remaining, Acc) when Remaining =< 0 ->
    iolist_to_binary(lists:reverse(Acc));
recv_all(Sess, Remaining, Acc) ->
    receive
        {masque_data, Sess, Bytes} ->
            recv_all(Sess, Remaining - byte_size(Bytes), [Bytes | Acc]);
        {masque_closed, Sess, Reason} ->
            ct:fail({closed_early, Reason, Remaining})
    after 20000 ->
        ct:fail({timeout, Remaining})
    end.

start_sampler(Pid) ->
    spawn(fun() -> sample(Pid, 0) end).

sample(Pid, Max) ->
    receive
        {stop, From} -> From ! {max_queue, Max}
    after 0 ->
        Len =
            case erlang:process_info(Pid, message_queue_len) of
                {message_queue_len, L} -> L;
                undefined -> 0
            end,
        timer:sleep(1),
        sample(Pid, max(Max, Len))
    end.
