%%% @doc Interop with quic-go's MASQUE libraries, over HTTP/3.
%%%
%%% Our client and server share code, so a mistake in both would pass
%%% every other suite. These cases run a third-party implementation in
%%% each role. The Go helper lives in `test/interop':
%%%
%%%   (cd test/interop && go build -o ../../_build/masque_interop .)
%%%   MASQUE_GO_BIN=$PWD/_build/masque_interop \
%%%     rebar3 ct --suite test/masque_interop_SUITE
%%%
%%% Skipped unless `MASQUE_GO_BIN' is set. CI builds and sets it.
-module(masque_interop_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("masque/include/masque_ip.hrl").

-export([suite/0, all/0, init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    peer_udp_client_through_our_proxy/1,
    peer_ip_client_through_our_proxy/1,
    our_udp_client_through_peer_proxy/1
]).
%% Called through a fun in `handler_opts'.
-export([ip_echo_gateway/2]).

-define(BIN_ENV, "MASQUE_GO_BIN").
-define(UDP_TEMPLATE, "/.well-known/masque/udp/{target_host}/{target_port}/").
-define(GATEWAY, {10, 201, 0, 254}).

suite() -> [{timetrap, {seconds, 60}}].

all() ->
    [
        peer_udp_client_through_our_proxy,
        peer_ip_client_through_our_proxy,
        our_udp_client_through_peer_proxy
    ].

init_per_suite(Config) ->
    case os:getenv(?BIN_ENV) of
        false ->
            {skip, "set MASQUE_GO_BIN to run interop; see the moduledoc"};
        Bin ->
            {ok, _} = application:ensure_all_started(masque),
            {ok, Certs} = masque_test_helpers:generate_certs(),
            {Echo, EchoPort} = start_udp_echo(),
            [{bin, Bin}, {certs, Certs}, {echo, Echo}, {echo_port, EchoPort} | Config]
    end.

end_per_suite(Config) ->
    exit(?config(echo, Config), kill),
    masque_test_helpers:cleanup_certs(?config(certs, Config)),
    ok.

init_per_testcase(our_udp_client_through_peer_proxy, Config) ->
    Config;
init_per_testcase(_Case, Config) ->
    {ok, Server} = masque_test_helpers:start_masque_server(
        (?config(certs, Config))#{
            address_pool => {4, {10, 201, 0, 0}, 24},
            routes => [
                #ip_route{
                    version = 4,
                    start_addr = {0, 0, 0, 0},
                    end_addr = {255, 255, 255, 255},
                    ip_protocol = 0
                }
            ],
            handler_opts => #{
                allow_private => true,
                allow_self => true,
                forward_fun => fun ?MODULE:ip_echo_gateway/2
            }
        }
    ),
    [{server, Server} | Config].

end_per_testcase(our_udp_client_through_peer_proxy, _Config) ->
    ok;
end_per_testcase(_Case, Config) ->
    masque_test_helpers:stop_masque_server(?config(server, Config)).

%%====================================================================
%% Cases
%%====================================================================

peer_udp_client_through_our_proxy(Config) ->
    #{port := Port} = ?config(server, Config),
    Template = io_lib:format("https://127.0.0.1:~p~s", [Port, ?UDP_TEMPLATE]),
    Target = io_lib:format("127.0.0.1:~p", [?config(echo_port, Config)]),
    Out = run(Config, ["udp-client", "-t", Template, "-target", Target, "-payload", "ping"]),
    %% quic-go may log warnings about socket buffers around the result.
    ct:log("~s", [Out]),
    ?assertMatch({match, _}, re:run(Out, "^echo:ping$", [multiline])).

peer_ip_client_through_our_proxy(Config) ->
    #{port := Port} = ?config(server, Config),
    Url = io_lib:format("https://127.0.0.1:~p/.well-known/masque/ip/*/*/", [Port]),
    Out = run(Config, ["ip-client", "-url", Url, "-gateway", "10.201.0.254"]),
    ct:log("~s", [Out]),
    ?assertMatch(
        {match, _}, re:run(Out, "assigned:10\\.201\\.0\\.[0-9]+ reply-from:10\\.201\\.0\\.254")
    ).

our_udp_client_through_peer_proxy(Config) ->
    #{cert_file := Cert, key_file := Key} = ?config(certs, Config),
    Template = "https://127.0.0.1:0" ++ ?UDP_TEMPLATE,
    Port = open_port(
        {spawn_executable, ?config(bin, Config)},
        [
            binary,
            {line, 256},
            exit_status,
            {args, ["proxy", "-t", Template, "-c", Cert, "-k", Key]}
        ]
    ),
    try
        ProxyPort = await_ready(Port),
        Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(ProxyPort)]),
        {ok, Sess} = masque:connect(
            Uri,
            {<<"127.0.0.1">>, ?config(echo_port, Config)},
            #{transports => [h3], verify => verify_none, timeout => 5000}
        ),
        ok = echo(Sess, <<"ping">>, 20),
        masque:close(Sess)
    after
        {os_pid, Pid} = erlang:port_info(Port, os_pid),
        _ = os:cmd("kill " ++ integer_to_list(Pid)),
        port_close(Port)
    end.

%%====================================================================
%% Helpers
%%====================================================================

ip_echo_gateway(Packet, State) ->
    <<_:96, Src:4/binary, _/binary>> = Packet,
    {A, B, C, D} = ?GATEWAY,
    <<Head:12/binary, _:8/binary, Rest/binary>> = Packet,
    H0 = <<Head/binary, A, B, C, D, Src/binary>>,
    <<Before:10/binary, _:16, After/binary>> = H0,
    Zeroed = <<Before/binary, 0:16, After/binary>>,
    Sum = masque_ip_packet:checksum(Zeroed),
    {reply, <<Before/binary, Sum:16, After/binary, Rest/binary>>, State}.

run(Config, Args) ->
    Port = open_port(
        {spawn_executable, ?config(bin, Config)},
        [
            binary,
            exit_status,
            stderr_to_stdout,
            {args, [lists:flatten(A) || A <- Args]}
        ]
    ),
    collect(Port, []).

collect(Port, Acc) ->
    receive
        {Port, {data, Bin}} ->
            collect(Port, [Bin | Acc]);
        {Port, {exit_status, 0}} ->
            binary_to_list(iolist_to_binary(lists:reverse(Acc)));
        {Port, {exit_status, Code}} ->
            ct:fail({helper_failed, Code, iolist_to_binary(lists:reverse(Acc))})
    after 30000 ->
        ct:fail(helper_stuck)
    end.

await_ready(Port) ->
    receive
        {Port, {data, {eol, <<"ready:", P/binary>>}}} -> binary_to_integer(P);
        {Port, {exit_status, Code}} -> ct:fail({helper_exited, Code})
    after 10000 ->
        ct:fail(helper_not_ready)
    end.

echo(_Sess, _Payload, 0) ->
    ct:fail(no_echo);
echo(Sess, Payload, N) ->
    ok = masque:send(Sess, Payload),
    receive
        {masque_data, Sess, Payload} -> ok
    after 500 -> echo(Sess, Payload, N - 1)
    end.

start_udp_echo() ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Sock),
    Pid = spawn(fun() -> udp_echo_loop(Sock) end),
    ok = gen_udp:controlling_process(Sock, Pid),
    {Pid, Port}.

udp_echo_loop(Sock) ->
    case gen_udp:recv(Sock, 0) of
        {ok, {IP, Port, Data}} ->
            _ = gen_udp:send(Sock, IP, Port, Data),
            udp_echo_loop(Sock);
        {error, _} ->
            ok
    end.
