%%% @doc A real outside client: `curl' through the CONNECT-TCP proxy.
%%%
%%% Our client testing our server can hide mistakes both share. Skipped
%%% when curl is not installed, or lacks the feature a case needs.
-module(masque_curl_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([suite/0, all/0, init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([h1_download/1, h1_upload/1, h1_refused_target/1, h2_classic_connect_refused/1]).

-define(BODY_BYTES, 8 * 1024 * 1024).

suite() -> [{timetrap, {minutes, 2}}].

all() ->
    [h1_download, h1_upload, h1_refused_target, h2_classic_connect_refused].

init_per_suite(Config) ->
    case os:find_executable("curl") of
        false ->
            {skip, "curl not installed"};
        Curl ->
            {ok, _} = application:ensure_all_started(masque),
            {ok, Certs} = masque_test_helpers:generate_certs(),
            {Http, HttpPort} = start_http_target(),
            [{curl, Curl}, {certs, Certs}, {http, Http}, {http_port, HttpPort} | Config]
    end.

end_per_suite(Config) ->
    exit(?config(http, Config), kill),
    masque_test_helpers:cleanup_certs(?config(certs, Config)),
    ok.

init_per_testcase(Case, Config) ->
    #{cert_file := Cert, key_file := Key} = ?config(certs, Config),
    Opts = #{
        port => 0,
        cert => Cert,
        key => Key,
        handler_opts => handler_opts(Case)
    },
    Name = list_to_atom("curl_" ++ integer_to_list(erlang:unique_integer([positive]))),
    case transport(Case) of
        h1 ->
            {ok, Ref} = masque:start_listener_h1(Name, Opts),
            [{name, Name}, {port, h1:server_port(Ref)} | Config];
        h2 ->
            {ok, {_, _, Port}} = masque:start_listener_h2(Name, Opts),
            [{name, Name}, {port, Port} | Config]
    end.

end_per_testcase(Case, Config) ->
    case transport(Case) of
        h1 -> masque:stop_listener_h1(?config(name, Config));
        h2 -> masque:stop_listener_h2(?config(name, Config))
    end,
    ok.

transport(Case) ->
    case atom_to_list(Case) of
        "h1_" ++ _ -> h1;
        "h2_" ++ _ -> h2
    end.

handler_opts(h1_refused_target) -> #{};
handler_opts(_) -> #{allow_private => true, allow_self => true}.

%%====================================================================
%% Cases
%%====================================================================

h1_download(Config) -> download(Config, "").
h1_upload(Config) -> upload(Config, "").

%% Over HTTP/2 the listener speaks Extended CONNECT only, so curl's
%% classic CONNECT gets a clean refusal.
h2_classic_connect_refused(Config) ->
    {Code, Out} = curl(Config, "--proxy-http2", "-sS -o /dev/null", "/body"),
    ct:log("curl exit ~p: ~s", [Code, Out]),
    ?assertNotEqual(0, Code).

%% The built-in handler refuses a loopback target; curl sees a failed
%% tunnel, not a hang.
h1_refused_target(Config) ->
    {Code, Out} = curl(Config, "", "-s -o /dev/null -w %{http_connect}", "/body"),
    ct:log("curl exit ~p, proxy said ~s", [Code, Out]),
    ?assertNotEqual(0, Code),
    ?assertEqual("502", string:trim(Out)).

download(Config, Flag) ->
    {Code, Out} = curl(Config, Flag, "-s", "/body"),
    ?assertEqual(0, Code),
    ?assertEqual(sha(body()), sha(list_to_binary(Out))).

upload(Config, Flag) ->
    Dir = ?config(priv_dir, Config),
    File = filename:join(Dir, "upload.bin"),
    ok = file:write_file(File, body()),
    {Code, Out} = curl(Config, Flag, "-s -X POST --data-binary @" ++ File, "/sum"),
    ?assertEqual(0, Code),
    ?assertEqual(binary:encode_hex(sha(body())), list_to_binary(string:trim(Out))).

%%====================================================================
%% curl
%%====================================================================

curl(Config, ProxyFlag, Args, Path) ->
    Cmd = lists:flatten(
        io_lib:format(
            "~s --max-time 60 --proxy https://127.0.0.1:~p --proxy-insecure --proxytunnel ~s ~s "
            "http://127.0.0.1:~p~s",
            [
                ?config(curl, Config),
                ?config(port, Config),
                ProxyFlag,
                Args,
                ?config(http_port, Config),
                Path
            ]
        )
    ),
    ct:log("~s", [Cmd]),
    Port = open_port({spawn, Cmd}, [binary, exit_status, stream, stderr_to_stdout]),
    collect(Port, []).

collect(Port, Acc) ->
    receive
        {Port, {data, Bin}} ->
            collect(Port, [Bin | Acc]);
        {Port, {exit_status, Code}} ->
            {Code, binary_to_list(iolist_to_binary(lists:reverse(Acc)))}
    after 70000 ->
        ct:fail(curl_stuck)
    end.

body() ->
    binary:copy(<<"0123456789abcdef">>, ?BODY_BYTES div 16).

sha(Bin) -> crypto:hash(sha256, Bin).

%%====================================================================
%% A minimal HTTP/1.1 target
%%====================================================================

start_http_target() ->
    {ok, Listen} = gen_tcp:listen(0, [
        binary, {active, false}, {ip, {127, 0, 0, 1}}, {reuseaddr, true}, {packet, http_bin}
    ]),
    {ok, Port} = inet:port(Listen),
    Pid = spawn(fun() -> http_accept(Listen) end),
    ok = gen_tcp:controlling_process(Listen, Pid),
    {Pid, Port}.

http_accept(Listen) ->
    {ok, Sock} = gen_tcp:accept(Listen),
    Pid = spawn(fun() ->
        receive
            go -> http_request(Sock)
        end
    end),
    _ = gen_tcp:controlling_process(Sock, Pid),
    Pid ! go,
    http_accept(Listen).

http_request(Sock) ->
    {ok, {http_request, Method, {abs_path, Path}, _}} = gen_tcp:recv(Sock, 0),
    Length = http_headers(Sock, 0),
    ok = inet:setopts(Sock, [{packet, raw}]),
    Reply = http_reply(Method, Path, Sock, Length),
    Head = io_lib:format(
        "HTTP/1.1 200 OK\r\nContent-Length: ~p\r\nConnection: close\r\n\r\n", [byte_size(Reply)]
    ),
    ok = gen_tcp:send(Sock, [Head, Reply]),
    gen_tcp:close(Sock).

http_headers(Sock, Length) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, {http_header, _, 'Content-Length', _, V}} ->
            http_headers(Sock, binary_to_integer(V));
        {ok, {http_header, _, _, _, _}} ->
            http_headers(Sock, Length);
        {ok, http_eoh} ->
            Length
    end.

http_reply('GET', <<"/body">>, _Sock, _Length) ->
    body();
http_reply('POST', <<"/sum">>, Sock, Length) ->
    {ok, Bin} = gen_tcp:recv(Sock, Length),
    binary:encode_hex(sha(Bin)).
