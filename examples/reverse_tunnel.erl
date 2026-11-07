%%% @doc Example - expose a local service through a proxy with reverse
%%% connect (draft-rosomakho-masque-reverse-connect-01), the way a tunnel
%%% agent does.
%%%
%%% Three parts on loopback, with a throwaway self-signed certificate:
%%%
%%%   * the local service: an echo server the outside cannot reach;
%%%   * the agent: opens a control channel to the edge with a token,
%%%     advertises the service, and answers each connection request by
%%%     accepting it and splicing the stream to the local service;
%%%   * the edge: a MASQUE listener with `accept_listen' that checks the
%%%     token (this module is its `listen_handler'), plus a public TCP
%%%     port. Each client of the public port gets a reverse connect
%%%     stream to the agent.
%%%
%%% ```
%%% public client --tcp--> edge public port
%%%                          | masque:request_connection/3
%%%                          v
%%%                        edge listener ==connect-listen== agent
%%%                                      ==connect-accept== agent --tcp--> local service
%%% '''
%%%
%%% Run from the project root:
%%%
%%% ```
%%% rebar3 shell
%%% 1> c("examples/reverse_tunnel").
%%% 2> {ok, Ports} = reverse_tunnel:start().          % h3; or start(#{transport => h2 | h1})
%%% 3> reverse_tunnel:run(<<"hello through the tunnel">>).
%%% {ok,<<"hello through the tunnel">>}
%%% 4> reverse_tunnel:stop().
%%% '''
%%%
%%% Any TCP client works on the public port, for example
%%% `nc 127.0.0.1 PublicPort'.
-module(reverse_tunnel).

-export([start/0, start/1, stop/0, run/1]).
%% listen_handler callbacks (the edge side)
-export([authenticate/1, init/2, handle_services/2, terminate/2]).

-define(TOKEN, <<"Bearer example-token">>).
-define(CONTROL, reverse_tunnel_control).

%%====================================================================
%% Public API
%%====================================================================

start() ->
    start(#{}).

%% Start the local service, the edge and the agent. Returns the ports.
-spec start(#{transport => h3 | h2 | h1}) ->
    {ok, #{public := inet:port_number(), edge := inet:port_number(), local := inet:port_number()}}.
start(Opts) ->
    {ok, _} = application:ensure_all_started(masque),
    Transport = maps:get(transport, Opts, h3),
    {ok, Dir, Cert, Key, CertFile, KeyFile} = ephemeral_cert(),
    {LocalPid, LocalPort} = start_echo(),
    EdgePort = start_edge(Transport, Cert, Key, CertFile, KeyFile),
    {PublicPid, PublicPort} = start_public(LocalPort),
    Agent = start_agent(Transport, EdgePort, LocalPort),
    persistent_term:put({?MODULE, state}, #{
        transport => Transport,
        dir => Dir,
        pids => [LocalPid, PublicPid, Agent],
        ports => #{public => PublicPort, edge => EdgePort, local => LocalPort}
    }),
    {ok, #{public => PublicPort, edge => EdgePort, local => LocalPort}}.

%% Connect to the edge's public port like any client, send `Payload' and
%% read the echo that came back from the agent's local service.
-spec run(binary()) -> {ok, binary()} | {error, term()}.
run(Payload) ->
    #{ports := #{public := Port}} = persistent_term:get({?MODULE, state}),
    {ok, Sock} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}], 5000),
    ok = gen_tcp:send(Sock, Payload),
    Result = recv_exactly(Sock, byte_size(Payload), <<>>),
    gen_tcp:close(Sock),
    Result.

stop() ->
    case persistent_term:get({?MODULE, state}, undefined) of
        undefined ->
            ok;
        #{pids := Pids, dir := Dir} ->
            [exit(P, shutdown) || P <- Pids],
            stop_edge(),
            os:cmd("rm -rf " ++ Dir),
            persistent_term:erase({?MODULE, state}),
            ok
    end.

%%====================================================================
%% Edge: the listener and its listen_handler
%%====================================================================

%% h1 listeners keep the listen socket in the process that starts them,
%% so a keeper process owns the listener for every transport.
start_edge(Transport, Cert, Key, CertFile, KeyFile) ->
    Self = self(),
    Keeper = spawn(fun() ->
        Port = start_listener(Transport, Cert, Key, CertFile, KeyFile),
        Self ! {edge_port, Port},
        receive
            stop -> stop_listener(Transport)
        end
    end),
    persistent_term:put({?MODULE, keeper}, Keeper),
    receive
        {edge_port, Port} -> Port
    after 10000 -> error(edge_not_started)
    end.

stop_edge() ->
    case persistent_term:get({?MODULE, keeper}, undefined) of
        undefined -> ok;
        Keeper -> Keeper ! stop
    end,
    persistent_term:erase({?MODULE, keeper}).

listener_opts() ->
    #{
        port => 0,
        accept_listen => true,
        listen_handler => ?MODULE
    }.

start_listener(h3, Cert, Key, _CertFile, _KeyFile) ->
    {ok, _} = masque:start_listener(reverse_tunnel_edge, (listener_opts())#{
        cert => Cert, key => Key
    }),
    {ok, Port} = quic:get_server_port(reverse_tunnel_edge),
    Port;
start_listener(h2, _Cert, _Key, CertFile, KeyFile) ->
    {ok, {_, _, Port}} = masque:start_listener_h2(
        reverse_tunnel_edge, (listener_opts())#{cert => CertFile, key => KeyFile}
    ),
    Port;
start_listener(h1, _Cert, _Key, CertFile, KeyFile) ->
    {ok, Ref} = masque:start_listener_h1(
        reverse_tunnel_edge, (listener_opts())#{cert => CertFile, key => KeyFile}
    ),
    h1:server_port(Ref).

stop_listener(h3) -> masque:stop_listener(reverse_tunnel_edge);
stop_listener(h2) -> masque:stop_listener_h2(reverse_tunnel_edge);
stop_listener(h1) -> masque:stop_listener_h1(reverse_tunnel_edge).

%% listen_handler: only the agent with the token may open a channel.
authenticate(#{headers := Headers}) ->
    case lists:keyfind(<<"authorization">>, 1, Headers) of
        {_, ?TOKEN} -> {ok, example_agent};
        _ -> {reject, {other, 401}}
    end.

%% Runs in the control session: register it so the public port finds it.
init(Agent, _Req) ->
    try
        unregister(?CONTROL)
    catch
        error:badarg -> ok
    end,
    true = register(?CONTROL, self()),
    {ok, Agent}.

handle_services(Services, Agent) ->
    logger:notice("agent ~p offers ~p", [Agent, Services]),
    {ok, Agent}.

terminate(_Reason, _Agent) ->
    ok.

%% The public port: each client gets a stream to the agent's service.
start_public(LocalPort) ->
    {ok, Listen} = gen_tcp:listen(0, [
        binary,
        {active, false},
        {ip, {127, 0, 0, 1}},
        {reuseaddr, true},
        {exit_on_close, false},
        {backlog, 128}
    ]),
    {ok, Port} = inet:port(Listen),
    Pid = spawn(fun() -> public_accept(Listen, LocalPort) end),
    ok = gen_tcp:controlling_process(Listen, Pid),
    {Pid, Port}.

public_accept(Listen, LocalPort) ->
    {ok, Client} = gen_tcp:accept(Listen),
    Pid = spawn(fun() ->
        receive
            go -> public_client(Client, LocalPort)
        end
    end),
    ok = gen_tcp:controlling_process(Client, Pid),
    Pid ! go,
    public_accept(Listen, LocalPort).

public_client(Client, LocalPort) ->
    Service = #{destination => local, protocol => tcp, port => LocalPort},
    case masque:request_connection(whereis(?CONTROL), Service, #{timeout => 10000}) of
        {ok, Stream} ->
            splice(Stream, Client, edge);
        {error, Reason} ->
            logger:warning("no tunnel for a public client: ~p", [Reason]),
            gen_tcp:close(Client)
    end.

%%====================================================================
%% Agent
%%====================================================================

start_agent(Transport, EdgePort, LocalPort) ->
    Self = self(),
    Agent = spawn(fun() ->
        Edge = iolist_to_binary(["https://127.0.0.1:", integer_to_list(EdgePort)]),
        {ok, Listen} = masque:reverse_listen(Edge, {local, tcp}, #{
            transports => [Transport],
            verify => verify_none,
            request_headers => [{<<"authorization">>, ?TOKEN}]
        }),
        ok = masque:advertise_services(Listen, [
            #{destination => local, protocol => tcp, port => LocalPort}
        ]),
        Self ! agent_up,
        agent_loop(Listen, LocalPort)
    end),
    receive
        agent_up -> Agent
    after 10000 -> error(agent_not_started)
    end.

%% Accept requests for the local service and decline the rest: an agent
%% only serves what it was asked to expose.
agent_loop(Listen, LocalPort) ->
    receive
        {masque_connection_request, Listen, Id, #{protocol := tcp, port := LocalPort}} ->
            _ = spawn(fun() -> agent_stream(Listen, Id, LocalPort) end),
            agent_loop(Listen, LocalPort);
        {masque_connection_request, Listen, Id, _Other} ->
            _ = masque:reverse_decline(Listen, Id),
            agent_loop(Listen, LocalPort);
        {masque_closed, Listen, Reason} ->
            logger:warning("control channel ended: ~p", [Reason])
    end.

%% Accept first, then dial the local service: if it is down, close the
%% stream, as the draft asks.
agent_stream(Listen, Id, LocalPort) ->
    {ok, Stream} = masque:reverse_accept(Listen, Id, #{verify => verify_none}),
    case gen_tcp:connect({127, 0, 0, 1}, LocalPort, [binary, {active, false}], 5000) of
        {ok, Local} -> splice(Stream, Local, agent);
        {error, _} -> masque:close(Stream)
    end.

%%====================================================================
%% Splicing a reverse connect stream and a TCP socket
%%====================================================================

%% Bytes and FIN both ways. The edge returns credit with
%% `masque:consumed/2' once the bytes are written to the public client,
%% so a slow client slows the agent; the agent's client session manages
%% its own credit.
splice(Stream, Sock, Side) ->
    ok = inet:setopts(Sock, [{active, once}]),
    splice_loop(Stream, Sock, Side).

splice_loop(Stream, Sock, Side) ->
    receive
        {tcp, Sock, Bytes} ->
            ok = masque:send(Stream, Bytes),
            ok = inet:setopts(Sock, [{active, once}]),
            splice_loop(Stream, Sock, Side);
        {tcp_closed, Sock} ->
            _ = masque:shutdown_write(Stream),
            splice_drain(Stream, Sock, Side);
        {masque_data, Stream, Bytes} ->
            ok = gen_tcp:send(Sock, Bytes),
            ok = credit(Side, Stream, Bytes),
            splice_loop(Stream, Sock, Side);
        {masque_closed, Stream, peer_fin} ->
            ok = gen_tcp:shutdown(Sock, write),
            splice_loop(Stream, Sock, Side);
        {masque_closed, Stream, _} ->
            gen_tcp:close(Sock)
    end.

%% The socket is done sending; pass on what the stream still brings.
splice_drain(Stream, Sock, Side) ->
    receive
        {masque_data, Stream, Bytes} ->
            _ = gen_tcp:send(Sock, Bytes),
            ok = credit(Side, Stream, Bytes),
            splice_drain(Stream, Sock, Side);
        {masque_closed, Stream, peer_fin} ->
            gen_tcp:close(Sock);
        {masque_closed, Stream, _} ->
            gen_tcp:close(Sock)
    after 30000 ->
        _ = masque:close(Stream),
        gen_tcp:close(Sock)
    end.

credit(edge, Stream, Bytes) -> masque:consumed(Stream, byte_size(Bytes));
credit(agent, _Stream, _Bytes) -> ok.

%%====================================================================
%% Local service and helpers
%%====================================================================

start_echo() ->
    {ok, Listen} = gen_tcp:listen(0, [
        binary, {active, false}, {ip, {127, 0, 0, 1}}, {reuseaddr, true}, {backlog, 128}
    ]),
    {ok, Port} = inet:port(Listen),
    Pid = spawn(fun() -> echo_accept(Listen) end),
    ok = gen_tcp:controlling_process(Listen, Pid),
    {Pid, Port}.

echo_accept(Listen) ->
    {ok, Sock} = gen_tcp:accept(Listen),
    Pid = spawn(fun() ->
        receive
            go -> echo_loop(Sock)
        end
    end),
    ok = gen_tcp:controlling_process(Sock, Pid),
    Pid ! go,
    echo_accept(Listen).

echo_loop(Sock) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, Bytes} ->
            ok = gen_tcp:send(Sock, Bytes),
            echo_loop(Sock);
        {error, _} ->
            gen_tcp:close(Sock)
    end.

recv_exactly(_Sock, 0, Acc) ->
    {ok, Acc};
recv_exactly(Sock, Want, Acc) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, Bytes} when byte_size(Bytes) =< Want ->
            recv_exactly(Sock, Want - byte_size(Bytes), <<Acc/binary, Bytes/binary>>);
        {ok, Bytes} ->
            {ok, <<Acc/binary, Bytes/binary>>};
        {error, _} = Err ->
            Err
    end.

ephemeral_cert() ->
    Dir = filename:join(
        "/tmp", "reverse_tunnel_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),
    ok = filelib:ensure_dir(filename:join(Dir, ".keep")),
    CertFile = filename:join(Dir, "cert.pem"),
    KeyFile = filename:join(Dir, "key.pem"),
    os:cmd(
        lists:flatten(
            io_lib:format(
                "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
                "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null",
                [KeyFile, CertFile]
            )
        )
    ),
    {ok, CertPem} = file:read_file(CertFile),
    {ok, KeyPem} = file:read_file(KeyFile),
    [{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),
    [{KeyType, KeyDerRaw, not_encrypted}] = public_key:pem_decode(KeyPem),
    KeyDer = public_key:der_decode(KeyType, KeyDerRaw),
    {ok, Dir, CertDer, KeyDer, CertFile, KeyFile}.
