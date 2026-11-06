%%% @doc The proxy side of `masque_netsim_SUITE', run on a peer node
%%% inside the `mq_srv' network namespace.
-module(masque_netsim_server).

-include_lib("masque/include/masque_ip.hrl").

-export([start/1, peers/0, diagnose/0, ip_gateway/2]).

-define(PORT, 4433).
-define(H2_PORT, 4434).
%% Must match masque_netsim_SUITE.
-define(BYTES, 16 * 1024 * 1024).

%% Start the proxy and its targets. Returns their ports.
start(#{cert := Cert, key := Key, log := Log} = Opts) ->
    ok = logger:add_handler(netsim_file, logger_std_h, #{config => #{file => Log}}),
    {ok, _} = application:ensure_all_started(masque),
    {ok, _} = masque:start_listener(netsim, #{
        port => ?PORT,
        cert => Cert,
        key => Key,
        accept_bind => true,
        address_pool => {4, {10, 203, 0, 0}, 24},
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
            allow_loopback => true,
            bind_address => {127, 0, 0, 1},
            forward_fun => fun ?MODULE:ip_gateway/2
        }
    }),
    case Opts of
        #{cert_file := CertFile, key_file := KeyFile} ->
            {ok, _} = masque:start_listener_h2(netsim_h2, #{
                port => ?H2_PORT,
                cert => CertFile,
                key => KeyFile,
                handler_opts => #{allow_private => true, allow_self => true}
            });
        _ ->
            ok
    end,
    Parent = self(),
    spawn(fun() ->
        {ok, Listen} = gen_tcp:listen(0, [
            binary, {active, false}, {ip, {127, 0, 0, 1}}, {reuseaddr, true}, {exit_on_close, false}
        ]),
        {ok, TcpPort} = inet:port(Listen),
        {ok, Udp} = gen_udp:open(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
        {ok, UdpPort} = inet:port(Udp),
        spawn(fun() -> udp_echo(Udp) end),
        Parent ! {ports, #{proxy => ?PORT, proxy_h2 => ?H2_PORT, tcp => TcpPort, udp => UdpPort}},
        tcp_accept(Listen)
    end),
    receive
        {ports, Ports} -> Ports
    after 10000 -> error(targets_not_started)
    end.

%% Addresses the proxy currently sees its clients on.
peers() ->
    [
        IP
     || P <- processes(),
        {dictionary, D} <- [process_info(P, dictionary)],
        {_, {M, init, 1}} <- [lists:keyfind('$initial_call', 1, D)],
        lists:suffix("server_session", atom_to_list(M)),
        {ok, {IP, _}} <- [peername(P)]
    ].

%% A session may end while we look at it.
peername(Session) ->
    try
        quic:peername(quic_h3:get_quic_conn(element(2, sys:get_state(Session))))
    catch
        _:_ -> gone
    end.

%% Every session and QUIC connection, for a stalled test's report.
diagnose() ->
    Init = fun(P) ->
        case process_info(P, dictionary) of
            {dictionary, D} -> proplists:get_value('$initial_call', D);
            _ -> undefined
        end
    end,
    Sessions = [
        {P, process_info(P, [current_stacktrace, message_queue_len])}
     || P <- processes(), Init(P) =:= {masque_tcp_server_session, init, 1}
    ],
    Conns = [
        {P, quic:get_send_queue_info(P), quic:get_stats(P)}
     || P <- processes(), Init(P) =:= {quic_connection, init, 1}
    ],
    #{sessions => Sessions, connections => Conns}.

ip_gateway(Packet, State) ->
    {reply, Packet, State}.

tcp_accept(Listen) ->
    {ok, Sock} = gen_tcp:accept(Listen),
    Pid = spawn(fun() ->
        receive
            go -> tcp_mode(Sock)
        end
    end),
    _ = gen_tcp:controlling_process(Sock, Pid),
    Pid ! go,
    tcp_accept(Listen).

tcp_mode(Sock) ->
    case gen_tcp:recv(Sock, 4) of
        {ok, <<"echo">>} ->
            tcp_echo(Sock);
        {ok, <<"down">>} ->
            _ = gen_tcp:send(Sock, payload()),
            tcp_hold(Sock);
        {ok, <<"sink">>} ->
            {ok, Bin} = gen_tcp:recv(Sock, ?BYTES),
            _ = gen_tcp:send(Sock, crypto:hash(sha256, Bin)),
            tcp_hold(Sock);
        {error, _} ->
            gen_tcp:close(Sock)
    end.

tcp_echo(Sock) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, Bin} ->
            _ = gen_tcp:send(Sock, Bin),
            tcp_echo(Sock);
        {error, _} ->
            gen_tcp:close(Sock)
    end.

tcp_hold(Sock) ->
    _ = gen_tcp:recv(Sock, 0),
    gen_tcp:close(Sock).

udp_echo(Sock) ->
    case gen_udp:recv(Sock, 0) of
        {ok, {IP, Port, Data}} ->
            _ = gen_udp:send(Sock, IP, Port, Data),
            udp_echo(Sock);
        {error, _} ->
            ok
    end.

payload() ->
    binary:copy(<<"0123456789abcdef">>, ?BYTES div 16).
