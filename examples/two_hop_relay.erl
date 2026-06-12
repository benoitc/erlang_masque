%%% @doc Example - a minimal two-hop MASQUE relay (Apple Private
%%% Relay shape).
%%%
%%% Starts two listeners on loopback with self-signed certs:
%%%
%%%   * `egress' - a regular MASQUE proxy that forwards CONNECT-UDP
%%%     / CONNECT-TCP tunnels to their real targets.
%%%   * `ingress' - a chaining listener (`masque_chain_handler') that
%%%     forwards every accepted tunnel to the egress. This is the
%%%     hop a client connects to.
%%%
%%% Each listener is bound to all three transports (h3 + h2 + h1) so
%%% a client can race them. `run_udp/0' and `run_tcp/0' dial the
%%% ingress with `transports => [h3, h2, h1]' and round-trip a
%%% payload through the chain; h3 usually wins.
%%%
%%% Run from the project root:
%%%
%%% ```
%%% rebar3 shell
%%% 1> c("examples/two_hop_relay").
%%% 2> {ok, Ports} = two_hop_relay:start().
%%% 3> two_hop_relay:run_udp().
%%% 4> two_hop_relay:stop().
%%% '''
%%%
%%% The example deliberately does NOT wire authentication (Privacy
%%% Pass, mTLS, etc.). A real relay plugs those in via the handler's
%%% `accept/1' callback or a custom chain handler. The point of this
%%% file is to show the two-hop shape, not a production policy
%%% engine.
-module(two_hop_relay).

-export([start/0, stop/0]).
-export([start/1]).
-export([run_udp/0, run_udp/1, run_tcp/0, run_tcp/1]).

-define(EGRESS_UDP,   two_hop_egress_udp).
-define(EGRESS_H2,    two_hop_egress_h2).
-define(EGRESS_H1,    two_hop_egress_h1).
-define(INGRESS_UDP,  two_hop_ingress_udp).
-define(INGRESS_H2,   two_hop_ingress_h2).
-define(INGRESS_H1,   two_hop_ingress_h1).

%%====================================================================
%% Public API
%%====================================================================

start() ->
    start(#{}).

%% Returns a map of the listening ports plus an internal target a
%% follow-up dial can hit. Target is whatever UDP/TCP service the
%% caller wants to tunnel to; the example defaults to a loopback
%% echo on port 7 so `run_udp/0' and `run_tcp/0' Just Work.
-spec start(map()) ->
    {ok, #{ingress_h3 := inet:port_number(),
           ingress_h2 := inet:port_number(),
           ingress_h1 := inet:port_number(),
           udp_echo   := inet:port_number(),
           tcp_echo   := inet:port_number()}}.
start(_Opts) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Dir, Cert, Key, CertFile, KeyFile} = ephemeral_cert(),
    persistent_term:put({?MODULE, tmp_dir}, Dir),
    {UdpEchoPid, UdpEchoPort} = start_udp_echo(),
    {TcpEchoPid, TcpEchoPort} = start_tcp_echo(),
    persistent_term:put({?MODULE, echoes}, {UdpEchoPid, TcpEchoPid}),

    %% Egress - all three transports, default proxy handlers.
    EgressCommon = #{allow_private => true},
    {ok, _} = masque:start_listener(?EGRESS_UDP,
        #{port => 0, cert => Cert, key => Key,
          handler_opts => EgressCommon}),
    {ok, EgressH3Ref} = {ok, ?EGRESS_UDP},
    {ok, EgressH3Port} = quic:get_server_port(?EGRESS_UDP),
    {ok, EgressH2RefObj} = masque:start_listener_h2(?EGRESS_H2,
        #{port => 0, cert => CertFile, key => KeyFile,
          handler_opts => EgressCommon}),
    {_, _, EgressH2Port} = EgressH2RefObj,
    %% The h1 listen socket must outlive this call, so keep it on
    %% a detached keeper process.
    EgressH1Port = start_h1(?EGRESS_H1, CertFile, KeyFile,
                             #{handler_opts => EgressCommon}),

    %% Ingress - chains to the egress on each transport.
    EgressUri = upstream_uri(EgressH3Port),
    IngressCommon = #{
        upstream_proxy => EgressUri,
        upstream_opts => #{verify => verify_none,
                           transports => [h3],
                           alpn => [<<"h3">>]}
    },
    {ok, _} = masque:start_chain_listener(?INGRESS_UDP,
        #{port => 0, cert => Cert, key => Key,
          handler_opts => IngressCommon}),
    {ok, IngressH3Port} = quic:get_server_port(?INGRESS_UDP),
    {ok, IngressH2Ref} = masque:start_chain_listener_h2(?INGRESS_H2,
        #{port => 0, cert => CertFile, key => KeyFile,
          handler_opts => IngressCommon}),
    {_, _, IngressH2Port} = IngressH2Ref,
    IngressH1Port = start_chain_h1(?INGRESS_H1, CertFile, KeyFile,
                                     #{handler_opts => IngressCommon}),

    persistent_term:put({?MODULE, egress_h3_ref}, EgressH3Ref),
    persistent_term:put({?MODULE, egress_h2_ref}, EgressH2RefObj),
    persistent_term:put({?MODULE, ingress_h2_ref}, IngressH2Ref),
    _ = EgressH1Port,
    _ = EgressH2Port,

    Ports = #{ingress_h3 => IngressH3Port,
              ingress_h2 => IngressH2Port,
              ingress_h1 => IngressH1Port,
              udp_echo   => UdpEchoPort,
              tcp_echo   => TcpEchoPort},
    persistent_term:put({?MODULE, ports}, Ports),
    {ok, Ports}.

stop() ->
    _ = masque:stop_listener(?INGRESS_UDP),
    _ = masque:stop_listener_h2(?INGRESS_H2),
    _ = masque:stop_listener_h1(?INGRESS_H1),
    _ = masque:stop_listener(?EGRESS_UDP),
    _ = masque:stop_listener_h2(?EGRESS_H2),
    _ = masque:stop_listener_h1(?EGRESS_H1),
    case persistent_term:get({?MODULE, echoes}, undefined) of
        undefined -> ok;
        {UdpPid, TcpPid} ->
            _ = (try exit(UdpPid, shutdown) catch _:_ -> ok end),
            _ = (try exit(TcpPid, shutdown) catch _:_ -> ok end)
    end,
    case persistent_term:get({?MODULE, tmp_dir}, undefined) of
        undefined -> ok;
        Dir       -> os:cmd("rm -rf " ++ Dir)
    end,
    case persistent_term:get({?MODULE, {h1_keeper, ?EGRESS_H1}}, undefined) of
        undefined -> ok;
        EK       -> EK ! stop
    end,
    case persistent_term:get({?MODULE, {h1_keeper, ?INGRESS_H1}}, undefined) of
        undefined -> ok;
        IK       -> IK ! stop
    end,
    [persistent_term:erase(K)
     || K <- [{?MODULE, tmp_dir}, {?MODULE, echoes},
              {?MODULE, egress_h3_ref}, {?MODULE, egress_h2_ref},
              {?MODULE, ingress_h2_ref}, {?MODULE, ports},
              {?MODULE, {h1_keeper, ?EGRESS_H1}},
              {?MODULE, {h1_keeper, ?INGRESS_H1}}]],
    ok.

%%====================================================================
%% Convenience: round-trip a payload through the chain
%%====================================================================

run_udp() ->
    run_udp(#{}).

-spec run_udp(map()) -> {ok, binary()} | {error, term()}.
run_udp(Opts) ->
    Ports = require_started(),
    Port = case maps:get(transports, Opts, [h3, h2, h1]) of
        [h3 | _] -> maps:get(ingress_h3, Ports);
        [h2 | _] -> maps:get(ingress_h2, Ports);
        [h1 | _] -> maps:get(ingress_h1, Ports)
    end,
    Target = {<<"127.0.0.1">>, maps:get(udp_echo, Ports)},
    ConnectOpts = connect_opts(Opts, udp),
    case masque:connect(proxy_uri(Port), Target, ConnectOpts) of
        {ok, Sess} ->
            Payload = <<"hello two-hop">>,
            ok = masque:send(Sess, Payload),
            Result = receive
                {masque_data, Sess, Echo} -> {ok, Echo}
            after 3000 ->
                {error, no_echo}
            end,
            _ = masque:close(Sess),
            Result;
        Err -> Err
    end.

run_tcp() ->
    run_tcp(#{}).

-spec run_tcp(map()) -> {ok, binary()} | {error, term()}.
run_tcp(Opts) ->
    Ports = require_started(),
    Port = case maps:get(transports, Opts, [h3, h2, h1]) of
        [h3 | _] -> maps:get(ingress_h3, Ports);
        [h2 | _] -> maps:get(ingress_h2, Ports);
        [h1 | _] -> maps:get(ingress_h1, Ports)
    end,
    Target = {<<"127.0.0.1">>, maps:get(tcp_echo, Ports)},
    ConnectOpts = connect_opts(Opts, tcp),
    case masque:connect(proxy_uri(Port), Target, ConnectOpts) of
        {ok, Sess} ->
            Payload = <<"hello two-hop over tcp">>,
            ok = masque:send(Sess, Payload),
            Result = receive
                {masque_data, Sess, Echo} -> {ok, Echo}
            after 3000 ->
                {error, no_echo}
            end,
            _ = masque:close(Sess),
            Result;
        Err -> Err
    end.

%%====================================================================
%% Internal
%%====================================================================

connect_opts(Opts, Protocol) ->
    Base = #{
        protocol => Protocol,
        transports => maps:get(transports, Opts, [h3, h2, h1]),
        verify => verify_none,
        ssl_opts => [{verify, verify_none}],
        timeout => 5000
    },
    maps:merge(Base, maps:without([transports], Opts)).

proxy_uri(Port) ->
    iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]).

upstream_uri(Port) ->
    iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]).

require_started() ->
    case persistent_term:get({?MODULE, ports}, undefined) of
        undefined -> erlang:error(not_started);
        P         -> P
    end.

%% h1 listeners tie the listen socket to the calling process; use
%% a detached keeper so the socket survives the example's own
%% start/1 returning.
start_h1(Name, CertFile, KeyFile, Extra) ->
    start_h1_keeper(Name,
                     fun() ->
                         masque:start_listener_h1(Name,
                             maps:merge(#{port => 0,
                                          cert => CertFile,
                                          key  => KeyFile}, Extra))
                     end).

start_chain_h1(Name, CertFile, KeyFile, Extra) ->
    start_h1_keeper(Name,
                     fun() ->
                         masque:start_chain_listener_h1(Name,
                             maps:merge(#{port => 0,
                                          cert => CertFile,
                                          key  => KeyFile}, Extra))
                     end).

start_h1_keeper(Name, StartFun) ->
    Parent = self(),
    Keeper = erlang:spawn(fun() ->
        case StartFun() of
            {ok, Ref} ->
                Parent ! {self(), started, h1:server_port(Ref)},
                receive stop -> ok end;
            {error, Reason} ->
                Parent ! {self(), failed, Reason}
        end
    end),
    persistent_term:put({?MODULE, {h1_keeper, Name}}, Keeper),
    receive
        {Keeper, started, Port} -> Port;
        {Keeper, failed, R}     -> erlang:error({h1_start_failed, Name, R})
    after 5000 ->
        erlang:error({h1_start_timeout, Name})
    end.

%%--------------------------------------------------------------------
%% Loopback echo fixtures
%%--------------------------------------------------------------------

start_udp_echo() ->
    Parent = self(),
    Pid = erlang:spawn(fun() ->
        {ok, S} = gen_udp:open(0, [binary, {active, true},
                                    {ip, {127,0,0,1}}]),
        {ok, P} = inet:port(S),
        Parent ! {self(), port, P},
        udp_echo_loop(S)
    end),
    receive {Pid, port, Port} -> {Pid, Port}
    after 2000 -> erlang:error(udp_echo_start_timeout)
    end.

udp_echo_loop(S) ->
    receive
        {udp, S, Ip, Port, Data} ->
            gen_udp:send(S, Ip, Port, Data),
            udp_echo_loop(S);
        stop -> gen_udp:close(S)
    end.

start_tcp_echo() ->
    Parent = self(),
    Pid = erlang:spawn(fun() ->
        {ok, L} = gen_tcp:listen(0, [binary, {active, false},
                                      {reuseaddr, true},
                                      {ip, {127,0,0,1}}]),
        {ok, Port} = inet:port(L),
        Parent ! {self(), port, Port},
        tcp_accept_loop(L)
    end),
    receive {Pid, port, Port} -> {Pid, Port}
    after 2000 -> erlang:error(tcp_echo_start_timeout)
    end.

tcp_accept_loop(L) ->
    case gen_tcp:accept(L, 30000) of
        {ok, Sock} ->
            _ = spawn(fun() -> tcp_echo_loop(Sock) end),
            tcp_accept_loop(L);
        {error, _} -> ok
    end.

tcp_echo_loop(Sock) ->
    case gen_tcp:recv(Sock, 0, 30000) of
        {ok, Data} ->
            _ = gen_tcp:send(Sock, Data),
            tcp_echo_loop(Sock);
        _ -> gen_tcp:close(Sock)
    end.

%%--------------------------------------------------------------------
%% Ephemeral self-signed cert
%%--------------------------------------------------------------------

ephemeral_cert() ->
    Dir = filename:join(
        "/tmp", "two_hop_relay_" ++
            integer_to_list(erlang:unique_integer([positive]))),
    ok = filelib:ensure_dir(filename:join(Dir, ".keep")),
    CertFile = filename:join(Dir, "cert.pem"),
    KeyFile  = filename:join(Dir, "key.pem"),
    Cmd = lists:flatten(io_lib:format(
        "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
        "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null",
        [KeyFile, CertFile])),
    os:cmd(Cmd),
    {ok, CertPem} = file:read_file(CertFile),
    {ok, KeyPem}  = file:read_file(KeyFile),
    [{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),
    [{KeyType, KeyDerRaw, not_encrypted}] = public_key:pem_decode(KeyPem),
    KeyDer = public_key:der_decode(KeyType, KeyDerRaw),
    {ok, Dir, CertDer, KeyDer, CertFile, KeyFile}.
