%%% @doc Example — minimal CONNECT-IP proxy + client (RFC 9484).
%%%
%%% Starts a listener on `Port' with a self-signed certificate and the
%%% built-in `masque_ip_proxy_handler' configured with a /24 pool and
%%% an echo `forward_fun'. A second function dials back into the
%%% proxy, pushes an ICMPv4 echo request, and prints the reply that
%%% comes back from the tunnel.
%%%
%%% Run from the project root:
%%%
%%%     rebar3 shell
%%%     1> c("examples/ip_echo").
%%%     2> {ok, _} = ip_echo:start(4443).
%%%     3> ip_echo:ping().
%%%
%%% `ip_echo:stop().' tears the listener down.
-module(ip_echo).

-export([start/0, start/1, stop/0, ping/0, ping/1]).

-define(LISTENER, ip_echo_proxy).

-include_lib("masque/include/masque_ip.hrl").

%%====================================================================
%% Server side
%%====================================================================

start() -> start(4443).

start(Port) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, TmpDir, Cert, Key} = ephemeral_cert(),
    persistent_term:put({?MODULE, tmp_dir}, TmpDir),
    Opts = #{
        port            => Port,
        cert            => Cert,
        key             => Key,
        ip_handler      => masque_ip_proxy_handler,
        address_pool    => {4, {10,200,0,0}, 24},
        routes          => [#ip_route{version = 4,
                                      start_addr = {0,0,0,0},
                                      end_addr = {255,255,255,255},
                                      ip_protocol = 0}],
        handler_opts    => #{
            allow_private => true,
            forward_fun   => fun echo_fun/2
        }
    },
    masque:start_listener(?LISTENER, Opts).

stop() ->
    _ = masque:stop_listener(?LISTENER),
    TmpDir = persistent_term:get({?MODULE, tmp_dir}, undefined),
    case TmpDir of
        undefined -> ok;
        _         -> os:cmd("rm -rf " ++ TmpDir), ok
    end,
    persistent_term:erase({?MODULE, tmp_dir}),
    ok.

%% Echo every packet straight back to the client.
echo_fun(Packet, State) ->
    {reply, Packet, State}.

%%====================================================================
%% Client side
%%====================================================================

ping() -> ping(4443).

ping(Port) ->
    {ok, _} = application:ensure_all_started(masque),
    Url = iolist_to_binary(
            ["https://127.0.0.1:", integer_to_binary(Port)]),
    {ok, Sess} =
        masque:connect(Url, {'*', '*'},
                       #{protocol   => ip,
                         transports => [h3],
                         verify     => verify_none}),
    %% Swallow the initial ROUTE_ADVERTISEMENT before asking for an
    %% address.
    receive {masque_route_advertisement, Sess, _} -> ok
    after 500 -> ok
    end,
    {ok, [_Id]} =
        masque:request_addresses(Sess, [{4, {0,0,0,0}, 0}]),
    receive
        {masque_address_assign, Sess,
         [#ip_assignment{address = MyAddr}]} ->
            io:format("proxy gave me ~p~n", [MyAddr]),
            Packet = icmp_echo(MyAddr, {10,200,0,254}),
            ok = masque:send_ip_packet(Sess, Packet),
            receive
                {masque_ip_packet, Sess, Got} ->
                    io:format("got ~p bytes back~n", [byte_size(Got)])
            after 2000 ->
                    io:format("no echo within 2s~n")
            end
    after 2000 ->
            io:format("no address assignment within 2s~n")
    end,
    masque:close(Sess).

%%====================================================================
%% Self-signed cert (same shape as udp_echo_proxy)
%%====================================================================

ephemeral_cert() ->
    TmpDir = filename:join(
        ["/tmp",
         "masque_ip_echo_" ++ integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),
    CertFile = filename:join(TmpDir, "cert.pem"),
    KeyFile  = filename:join(TmpDir, "key.pem"),
    Cmd = lists:flatten(io_lib:format(
        "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
        "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null",
        [KeyFile, CertFile])),
    os:cmd(Cmd),
    {ok, CertPem} = file:read_file(CertFile),
    {ok, KeyPem}  = file:read_file(KeyFile),
    [{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),
    KeyDer = decode_key(KeyPem),
    {ok, TmpDir, CertDer, KeyDer}.

decode_key(KeyPem) ->
    case public_key:pem_decode(KeyPem) of
        [{'RSAPrivateKey', Der, not_encrypted}]  -> public_key:der_decode('RSAPrivateKey', Der);
        [{'ECPrivateKey',  Der, not_encrypted}]  -> public_key:der_decode('ECPrivateKey', Der);
        [{'PrivateKeyInfo', Der, not_encrypted}] -> public_key:der_decode('PrivateKeyInfo', Der);
        [{_Type, Der, not_encrypted}]            -> Der
    end.

%%====================================================================
%% Minimal ICMPv4 echo-request builder
%%====================================================================

icmp_echo({SA,SB,SC,SD}, {DA,DB,DC,DD}) ->
    TotalLen = 28,
    IPHdr = <<16#45:8, 0:8, TotalLen:16,
              0:16, 0:16, 64:8, 1:8, 0:16,
              SA:8, SB:8, SC:8, SD:8,
              DA:8, DB:8, DC:8, DD:8>>,
    Icmp0 = <<8:8, 0:8, 0:16, 1:16, 1:16>>,
    Csum  = inet_checksum(Icmp0),
    Icmp  = <<8:8, 0:8, Csum:16, 1:16, 1:16>>,
    <<IPHdr/binary, Icmp/binary>>.

inet_checksum(Bin) -> finish(sum(Bin, 0)).
sum(<<A:16, Rest/binary>>, Acc) -> sum(Rest, Acc + A);
sum(<<A:8>>, Acc)                -> Acc + (A bsl 8);
sum(<<>>, Acc)                   -> Acc.
finish(Sum) ->
    S = (Sum band 16#FFFF) + (Sum bsr 16),
    S2 = (S band 16#FFFF) + (S bsr 16),
    (bnot S2) band 16#FFFF.
