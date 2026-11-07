%%% @doc Wire vectors for Connect-UDP-Bind
%%% (draft-ietf-masque-connect-udp-listen-16) against a real listener on
%%% h3, h2 and h1. Each case builds the request, capsules and datagrams
%%% by hand and checks what the proxy answers.
-module(masque_udp_bind_vectors_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("masque_udp_bind.hrl").

-export([suite/0, all/0, groups/0]).
-export([init_per_suite/1, end_per_suite/1, init_per_group/2, end_per_group/2]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    one_wildcard_is_400/1,
    header_parameters_enable_bind/1,
    repeated_header_is_ignored/1,
    compressed_echo/1,
    context_zero_aborts/1,
    refused_target_is_rejected/1,
    unadvertised_family_is_rejected/1,
    table_full_is_rejected/1,
    duplicate_id_aborts/1,
    reused_id_aborts/1,
    closed_context_datagram_is_discarded/1,
    unknown_ack_aborts/1,
    second_uncompressed_aborts/1
]).

-define(LIMIT, 2).

suite() -> [{timetrap, {minutes, 3}}].

all() -> [{group, h3}, {group, h2}, {group, h1}].

groups() ->
    Cases = [
        one_wildcard_is_400,
        header_parameters_enable_bind,
        repeated_header_is_ignored,
        compressed_echo,
        context_zero_aborts,
        refused_target_is_rejected,
        unadvertised_family_is_rejected,
        table_full_is_rejected,
        duplicate_id_aborts,
        reused_id_aborts,
        closed_context_datagram_is_discarded,
        unknown_ack_aborts,
        second_uncompressed_aborts
    ],
    [{h3, [], Cases}, {h2, [], Cases}, {h1, [], Cases}].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Certs} = masque_test_helpers:generate_certs(),
    {Echo, EchoPort} = start_udp_echo(),
    [{certs, Certs}, {echo, Echo}, {echo_port, EchoPort} | Config].

end_per_suite(Config) ->
    exit(?config(echo, Config), kill),
    masque_test_helpers:cleanup_certs(?config(certs, Config)).

init_per_group(T, Config) -> [{transport, T} | Config].

end_per_group(_T, _Config) -> ok.

init_per_testcase(_Case, Config) ->
    [{server, start_server(?config(transport, Config), ?config(certs, Config))} | Config].

end_per_testcase(_Case, Config) ->
    stop_server(?config(transport, Config), ?config(server, Config)),
    ok.

%%====================================================================
%% Cases
%%====================================================================

%% Section 2: only one of the variables set to `*' is malformed: 400.
one_wildcard_is_400(Config) ->
    W = open(Config, <<"/.well-known/masque/udp/%2A/53/">>, [bind_header()]),
    ?assertEqual(400, status(W)),
    close(W).

%% Section 6: unknown parameters are ignored.
header_parameters_enable_bind(Config) ->
    W = open(Config, unscoped_path(), [{<<"connect-udp-bind">>, <<"?1;future=1">>}]),
    ?assertEqual(success(W), status(W)),
    ?assertEqual(<<"?1">>, proplists:get_value(<<"connect-udp-bind">>, headers(W))),
    close(W).

%% Section 6: a field sent twice is a List and is ignored, so the
%% request is plain CONNECT-UDP, where `*' is not a target.
repeated_header_is_ignored(Config) ->
    W = open(Config, unscoped_path(), [bind_header(), bind_header()]),
    ?assertEqual(400, status(W)),
    close(W).

%% Sections 3.1, 3.2 and 5: a compressed context to an allowed peer is
%% acknowledged and carries datagrams both ways.
compressed_echo(Config) ->
    W = bound(Config),
    ok = send_capsule(W, assign(2, {127, 0, 0, 1}, ?config(echo_port, Config))),
    ?assertEqual({ack, 2}, next_capsule(W)),
    ok = send_datagram(W, 2, <<"ping">>),
    ?assertEqual({2, <<"ping">>}, next_datagram(W)),
    close(W).

%% Section 3: with both variables `*', a datagram on context 0 aborts
%% the request stream.
context_zero_aborts(Config) ->
    W = bound(Config),
    ok = send_datagram(W, 0, <<"x">>),
    ?assertEqual(aborted, stream_end(W)),
    close(W).

%% Section 9: a registration to a target the proxy refuses (a private
%% address here) is rejected with COMPRESSION_CLOSE; the stream stays.
refused_target_is_rejected(Config) ->
    W = bound(Config),
    ok = send_capsule(W, assign(2, {10, 0, 0, 1}, 53)),
    ?assertEqual({close, 2}, next_capsule(W)),
    ok = send_capsule(W, assign(4, {127, 0, 0, 1}, ?config(echo_port, Config))),
    ?assertEqual({ack, 4}, next_capsule(W)),
    close(W).

%% Section 7: the proxy only advertised IPv4, so an IPv6 registration
%% is rejected.
unadvertised_family_is_rejected(Config) ->
    W = bound(Config),
    ok = send_capsule(W, assign(2, {0, 0, 0, 0, 0, 0, 0, 1}, 53)),
    ?assertEqual({close, 2}, next_capsule(W)),
    close(W).

%% Section 9: registrations beyond the limit are rejected.
table_full_is_rejected(Config) ->
    W = bound(Config),
    Port = ?config(echo_port, Config),
    ok = send_capsule(W, assign(2, {127, 0, 0, 1}, Port)),
    ?assertEqual({ack, 2}, next_capsule(W)),
    ok = send_capsule(W, assign(4, {127, 0, 0, 1}, Port + 1)),
    ?assertEqual({ack, 4}, next_capsule(W)),
    ok = send_capsule(W, assign(6, {127, 0, 0, 1}, Port + 2)),
    ?assertEqual({close, 6}, next_capsule(W)),
    close(W).

%% Section 3.1: the same context id twice is malformed.
duplicate_id_aborts(Config) ->
    W = bound(Config),
    Port = ?config(echo_port, Config),
    ok = send_capsule(W, assign(2, {127, 0, 0, 1}, Port)),
    ?assertEqual({ack, 2}, next_capsule(W)),
    ok = send_capsule(W, assign(2, {127, 0, 0, 1}, Port + 1)),
    ?assertEqual(aborted, stream_end(W)),
    close(W).

%% Section 3.3: a closed id is never reused.
reused_id_aborts(Config) ->
    W = bound(Config),
    Port = ?config(echo_port, Config),
    ok = send_capsule(W, assign(2, {127, 0, 0, 1}, Port)),
    ?assertEqual({ack, 2}, next_capsule(W)),
    ok = send_capsule(W, close_capsule(2)),
    ok = send_capsule(W, assign(2, {127, 0, 0, 1}, Port)),
    ?assertEqual(aborted, stream_end(W)),
    close(W).

%% Section 3.3: datagrams for a closed context are discarded silently.
closed_context_datagram_is_discarded(Config) ->
    W = bound(Config),
    Port = ?config(echo_port, Config),
    ok = send_capsule(W, assign(2, {127, 0, 0, 1}, Port)),
    ?assertEqual({ack, 2}, next_capsule(W)),
    ok = send_capsule(W, close_capsule(2)),
    ok = send_datagram(W, 2, <<"late">>),
    ok = send_capsule(W, assign(4, {127, 0, 0, 1}, Port)),
    ?assertEqual({ack, 4}, next_capsule(W)),
    close(W).

%% Section 3.2: an ACK for a context we never assigned is malformed.
unknown_ack_aborts(Config) ->
    W = bound(Config),
    ok = send_capsule(W, masque_compression_capsule:encode(#compression_ack{context_id = 7})),
    ?assertEqual(aborted, stream_end(W)),
    close(W).

%% Section 4: a second uncompressed context while one is open is
%% malformed.
second_uncompressed_aborts(Config) ->
    W = bound(Config),
    ok = send_capsule(W, uncompressed(2)),
    ?assertEqual({ack, 2}, next_capsule(W)),
    ok = send_capsule(W, uncompressed(4)),
    ?assertEqual(aborted, stream_end(W)),
    close(W).

%%====================================================================
%% Capsules
%%====================================================================

assign(Id, IP, Port) ->
    V =
        case tuple_size(IP) of
            4 -> 4;
            8 -> 6
        end,
    masque_compression_capsule:encode(#compression_assign{
        context_id = Id, ip_version = V, address = IP, port = Port
    }).

uncompressed(Id) ->
    masque_compression_capsule:encode(#compression_assign{context_id = Id, ip_version = 0}).

close_capsule(Id) ->
    masque_compression_capsule:encode(#compression_close{context_id = Id}).

bind_header() -> {<<"connect-udp-bind">>, <<"?1">>}.

unscoped_path() -> <<"/.well-known/masque/udp/%2A/%2A/">>.

%%====================================================================
%% One request on the transport under test
%%====================================================================

%% An unscoped bind that the proxy accepted.
bound(Config) ->
    W = open(Config, unscoped_path(), [bind_header()]),
    ?assertEqual(success(W), status(W)),
    W.

%% h1 upgrades with 101; h3 and h2 answer 200.
success(#{tag := h1}) -> 101;
success(_) -> 200.

open(Config, Path, Extra) ->
    #{port := Port} = ?config(server, Config),
    case ?config(transport, Config) of
        h3 ->
            {ok, Conn} = masque_test_helpers:h3_client_connect(Port, #{}),
            Headers = [
                {<<":method">>, <<"CONNECT">>},
                {<<":protocol">>, <<"connect-udp">>},
                {<<":scheme">>, <<"https">>},
                {<<":authority">>, <<"127.0.0.1">>},
                {<<":path">>, Path},
                {<<"capsule-protocol">>, <<"?1">>}
                | Extra
            ],
            {ok, Sid} = quic_h3:request(Conn, Headers, #{end_stream => false}),
            response(#{tag => quic_h3, conn => Conn, sid => Sid});
        h2 ->
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
                {<<"capsule-protocol">>, <<"?1">>}
                | Extra
            ],
            {ok, Sid} = h2:request(Conn, Headers, #{protocol => <<"connect-udp">>}),
            response(#{tag => h2, conn => Conn, sid => Sid});
        h1 ->
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
                <<" HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n">>,
                <<"Capsule-Protocol: ?1\r\n">>,
                [[K, <<": ">>, V, <<"\r\n">>] || {K, V} <- Extra],
                <<"\r\n">>
            ]),
            h1_response(#{tag => h1, sock => Sock}, <<>>)
    end.

response(#{tag := Tag, conn := Conn, sid := Sid} = W) ->
    receive
        {Tag, Conn, {response, Sid, Status, Hdrs}} ->
            W#{status => Status, headers => Hdrs, buf => <<>>}
    after 5000 -> ct:fail(no_response)
    end.

h1_response(#{sock := Sock} = W, Acc) ->
    case binary:split(Acc, <<"\r\n\r\n">>) of
        [Head, Rest] ->
            [StatusLine | Lines] = binary:split(Head, <<"\r\n">>, [global]),
            [_, Code | _] = binary:split(StatusLine, <<" ">>, [global]),
            Hdrs = [
                {string:lowercase(string:trim(K)), string:trim(V)}
             || L <- Lines, [K, V] <- [binary:split(L, <<":">>)]
            ],
            W#{status => binary_to_integer(Code), headers => Hdrs, buf => Rest};
        [_] ->
            {ok, More} = ssl:recv(Sock, 0, 5000),
            h1_response(W, <<Acc/binary, More/binary>>)
    end.

status(#{status := S}) -> S.
headers(#{headers := H}) -> H.

send_capsule(#{tag := quic_h3, conn := C, sid := Sid}, Bin) ->
    quic_h3:send_data(C, Sid, iolist_to_binary(Bin), false);
send_capsule(#{tag := h2, conn := C, sid := Sid}, Bin) ->
    h2:send_data(C, Sid, iolist_to_binary(Bin), false);
send_capsule(#{tag := h1, sock := Sock}, Bin) ->
    ssl:send(Sock, Bin).

%% QUIC datagrams on h3, DATAGRAM capsules on h2 and h1.
send_datagram(#{tag := quic_h3, conn := C, sid := Sid}, Ctx, Payload) ->
    quic_h3:send_datagram(C, Sid, iolist_to_binary(masque_datagram:encode(Ctx, Payload)));
send_datagram(W, Ctx, Payload) ->
    Inner = iolist_to_binary(masque_datagram:encode(Ctx, Payload)),
    send_capsule(W, masque_capsule:encode(0, Inner)).

%% The next compression capsule from the proxy: `{ack | close, Id}'.
next_capsule(W) ->
    case next_item(W) of
        {capsule, ?MASQUE_CAPSULE_COMPRESSION_ACK, V} ->
            {ok, #compression_ack{context_id = Id}} = masque_compression_capsule:decode_ack(V),
            {ack, Id};
        {capsule, ?MASQUE_CAPSULE_COMPRESSION_CLOSE, V} ->
            {ok, #compression_close{context_id = Id}} = masque_compression_capsule:decode_close(V),
            {close, Id};
        Other ->
            ct:fail({unexpected, Other})
    end.

%% The next datagram from the proxy: `{Context, Payload}'.
next_datagram(#{tag := quic_h3, conn := C, sid := Sid}) ->
    receive
        {quic_h3, C, {datagram, Sid, Bin}} ->
            {ok, {Ctx, Payload}} = masque_datagram:decode(Bin),
            {Ctx, Payload}
    after 5000 -> ct:fail(no_datagram)
    end;
next_datagram(W) ->
    case next_item(W) of
        {capsule, 0, V} ->
            {ok, {Ctx, Payload}} = masque_datagram:decode(V),
            {Ctx, Payload};
        Other ->
            ct:fail({unexpected, Other})
    end.

%% `aborted' when the proxy reset the stream (or closed the h1
%% connection) instead of carrying on.
stream_end(#{tag := h1, sock := Sock}) ->
    case ssl:recv(Sock, 0, 5000) of
        {error, closed} -> aborted;
        Other -> ct:fail({still_open, Other})
    end;
stream_end(#{tag := Tag, conn := C, sid := Sid}) ->
    receive
        {Tag, C, {stream_reset, Sid, _}} -> aborted
    after 5000 -> ct:fail(not_aborted)
    end.

next_item(W) ->
    next_item(W, buffered(W)).

next_item(W, Buf) ->
    case masque_capsule:decode(Buf) of
        {ok, {Type, Value, Rest}} ->
            put({buf, W}, Rest),
            {capsule, Type, Value};
        _ ->
            next_item(W, <<Buf/binary, (recv(W))/binary>>)
    end.

buffered(#{buf := B0} = W) ->
    case get({buf, W}) of
        undefined -> B0;
        B -> B
    end.

recv(#{tag := h1, sock := Sock}) ->
    case ssl:recv(Sock, 0, 5000) of
        {ok, Bin} -> Bin;
        Other -> ct:fail({recv, Other})
    end;
recv(#{tag := Tag, conn := C, sid := Sid}) ->
    receive
        {Tag, C, {data, Sid, Bin, _}} -> Bin;
        {Tag, C, {stream_reset, Sid, Code}} -> ct:fail({reset, Code})
    after 5000 -> ct:fail(no_capsule)
    end.

close(#{tag := quic_h3, conn := C}) -> quic_h3:close(C);
close(#{tag := h2, conn := C}) -> h2:close(C);
close(#{tag := h1, sock := Sock}) -> ssl:close(Sock).

%%====================================================================
%% Servers and peers
%%====================================================================

listener_opts() ->
    #{
        accept_bind => true,
        handler_opts => #{
            bind_address => {127, 0, 0, 1},
            allow_loopback => true,
            max_compression_contexts => ?LIMIT
        }
    }.

start_server(h3, Certs) ->
    {ok, Srv} = masque_test_helpers:start_masque_server(maps:merge(Certs, listener_opts())),
    Srv;
start_server(h2, #{cert_file := Cert, key_file := Key}) ->
    Name = unique(h2),
    {ok, {_, _, Port}} = masque:start_listener_h2(Name, (listener_opts())#{
        port => 0, cert => Cert, key => Key
    }),
    #{name => Name, port => Port};
start_server(h1, #{cert_file := Cert, key_file := Key}) ->
    Name = unique(h1),
    {ok, Ref} = masque:start_listener_h1(Name, (listener_opts())#{
        port => 0, cert => Cert, key => Key
    }),
    #{name => Name, port => h1:server_port(Ref)}.

stop_server(h3, Srv) -> masque_test_helpers:stop_masque_server(Srv);
stop_server(h2, #{name := Name}) -> masque:stop_listener_h2(Name);
stop_server(h1, #{name := Name}) -> masque:stop_listener_h1(Name).

unique(P) ->
    list_to_atom(
        "bindvec_" ++ atom_to_list(P) ++ "_" ++ integer_to_list(erlang:unique_integer([positive]))
    ).

start_udp_echo() ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Sock),
    Pid = spawn(fun() -> udp_echo(Sock) end),
    ok = gen_udp:controlling_process(Sock, Pid),
    {Pid, Port}.

udp_echo(Sock) ->
    case gen_udp:recv(Sock, 0) of
        {ok, {IP, Port, Data}} ->
            _ = gen_udp:send(Sock, IP, Port, Data),
            udp_echo(Sock);
        {error, _} ->
            ok
    end.
