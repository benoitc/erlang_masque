%%% @doc Session lifecycle tests: server and client sessions end when
%%% the underlying connection or stream goes away.
%%%
%%% Server-side session pids are captured through
%%% `masque_report_handler', whose `init/2' reports `self()' to the
%%% test process.
-module(masque_lifecycle_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("masque_ip.hrl").

-export([
    suite/0,
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([
    h3_client_close_stops_server_session/1,
    h2_client_close_stops_server_session/1,
    h3_server_close_notifies_client/1,
    h2_server_close_notifies_client/1,
    h3_goaway_keeps_processed_tunnel/1,
    h3_client_fin_ends_server_session/1,
    h2_client_fin_ends_server_session/1,
    h1_close_leaves_no_server_session/1,
    h3_server_fin_notifies_client/1,
    h2_server_fin_notifies_client/1,
    h3_early_address_request_answered/1,
    h3_tcp_bytes_before_claim_arrive/1,
    h3_udp_bind_round_trip/1,
    h2_udp_bind_round_trip/1,
    h3_bind_handler_crash_resets_stream/1,
    h2_bind_handler_crash_resets_stream/1,
    h3_udp_handler_crash_resets_stream/1,
    h2_udp_handler_crash_resets_stream/1,
    h3_reset_while_starting_answers_listener/1,
    h1_bind_handler_crash_closes_tunnel/1,
    unsupported_call_keeps_session/1,
    udp_bind_skips_pool/1,
    h1_every_tunnel_counts_open_and_close/1,
    h1_udp_bind_assign_by_address/1,
    h1_udp_bind_pending_limit/1,
    h3_reset_while_finalizing_answers_listener/1,
    bind_message_before_finalize/1,
    h3_unknown_reject_reason_gets_response/1,
    h2_unknown_reject_reason_gets_response/1,
    h2_failed_session_releases_tunnel_slot/1,
    h3_tcp_target_reset_resets_tunnel/1,
    h2_tcp_target_reset_resets_tunnel/1,
    h3_tcp_client_fin_half_closes/1,
    h2_tcp_client_fin_half_closes/1,
    h3_tcp_target_fin_half_closes/1,
    h2_tcp_target_fin_half_closes/1,
    tcp_send_capsule_not_supported/1,
    h2_tcp_rejects_capsule_protocol_response/1,
    h3_udp_bind_close_ends_connection/1,
    h2_udp_bind_close_ends_connection/1,
    h3_udp_bind_parked_session_closes_connection/1,
    h2_udp_bind_parked_session_closes_connection/1,
    h3_tcp_data_before_finalize_is_kept/1,
    h3_udp_output_before_finalize_is_kept/1,
    h3_ip_output_before_finalize_is_kept/1,
    h3_udp_bind_output_before_finalize_is_kept/1
]).

-define(TPL, <<"/.well-known/masque/udp/{target_host}/{target_port}/">>).

%%====================================================================
%% CT callbacks
%%====================================================================

suite() -> [{timetrap, {seconds, 30}}].

all() ->
    [
        h3_client_close_stops_server_session,
        h2_client_close_stops_server_session,
        h3_server_close_notifies_client,
        h2_server_close_notifies_client,
        h3_goaway_keeps_processed_tunnel,
        h3_client_fin_ends_server_session,
        h2_client_fin_ends_server_session,
        h1_close_leaves_no_server_session,
        h3_server_fin_notifies_client,
        h2_server_fin_notifies_client,
        h3_early_address_request_answered,
        h3_tcp_bytes_before_claim_arrive,
        h3_udp_bind_round_trip,
        h2_udp_bind_round_trip,
        h3_bind_handler_crash_resets_stream,
        h2_bind_handler_crash_resets_stream,
        h3_udp_handler_crash_resets_stream,
        h2_udp_handler_crash_resets_stream,
        h3_reset_while_starting_answers_listener,
        h1_bind_handler_crash_closes_tunnel,
        unsupported_call_keeps_session,
        udp_bind_skips_pool,
        h1_every_tunnel_counts_open_and_close,
        h1_udp_bind_assign_by_address,
        h1_udp_bind_pending_limit,
        h3_reset_while_finalizing_answers_listener,
        bind_message_before_finalize,
        h3_unknown_reject_reason_gets_response,
        h2_unknown_reject_reason_gets_response,
        h2_failed_session_releases_tunnel_slot,
        h3_tcp_target_reset_resets_tunnel,
        h2_tcp_target_reset_resets_tunnel,
        h3_tcp_client_fin_half_closes,
        h2_tcp_client_fin_half_closes,
        h3_tcp_target_fin_half_closes,
        h2_tcp_target_fin_half_closes,
        tcp_send_capsule_not_supported,
        h2_tcp_rejects_capsule_protocol_response,
        h3_udp_bind_close_ends_connection,
        h2_udp_bind_close_ends_connection,
        h3_udp_bind_parked_session_closes_connection,
        h2_udp_bind_parked_session_closes_connection,
        h3_tcp_data_before_finalize_is_kept,
        h3_udp_output_before_finalize_is_kept,
        h3_ip_output_before_finalize_is_kept,
        h3_udp_bind_output_before_finalize_is_kept
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

init_per_testcase(Case, Config) ->
    Certs = ?config(certs, Config),
    Extra = extra_opts(Case),
    HOpts = maps:merge(
        #{report_to => self(), allow_private => true},
        maps:get(handler_opts, Extra, #{})
    ),
    Opts = maps:merge(
        #{
            handler => masque_report_handler,
            ip_handler => masque_ip_echo_handler
        },
        Extra#{handler_opts => HOpts}
    ),
    {ok, H3} = masque_test_helpers:start_masque_server(maps:merge(Certs, Opts)),
    {ok, H2} = start_h2_server(Certs, Opts),
    H1 =
        case atom_to_list(Case) of
            "h1_" ++ _ -> start_h1_server(Certs, Opts);
            _ -> undefined
        end,
    [{h3, H3}, {h2, H2}, {h1, H1} | Config].

end_per_testcase(_Case, Config) ->
    _ =
        (try
            masque_test_helpers:stop_masque_server(?config(h3, Config))
        catch
            _:_ -> ok
        end),
    _ =
        (try
            h2:stop_server(maps:get(h2_ref, ?config(h2, Config)))
        catch
            _:_ -> ok
        end),
    _ =
        (try
            masque:stop_listener_h1(maps:get(name, ?config(h1, Config)))
        catch
            _:_ -> ok
        end),
    ok.

extra_opts(Case) when
    Case =:= h3_udp_bind_round_trip;
    Case =:= h2_udp_bind_round_trip;
    Case =:= h3_udp_bind_close_ends_connection;
    Case =:= h2_udp_bind_close_ends_connection
->
    bind_opts();
extra_opts(Case) when
    Case =:= h3_bind_handler_crash_resets_stream;
    Case =:= h2_bind_handler_crash_resets_stream;
    Case =:= h3_udp_bind_parked_session_closes_connection;
    Case =:= h2_udp_bind_parked_session_closes_connection
->
    (bind_opts())#{bind_handler => masque_crash_bind_handler};
extra_opts(Case) when
    Case =:= h3_unknown_reject_reason_gets_response;
    Case =:= h2_unknown_reject_reason_gets_response
->
    #{handler => masque_weird_reject_handler};
extra_opts(h3_tcp_data_before_finalize_is_kept) ->
    #{tcp_handler => masque_report_tcp_handler, handler_opts => #{early_data => <<"early">>}};
extra_opts(h3_udp_output_before_finalize_is_kept) ->
    #{handler_opts => #{early_data => <<"early">>}};
extra_opts(h3_ip_output_before_finalize_is_kept) ->
    #{handler_opts => #{early_routes => [early_route()], early_packet => early_ip_packet()}};
extra_opts(h3_udp_bind_output_before_finalize_is_kept) ->
    B = bind_opts(),
    HOpts = maps:get(handler_opts, B),
    B#{
        bind_handler => masque_crash_bind_handler,
        handler_opts => HOpts#{early_assign => {{127, 0, 0, 1}, 9}}
    };
extra_opts(h1_bind_handler_crash_closes_tunnel) ->
    (bind_opts())#{bind_handler => masque_crash_bind_handler};
extra_opts(udp_bind_skips_pool) ->
    bind_opts();
extra_opts(h1_every_tunnel_counts_open_and_close) ->
    bind_opts();
extra_opts(h1_udp_bind_assign_by_address) ->
    early_assign_opts(#{});
extra_opts(h1_udp_bind_pending_limit) ->
    early_assign_opts(#{max_pending_compression_responses => 0});
extra_opts(h2_failed_session_releases_tunnel_slot) ->
    #{handler => masque_stop_init_handler, max_tunnels_per_connection => 1};
extra_opts(_Case) ->
    #{}.

early_assign_opts(Extra) ->
    B = bind_opts(),
    HOpts = maps:get(handler_opts, B),
    B#{
        bind_handler => masque_crash_bind_handler,
        handler_opts => maps:merge(HOpts#{early_assign => {{127, 0, 0, 1}, 9}}, Extra)
    }.

bind_opts() ->
    #{
        accept_bind => true,
        handler_opts => #{bind_address => {127, 0, 0, 1}, allow_loopback => true}
    }.

%%====================================================================
%% Connection close
%%====================================================================

h3_client_close_stops_server_session(Config) ->
    {Conn, _Sid} = h3_open_udp(Config),
    Pid = await_session(),
    MRef = erlang:monitor(process, Pid),
    ok = quic_h3:close(Conn),
    await_down(MRef, Pid).

h2_client_close_stops_server_session(Config) ->
    Baseline = session_count(masque_h2_session_sup),
    {Conn, _Sid} = h2_open_udp(Config),
    Pid = await_session(),
    ?assertEqual(Baseline + 1, session_count(masque_h2_session_sup)),
    MRef = erlang:monitor(process, Pid),
    ok = h2:close(Conn),
    await_down(MRef, Pid),
    ok = wait_count(masque_h2_session_sup, Baseline, 50).

h3_server_close_notifies_client(Config) ->
    Sess = connect(Config, h3),
    Pid = await_session(),
    ServerConn = element(2, sys:get_state(Pid)),
    _ = quic_h3:close(ServerConn),
    await_closed(Sess).

h2_server_close_notifies_client(Config) ->
    Sess = connect(Config, h2),
    Pid = await_session(),
    ServerConn = element(2, sys:get_state(Pid)),
    _ = h2:close(ServerConn),
    await_closed(Sess).

%% A GOAWAY whose id is above the tunnel's stream leaves it running;
%% one that covers the stream ends it with `goaway'. The events are
%% injected: quic_h3 2.0.0 leaves calls such as `send_datagram'
%% unanswered once it has received a real GOAWAY.
h3_goaway_keeps_processed_tunnel(Config) ->
    Sess = connect(Config, h3),
    _ = await_session(),
    Sess ! {quic_h3, self(), {goaway, 1 bsl 40}},
    ok = masque:send(Sess, <<"still here">>),
    receive
        {masque_data, Sess, <<"still here">>} -> ok
    after 5000 -> ct:fail(no_echo_after_goaway)
    end,
    Sess ! {quic_h3, self(), {goaway, 0}},
    receive
        {masque_closed, Sess, goaway} -> ok
    after 5000 -> ct:fail(no_goaway_close)
    end.

%%====================================================================
%% Clean FIN and early data
%%====================================================================

h3_client_fin_ends_server_session(Config) ->
    {Conn, Sid} = h3_open_udp(Config),
    Pid = await_session(),
    MRef = erlang:monitor(process, Pid),
    ok = quic_h3:send_data(Conn, Sid, <<>>, true),
    receive
        {'DOWN', MRef, process, Pid, normal} -> ok
    after 5000 -> ct:fail(no_normal_stop)
    end,
    ok = await_fin(quic_h3, Conn, Sid),
    quic_h3:close(Conn).

h2_client_fin_ends_server_session(Config) ->
    Baseline = session_count(masque_h2_session_sup),
    {Conn, Sid} = h2_open_udp(Config),
    Pid = await_session(),
    MRef = erlang:monitor(process, Pid),
    ok = h2:send_data(Conn, Sid, <<>>, true),
    receive
        {'DOWN', MRef, process, Pid, normal} -> ok
    after 5000 -> ct:fail(no_normal_stop)
    end,
    ok = await_fin(h2, Conn, Sid),
    ok = wait_count(masque_h2_session_sup, Baseline, 50),
    h2:close(Conn).

h1_close_leaves_no_server_session(Config) ->
    Baseline = session_count(masque_h1_session_sup),
    Sess = connect(Config, h1),
    Pid = await_session(),
    MRef = erlang:monitor(process, Pid),
    ok = masque:close(Sess),
    await_down(MRef, Pid),
    ok = wait_count(masque_h1_session_sup, Baseline, 50).

h3_server_fin_notifies_client(Config) ->
    server_fin_notifies_client(Config, h3).

h2_server_fin_notifies_client(Config) ->
    server_fin_notifies_client(Config, h2).

server_fin_notifies_client(Config, Transport) ->
    Sess = connect(Config, Transport),
    Pid = await_session(),
    MRef = erlang:monitor(process, Pid),
    ok = masque:send_capsule(Sess, 16#ff00, <<>>),
    receive
        {masque_closed, Sess, peer_fin} -> ok
    after 5000 -> ct:fail(no_peer_fin)
    end,
    receive
        {'DOWN', MRef, process, Pid, normal} -> ok
    after 5000 -> ct:fail(server_session_alive)
    end.

%% An ADDRESS_REQUEST written right behind the request, before the 2xx
%% and the stream claim, is answered.
h3_early_address_request_answered(Config) ->
    {ok, Conn} = masque_test_helpers:h3_client_connect(
        maps:get(port, ?config(h3, Config)), #{}
    ),
    Path = <<"/.well-known/masque/ip/*/*/">>,
    Headers = [
        {<<":method">>, <<"CONNECT">>},
        {<<":protocol">>, <<"connect-ip">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"localhost">>},
        {<<":path">>, Path},
        {<<"capsule-protocol">>, <<"?1">>}
    ],
    {ok, Sid} = quic_h3:request(Conn, Headers, #{end_stream => false}),
    Req = #ip_prefix_request{
        request_id = 7, version = 4, address = {0, 0, 0, 0}, prefix_len = 32
    },
    Cap = iolist_to_binary(masque_ip_capsule:encode(address_request, [Req])),
    ok = quic_h3:send_data(Conn, Sid, Cap, false),
    {ok, 200, _} = masque_test_helpers:h3_await_response(Sid, 5000),
    Bin = recv_stream(quic_h3, Conn, Sid, <<>>, 5000),
    {ok, {?MASQUE_CAPSULE_ADDRESS_ASSIGN, Body, _}} = masque_capsule:decode(Bin),
    {ok, [#ip_assignment{request_id = 7}]} =
        masque_ip_capsule:decode_address_assign(Body),
    quic_h3:close(Conn).

%% CONNECT-TCP bytes written before the proxy claims the stream reach
%% the target instead of being dropped.
h3_tcp_bytes_before_claim_arrive(Config) ->
    {EchoPid, EchoPort} = start_tcp_echo(),
    {ok, Conn} = masque_test_helpers:h3_client_connect(
        maps:get(port, ?config(h3, Config)), #{}
    ),
    Path = masque_uri:expand(
        <<"/.well-known/masque/tcp/{target_host}/{target_port}/">>,
        #{target_host => <<"127.0.0.1">>, target_port => EchoPort}
    ),
    Headers = [
        {<<":method">>, <<"CONNECT">>},
        {<<":protocol">>, <<"connect-tcp">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"localhost">>},
        {<<":path">>, Path}
    ],
    {ok, Sid} = quic_h3:request(Conn, Headers, #{end_stream => false}),
    ok = quic_h3:send_data(Conn, Sid, <<"early bytes">>, false),
    {ok, 200, _} = masque_test_helpers:h3_await_response(Sid, 5000),
    <<"early bytes">> = recv_stream(quic_h3, Conn, Sid, <<>>, 5000),
    quic_h3:close(Conn),
    exit(EchoPid, kill).

%%====================================================================
%% Connect-UDP-Bind lifecycle
%%====================================================================

h3_udp_bind_round_trip(Config) ->
    udp_bind_round_trip(Config, h3).

h2_udp_bind_round_trip(Config) ->
    udp_bind_round_trip(Config, h2).

udp_bind_round_trip(Config, Transport) ->
    {ok, Peer} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}, {active, true}]),
    {ok, PeerPort} = inet:port(Peer),
    Sess = bind_connect(Config, Transport),
    %% The uncompressed context carries both directions.
    {ok, _} = masque:open_uncompressed_context(Sess),
    receive
        {masque_compression_acked, Sess, _} -> ok
    after 5000 -> ct:fail(no_compression_ack)
    end,
    ok = masque:send_to(Sess, {{127, 0, 0, 1}, PeerPort}, <<"ping">>),
    {ProxyIP, ProxyPort} =
        receive
            {udp, Peer, FromIP, FromPort, <<"ping">>} -> {FromIP, FromPort}
        after 5000 -> ct:fail(no_packet_at_peer)
        end,
    ok = gen_udp:send(Peer, ProxyIP, ProxyPort, <<"pong">>),
    receive
        {masque_bind_packet, Sess, {{127, 0, 0, 1}, PeerPort}, <<"pong">>} -> ok
    after 5000 -> ct:fail(no_packet_from_peer)
    end,
    ok = masque:close(Sess),
    gen_udp:close(Peer).

h3_udp_bind_close_ends_connection(Config) ->
    udp_bind_close_ends_connection(Config, h3).

h2_udp_bind_close_ends_connection(Config) ->
    udp_bind_close_ends_connection(Config, h2).

%% The session dialed its own connection; closing the session closes it.
udp_bind_close_ends_connection(Config, Transport) ->
    Sess = bind_connect(Config, Transport),
    %% `conn' is the 9th field of the session's `#data{}' record.
    {open, Data} = sys:get_state(Sess),
    Conn = element(10, Data),
    true = is_process_alive(Conn),
    MRef = erlang:monitor(process, Conn),
    ok = masque:close(Sess),
    receive
        {'DOWN', MRef, process, Conn, _} -> ok
    after 5000 -> ct:fail(connection_alive)
    end.

h3_udp_bind_parked_session_closes_connection(Config) ->
    udp_bind_parked_session_closes_connection(Config, h3).

h2_udp_bind_parked_session_closes_connection(Config) ->
    udp_bind_parked_session_closes_connection(Config, h2).

%% A queue-mode session whose tunnel ended with data unread lingers
%% for `recv/2', but its connection closes right away.
udp_bind_parked_session_closes_connection(Config, Transport) ->
    {ok, Peer} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}, {active, true}]),
    {ok, PeerPort} = inet:port(Peer),
    Sess = bind_connect(Config, Transport),
    ok = masque:set_mode(Sess, queue),
    {ok, _} = masque:open_uncompressed_context(Sess),
    ok = wait_until(fun() -> uncompressed_acked(Sess) end, 50),
    ok = masque:send_to(Sess, {{127, 0, 0, 1}, PeerPort}, <<"ping">>),
    {ProxyIP, ProxyPort} =
        receive
            {udp, Peer, FromIP, FromPort, <<"ping">>} -> {FromIP, FromPort}
        after 5000 -> ct:fail(no_packet_at_peer)
        end,
    ok = gen_udp:send(Peer, ProxyIP, ProxyPort, <<"pong">>),
    timer:sleep(200),
    {open, Data} = sys:get_state(Sess),
    Conn = element(10, Data),
    MRef = erlang:monitor(process, Conn),
    %% The crash handler resets the stream on this capsule.
    ok = masque:send_capsule(Sess, 16#ff01, <<>>),
    receive
        {'DOWN', MRef, process, Conn, _} -> ok
    after 5000 -> ct:fail(connection_alive)
    end,
    {ok, _, <<"pong">>} = masque:recv(Sess, 1000),
    {error, closed} = masque:recv(Sess, 1000),
    gen_udp:close(Peer).

uncompressed_acked(Sess) ->
    receive
        {masque_compression_acked, Sess, _} -> true
    after 0 -> false
    end.

h3_bind_handler_crash_resets_stream(Config) ->
    bind_handler_crash_resets_stream(Config, h3).

h2_bind_handler_crash_resets_stream(Config) ->
    bind_handler_crash_resets_stream(Config, h2).

bind_handler_crash_resets_stream(Config, Transport) ->
    Sess = bind_connect(Config, Transport),
    ok = masque:send_capsule(Sess, 16#ff01, <<>>),
    receive
        {masque_closed, Sess, peer_reset} -> ok
    after 5000 -> ct:fail(no_reset_on_crash)
    end.

%% A crash in a callback after init stops the session and resets the
%% stream; the session must not keep running on stale handler state.
h3_udp_handler_crash_resets_stream(Config) ->
    udp_handler_crash_resets_stream(Config, h3).

h2_udp_handler_crash_resets_stream(Config) ->
    udp_handler_crash_resets_stream(Config, h2).

udp_handler_crash_resets_stream(Config, Transport) ->
    Sess = connect(Config, Transport),
    Pid = await_session(),
    MRef = erlang:monitor(process, Pid),
    ok = masque:send_capsule(Sess, 16#ff01, <<>>),
    await_down(MRef, Pid),
    receive
        {masque_closed, Sess, peer_reset} -> ok
    after 5000 -> ct:fail(no_reset_on_crash)
    end.

%% The h1 udp-bind session applies the same handler and compression
%% rules as the h3/h2 one.
h1_bind_handler_crash_closes_tunnel(Config) ->
    Sess = bind_connect(Config, h1),
    ok = masque:send_capsule(Sess, 16#ff01, <<>>),
    receive
        {masque_closed, Sess, _} -> ok
    after 5000 -> ct:fail(no_close_on_crash)
    end.

h1_udp_bind_assign_by_address(Config) ->
    Sess = bind_connect(Config, h1),
    receive
        {masque_compression_assigned, Sess, _Id, {{127, 0, 0, 1}, 9}} -> ok
    after 5000 -> ct:fail(no_assign)
    end,
    ok = masque:close(Sess).

h1_udp_bind_pending_limit(Config) ->
    Sess = bind_connect(Config, h1),
    receive
        {masque_compression_assigned, Sess, _, _} = M -> ct:fail({unexpected, M})
    after 500 -> ok
    end,
    {open, _} = sys:get_state(Sess),
    ok = masque:close(Sess).

%% `upstream_pool => true' has no effect on a bind: no pooled
%% connection is checked out, on the single-transport path or in a race.
udp_bind_skips_pool(Config) ->
    Checkout = {masque_racer, checkout_pool, 2},
    _ = erlang:trace_pattern(Checkout, true, [call_count]),
    try
        Port = maps:get(port, ?config(h3, Config)),
        Proxy = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
        lists:foreach(
            fun(Ts) ->
                {ok, Sess} = masque:bind_connect(Proxy, unscoped, #{
                    transports => Ts, verify => verify_none, upstream_pool => true
                }),
                ok = masque:close(Sess)
            end,
            [[h3], [h3, h2]]
        ),
        ?assertEqual({call_count, 0}, erlang:trace_info(Checkout, call_count))
    after
        _ = erlang:trace_pattern(Checkout, false, [call_count])
    end.

%% A call a session does not support is answered with an error; the
%% session keeps running.
unsupported_call_keeps_session(Config) ->
    {EchoPid, EchoPort} = start_tcp_echo(),
    Tcp = tcp_connect(Config, h3, EchoPort),
    {error, not_supported} = masque:send(Tcp, 0, <<"x">>),
    {open, _} = sys:get_state(Tcp),
    ok = masque:close(Tcp),
    exit(EchoPid, kill),
    Port = maps:get(port, ?config(h2, Config)),
    {ok, Ip} = masque:connect(
        iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
        {'*', '*'},
        #{protocol => ip, transports => [h2], verify => verify_none}
    ),
    {error, not_supported} = masque:shutdown_write(Ip),
    {open, _} = sys:get_state(Ip),
    ok = masque:close(Ip).

%% Every server session reports `tunnel_opened' once and
%% `tunnel_closed' once, so `masque.tunnels.active' returns to where it
%% started. Counted with call-count tracing on `masque_metrics'.
h1_every_tunnel_counts_open_and_close(Config) ->
    Opened = {masque_metrics, tunnel_opened, 1},
    Closed = {masque_metrics, tunnel_closed, 2},
    _ = erlang:trace_pattern(Opened, true, [call_count]),
    _ = erlang:trace_pattern(Closed, true, [call_count]),
    try
        {call_count, O0} = erlang:trace_info(Opened, call_count),
        {call_count, C0} = erlang:trace_info(Closed, call_count),
        Kinds = [udp, tcp, ip, udp_bind],
        Tunnels = [{T, K} || T <- [h3, h2, h1], K <- Kinds],
        lists:foreach(fun({T, K}) -> open_and_close(Config, T, K) end, Tunnels),
        N = length(Tunnels),
        ok = wait_until(
            fun() ->
                {call_count, O} = erlang:trace_info(Opened, call_count),
                {call_count, C} = erlang:trace_info(Closed, call_count),
                {O - O0, C - C0} =:= {N, N}
            end,
            100
        )
    after
        _ = erlang:trace_pattern(Opened, false, [call_count]),
        _ = erlang:trace_pattern(Closed, false, [call_count])
    end.

open_and_close(Config, T, K) ->
    Port = maps:get(port, ?config(T, Config)),
    Proxy = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
    Opts = #{verify => verify_none, transports => [T]},
    {ok, Sess} =
        case K of
            udp ->
                masque:connect(Proxy, {<<"192.0.2.6">>, 443}, Opts);
            tcp ->
                {_Echo, EchoPort} = start_tcp_echo(),
                masque:connect(Proxy, {<<"127.0.0.1">>, EchoPort}, Opts#{protocol => tcp});
            ip ->
                masque:connect(Proxy, {'*', '*'}, Opts#{protocol => ip});
            udp_bind ->
                masque:bind_connect(Proxy, unscoped, Opts)
        end,
    ok = masque:close(Sess).

%% A peer reset of a stream whose session is still starting answers
%% the waiting listener at once instead of after the 30 s
%% `start_session' timeout, and leaves no session behind.
h3_reset_while_starting_answers_listener(_Config) ->
    {Router, Caller} = start_pending_session(#{init_delay => 500}),
    Pid = await_session(),
    MRef = erlang:monitor(process, Pid),
    Router ! {quic_h3, self(), {stream_reset, 0, 0}},
    await_start_result(Caller, {error, stream_dead}),
    await_down(MRef, Pid),
    ok = gen_server:stop(Router).

%% Same, once the session has started and waits for its finalize.
h3_reset_while_finalizing_answers_listener(_Config) ->
    {Router, Caller} = start_pending_session(#{}),
    Pid = await_session(),
    %% Queued ahead of the router's finalize cast: the session stays
    %% started but unfinalized until it is resumed.
    ok = sys:suspend(Pid),
    MRef = erlang:monitor(process, Pid),
    ok = wait_finalizing(Router, 50),
    Router ! {quic_h3, self(), {stream_reset, 0, 0}},
    await_start_result(Caller, {error, stream_dead}),
    ok = sys:resume(Pid),
    await_down(MRef, Pid),
    ok = gen_server:stop(Router).

start_pending_session(HOpts) ->
    {ok, Router} = masque_server_connection:start_link(0),
    unlink(Router),
    %% A dead conn pid: transport calls fail fast with noproc.
    Conn = spawn(fun() -> ok end),
    Args = #{
        conn => Conn,
        stream_id => 0,
        transport => h3,
        router => Router,
        protocol => udp,
        handler => masque_report_handler,
        handler_opts => HOpts#{report_to => self()},
        req => #{target_host => <<"192.0.2.6">>, target_port => 443}
    },
    Self = self(),
    Caller = spawn(fun() ->
        Self ! {start_result, self(), masque_server_connection:start_session(Router, Args)}
    end),
    {Router, Caller}.

await_start_result(Caller, Expected) ->
    receive
        {start_result, Caller, Result} -> ?assertEqual(Expected, Result)
    after 2000 -> ct:fail(listener_still_waiting)
    end.

wait_finalizing(_Router, 0) ->
    ct:fail(never_finalizing);
wait_finalizing(Router, N) ->
    case element(4, sys:get_state(Router)) of
        #{0 := {_, {finalizing, _, _}, _}} ->
            ok;
        _ ->
            timer:sleep(20),
            wait_finalizing(Router, N - 1)
    end.

%% Messages reaching an h3 session before the router finalizes it (and
%% a stop in that window) must not crash it.
bind_message_before_finalize(_Config) ->
    %% A dead conn pid: transport calls fail fast with noproc.
    Conn = spawn(fun() -> ok end),
    Args = #{
        conn => Conn,
        stream_id => 0,
        transport => h3,
        router => self(),
        protocol => udp_bind,
        handler => masque_udp_bind_proxy_handler,
        handler_opts => #{bind_address => {127, 0, 0, 1}},
        req => #{bind => unscoped}
    },
    {ok, Pid} = gen_server:start(masque_udp_bind_server_session, Args, []),
    MRef = erlang:monitor(process, Pid),
    Pid ! {masque_datagram_in, 0, <<0, 1, 2>>},
    Pid ! unrelated,
    gen_server:cast(Pid, ignored),
    timer:sleep(100),
    true = is_process_alive(Pid),
    ok = gen_server:stop(Pid),
    receive
        {'DOWN', MRef, process, Pid, normal} -> ok
    after 5000 -> ct:fail(no_clean_stop)
    end.

%%====================================================================
%% Request handling
%%====================================================================

h3_unknown_reject_reason_gets_response(Config) ->
    {ok, Conn} = masque_test_helpers:h3_client_connect(
        maps:get(port, ?config(h3, Config)), #{}
    ),
    {ok, Sid} = quic_h3:request(Conn, udp_headers(), #{end_stream => false}),
    {ok, 502, _} = masque_test_helpers:h3_await_response(Sid, 5000),
    quic_h3:close(Conn).

h2_unknown_reject_reason_gets_response(Config) ->
    {Conn, Sid} = h2_request_udp(Config),
    receive
        {h2, Conn, {response, Sid, 502, _}} -> ok
    after 5000 -> ct:fail(no_h2_response)
    end,
    h2:close(Conn).

%% With one tunnel allowed per connection, a session that fails to
%% start must give its slot back; the counter row goes away with the
%% connection.
h2_failed_session_releases_tunnel_slot(Config) ->
    Rows = ets:info(masque_h2_tunnel_counts, size),
    {ok, Conn} = h2_connect(Config),
    [
        begin
            {ok, Sid} = h2:request(
                Conn, udp_headers(), #{protocol => <<"connect-udp">>}
            ),
            receive
                {h2, Conn, {response, Sid, 502, _}} -> ok;
                {h2, Conn, {response, Sid, Other, _}} -> ct:fail({status, N, Other})
            after 5000 -> ct:fail({no_response, N})
            end
        end
     || N <- [1, 2, 3]
    ],
    ok = h2:close(Conn),
    ok = wait_until(fun() -> ets:info(masque_h2_tunnel_counts, size) =:= Rows end, 50).

h3_tcp_target_reset_resets_tunnel(Config) ->
    tcp_target_reset_resets_tunnel(Config, h3).

h2_tcp_target_reset_resets_tunnel(Config) ->
    tcp_target_reset_resets_tunnel(Config, h2).

tcp_target_reset_resets_tunnel(Config, Transport) ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, TPort} = inet:port(LSock),
    Target = spawn(fun() ->
        {ok, Sock} = gen_tcp:accept(LSock, 10000),
        {ok, _} = gen_tcp:recv(Sock, 0, 10000),
        ok = inet:setopts(Sock, [{linger, {true, 0}}]),
        gen_tcp:close(Sock)
    end),
    ok = gen_tcp:controlling_process(LSock, Target),
    Port = maps:get(port, ?config(Transport, Config)),
    {ok, Sess} = masque:connect(
        iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
        {<<"127.0.0.1">>, TPort},
        #{verify => verify_none, transports => [Transport], protocol => tcp}
    ),
    ok = masque:send(Sess, <<"x">>),
    receive
        {masque_closed, Sess, peer_reset} -> ok;
        {masque_closed, Sess, Other} -> ct:fail({closed_with, Other})
    after 5000 -> ct:fail(no_reset)
    end,
    gen_tcp:close(LSock).

%% The client's FIN reaches the target as a TCP FIN; the target's
%% reply still reaches the client.
h3_tcp_client_fin_half_closes(Config) ->
    tcp_client_fin_half_closes(Config, h3).

h2_tcp_client_fin_half_closes(Config) ->
    tcp_client_fin_half_closes(Config, h2).

tcp_client_fin_half_closes(Config, Transport) ->
    {LSock, TPort} = tcp_target_listen(),
    Self = self(),
    Target = spawn(fun() ->
        {ok, Sock} = gen_tcp:accept(LSock, 10000),
        Got = recv_until_closed(Sock, <<>>),
        ok = gen_tcp:send(Sock, <<"reply:", Got/binary>>),
        Self ! {target_got, Got},
        gen_tcp:close(Sock)
    end),
    ok = gen_tcp:controlling_process(LSock, Target),
    Sess = tcp_connect(Config, Transport, TPort),
    MRef = erlang:monitor(process, Sess),
    ok = masque:send(Sess, <<"request">>),
    ok = masque:shutdown_write(Sess),
    receive
        {target_got, <<"request">>} -> ok
    after 5000 -> ct:fail(target_saw_no_fin)
    end,
    <<"reply:request">> = recv_tcp(Sess, <<>>),
    receive
        {'DOWN', MRef, process, Sess, normal} -> ok
    after 5000 -> ct:fail(session_alive)
    end,
    gen_tcp:close(LSock).

%% The target's FIN reaches the client as end of data; the client can
%% still send until it half-closes too.
h3_tcp_target_fin_half_closes(Config) ->
    tcp_target_fin_half_closes(Config, h3).

h2_tcp_target_fin_half_closes(Config) ->
    tcp_target_fin_half_closes(Config, h2).

tcp_target_fin_half_closes(Config, Transport) ->
    {LSock, TPort} = tcp_target_listen(),
    Self = self(),
    Target = spawn(fun() ->
        {ok, Sock} = gen_tcp:accept(LSock, 10000),
        ok = gen_tcp:send(Sock, <<"banner">>),
        ok = gen_tcp:shutdown(Sock, write),
        Self ! {target_got, recv_until_closed(Sock, <<>>)},
        gen_tcp:close(Sock)
    end),
    ok = gen_tcp:controlling_process(LSock, Target),
    Sess = tcp_connect(Config, Transport, TPort),
    <<"banner">> = recv_tcp(Sess, <<>>),
    receive
        {masque_closed, Sess, peer_fin} -> ok
    after 5000 -> ct:fail(no_peer_fin)
    end,
    ok = masque:send(Sess, <<"late">>),
    ok = masque:send(Sess, <<" bytes">>),
    MRef = erlang:monitor(process, Sess),
    ok = masque:shutdown_write(Sess),
    receive
        {target_got, <<"late bytes">>} -> ok;
        {target_got, Other} -> ct:fail({target_got, Other})
    after 5000 -> ct:fail(target_saw_no_fin)
    end,
    receive
        {'DOWN', MRef, process, Sess, normal} -> ok
    after 5000 -> ct:fail(session_alive)
    end,
    gen_tcp:close(LSock).

%% Target bytes that reach an h3 session before the router finalizes
%% the stream (a fast target, a busy router) wait for the 2xx instead
%% of failing the tunnel.
h3_tcp_data_before_finalize_is_kept(Config) ->
    {EchoPid, EchoPort} = start_tcp_echo(),
    Sess = tcp_connect(Config, h3, EchoPort),
    <<"early">> = recv_tcp(Sess, <<>>),
    ok = masque:send(Sess, <<"then echo">>),
    <<"then echo">> = recv_tcp(Sess, <<>>),
    ok = masque:close(Sess),
    exit(EchoPid, kill).

%% A datagram the handler emits before the router finalizes the
%% stream is sent after the 2xx.
h3_udp_output_before_finalize_is_kept(Config) ->
    Sess = connect(Config, h3),
    receive
        {masque_data, Sess, <<"early">>} -> ok
    after 5000 -> ct:fail(no_early_datagram)
    end,
    ok = masque:close(Sess).

%% A ROUTE_ADVERTISEMENT and an IP packet the handler emits before
%% the router finalizes the stream reach the client, in order.
h3_ip_output_before_finalize_is_kept(Config) ->
    Port = maps:get(port, ?config(h3, Config)),
    {ok, Sess} = masque:connect(
        iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
        {'*', '*'},
        #{protocol => ip, transports => [h3], verify => verify_none}
    ),
    Route = early_route(),
    Pkt = early_ip_packet(),
    receive
        {masque_route_advertisement, Sess, [Route]} -> ok
    after 5000 -> ct:fail(no_early_routes)
    end,
    receive
        {masque_ip_packet, Sess, Pkt} -> ok
    after 5000 -> ct:fail(no_early_packet)
    end,
    ok = masque:close(Sess).

%% A COMPRESSION_ASSIGN the handler emits before the router finalizes
%% the stream reaches the client.
h3_udp_bind_output_before_finalize_is_kept(Config) ->
    Sess = bind_connect(Config, h3),
    receive
        {masque_compression_assigned, Sess, _Id, {{127, 0, 0, 1}, 9}} -> ok
    after 5000 -> ct:fail(no_early_assign)
    end,
    ok = masque:close(Sess).

early_route() ->
    #ip_route{
        version = 4,
        start_addr = {192, 0, 2, 0},
        end_addr = {192, 0, 2, 255},
        ip_protocol = 0
    }.

early_ip_packet() ->
    Udp = <<1000:16, 2000:16, 12:16, 0:16, "ping">>,
    Len = 20 + byte_size(Udp),
    Hdr0 = <<16#45, 0, Len:16, 0:16, 0:16, 64, 17, 0:16, 192, 0, 2, 1, 192, 0, 2, 2>>,
    Sum = masque_ip_packet:checksum(Hdr0),
    <<Pre:10/binary, 0:16, Post/binary>> = Hdr0,
    <<Pre/binary, Sum:16, Post/binary, Udp/binary>>.

tcp_send_capsule_not_supported(Config) ->
    {EchoPid, EchoPort} = start_tcp_echo(),
    Sess = tcp_connect(Config, h3, EchoPort),
    {error, not_supported} = masque:send_capsule(Sess, 16#ff00, <<"x">>),
    ok = masque:send(Sess, <<"still raw">>),
    <<"still raw">> = recv_tcp(Sess, <<>>),
    ok = masque:close(Sess),
    exit(EchoPid, kill).

%% A CONNECT-TCP 2xx that switches the stream to capsules is refused.
h2_tcp_rejects_capsule_protocol_response(Config) ->
    #{cert_file := CertFile, key_file := KeyFile} = ?config(certs, Config),
    Handler = fun(Conn, Sid, _Method, _Path, _Headers) ->
        h2:send_response(Conn, Sid, 200, [{<<"capsule-protocol">>, <<"?1">>}])
    end,
    {ok, {_, _, Port} = Ref} = h2:start_server(0, #{
        cert => CertFile,
        key => KeyFile,
        handler => Handler,
        enable_connect_protocol => true
    }),
    try
        {error, _} = masque:connect(
            iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
            {<<"192.0.2.6">>, 443},
            #{verify => verify_none, transports => [h2], protocol => tcp}
        )
    after
        h2:stop_server(Ref)
    end.

%%====================================================================
%% Helpers
%%====================================================================

tcp_target_listen() ->
    {ok, LSock} = gen_tcp:listen(0, [
        binary, {active, false}, {ip, {127, 0, 0, 1}}, {exit_on_close, false}
    ]),
    {ok, TPort} = inet:port(LSock),
    {LSock, TPort}.

tcp_connect(Config, Transport, TPort) ->
    Port = maps:get(port, ?config(Transport, Config)),
    {ok, Sess} = masque:connect(
        iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
        {<<"127.0.0.1">>, TPort},
        #{verify => verify_none, transports => [Transport], protocol => tcp}
    ),
    Sess.

recv_until_closed(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, Bytes} -> recv_until_closed(Sock, <<Acc/binary, Bytes/binary>>);
        {error, _} -> Acc
    end.

%% Collect tunnel bytes until none arrive for 200 ms.
recv_tcp(Sess, Acc) ->
    receive
        {masque_data, Sess, Bytes} -> recv_tcp(Sess, <<Acc/binary, Bytes/binary>>)
    after 200 ->
        case Acc of
            <<>> -> recv_tcp_wait(Sess);
            _ -> Acc
        end
    end.

recv_tcp_wait(Sess) ->
    receive
        {masque_data, Sess, Bytes} -> recv_tcp(Sess, Bytes)
    after 5000 -> ct:fail(no_tunnel_data)
    end.

h2_connect(Config) ->
    h2:connect(
        "127.0.0.1",
        maps:get(port, ?config(h2, Config)),
        #{transport => ssl, verify => verify_none, sync => true}
    ).

h2_request_udp(Config) ->
    {ok, Conn} = h2_connect(Config),
    {ok, Sid} = h2:request(Conn, udp_headers(), #{protocol => <<"connect-udp">>}),
    {Conn, Sid}.

wait_until(_Fun, 0) ->
    ct:fail(condition_not_met);
wait_until(Fun, N) ->
    case Fun() of
        true ->
            ok;
        false ->
            timer:sleep(100),
            wait_until(Fun, N - 1)
    end.

bind_connect(Config, Transport) ->
    Port = maps:get(port, ?config(Transport, Config)),
    {ok, Sess} = masque:bind_connect(
        iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
        unscoped,
        #{transports => [Transport], verify => verify_none, timeout => 5000}
    ),
    Sess.

start_h1_server(#{cert_file := CertFile, key_file := KeyFile}, Opts) ->
    Name = list_to_atom(
        "h1_lifecycle_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),
    {ok, Ref} = masque:start_listener_h1(
        Name,
        Opts#{port => 0, cert => CertFile, key => KeyFile}
    ),
    #{name => Name, port => h1:server_port(Ref)}.

start_tcp_echo() ->
    {ok, LSock} = gen_tcp:listen(0, [
        binary, {active, true}, {ip, {127, 0, 0, 1}}, {reuseaddr, true}
    ]),
    {ok, Port} = inet:port(LSock),
    Pid = spawn(fun() ->
        {ok, Sock} = gen_tcp:accept(LSock, 10000),
        tcp_echo_loop(Sock)
    end),
    ok = gen_tcp:controlling_process(LSock, Pid),
    {Pid, Port}.

tcp_echo_loop(Sock) ->
    receive
        {tcp, Sock, Data} ->
            _ = gen_tcp:send(Sock, Data),
            tcp_echo_loop(Sock);
        {tcp_closed, Sock} ->
            ok
    end.

%% Collect stream bytes until at least one byte arrived and no more
%% show up for 200 ms.
recv_stream(Tag, Conn, Sid, Acc, Timeout) ->
    receive
        {Tag, Conn, {data, Sid, Bytes, _Fin}} ->
            recv_stream(Tag, Conn, Sid, <<Acc/binary, Bytes/binary>>, 200)
    after Timeout ->
        case Acc of
            <<>> -> ct:fail(no_stream_data);
            _ -> Acc
        end
    end.

await_fin(Tag, Conn, Sid) ->
    receive
        {Tag, Conn, {data, Sid, _, true}} -> ok;
        {Tag, Conn, {data, Sid, _, false}} -> await_fin(Tag, Conn, Sid)
    after 5000 -> ct:fail(no_fin_back)
    end.

start_h2_server(#{cert_file := CertFile, key_file := KeyFile}, Opts) ->
    Name = list_to_atom(
        "h2_lifecycle_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),
    {ok, {_, _, Port} = Ref} = masque_h2_server:start_listener(
        Name,
        Opts#{port => 0, cert => CertFile, key => KeyFile}
    ),
    {ok, #{name => Name, port => Port, h2_ref => Ref}}.

connect(Config, Transport) ->
    Server = ?config(Transport, Config),
    ProxyURI = iolist_to_binary(
        ["https://127.0.0.1:", integer_to_list(maps:get(port, Server))]
    ),
    {ok, Sess} = masque:connect(
        ProxyURI,
        {<<"192.0.2.6">>, 443},
        #{verify => verify_none, transports => [Transport]}
    ),
    Sess.

h3_open_udp(Config) ->
    {ok, Conn} = masque_test_helpers:h3_client_connect(
        maps:get(port, ?config(h3, Config)), #{}
    ),
    {ok, Sid} = quic_h3:request(Conn, udp_headers(), #{end_stream => false}),
    {ok, 200, _} = masque_test_helpers:h3_await_response(Sid, 5000),
    {Conn, Sid}.

h2_open_udp(Config) ->
    {ok, Conn} = h2:connect(
        "127.0.0.1",
        maps:get(port, ?config(h2, Config)),
        #{transport => ssl, verify => verify_none, sync => true}
    ),
    {ok, Sid} = h2:request(Conn, udp_headers(), #{protocol => <<"connect-udp">>}),
    receive
        {h2, Conn, {response, Sid, 200, _}} -> ok
    after 5000 -> ct:fail(no_h2_response)
    end,
    {Conn, Sid}.

udp_headers() ->
    [
        {<<":method">>, <<"CONNECT">>},
        {<<":protocol">>, <<"connect-udp">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"localhost">>},
        {<<":path">>,
            masque_uri:expand(?TPL, #{
                target_host => <<"192.0.2.6">>, target_port => 443
            })},
        {<<"capsule-protocol">>, <<"?1">>}
    ].

await_session() ->
    receive
        {masque_session, Pid} -> Pid
    after 5000 -> ct:fail(no_server_session)
    end.

await_down(MRef, Pid) ->
    receive
        {'DOWN', MRef, process, Pid, _} -> ok
    after 5000 -> ct:fail({session_still_alive, Pid})
    end.

await_closed(Sess) ->
    receive
        {masque_closed, Sess, _Reason} -> ok
    after 5000 -> ct:fail(no_masque_closed)
    end.

session_count(Sup) ->
    proplists:get_value(active, supervisor:count_children(Sup)).

wait_count(Sup, Expected, 0) ->
    ct:fail({session_count, Sup, session_count(Sup), Expected});
wait_count(Sup, Expected, N) ->
    case session_count(Sup) of
        Expected ->
            ok;
        _ ->
            timer:sleep(100),
            wait_count(Sup, Expected, N - 1)
    end.
