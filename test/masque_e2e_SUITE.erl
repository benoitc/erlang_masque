%%% @doc End-to-end tests: real sockets through real listeners.
%%%
%%% Every case runs a real `gen_tcp' or `gen_udp' target behind a real
%%% listener and checks what reaches the far side, over h3, h2 and h1.
-module(masque_e2e_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("masque/include/masque_ip.hrl").

-export([suite/0, all/0, groups/0]).
-export([init_per_suite/1, end_per_suite/1, init_per_group/2, end_per_group/2]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    tcp_download/1,
    tcp_upload/1,
    tcp_full_duplex/1,
    tcp_full_duplex_large/1,
    tcp_stalled_target/1,
    tcp_quiet_tunnel/1,
    h3_client_vanishes/1,
    h1_udp_stalled_client/1,
    h1_classic_connect_optimistic_data/1,
    tcp_first_bytes_survive_handover/1,
    capsule_abort_resets_target/1,
    capsule_listener_without_header/1,
    capsule_h1_without_header/1,
    vec_tokens/1,
    vec_graceful_close/1,
    vec_half_close_then_data/1,
    vec_target_reset/1,
    vec_client_abort/1,
    vec_idle_timeout_aborts/1,
    vec_second_final/1,
    vec_data_after_final/1,
    vec_truncated_capsule/1,
    vec_truncated_without_final/1,
    vec_large_capsule_streams/1,
    vec_continue_before_dial/1,
    vec_rejections/1,
    vec_policy_refusal/1,
    vec_happy_eyeballs/1,
    vec_eof_timeout_aborts/1,
    vec_client_second_final/1,
    vec_client_data_after_final/1,
    vec_client_truncated_capsule/1,
    vec_connect_timeout/1,
    vec_upgrade_authorization/1,
    vec_cleartext_abort_resets/1,
    vec_trailers_abort/1,
    vec_peer_reset_resets_send/1,
    tcp_client_abort_resets_target/1,
    capsule_optimistic_data/1,
    tcp_fallback_on_426/1,
    tcp_fallback_on_501/1,
    tcp_no_fallback_on_plain_426/1,
    tcp_half_close_client/1,
    tcp_half_close_target/1,
    tcp_target_reset/1,
    tcp_client_close_reaches_target/1,
    tcp_concurrent_tunnels/1,
    tcp_stalled_client/1,
    udp_echo_sizes/1,
    udp_oversize_refused/1,
    udp_oversize_aborts/1,
    ip_full_assign_set/1,
    udp_burst/1,
    h3_udp_quiet_tunnel/1,
    bind_two_peers/1,
    bind_compressed_peer/1,
    bind_peer_filter/1,
    ip_gateway_echo/1,
    ip_two_clients/1,
    ip_ttl_kept_on_decapsulation/1,
    ip_time_exceeded/1,
    ip_packet_too_big/1,
    ip_spoofed_source_gets_icmp/1,
    chain_tcp_full_duplex/1,
    chain_tcp_upload/1,
    chain_tcp_upload_large/1,
    chain_udp_echo/1,
    chain_ip_echo/1,
    stop_listener_with_open_tunnels/1,
    owner_crash_cleans_up/1,
    goaway_keeps_open_tunnel/1,
    h3_goaway_transfer_continues/1,
    h2_goaway_tells_client/1,
    goaway_refuses_new_requests/1,
    goaway_pool_moves_on/1,
    udp_body_fields_refused/1,
    udp_capsule_protocol_parameters/1,
    udp_truncated_capsule_at_fin/1,
    udp_unknown_capsule_skipped/1,
    unknown_protocol_not_implemented/1,
    h1_duplicate_host_refused/1,
    ps_request_error/1,
    ps_policy_refusal/1,
    ps_dns_error/1,
    ps_connection_refused/1,
    ps_internal_error/1,
    ps_denied/1,
    client_capsule_parameters_accepted/1,
    client_truncated_capsule_at_fin/1,
    client_bad_udp_responses/1,
    client_bad_ip_responses/1,
    client_bad_tcp_responses/1,
    client_h1_transfer_encoding_refused/1
]).
%% Called through a fun in `handler_opts'.
-export([ip_router/2]).

-define(TRANSFER_BYTES, 16 * 1024 * 1024).
-define(LARGE_BYTES, 64 * 1024 * 1024).
-define(CHUNK_BYTES, 16 * 1024).
%% Window and socket messages a session may hold, plus some margin.
-define(MAX_MAILBOX, 2000).
%% Longer than the 30 s tunnel write timeouts, so a stall is reported
%% by the test and not by the transport.
-define(STALL_MS, 45000).
%% Past QUIC's 30 s default idle timeout.
-define(QUIET_MS, 40000).
%% A keepalive ping after 15 s restarts QUIC's 30 s idle timer once, so
%% the proxy gives up after 45 s, plus teardown.
-define(VANISH_MS, 70000).
%% Field `conn' of the h3 client session records.
-define(H3_CONN_ELEMENT, 10).
-define(LEAK_MS, 10000).
-define(IP_GATEWAY, {10, 200, 0, 254}).
%% The target reports to the running test case under this name.
-define(PROBE, masque_e2e_probe).
-define(CONCURRENT_TUNNELS, 50).
-define(HANDOVER_ROUNDS, 20).
%% TEST-NET-1 (RFC 5737): nothing answers there.
-define(BLACKHOLE, {192, 0, 2, 1}).
-define(CONCURRENT_BYTES, 256 * 1024).

suite() -> [{timetrap, {minutes, 5}}].

all() ->
    [
        {group, h3},
        {group, h2},
        {group, h1},
        {group, h3_capsule},
        {group, h2_capsule},
        {group, h1_capsule},
        {group, h3_token_12},
        {group, h2_token_12},
        {group, h1_token_12},
        {group, h3_token_08},
        {group, h2_token_08},
        {group, h1_token_08}
    ].

groups() ->
    Tcp = [
        tcp_download,
        tcp_upload,
        tcp_full_duplex,
        tcp_full_duplex_large,
        tcp_stalled_target,
        tcp_quiet_tunnel,
        tcp_target_reset,
        tcp_client_close_reaches_target,
        tcp_client_abort_resets_target,
        tcp_concurrent_tunnels,
        tcp_stalled_client,
        tcp_first_bytes_survive_handover
    ],
    HalfClose = [tcp_half_close_client, tcp_half_close_target],
    GoAway = [goaway_keeps_open_tunnel, goaway_refuses_new_requests, goaway_pool_moves_on],
    Other = [
        udp_echo_sizes,
        udp_oversize_refused,
        udp_oversize_aborts,
        ip_full_assign_set,
        udp_burst,
        bind_two_peers,
        bind_compressed_peer,
        bind_peer_filter,
        ip_gateway_echo,
        ip_two_clients,
        ip_ttl_kept_on_decapsulation,
        ip_time_exceeded,
        ip_packet_too_big,
        ip_spoofed_source_gets_icmp,
        chain_tcp_full_duplex,
        chain_tcp_upload,
        chain_tcp_upload_large,
        chain_udp_echo,
        chain_ip_echo,
        stop_listener_with_open_tunnels,
        owner_crash_cleans_up
    ],
    %% draft-ietf-httpbis-connect-tcp-18 wire vectors, on every transport.
    Vectors = [
        vec_tokens,
        vec_graceful_close,
        vec_half_close_then_data,
        vec_target_reset,
        vec_client_abort,
        vec_idle_timeout_aborts,
        vec_second_final,
        vec_data_after_final,
        vec_truncated_capsule,
        vec_truncated_without_final,
        vec_large_capsule_streams,
        vec_continue_before_dial,
        vec_rejections,
        vec_policy_refusal,
        vec_happy_eyeballs,
        vec_eof_timeout_aborts,
        vec_client_second_final,
        vec_client_data_after_final,
        vec_client_truncated_capsule,
        vec_connect_timeout
    ],
    Capsule = [
        capsule_abort_resets_target, capsule_listener_without_header, capsule_optimistic_data
    ],
    %% The CONNECT-TCP cases that matter for each token's framing.
    Core = [
        tcp_download,
        tcp_upload,
        tcp_full_duplex,
        tcp_target_reset,
        tcp_client_close_reaches_target
        | HalfClose
    ],
    Fallback = [tcp_fallback_on_426, tcp_fallback_on_501, tcp_no_fallback_on_plain_426],
    %% RFC 9297, RFC 9298, RFC 9209 and RFC 9110 wire vectors: listener
    %% checks, Proxy-Status types, and clients against a scripted proxy.
    Framing = [
        udp_body_fields_refused,
        udp_capsule_protocol_parameters,
        udp_truncated_capsule_at_fin,
        ps_request_error,
        ps_policy_refusal,
        ps_dns_error,
        ps_connection_refused,
        ps_internal_error,
        ps_denied,
        client_capsule_parameters_accepted,
        client_truncated_capsule_at_fin
    ],
    ExtendedConnect = [
        unknown_protocol_not_implemented,
        client_bad_udp_responses,
        client_bad_ip_responses,
        client_bad_tcp_responses
    ],
    [
        {h3, [],
            Tcp ++ HalfClose ++ Other ++ Framing ++ ExtendedConnect ++
                [
                    h3_client_vanishes,
                    h3_udp_quiet_tunnel,
                    h3_goaway_transfer_continues
                    | GoAway
                ]},
        {h2, [],
            Tcp ++ HalfClose ++ Other ++ Framing ++ ExtendedConnect ++
                [udp_unknown_capsule_skipped, h2_goaway_tells_client | GoAway]},
        {h1, [],
            Tcp ++ Other ++ Framing ++
                [
                    udp_unknown_capsule_skipped,
                    h1_duplicate_host_refused,
                    client_h1_transfer_encoding_refused,
                    h1_udp_stalled_client,
                    h1_classic_connect_optimistic_data
                    | Fallback
                ]},
        %% CONNECT-TCP in capsules (draft-ietf-httpbis-connect-tcp-18),
        %% with the client's default token, `connect-tcp'.
        {h3_capsule, [], Tcp ++ HalfClose ++ Capsule ++ Vectors ++ [vec_peer_reset_resets_send]},
        {h2_capsule, [], Tcp ++ HalfClose ++ Capsule ++ Vectors ++ [vec_trailers_abort]},
        %% Capsules carry FIN, so h1 can half-close in this mode.
        {h1_capsule, [],
            Tcp ++ HalfClose ++
                [capsule_h1_without_header | Vectors] ++
                [vec_upgrade_authorization, vec_cleartext_abort_resets]},
        %% The client on the draft's interop token, and on draft -09's
        %% token and provisional codes.
        {h3_token_12, [], Core},
        {h2_token_12, [], Core},
        {h1_token_12, [], Core},
        {h3_token_08, [], Core},
        {h2_token_08, [], Core},
        {h1_token_08, [], Core}
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Certs} = masque_test_helpers:generate_certs(),
    {ok, Listen} = gen_tcp:listen(0, [
        binary,
        {active, false},
        {ip, {127, 0, 0, 1}},
        {reuseaddr, true},
        {backlog, 128},
        {exit_on_close, false},
        %% So the target can tell a reset from a clean close.
        {show_econnreset, true}
    ]),
    {ok, TargetPort} = inet:port(Listen),
    Target = spawn(fun() -> target_accept(Listen) end),
    ok = gen_tcp:controlling_process(Listen, Target),
    {UdpEcho, UdpPort} = start_udp_echo(),
    [
        {certs, Certs},
        {target_port, TargetPort},
        {target, Target},
        {udp_echo, UdpEcho},
        {udp_port, UdpPort}
        | Config
    ].

end_per_suite(Config) ->
    exit(?config(target, Config), kill),
    exit(?config(udp_echo, Config), kill),
    masque_test_helpers:cleanup_certs(?config(certs, Config)),
    ok.

init_per_group(Group, Config) ->
    case atom_to_list(Group) of
        "h3_capsule" -> [{transport, h3}, {tcp_framing, capsule} | Config];
        "h2_capsule" -> [{transport, h2}, {tcp_framing, capsule} | Config];
        "h1_capsule" -> [{transport, h1}, {tcp_framing, capsule} | Config];
        [$h, N | "_token_12"] -> token_group([$h, N], <<"connect-tcp-12">>, Config);
        [$h, N | "_token_08"] -> token_group([$h, N], <<"connect-tcp-08">>, Config);
        _ -> [{transport, Group} | Config]
    end.

token_group(Transport, Token, Config) ->
    [
        {transport, list_to_existing_atom(Transport)},
        {tcp_framing, capsule},
        {tcp_protocol, Token}
        | Config
    ].

end_per_group(_Transport, _Config) ->
    ok.

%% Listeners link to the process that starts them, and a group's init
%% process exits at once, so each case starts its own.
init_per_testcase(Case, Config) ->
    true = register(?PROBE, self()),
    Transport = ?config(transport, Config),
    Certs = ?config(certs, Config),
    Server = start_server(Transport, Certs, case_opts(Case, Transport)),
    [{server, Server} | Config].

%% Clients run against a listener whose templates match nothing, so its
%% `fallback' answers every request with the response the case scripts.
case_opts(Case, Transport) ->
    case atom_to_list(Case) of
        "client_" ++ _ ->
            #{
                uri_template => <<"/fake/udp/{target_host}/{target_port}/">>,
                tcp_uri_template => <<"/fake/tcp/{target_host}/{target_port}/">>,
                ip_uri_template => <<"/fake/ip/{target}/{ipproto}/">>,
                fallback => fun(Conn, Sid, _Method, _Path, _Headers) ->
                    fake_reply(Transport, Conn, Sid)
                end
            };
        _ ->
            case_opts(Case)
    end.

case_opts(capsule_listener_without_header) ->
    #{tcp_framing => capsule};
case_opts(vec_policy_refusal) ->
    #{handler_opts => #{allow_private => false}};
case_opts(vec_idle_timeout_aborts) ->
    #{handler_opts => #{allow_private => true, allow_self => true, idle_timeout_ms => 1000}};
case_opts(vec_continue_before_dial) ->
    Slow = fun(_Host) ->
        timer:sleep(1500),
        {ok, {127, 0, 0, 1}}
    end,
    #{handler_opts => #{allow_private => true, allow_self => true, resolver => Slow}};
case_opts(vec_trailers_abort) ->
    case_opts(vec_continue_before_dial);
case_opts(vec_connect_timeout) ->
    #{
        handler_opts => #{
            allow_private => true,
            allow_self => true,
            connect_timeout => 500,
            resolver => fun(_Host) -> {ok, ?BLACKHOLE} end
        }
    };
case_opts(vec_upgrade_authorization) ->
    #{
        authenticate => fun(#{headers := Headers}) ->
            probe({auth_headers, Headers}),
            ok
        end
    };
case_opts(ip_full_assign_set) ->
    Pools = [{4, {10, 200, 0, 0}, 24}, {6, {16#fd00, 0, 0, 0, 0, 0, 0, 0}, 64}],
    #{handler_opts => (default_handler_opts())#{address_pool => Pools}};
case_opts(ps_policy_refusal) ->
    #{handler_opts => #{allow_private => false}};
case_opts(ps_dns_error) ->
    #{resolver => fun(_Host) -> {error, nxdomain} end};
case_opts(ps_internal_error) ->
    #{handler => masque_stop_init_handler};
case_opts(ps_denied) ->
    #{authenticate => fun(_Req) -> false end};
case_opts(ip_time_exceeded) ->
    #{handler_opts => (default_handler_opts())#{ttl_decrement => decapsulation}};
case_opts(ip_packet_too_big) ->
    #{handler_opts => (default_handler_opts())#{mtu => 576}};
case_opts(bind_peer_filter) ->
    #{accept_bind => true, handler_opts => #{bind_address => {127, 0, 0, 1}}};
case_opts(_) ->
    #{}.

%% Every case must leave no session behind, whatever else it checks.
end_per_testcase(_Case, Config) ->
    try
        unregister(?PROBE)
    catch
        error:badarg -> ok
    end,
    %% A case that already failed keeps its own reason: a session left
    %% behind by a crashed case is a symptom, not the cause.
    Left =
        case ?config(tc_status, Config) of
            ok -> wait_no_server_sessions(?LEAK_MS);
            _ -> []
        end,
    Detail = [{session_module(P), sys:get_state(P)} || P <- Left],
    stop_server(?config(transport, Config), ?config(server, Config)),
    case Left of
        [] -> ok;
        _ -> {fail, {sessions_left_behind, Detail}}
    end.

wait_no_server_sessions(Left) when Left =< 0 ->
    server_sessions();
wait_no_server_sessions(Left) ->
    case server_sessions() of
        [] ->
            [];
        _ ->
            timer:sleep(200),
            wait_no_server_sessions(Left - 200)
    end.

%%====================================================================
%% CONNECT-TCP
%%====================================================================

tcp_download(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"down">>),
    Got = recv_bytes(Sess, ?TRANSFER_BYTES),
    ?assertEqual(sha(payload()), sha(Got)),
    close(Sess).

tcp_upload(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"sink">>),
    ok = send_all(Sess, payload()),
    Sum = sha(payload()),
    ?assertEqual(Sum, recv_bytes(Sess, byte_size(Sum))),
    close(Sess).

%% The target sends everything back on one thread while the client is
%% still sending, as an echo service or a busy bidirectional protocol
%% does. Neither direction may wait for the other to finish.
tcp_full_duplex(Config) ->
    full_duplex(Config, payload()).

tcp_full_duplex_large(Config) ->
    full_duplex(Config, binary:copy(<<"0123456789abcdef">>, ?LARGE_BYTES div 16)).

full_duplex(Config, Payload) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"echo">>),
    {Sender, MRef} = spawn_monitor(fun() -> exit({sent, send_all(Sess, Payload)}) end),
    Got = recv_bytes(Sess, byte_size(Payload)),
    receive
        {'DOWN', MRef, process, Sender, {sent, ok}} -> ok;
        {'DOWN', MRef, process, Sender, Other} -> ct:fail({sender, Other})
    after ?STALL_MS -> ct:fail(sender_stuck)
    end,
    ?assertEqual(sha(Payload), sha(Got)),
    close(Sess).

%% A target that stops reading ends the tunnel within the write timeout
%% and the proxy holds a bounded amount in the meantime.
tcp_stalled_target(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"stal">>),
    {Sender, MRef} = spawn_monitor(fun() ->
        try send_all(Sess, binary:copy(payload(), 8)) of
            R -> exit(R)
        catch
            exit:R -> exit(R)
        end
    end),
    timer:sleep(5000),
    Peak = max_session_mailbox(),
    ?assert(Peak < ?MAX_MAILBOX),
    receive
        {masque_closed, Sess, _Reason} -> ok
    after ?STALL_MS -> ct:fail({tunnel_not_ended, tunnel_stacks()})
    end,
    exit(Sender, kill),
    receive
        {'DOWN', MRef, process, Sender, _} -> ok
    end,
    close(Sess).

%% A tunnel with no traffic stays open until the 300 s session idle
%% timeout, so a quiet SSH or database connection is not cut.
tcp_quiet_tunnel(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"echo">>),
    ok = masque:send(Sess, <<"before">>),
    <<"before">> = recv_bytes(Sess, 6),
    receive
        {masque_closed, Sess, Reason} -> ct:fail({closed_while_quiet, Reason})
    after ?QUIET_MS -> ok
    end,
    ok = masque:send(Sess, <<"after">>),
    <<"after">> = recv_bytes(Sess, 5),
    close(Sess).

%% Keepalive must not hide a client that disappears without a word:
%% no CONNECTION_CLOSE reaches the proxy, and its pings go unanswered.
h3_client_vanishes(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"echo">>),
    ok = masque:send(Sess, <<"x">>),
    <<"x">> = recv_bytes(Sess, 1),
    {_, Data} = sys:get_state(Sess),
    QConn = quic_h3:get_quic_conn(element(?H3_CONN_ELEMENT, Data)),
    ?assertMatch([_ | _], server_sessions()),
    exit(Sess, kill),
    exit(QConn, kill),
    await_no_server_sessions(?VANISH_MS).

await_no_server_sessions(Left) when Left =< 0 ->
    ct:fail({server_session_left_behind, server_sessions()});
await_no_server_sessions(Left) ->
    case server_sessions() of
        [] ->
            ok;
        _ ->
            timer:sleep(500),
            await_no_server_sessions(Left - 500)
    end.

server_sessions() ->
    [
        P
     || P <- processes(),
        Mod <- session_module(P),
        lists:suffix("server_session", atom_to_list(Mod))
    ].

%% FIN from the client leaves the path back open.
tcp_half_close_client(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"gath">>),
    ok = send_all(Sess, payload()),
    ok = masque:shutdown_write(Sess),
    Sum = sha(payload()),
    ?assertEqual(Sum, recv_bytes(Sess, byte_size(Sum))),
    close(Sess).

%% FIN from the target leaves the client's path open.
tcp_half_close_target(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"fin1">>),
    <<"bye">> = recv_bytes(Sess, 3),
    receive
        {masque_closed, Sess, peer_fin} -> ok
    after 5000 -> ct:fail(no_peer_fin)
    end,
    ok = masque:send(Sess, <<"late">>),
    receive
        {target, got, <<"late">>} -> ok
    after 5000 -> ct:fail(late_bytes_lost)
    end,
    close(Sess).

%% A target reset is not reported as a clean end.
tcp_target_reset(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"rset">>),
    <<"x">> = recv_bytes(Sess, 1),
    %% Raw h1 cannot tell a reset from a close; capsule mode can, since a
    %% clean end sends FINAL_DATA first.
    Expected =
        case {?config(transport, Config), proplists:get_value(tcp_framing, Config, raw)} of
            {h1, raw} -> peer_closed;
            _ -> peer_reset
        end,
    receive
        {masque_closed, Sess, Reason} -> ?assertEqual(Expected, Reason)
    after 5000 -> ct:fail(no_close_after_reset)
    end.

%% Section 3.5: a graceful close reaches the target as a FIN, on every
%% transport and framing (on h1 in capsule framing as FINAL_DATA).
tcp_client_close_reaches_target(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"wclo">>),
    <<"x">> = recv_bytes(Sess, 1),
    close(Sess),
    receive
        {target, closed, Reason} -> ?assertEqual(closed, Reason)
    after 5000 -> ct:fail(target_not_told)
    end,
    await_no_server_sessions(5000).

%% Section 3.5: `masque:abort/1' reaches the target as a reset. Raw h1
%% has no way to say so: the proxy sees the connection close.
tcp_client_abort_resets_target(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"wclo">>),
    <<"x">> = recv_bytes(Sess, 1),
    ok = masque:abort(Sess),
    receive
        {target, closed, Reason} -> ?assertEqual(abort_seen_at_target(Config), Reason)
    after 5000 -> ct:fail(target_not_told)
    end,
    ?assertNot(is_process_alive(Sess)),
    ok = masque:abort(Sess),
    await_no_server_sessions(5000).

abort_seen_at_target(Config) ->
    case {?config(transport, Config), proplists:get_value(tcp_framing, Config, raw)} of
        {h1, raw} -> closed;
        _ -> econnreset
    end.

%% Bytes sent the moment the tunnel opens must reach the target, under
%% enough load to expose a race in handing the socket to the session.
tcp_first_bytes_survive_handover(Config) ->
    Parent = self(),
    Pids = [
        spawn_link(fun() ->
            [first_bytes_round(Config) || _ <- lists:seq(1, ?HANDOVER_ROUNDS)],
            Parent ! {done, self()}
        end)
     || _ <- lists:seq(1, ?CONCURRENT_TUNNELS)
    ],
    lists:foreach(
        fun(Pid) ->
            receive
                {done, Pid} -> ok
            after ?STALL_MS -> ct:fail(handover_stuck)
            end
        end,
        Pids
    ).

first_bytes_round(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"echo">>),
    ok = masque:send(Sess, <<"z">>),
    <<"z">> = recv_bytes(Sess, 1),
    close(Sess).

%% A client whose stream ends without FINAL_DATA aborted the tunnel, so
%% the target gets a reset rather than a clean close
%% (draft-ietf-httpbis-connect-tcp-18 section 3.5).
capsule_abort_resets_target(Config) ->
    Headers = tcp_request(Config) ++ [{<<"capsule-protocol">>, <<"?1">>}],
    Data = masque_tcp_capsule:encode(final, <<"wclo">>, false),
    Stream =
        case ?config(transport, Config) of
            h3 ->
                Conn = raw_h3_connect(Config),
                {ok, Sid} = quic_h3:request(Conn, Headers, #{end_stream => false}),
                receive
                    {quic_h3, Conn, {response, Sid, 200, _}} -> ok
                after 5000 -> ct:fail(no_response)
                end,
                ok = quic_h3:send_data(Conn, Sid, Data, false),
                timer:sleep(300),
                ok = quic_h3:send_data(Conn, Sid, <<>>, true),
                {h3, Conn};
            h2 ->
                Conn = raw_h2_connect(Config),
                {ok, Sid} = h2:request(Conn, Headers, #{protocol => <<"connect-tcp">>}),
                receive
                    {h2, Conn, {response, Sid, 200, _}} -> ok
                after 5000 -> ct:fail(no_response)
                end,
                ok = h2:send_data(Conn, Sid, Data, false),
                timer:sleep(300),
                ok = h2:send_data(Conn, Sid, <<>>, true),
                {h2, Conn}
        end,
    receive
        {target, closed, Reason} -> ?assertEqual(econnreset, Reason)
    after 5000 -> ct:fail(target_not_told)
    end,
    case Stream of
        {h3, C} -> quic_h3:close(C);
        {h2, C} -> h2:close(C)
    end.

%% A client of the plain `connect-tcp' token may leave
%% `capsule-protocol' out (section 3.3 makes it a SHOULD). A listener set to
%% `tcp_framing => capsule' still frames its tunnel in capsules.
capsule_listener_without_header(Config) ->
    Headers = tcp_request(Config),
    Echo = masque_tcp_capsule:encode(final, <<"echo">>, false),
    Ping = masque_tcp_capsule:encode(final, <<"ping">>, false),
    case ?config(transport, Config) of
        h3 ->
            Conn = raw_h3_connect(Config),
            {ok, Sid} = quic_h3:request(Conn, Headers, #{end_stream => false}),
            receive
                {quic_h3, Conn, {response, Sid, 200, _}} -> ok
            after 5000 -> ct:fail(no_response)
            end,
            ok = quic_h3:send_data(Conn, Sid, <<Echo/binary, Ping/binary>>, false),
            ?assertEqual(Ping, raw_recv(quic_h3, Conn, Sid, byte_size(Ping), <<>>)),
            quic_h3:close(Conn);
        h2 ->
            Conn = raw_h2_connect(Config),
            {ok, Sid} = h2:request(Conn, Headers, #{protocol => <<"connect-tcp">>}),
            receive
                {h2, Conn, {response, Sid, 200, _}} -> ok
            after 5000 -> ct:fail(no_response)
            end,
            ok = h2:send_data(Conn, Sid, <<Echo/binary, Ping/binary>>, false),
            ?assertEqual(Ping, raw_recv(h2, Conn, Sid, byte_size(Ping), <<>>)),
            h2:close(Conn)
    end.

%% On h1 the upgrade token says CONNECT-TCP, so `Capsule-Protocol' may be
%% left out of the request (section 3.2 makes it a SHOULD).
capsule_h1_without_header(Config) ->
    W = wire_open(Config, <<"connect-tcp">>, []),
    ok = wire_send(W, [
        masque_tcp_capsule:encode(final, <<"echo">>, false),
        masque_tcp_capsule:encode(final, <<"ping">>, false)
    ]),
    ?assertEqual(<<"ping">>, wire_payload(W, final, 4)),
    wire_close(W).

%% Bytes sent before the 2xx (section 4.1) reach the target once it is
%% connected, and are dropped with the request when the target refuses.
capsule_optimistic_data(Config) ->
    Echo = masque_tcp_capsule:encode(final, <<"echo">>, false),
    Ping = masque_tcp_capsule:encode(final, <<"ping">>, false),
    Token = <<"connect-tcp-12">>,
    {Tag, Conn, Sid} = raw_request(Config, tcp_request(Config, Token), Token),
    ok = raw_send(Tag, Conn, Sid, <<Echo/binary, Ping/binary>>),
    {100, _} = raw_response(Tag, Conn, Sid),
    {200, _} = raw_response(Tag, Conn, Sid),
    ?assertEqual(Ping, raw_recv(Tag, Conn, Sid, byte_size(Ping), <<>>)),
    {ok, Closed} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}]),
    {ok, ClosedPort} = inet:port(Closed),
    ok = gen_tcp:close(Closed),
    Refused = tcp_request(Config, Token, ClosedPort),
    {Tag, Conn, Sid2} = raw_request(Config, Conn, Refused, Token),
    ok = raw_send(Tag, Conn, Sid2, Ping),
    {100, _} = raw_response(Tag, Conn, Sid2),
    {Status, _} = raw_response(Tag, Conn, Sid2),
    ?assert(Status >= 400),
    raw_close(Tag, Conn).

%%--------------------------------------------------------------------
%% draft-ietf-httpbis-connect-tcp-18 wire vectors
%%
%% These cases drive the listener with hand-built requests and capsules
%% on all three transports, so every byte on the wire is the test's.
%%--------------------------------------------------------------------

%% Every token a client may use (sections 3.2, 3.3, 8.1.1, and the -09
%% and -10 tokens with their provisional codes): the listener confirms
%% with 100 (section 4.3), then answers 2xx or 101 with
%% `capsule-protocol' and `Proxy-Status', and frames the tunnel with
%% that token's codes. Unknown capsules in between are skipped.
vec_tokens(Config) ->
    lists:foreach(
        fun({Token, Version, Extra}) ->
            ct:log("token ~s", [Token]),
            W = wire_open(Config, Token, Extra),
            Other = iolist_to_binary(masque_capsule:encode(16#ff37a0, <<"skip me">>)),
            ok = wire_send(W, [
                masque_tcp_capsule:encode(Version, <<"echo">>, false),
                Other,
                masque_tcp_capsule:encode(Version, <<"ping">>, false)
            ]),
            ?assertEqual(<<"ping">>, wire_payload(W, Version, 4)),
            wire_close(W)
        end,
        [
            {<<"connect-tcp-12">>, final, []},
            {<<"connect-tcp">>, final, [{<<"capsule-protocol">>, <<"?1">>}]},
            {<<"connect-tcp-08">>, provisional, []},
            {<<"connect-tcp-07">>, provisional, []}
        ]
    ).

%% Figure 6: DATA{"abc"}, FINAL_DATA{""} reach the target as bytes and
%% a FIN; the target's answer and FIN come back as capsules ending in
%% FINAL_DATA, and the stream ends cleanly.
vec_graceful_close(Config) ->
    W = wire_open(Config, <<"connect-tcp-12">>, []),
    ok = wire_send(W, [
        masque_tcp_capsule:encode(final, <<"grac">>, false),
        masque_tcp_capsule:encode(final, <<"abc">>, false),
        masque_tcp_capsule:encode(final, <<>>, true)
    ]),
    receive
        {target, got_all, Got} -> ?assertEqual(<<"abc">>, Got)
    after 5000 -> ct:fail(target_no_fin)
    end,
    ?assertEqual({<<"xyz">>, final, clean}, wire_drain(W, final)),
    wire_close(W).

%% Figure 9, first half: the target answers after the client's FIN, and
%% its last bytes and FIN arrive while the client side is closed.
vec_half_close_then_data(Config) ->
    W = wire_open(Config, <<"connect-tcp-12">>, []),
    ok = wire_send(W, [
        masque_tcp_capsule:encode(final, <<"fin1">>, false)
    ]),
    %% The target sent "bye" and its FIN; ours is still open.
    {Bye, final, _} = wire_drain_until_final(W, final),
    ?assertEqual(<<"bye">>, Bye),
    ok = wire_send(W, masque_tcp_capsule:encode(final, <<"late">>, true)),
    receive
        {target, got, Late} -> ?assertEqual(<<"late">>, Late)
    after 5000 -> ct:fail(late_bytes_lost)
    end,
    wire_close(W).

%% Figure 7: a target RST aborts the stream (H3_CONNECT_ERROR,
%% CONNECT_ERROR, or on h1 a close without FINAL_DATA).
vec_target_reset(Config) ->
    W = wire_open(Config, <<"connect-tcp-12">>, []),
    ok = wire_send(W, masque_tcp_capsule:encode(final, <<"rset">>, false)),
    ?assertMatch({<<"x">>, _, aborted}, wire_drain(W, final)),
    wire_close(W).

%% Figure 7 the other way: the client aborts, the target gets an RST.
vec_client_abort(Config) ->
    W = wire_open(Config, <<"connect-tcp-12">>, []),
    ok = wire_send(W, masque_tcp_capsule:encode(final, <<"wclo">>, false)),
    timer:sleep(200),
    ok = wire_abort(W),
    expect_target_reset().

%% Figure 8 and section 3.5: a local timeout is an abrupt close. The
%% listener's idle timeout resets the stream and the target.
vec_idle_timeout_aborts(Config) ->
    W = wire_open(Config, <<"connect-tcp-12">>, []),
    ok = wire_send(W, masque_tcp_capsule:encode(final, <<"wclo">>, false)),
    expect_target_reset(),
    ?assertMatch({<<"x">>, _, aborted}, wire_drain(W, final)),
    wire_close(W).

%% Section 3.5.1: invalid data is an abrupt close. Each vector follows
%% a FINAL_DATA, so a target still writing sees its connection reset.
vec_second_final(Config) ->
    invalid_after_final(Config, masque_tcp_capsule:encode(final, <<>>, true), end_stream).

vec_data_after_final(Config) ->
    invalid_after_final(Config, masque_tcp_capsule:encode(final, <<"x">>, false), end_stream).

%% A capsule cut by the end of the stream, after FINAL_DATA.
vec_truncated_capsule(Config) ->
    invalid_after_final(Config, <<16#3f, 10, "abc">>, end_stream).

%% A capsule cut by the end of the stream, without FINAL_DATA: an abort.
vec_truncated_without_final(Config) ->
    W = wire_open(Config, <<"connect-tcp-12">>, []),
    ok = wire_send(W, [masque_tcp_capsule:encode(final, <<"wclo">>, false), <<16#08, 5, "ab">>]),
    timer:sleep(200),
    ok = wire_end(W),
    expect_target_reset(),
    wire_close(W).

invalid_after_final(Config, Bad, end_stream) ->
    W = wire_open(Config, <<"connect-tcp-12">>, []),
    ok = wire_send(W, [
        masque_tcp_capsule:encode(final, <<"fins">>, false),
        masque_tcp_capsule:encode(final, <<>>, true)
    ]),
    receive
        {target, fin} -> ok
    after 5000 -> ct:fail(target_no_fin)
    end,
    ok = wire_send(W, Bad),
    ok = wire_end(W),
    receive
        {target, after_fin, Result} -> ?assertMatch({error, _}, Result)
    after 5000 -> ct:fail(target_not_reset)
    end,
    wire_close(W).

%% Section 3.1: payload is forwarded before its capsule ends. One DATA
%% capsule of 1 MiB: the target echoes its first bytes while the rest
%% has not been sent.
vec_large_capsule_streams(Config) ->
    Len = 1024 * 1024,
    W = wire_open(Config, <<"connect-tcp-12">>, []),
    First = binary:copy(<<"a">>, 1000),
    ok = wire_send(W, [<<16#08, 2#10:2, Len:30>>, <<"echo">>, First]),
    ?assertEqual(First, wire_payload(W, final, 1000)),
    Rest = binary:copy(<<"b">>, Len - 1004),
    ok = wire_send(W, Rest),
    ?assertEqual(Rest, wire_payload(W, final, byte_size(Rest))),
    wire_close(W).

%% Section 4.3: the 100 comes before the target is dialed. The resolver
%% takes 1.5 s; the 100 must not wait for it.
vec_continue_before_dial(Config) ->
    T0 = erlang:monotonic_time(millisecond),
    W = wire_open(Config, <<"connect-tcp-12">>, [], fun(Status) ->
        Elapsed = erlang:monotonic_time(millisecond) - T0,
        ct:log("status ~p after ~p ms", [Status, Elapsed]),
        case Status of
            100 -> ?assert(Elapsed < 1000);
            _ -> ?assert(Elapsed >= 1400)
        end
    end),
    ok = wire_send(W, masque_tcp_capsule:encode(final, <<"echo">>, false)),
    wire_close(W).

%% Section 4.2 and 4.3: a refused request gets a 4xx or 5xx with
%% `Proxy-Status' and no tunnel; on h1 the response is not cacheable
%% (section 3.4.3). A target that refuses the connection is a 5xx,
%% after the 100.
vec_rejections(Config) ->
    {ok, Closed} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}]),
    {ok, ClosedPort} = inet:port(Closed),
    ok = gen_tcp:close(Closed),
    {Statuses, Hdrs} = wire_reject(Config, <<"connect-tcp-12">>, ClosedPort),
    ?assertEqual(100, hd(Statuses)),
    Final = lists:last(Statuses),
    ?assert(Final >= 500 andalso Final < 600),
    ?assertMatch(<<"masque; error=", _/binary>>, proplists:get_value(<<"proxy-status">>, Hdrs)),
    {Statuses2, Hdrs2} = wire_reject(Config, <<"connect-tcp-12">>, 0),
    ?assert(lists:last(Statuses2) >= 400 andalso lists:last(Statuses2) < 500),
    ?assertNotEqual(undefined, proplists:get_value(<<"proxy-status">>, Hdrs2)),
    case ?config(transport, Config) of
        h1 ->
            ?assertEqual(<<"no-store">>, proplists:get_value(<<"cache-control">>, Hdrs)),
            ?assertEqual(<<"no-store">>, proplists:get_value(<<"cache-control">>, Hdrs2));
        _ ->
            ok
    end.

%% Section 4.2: a target the proxy's policy refuses (here a private
%% address) is a 403, not a failed connection.
vec_policy_refusal(Config) ->
    {Statuses, Hdrs} = wire_reject(Config, <<"connect-tcp-12">>, ?config(target_port, Config)),
    ?assertEqual([100, 403], Statuses),
    ?assertEqual(
        <<"masque; error=destination_ip_prohibited">>,
        proplists:get_value(<<"proxy-status">>, Hdrs)
    ).

%% Section 4.1: a target name with addresses in both families is raced.
%% `localhost' gives `::1' first, where nothing listens, then
%% `127.0.0.1', where the target is.
vec_happy_eyeballs(Config) ->
    Sess = connect(Config, {<<"localhost">>, ?config(target_port, Config)}, #{protocol => tcp}),
    ok = masque:send(Sess, <<"echo">>),
    ok = masque:send(Sess, <<"z">>),
    <<"z">> = recv_bytes(Sess, 1),
    close(Sess).

%% Section 3.5: the handler's `eof_timeout' (30 s on a half-closed,
%% quiet tunnel) is a local timeout, so it aborts: the stream is reset
%% (on h1 the connection ends without FINAL_DATA) and so is the target.
vec_eof_timeout_aborts(Config) ->
    W = wire_open(Config, <<"connect-tcp-12">>, []),
    ok = wire_send(W, [
        masque_tcp_capsule:encode(final, <<"eoft">>, false),
        masque_tcp_capsule:encode(final, <<>>, true)
    ]),
    Target =
        receive
            {target, fin, T} -> T
        after 5000 -> ct:fail(target_no_fin)
        end,
    timer:sleep(31000),
    ?assertEqual({<<>>, no_final, aborted}, wire_drain(W, final)),
    Target ! write,
    receive
        {target, after_eof, Result} -> ?assertMatch({error, _}, Result)
    after 5000 -> ct:fail(target_not_reset)
    end,
    wire_close(W).

%% Section 3.5.1 the other way: invalid data from the proxy aborts the
%% client's tunnel. The owner hears `{bad_capsule, _}' and the proxy
%% sees the stream reset (on h1, the connection end without FINAL_DATA).
vec_client_second_final(Config) ->
    invalid_to_client(Config, masque_tcp_capsule:encode(final, <<>>, true), false).

vec_client_data_after_final(Config) ->
    invalid_to_client(Config, masque_tcp_capsule:encode(final, <<"b">>, false), false).

%% A capsule of another type (skipped after FINAL_DATA) cut by the end
%% of the stream.
vec_client_truncated_capsule(Config) ->
    invalid_to_client(Config, <<16#3f, 10, "abc">>, true).

invalid_to_client(Config, Bad, EndStream) ->
    T = ?config(transport, Config),
    Bytes = iolist_to_binary([
        masque_tcp_capsule:encode(final, <<"a">>, false),
        masque_tcp_capsule:encode(final, <<>>, true),
        Bad
    ]),
    {Port, Stop} = start_fake_tcp_proxy(T, ?config(certs, Config), Bytes, EndStream),
    try
        Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
        {ok, Sess} = masque:connect(Uri, {<<"127.0.0.1">>, 9}, #{
            protocol => tcp,
            tcp_framing => capsule,
            transports => [T],
            verify => verify_none,
            timeout => 5000
        }),
        %% The payload before the invalid bytes, and the half-close of
        %% the FINAL_DATA, may be delivered or not, depending on how the
        %% transport cuts the stream.
        ?assertMatch({bad_capsule, _}, client_end(Sess)),
        receive
            {fake_tcp_proxy, Ending} -> ?assertEqual(fake_abort(T), Ending)
        after 5000 -> ct:fail(proxy_not_told)
        end
    after
        Stop()
    end.

client_end(Sess) ->
    receive
        {masque_closed, Sess, peer_fin} -> client_end(Sess);
        {masque_closed, Sess, Reason} -> Reason
    after 5000 -> ct:fail(client_not_aborted)
    end.

fake_abort(h3) -> {reset, 16#10f};
fake_abort(h2) -> {reset, connect_error};
fake_abort(h1) -> {closed, no_final}.

%% Section 4.2: a target that does not answer within the handler's
%% `connect_timeout' gets 504 in capsule framing. The listener resolves
%% every name to TEST-NET-1, which drops the SYN where there is a
%% default route; without one the case is skipped.
vec_connect_timeout(Config) ->
    case gen_tcp:connect(?BLACKHOLE, 443, [], 300) of
        {error, timeout} ->
            {Statuses, _Hdrs} = wire_reject(Config, <<"connect-tcp-12">>, 443),
            ?assertEqual([100, 504], Statuses);
        Other ->
            _ =
                case Other of
                    {ok, S} -> gen_tcp:close(S);
                    _ -> ok
                end,
            {skip, {no_blackhole, Other}}
    end.

%% Section 3.4.2: the upgrade is an ordinary request to the proxy, so
%% the credential is sent as `Authorization', never `Proxy-Authorization'.
vec_upgrade_authorization(Config) ->
    #{port := Port} = ?config(server, Config),
    Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
    {ok, Sess} = masque:connect(Uri, {<<"127.0.0.1">>, ?config(target_port, Config)}, #{
        protocol => tcp,
        tcp_framing => capsule,
        transports => [h1],
        verify => verify_none,
        timeout => 5000,
        proxy_authorization => <<"Bearer secret">>
    }),
    Headers =
        receive
            {auth_headers, H} -> [{string:lowercase(K), V} || {K, V} <- H]
        after 5000 -> ct:fail(not_authenticated)
        end,
    ?assertEqual(<<"Bearer secret">>, proplists:get_value(<<"authorization">>, Headers)),
    ?assertEqual(undefined, proplists:get_value(<<"proxy-authorization">>, Headers)),
    ok = masque:send(Sess, <<"echo">>),
    ok = masque:send(Sess, <<"z">>),
    <<"z">> = recv_bytes(Sess, 1),
    close(Sess).

%% Section 3.5: HTTP/1.1 without TLS aborts with a TCP RST. The handlers
%% run on a cleartext h1 server; a target reset reaches the client as one.
vec_cleartext_abort_resets(Config) ->
    #{handler := Handler} = masque_h1_server:h1_handlers(server_opts(#{})),
    Name = unique_name(h1_clear),
    {ok, Ref} = h1:start_server(Name, 0, #{transport => tcp, handler => Handler}),
    try
        {ok, Sock} = gen_tcp:connect({127, 0, 0, 1}, h1:server_port(Ref), [
            binary, {active, false}, {show_econnreset, true}
        ]),
        Path = iolist_to_binary([
            "/.well-known/masque/tcp/127.0.0.1/", integer_to_list(?config(target_port, Config)), "/"
        ]),
        ok = gen_tcp:send(Sock, [
            <<"GET ">>,
            Path,
            <<" HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\n">>,
            <<"Upgrade: connect-tcp-12\r\n\r\n">>
        ]),
        ok = gen_tcp:send(Sock, masque_tcp_capsule:encode(final, <<"rset">>, false)),
        ?assertEqual({error, econnreset}, clear_recv_until_error(Sock)),
        gen_tcp:close(Sock)
    after
        h1:stop_server(Ref)
    end.

clear_recv_until_error(Sock) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, _} -> clear_recv_until_error(Sock);
        {error, _} = Err -> Err
    end.

%% Section 4.3: no trailers on CONNECT-TCP streams. h2 hands the
%% session trailers that arrive before the 2xx (later ones it refuses
%% itself); the session treats them as malformed and aborts. The target
%% resolves slowly here, so the trailers come first.
vec_trailers_abort(Config) ->
    Token = <<"connect-tcp-12">>,
    {h2, Conn, Sid} = raw_request(Config, tcp_request(Config, Token), Token),
    ok = h2:send_data(Conn, Sid, masque_tcp_capsule:encode(final, <<"wclo">>, false), false),
    ok = h2:send_trailers(Conn, Sid, [{<<"x-trailer">>, <<"1">>}]),
    expect_target_reset(),
    ?assertEqual(
        {reset, connect_error}, drain_to_end({h2, Conn, Sid, make_ref()})
    ),
    h2:close(Conn).

drain_to_end(W) ->
    case wire_recv(W) of
        {data, _, true} -> fin;
        {data, _, false} -> drain_to_end(W);
        Other -> Other
    end.

%% A QUIC RESET_STREAM from the client (without STOP_SENDING) ends only
%% its half of the stream. The listener's half is reset too, not left
%% open, and the target gets an RST (section 3.5). quic_h3 resets it
%% with H3_REQUEST_INCOMPLETE, the code of an unfinished request.
vec_peer_reset_resets_send(Config) ->
    {quic_h3, Conn, Sid, _} = wire_open(Config, <<"connect-tcp-12">>, []),
    ok = quic_h3:send_data(Conn, Sid, masque_tcp_capsule:encode(final, <<"wclo">>, false), false),
    timer:sleep(200),
    ok = quic:reset_stream(quic_h3:get_quic_conn(Conn), Sid, 16#10f),
    expect_target_reset(),
    ?assertMatch({reset, _}, drain_to_end({quic_h3, Conn, Sid, make_ref()})),
    quic_h3:close(Conn).

%% A CONNECT-TCP proxy on `T' that answers with a capsule tunnel, sends
%% `Bytes' (ending the stream if `EndStream') and reports how the client
%% ended its side: `{reset, Code}', `fin', or on h1 `{closed, Final}'.
start_fake_tcp_proxy(h3, #{cert := Cert, key := Key}, Bytes, EndStream) ->
    Name = unique_name(fake_h3),
    {ok, _} = quic_h3:start_server(Name, 0, #{
        cert => Cert,
        key => Key,
        settings => #{enable_connect_protocol => 1, h3_datagram => 1},
        quic_opts => #{alpn => [<<"h3">>], max_datagram_frame_size => 65535},
        handler => fun(Conn, Sid, _Method, _Path, _Headers) ->
            _ = quic_h3:set_stream_handler(Conn, Sid, self()),
            ok = quic_h3:send_response(Conn, Sid, 200, [{<<"capsule-protocol">>, <<"?1">>}]),
            ok = quic_h3:send_data(Conn, Sid, Bytes, EndStream),
            fake_stream_end(quic_h3, Conn, Sid)
        end
    }),
    {ok, Port} = quic:get_server_port(Name),
    {Port, fun() -> quic_h3:stop_server(Name) end};
start_fake_tcp_proxy(h2, #{cert_file := Cert, key_file := Key}, Bytes, EndStream) ->
    {ok, {_, _, Port} = Ref} = h2:start_server(0, #{
        cert => Cert,
        key => Key,
        enable_connect_protocol => true,
        settings => #{enable_connect_protocol => 1},
        handler => fun(Conn, Sid, _Method, _Path, _Headers) ->
            _ = h2:set_stream_handler(Conn, Sid, self()),
            ok = h2:send_response(Conn, Sid, 200, [{<<"capsule-protocol">>, <<"?1">>}]),
            ok = h2:send_data(Conn, Sid, Bytes, EndStream),
            fake_stream_end(h2, Conn, Sid)
        end
    }),
    {Port, fun() -> h2:stop_server(Ref) end};
start_fake_tcp_proxy(h1, #{cert_file := Cert, key_file := Key}, Bytes, EndStream) ->
    {ok, Listen} = ssl:listen(0, [
        binary,
        {active, false},
        {reuseaddr, true},
        {ip, {127, 0, 0, 1}},
        {certfile, Cert},
        {keyfile, Key},
        {alpn_preferred_protocols, [<<"http/1.1">>]}
    ]),
    {ok, {_, Port}} = ssl:sockname(Listen),
    Pid = spawn(fun() ->
        {ok, T} = ssl:transport_accept(Listen),
        {ok, Sock} = ssl:handshake(T, 5000),
        {[_Head], _Rest} = fake_head(Sock, <<>>),
        ok = ssl:send(Sock, [
            <<"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n">>,
            <<"Upgrade: connect-tcp\r\nCapsule-Protocol: ?1\r\n\r\n">>,
            Bytes
        ]),
        _ = EndStream andalso ssl:close(Sock),
        probe({fake_tcp_proxy, fake_h1_end(Sock, <<>>)})
    end),
    {Port, fun() ->
        exit(Pid, kill),
        ssl:close(Listen)
    end}.

fake_stream_end(Tag, Conn, Sid) ->
    receive
        {Tag, Conn, {stream_reset, Sid, Code}} -> probe({fake_tcp_proxy, {reset, Code}});
        {Tag, Conn, {data, Sid, _, true}} -> probe({fake_tcp_proxy, fin});
        {Tag, Conn, {data, Sid, _, false}} -> fake_stream_end(Tag, Conn, Sid)
    after 10000 -> probe({fake_tcp_proxy, timeout})
    end.

%% What the client sent before its connection ended: FINAL_DATA or not.
fake_h1_end(Sock, Acc) ->
    case ssl:recv(Sock, 0, 10000) of
        {ok, Bin} ->
            fake_h1_end(Sock, <<Acc/binary, Bin/binary>>);
        {error, _} ->
            case masque_tcp_capsule:decode(masque_tcp_capsule:decoder(final), Acc) of
                {ok, Items, _} ->
                    case lists:keymember(final, 1, Items) of
                        true -> {closed, final};
                        false -> {closed, no_final}
                    end;
                Err ->
                    {closed, Err}
            end
    end.

expect_target_reset() ->
    receive
        {target, closed, Reason} -> ?assertEqual(econnreset, Reason)
    after 5000 -> ct:fail(target_not_reset)
    end.

%%--------------------------------------------------------------------
%% Wire helpers: one request on the transport under test.
%%--------------------------------------------------------------------

wire_open(Config, Token, Extra) ->
    wire_open(Config, Token, Extra, fun(_) -> ok end).

%% Opens the request, checks the 100 and the success response, and
%% calls `OnStatus' for each status as it arrives.
wire_open(Config, Token, Extra, OnStatus) ->
    TargetPort = ?config(target_port, Config),
    case ?config(transport, Config) of
        h1 ->
            {Sock, Heads, Rest} = h1_upgrade(Config, Token, Extra, TargetPort, OnStatus),
            ?assertEqual([100, 101], [St || {St, _} <- Heads]),
            {101, Hdrs} = lists:last(Heads),
            assert_capsule_response(Hdrs),
            ?assertEqual(Token, proplists:get_value(<<"upgrade">>, Hdrs)),
            Ref = make_ref(),
            put({h1_rest, Ref}, Rest),
            {h1, Sock, Rest, Ref};
        _ ->
            {Tag, Conn, Sid} = raw_request(
                Config, tcp_request(Config, Token, TargetPort) ++ Extra, Token
            ),
            {100, _} = raw_response(Tag, Conn, Sid),
            OnStatus(100),
            {200, Hdrs} = raw_response(Tag, Conn, Sid),
            OnStatus(200),
            assert_capsule_response(Hdrs),
            {Tag, Conn, Sid, make_ref()}
    end.

%% A request that is refused: the statuses seen and the final headers.
wire_reject(Config, Token, TargetPort) ->
    case ?config(transport, Config) of
        h1 ->
            {Sock, Heads, _} = h1_upgrade(Config, Token, [], TargetPort, fun(_) -> ok end),
            ssl:close(Sock),
            {[St || {St, _} <- Heads], element(2, lists:last(Heads))};
        _ ->
            {Tag, Conn, Sid} = raw_request(Config, tcp_request(Config, Token, TargetPort), Token),
            Result = reject_statuses(Tag, Conn, Sid, []),
            raw_close(Tag, Conn),
            Result
    end.

reject_statuses(Tag, Conn, Sid, Acc) ->
    case raw_response(Tag, Conn, Sid) of
        {St, _} when St < 200 -> reject_statuses(Tag, Conn, Sid, [St | Acc]);
        {St, Hdrs} -> {lists:reverse([St | Acc]), Hdrs}
    end.

wire_send({h1, Sock, _, _}, Bin) -> ssl:send(Sock, Bin);
wire_send({Tag, Conn, Sid, _}, Bin) -> raw_send(Tag, Conn, Sid, iolist_to_binary(Bin)).

%% End our side of the stream without FINAL_DATA. On h1 there is no
%% stream FIN, only the connection's end.
wire_end({h1, Sock, _, _}) ->
    ssl:close(Sock),
    ok;
wire_end({quic_h3, Conn, Sid, _}) ->
    quic_h3:send_data(Conn, Sid, <<>>, true);
wire_end({h2, Conn, Sid, _}) ->
    h2:send_data(Conn, Sid, <<>>, true).

wire_abort({h1, Sock, _, _}) ->
    ssl:close(Sock),
    ok;
wire_abort({quic_h3, Conn, Sid, _}) ->
    quic_h3:cancel(Conn, Sid, 16#10f);
wire_abort({h2, Conn, Sid, _}) ->
    h2:cancel(Conn, Sid, connect_error).

wire_close({h1, Sock, _, _}) -> ssl:close(Sock);
wire_close({Tag, Conn, _, _}) -> raw_close(Tag, Conn).

%% `Want' bytes of decoded payload.
wire_payload(W, Version, Want) ->
    wire_payload(W, masque_tcp_capsule:decoder(Version), Want, <<>>).

wire_payload(_W, _Dec, Want, Acc) when byte_size(Acc) >= Want ->
    Acc;
wire_payload(W, Dec, Want, Acc) ->
    case wire_recv(W) of
        {data, Bin, _} ->
            {ok, Items, Dec2} = masque_tcp_capsule:decode(Dec, Bin),
            wire_payload(W, Dec2, Want, <<Acc/binary, (payload(Items))/binary>>);
        Other ->
            ct:fail({stream_ended, Other, Acc})
    end.

%% Everything until the stream ends: the payload, whether FINAL_DATA
%% came, and whether the stream ended `clean' or `aborted'.
wire_drain(W, Version) ->
    wire_drain(W, masque_tcp_capsule:decoder(Version), <<>>, no_final).

wire_drain(W, Dec, Acc, Final) ->
    case wire_recv(W) of
        {data, Bin, Fin} ->
            {ok, Items, Dec2} = masque_tcp_capsule:decode(Dec, Bin),
            Final2 =
                case lists:keymember(final, 1, Items) of
                    true -> final;
                    false -> Final
                end,
            Acc2 = <<Acc/binary, (payload(Items))/binary>>,
            case Fin of
                true -> {Acc2, Final2, ending(Final2)};
                false -> wire_drain(W, Dec2, Acc2, Final2)
            end;
        {reset, Code} ->
            %% Section 3.5: an abort resets with H3_CONNECT_ERROR or
            %% CONNECT_ERROR.
            ?assertEqual(connect_error_code(W), Code),
            {Acc, Final, aborted};
        closed ->
            {Acc, Final, ending(Final)}
    end.

connect_error_code({quic_h3, _, _, _}) -> 16#10f;
connect_error_code({h2, _, _, _}) -> connect_error.

%% Until FINAL_DATA, without waiting for the stream to end.
wire_drain_until_final(W, Version) ->
    wire_drain_until_final(W, masque_tcp_capsule:decoder(Version), <<>>).

wire_drain_until_final(W, Dec, Acc) ->
    case wire_recv(W) of
        {data, Bin, _} ->
            {ok, Items, Dec2} = masque_tcp_capsule:decode(Dec, Bin),
            Acc2 = <<Acc/binary, (payload(Items))/binary>>,
            case lists:keymember(final, 1, Items) of
                true -> {Acc2, final, open};
                false -> wire_drain_until_final(W, Dec2, Acc2)
            end;
        Other ->
            ct:fail({stream_ended, Other, Acc})
    end.

ending(final) -> clean;
ending(no_final) -> aborted.

payload(Items) -> iolist_to_binary([P || {_, P} <- Items]).

%% On h1 the bytes read past the 101 come first.
wire_recv({h1, Sock, _, Ref} = W) ->
    case erase({h1_rest, Ref}) of
        Rest when is_binary(Rest), Rest =/= <<>> ->
            {data, Rest, false};
        _ ->
            case ssl:recv(Sock, 0, 10000) of
                {ok, Bin} -> {data, Bin, false};
                {error, closed} -> closed;
                {error, Reason} -> ct:fail({h1_recv, Reason, W})
            end
    end;
wire_recv({Tag, Conn, Sid, _}) ->
    receive
        {Tag, Conn, {data, Sid, Bin, Fin}} -> {data, Bin, Fin};
        {Tag, Conn, {stream_reset, Sid, Code}} -> {reset, Code}
    after 10000 -> ct:fail(no_stream_event)
    end.

assert_capsule_response(Hdrs) ->
    ?assertEqual(<<"?1">>, proplists:get_value(<<"capsule-protocol">>, Hdrs)),
    ?assertEqual(<<"masque">>, proplists:get_value(<<"proxy-status">>, Hdrs)).

raw_request(Config, Headers, Token) ->
    Conn =
        case ?config(transport, Config) of
            h3 -> raw_h3_connect(Config);
            h2 -> raw_h2_connect(Config)
        end,
    raw_request(Config, Conn, Headers, Token).

raw_request(Config, Conn, Headers, Token) ->
    case ?config(transport, Config) of
        h3 ->
            {ok, Sid} = quic_h3:request(Conn, Headers, #{end_stream => false}),
            {quic_h3, Conn, Sid};
        h2 ->
            {ok, Sid} = h2:request(Conn, Headers, #{protocol => Token}),
            {h2, Conn, Sid}
    end.

raw_send(quic_h3, Conn, Sid, Bin) -> quic_h3:send_data(Conn, Sid, Bin, false);
raw_send(h2, Conn, Sid, Bin) -> h2:send_data(Conn, Sid, Bin, false).

%% The next response on the stream, interim ones included (h2 tags
%% those `informational').
raw_response(Tag, Conn, Sid) ->
    receive
        {Tag, Conn, {response, Sid, Status, Hdrs}} -> {Status, Hdrs};
        {Tag, Conn, {informational, Sid, Status, Hdrs}} -> {Status, Hdrs}
    after 5000 -> ct:fail(no_response)
    end.

%% A raw upgrade on h1. Returns the responses read (interim ones first)
%% and the bytes past the last one; `OnStatus' sees each status as it
%% arrives.
h1_upgrade(Config, Token, Extra, TargetPort, OnStatus) ->
    #{port := Port} = ?config(server, Config),
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
    Host = iolist_to_binary(["127.0.0.1:", integer_to_list(Port)]),
    Path = iolist_to_binary([
        "/.well-known/masque/tcp/127.0.0.1/", integer_to_list(TargetPort), "/"
    ]),
    ok = ssl:send(Sock, [
        <<"GET ">>,
        Path,
        <<" HTTP/1.1\r\nHost: ">>,
        Host,
        <<"\r\nConnection: Upgrade\r\nUpgrade: ">>,
        Token,
        <<"\r\n">>,
        [[K, <<": ">>, V, <<"\r\n">>] || {K, V} <- Extra],
        <<"\r\n">>
    ]),
    {Heads, Rest} = h1_heads(Sock, <<>>, [], OnStatus),
    {Sock, Heads, Rest}.

h1_heads(Sock, Buf, Acc, OnStatus) ->
    case binary:split(Buf, <<"\r\n\r\n">>) of
        [Head, Rest] ->
            [StatusLine | Lines] = binary:split(Head, <<"\r\n">>, [global]),
            [_, Code | _] = binary:split(StatusLine, <<" ">>, [global]),
            Hdrs = [
                {string:lowercase(K), string:trim(V)}
             || L <- Lines, [K, V] <- [binary:split(L, <<":">>)]
            ],
            Status = binary_to_integer(Code),
            OnStatus(Status),
            Acc1 = [{Status, Hdrs} | Acc],
            case Status of
                100 -> h1_heads(Sock, Rest, Acc1, OnStatus);
                _ -> {lists:reverse(Acc1), Rest}
            end;
        [_] ->
            {ok, More} = ssl:recv(Sock, 0, 5000),
            h1_heads(Sock, <<Buf/binary, More/binary>>, Acc, OnStatus)
    end.

%% draft-ietf-httpbis-connect-tcp-18 section 5.2: a proxy that refuses
%% classic CONNECT with 426 and `Upgrade: connect-tcp', or with 501, is
%% retried on the default template, and remembered.
tcp_fallback_on_426(Config) ->
    fallback(Config, 426).

tcp_fallback_on_501(Config) ->
    fallback(Config, 501).

%% A 426 that does not offer connect-tcp is a plain refusal.
tcp_no_fallback_on_plain_426(Config) ->
    {_Proxy, Port} = start_fake_proxy(Config, plain_426),
    ?assertMatch({error, _}, fake_connect(Port)),
    receive
        {fake_proxy, <<"CONNECT">>, _} -> ok
    after 5000 -> ct:fail(no_connect)
    end,
    receive
        {fake_proxy, Method, Path} -> ct:fail({retried, Method, Path})
    after 500 -> ok
    end.

fallback(Config, Refusal) ->
    {_Proxy, Port} = start_fake_proxy(Config, Refusal),
    {ok, First} = fake_connect(Port),
    Path = <<"/.well-known/masque/tcp/127.0.0.1/9/">>,
    receive
        {fake_proxy, <<"CONNECT">>, _} -> ok
    after 5000 -> ct:fail(no_connect)
    end,
    receive
        {fake_proxy, <<"GET">>, P1} -> ?assertEqual(Path, P1)
    after 5000 -> ct:fail(no_retry)
    end,
    ok = masque:send(First, <<"hello">>),
    <<"hello">> = recv_bytes(First, 5),
    close(First),
    %% The proxy is remembered: no CONNECT the second time.
    {ok, Second} = fake_connect(Port),
    receive
        {fake_proxy, M2, P2} -> ?assertEqual({<<"GET">>, Path}, {M2, P2})
    after 5000 -> ct:fail(no_request)
    end,
    ok = masque:send(Second, <<"again">>),
    <<"again">> = recv_bytes(Second, 5),
    close(Second).

fake_connect(Port) ->
    Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
    masque:connect(Uri, {<<"127.0.0.1">>, 9}, #{
        protocol => tcp, transports => [h1], verify => verify_none, timeout => 5000
    }).

%% A TLS proxy that refuses classic CONNECT, then echoes the capsules of
%% an upgraded request back.
start_fake_proxy(Config, Refusal) ->
    #{cert_file := Cert, key_file := Key} = ?config(certs, Config),
    {ok, Listen} = ssl:listen(0, [
        binary,
        {active, false},
        {reuseaddr, true},
        {ip, {127, 0, 0, 1}},
        {certfile, Cert},
        {keyfile, Key},
        {alpn_preferred_protocols, [<<"http/1.1">>]}
    ]),
    {ok, {_, Port}} = ssl:sockname(Listen),
    Parent = self(),
    Proxy = spawn_link(fun() -> fake_accept(Listen, Refusal, Parent) end),
    {Proxy, Port}.

fake_accept(Listen, Refusal, Parent) ->
    {ok, T} = ssl:transport_accept(Listen),
    case ssl:handshake(T, 5000) of
        {ok, Sock} ->
            Pid = spawn(fun() ->
                receive
                    go -> fake_serve(Sock, Refusal, Parent)
                end
            end),
            ok = ssl:controlling_process(Sock, Pid),
            Pid ! go;
        _ ->
            ok
    end,
    fake_accept(Listen, Refusal, Parent).

fake_serve(Sock, Refusal, Parent) ->
    {[Head], Rest} = fake_head(Sock, <<>>),
    [Line | _] = binary:split(Head, <<"\r\n">>),
    [Method, Path | _] = binary:split(Line, <<" ">>, [global]),
    Parent ! {fake_proxy, Method, Path},
    case Method of
        <<"CONNECT">> ->
            _ = ssl:send(Sock, refusal(Refusal)),
            ssl:close(Sock);
        <<"GET">> ->
            ok = ssl:send(
                Sock,
                <<
                    "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
                    "Upgrade: connect-tcp\r\nCapsule-Protocol: ?1\r\n\r\n"
                >>
            ),
            fake_echo(Sock, Rest)
    end.

fake_head(Sock, Buf) ->
    case binary:split(Buf, <<"\r\n\r\n">>) of
        [Head, Rest] ->
            {[Head], Rest};
        [_] ->
            {ok, More} = ssl:recv(Sock, 0, 5000),
            fake_head(Sock, <<Buf/binary, More/binary>>)
    end.

%% Capsules are self-delimiting, so echoing the bytes echoes them.
fake_echo(Sock, <<>>) ->
    case ssl:recv(Sock, 0) of
        {ok, Bin} -> fake_echo(Sock, Bin);
        {error, _} -> ssl:close(Sock)
    end;
fake_echo(Sock, Bin) ->
    _ = ssl:send(Sock, Bin),
    fake_echo(Sock, <<>>).

refusal(426) ->
    <<
        "HTTP/1.1 426 Upgrade Required\r\nUpgrade: connect-tcp\r\nConnection: Upgrade\r\n"
        "Content-Length: 0\r\n\r\n"
    >>;
refusal(501) ->
    <<"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n">>;
refusal(plain_426) ->
    <<
        "HTTP/1.1 426 Upgrade Required\r\nUpgrade: TLS/1.3\r\nConnection: Upgrade\r\n"
        "Content-Length: 0\r\n\r\n"
    >>.

raw_recv(_Tag, _Conn, _Sid, Want, Acc) when byte_size(Acc) >= Want ->
    Acc;
raw_recv(Tag, Conn, Sid, Want, Acc) ->
    receive
        {Tag, Conn, {data, Sid, Bin, _}} ->
            raw_recv(Tag, Conn, Sid, Want, <<Acc/binary, Bin/binary>>)
    after 5000 -> ct:fail({no_data, Acc})
    end.

%% Many tunnels at once, sharing a connection where the transport can.
tcp_concurrent_tunnels(Config) ->
    Parent = self(),
    Pids = [
        spawn_link(fun() -> Parent ! {done, self(), concurrent_tunnel(Config, N)} end)
     || N <- lists:seq(1, ?CONCURRENT_TUNNELS)
    ],
    lists:foreach(
        fun(Pid) ->
            receive
                {done, Pid, ok} -> ok;
                {done, Pid, Other} -> ct:fail({tunnel_failed, Other})
            after ?STALL_MS -> ct:fail(concurrent_tunnel_stuck)
            end
        end,
        Pids
    ).

concurrent_tunnel(Config, N) ->
    Target = {<<"127.0.0.1">>, ?config(target_port, Config)},
    Sess = connect(Config, Target, #{protocol => tcp, upstream_pool => true}),
    ok = masque:send(Sess, <<"echo">>),
    Payload = binary:copy(<<N:32>>, ?CONCURRENT_BYTES div 4),
    {Sender, MRef} = spawn_monitor(fun() -> exit(send_all(Sess, Payload)) end),
    Got = recv_bytes(Sess, byte_size(Payload)),
    receive
        {'DOWN', MRef, process, Sender, ok} -> ok
    after ?STALL_MS -> ct:fail(sender_stuck)
    end,
    close(Sess),
    case Got =:= Payload of
        true -> ok;
        false -> {corrupt, N}
    end.

%% A client that takes bytes and then stops reading must not hold a
%% proxy session forever, and the session must not buffer without limit.
tcp_stalled_client(Config) ->
    Handle = raw_stalled_client(?config(transport, Config), Config),
    timer:sleep(5000),
    ?assertMatch([_ | _], server_sessions()),
    Peak = max_session_mailbox(),
    ct:log("peak session mailbox ~p", [Peak]),
    ?assert(Peak < ?MAX_MAILBOX),
    await_no_server_sessions(?STALL_MS),
    raw_close(?config(transport, Config), Handle).

raw_stalled_client(h1, Config) ->
    #{port := Port} = ?config(server, Config),
    Host = iolist_to_binary(["127.0.0.1:", integer_to_list(?config(target_port, Config))]),
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
        <<"CONNECT ">>, Host, <<" HTTP/1.1\r\nHost: ">>, Host, <<"\r\n\r\n">>
    ]),
    {ok, Reply} = ssl:recv(Sock, 0, 5000),
    ?assertMatch(<<"HTTP/1.1 200", _/binary>>, Reply),
    ok = ssl:send(Sock, <<"floo">>),
    Sock;
raw_stalled_client(h3, Config) ->
    Conn = raw_h3_connect(Config),
    {ok, Sid} = quic_h3:request(Conn, tcp_request(Config), #{
        end_stream => false, flow_control => manual
    }),
    receive
        {quic_h3, Conn, {response, Sid, 200, _}} -> ok
    after 5000 -> ct:fail(no_response)
    end,
    ok = quic_h3:send_data(Conn, Sid, <<"floo">>, false),
    Conn;
raw_stalled_client(h2, Config) ->
    Conn = raw_h2_connect(Config),
    {ok, Sid} = h2:request(Conn, tcp_request(Config), #{
        protocol => <<"connect-tcp">>, flow_control => manual
    }),
    receive
        {h2, Conn, {response, Sid, 200, _}} -> ok
    after 5000 -> ct:fail(no_response)
    end,
    ok = h2:send_data(Conn, Sid, <<"floo">>, false),
    Conn.

raw_h3_connect(Config) ->
    #{port := Port} = ?config(server, Config),
    {ok, Conn} = quic_h3:connect("127.0.0.1", Port, #{
        verify => verify_none,
        sync => true,
        settings => #{enable_connect_protocol => 1, h3_datagram => 1},
        h3_datagram_enabled => true,
        quic_opts => #{alpn => [<<"h3">>], max_datagram_frame_size => 65535}
    }),
    Conn.

raw_h2_connect(Config) ->
    #{port := Port} = ?config(server, Config),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{
        transport => ssl,
        ssl_opts => [{verify, verify_none}, {alpn_advertised_protocols, [<<"h2">>]}],
        sync => true,
        settings => #{enable_connect_protocol => 1}
    }),
    Conn.

tcp_request(Config) ->
    tcp_request(Config, <<"connect-tcp">>).

tcp_request(Config, Token) ->
    tcp_request(Config, Token, ?config(target_port, Config)).

tcp_request(Config, Token, TargetPortInt) ->
    #{port := Port} = ?config(server, Config),
    TargetPort = integer_to_binary(TargetPortInt),
    Base = [
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, iolist_to_binary(["127.0.0.1:", integer_to_list(Port)])},
        {<<":path">>, <<"/.well-known/masque/tcp/127.0.0.1/", TargetPort/binary, "/">>}
    ],
    case ?config(transport, Config) of
        h3 -> Base ++ [{<<":protocol">>, Token}];
        h2 -> Base
    end.

raw_close(h1, Sock) -> ssl:close(Sock);
raw_close(h3, Conn) -> quic_h3:close(Conn);
raw_close(quic_h3, Conn) -> quic_h3:close(Conn);
raw_close(h2, Conn) -> h2:close(Conn).

%%====================================================================
%% CONNECT-UDP
%%====================================================================

%% Capsule writes on h1 ignore errors, so a client that stops reading
%% must still end the session once the write timeout closes the socket.
%% Classic CONNECT with the first tunnel bytes in the same write as the
%% request: h1 0.13 returns them with the socket instead of reading them
%% as HTTP (and answering 400), and the session hands them to the target.
h1_classic_connect_optimistic_data(Config) ->
    #{port := Port} = ?config(server, Config),
    Host = iolist_to_binary(["127.0.0.1:", integer_to_list(?config(target_port, Config))]),
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
        <<"CONNECT ">>, Host, <<" HTTP/1.1\r\nHost: ">>, Host, <<"\r\n\r\n">>, <<"echoping">>
    ]),
    Got = recv_past_head(Sock, <<>>),
    ?assertMatch(<<"HTTP/1.1 200", _/binary>>, Got),
    [_Head, Echoed] = binary:split(Got, <<"\r\n\r\n">>),
    ?assertEqual(<<"ping">>, Echoed),
    ssl:close(Sock).

%% Read until the response head and four bytes after it have arrived.
recv_past_head(Sock, Acc) ->
    case binary:split(Acc, <<"\r\n\r\n">>) of
        [_, Rest] when byte_size(Rest) >= 4 ->
            Acc;
        _ ->
            {ok, Bin} = ssl:recv(Sock, 0, 5000),
            recv_past_head(Sock, <<Acc/binary, Bin/binary>>)
    end.

h1_udp_stalled_client(Config) ->
    {Flood, FloodPort} = start_udp_flood(),
    #{port := Port} = ?config(server, Config),
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
    Host = iolist_to_binary(["127.0.0.1:", integer_to_list(Port)]),
    Path = iolist_to_binary(["/.well-known/masque/udp/127.0.0.1/", integer_to_list(FloodPort), "/"]),
    ok = ssl:send(Sock, [
        <<"GET ">>,
        Path,
        <<" HTTP/1.1\r\nHost: ">>,
        Host,
        <<"\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n">>
    ]),
    {ok, Reply} = ssl:recv(Sock, 0, 5000),
    ?assertMatch(<<"HTTP/1.1 101", _/binary>>, Reply),
    Inner = iolist_to_binary(masque_datagram:encode(0, <<"floo">>)),
    ok = ssl:send(Sock, h1_capsule:encode(datagram, Inner)),
    timer:sleep(5000),
    ?assertMatch([_ | _], server_sessions()),
    Peak = max_session_mailbox(),
    ct:log("peak session mailbox ~p", [Peak]),
    ?assert(Peak < ?MAX_MAILBOX),
    await_no_server_sessions(?STALL_MS),
    exit(Flood, kill),
    ssl:close(Sock).

start_udp_flood() ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Sock),
    Pid = spawn(fun() ->
        {ok, {IP, From, _}} = gen_udp:recv(Sock, 0),
        udp_flood(Sock, IP, From, binary:copy(<<"f">>, 1024))
    end),
    ok = gen_udp:controlling_process(Sock, Pid),
    {Pid, Port}.

udp_flood(Sock, IP, Port, Chunk) ->
    _ = gen_udp:send(Sock, IP, Port, Chunk),
    udp_flood(Sock, IP, Port, Chunk).

udp_echo_sizes(Config) ->
    Sess = connect_udp(Config),
    lists:foreach(
        fun(Size) ->
            Payload = binary:copy(<<"u">>, Size),
            ok = echo_datagram(Sess, Payload)
        end,
        [1, 100, 1200]
    ),
    %% Only h2 and h1 can carry this, in capsules. On h3 it is refused
    %% rather than lost silently: past what the path carries now (quic 3
    %% reports the confirmed path MTU, not the peer's limit). 8000 bytes
    %% stays under macOS's 9216 byte limit on a UDP send to the target.
    Big = binary:copy(<<"b">>, 8000),
    case ?config(transport, Config) of
        h3 -> ?assertMatch({error, {datagram_too_large, 8000, _}}, masque:send(Sess, Big));
        _ -> ok = echo_datagram(Sess, Big)
    end,
    close(Sess).

udp_oversize_refused(Config) ->
    Sess = connect_udp(Config),
    ?assertMatch(
        {error, {payload_too_large, _, _}},
        masque:send(Sess, binary:copy(<<"o">>, 65528))
    ),
    ok = echo_datagram(Sess, <<"still fine">>),
    close(Sess).

%% RFC 9298 section 5: a context-zero payload over 65527 bytes aborts
%% the stream, so the payload sent after it is never echoed. masque's
%% own client refuses to send one, so the request is made by hand, with
%% the payload in a DATAGRAM capsule.
udp_oversize_aborts(Config) ->
    Big = masque_capsule:encode(0, masque_datagram:encode(0, binary:copy(<<"o">>, 65528))),
    After = masque_capsule:encode(0, masque_datagram:encode(0, <<"after">>)),
    Bytes = iolist_to_binary([Big, After]),
    case ?config(transport, Config) of
        h1 -> udp_oversize_h1(Config, Bytes);
        _ -> udp_oversize_raw(Config, Bytes)
    end,
    await_no_server_sessions(5000).

udp_oversize_raw(Config, Bytes) ->
    #{port := Port} = ?config(server, Config),
    UdpPort = integer_to_binary(?config(udp_port, Config)),
    Base = [
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, iolist_to_binary(["127.0.0.1:", integer_to_list(Port)])},
        {<<":path">>, <<"/.well-known/masque/udp/127.0.0.1/", UdpPort/binary, "/">>}
    ],
    %% Pseudo-headers come first on h3.
    Headers =
        case ?config(transport, Config) of
            h3 ->
                Base ++ [{<<":protocol">>, <<"connect-udp">>}, {<<"capsule-protocol">>, <<"?1">>}];
            h2 ->
                Base ++ [{<<"capsule-protocol">>, <<"?1">>}]
        end,
    {Tag, Conn, Sid} = raw_request(Config, Headers, <<"connect-udp">>),
    {200, _} = raw_response(Tag, Conn, Sid),
    ok = raw_send(Tag, Conn, Sid, Bytes),
    receive
        {Tag, Conn, {stream_reset, Sid, _}} -> ok;
        {Tag, Conn, {data, Sid, _, _}} -> ct:fail(echo_after_oversize)
    after 5000 -> ct:fail(no_reset)
    end,
    raw_close(Tag, Conn).

udp_oversize_h1(Config, Bytes) ->
    #{port := Port} = ?config(server, Config),
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
    Host = iolist_to_binary(["127.0.0.1:", integer_to_list(Port)]),
    Path = iolist_to_binary([
        "/.well-known/masque/udp/127.0.0.1/", integer_to_list(?config(udp_port, Config)), "/"
    ]),
    ok = ssl:send(Sock, [
        <<"GET ">>,
        Path,
        <<" HTTP/1.1\r\nHost: ">>,
        Host,
        <<"\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n">>
    ]),
    {ok, Reply} = ssl:recv(Sock, 0, 5000),
    ?assertMatch(<<"HTTP/1.1 101", _/binary>>, Reply),
    ok = ssl:send(Sock, Bytes),
    ?assertEqual({error, closed}, ssl:recv(Sock, 0, 5000)),
    ssl:close(Sock).

%% UDP may lose packets under a burst, but it must not break the
%% tunnel, and what arrives must be intact.
udp_burst(Config) ->
    Sess = connect_udp(Config),
    Count = 2000,
    Payload = binary:copy(<<"p">>, 1024),
    %% QUIC refuses a datagram it has no congestion window for; UDP may
    %% drop, so that counts as loss.
    Results = [masque:send(Sess, Payload) || _ <- lists:seq(1, Count)],
    [] = [R || R <- Results, R =/= ok, R =/= {error, congestion_limited}],
    Got = count_datagrams(Sess, Payload, 0),
    ct:log("udp burst: ~p of ~p echoed", [Got, Count]),
    ?assert(Got > 0),
    ok = echo_datagram(Sess, <<"after burst">>),
    close(Sess).

h3_udp_quiet_tunnel(Config) ->
    Sess = connect_udp(Config),
    ok = echo_datagram(Sess, <<"before">>),
    receive
        {masque_closed, Sess, Reason} -> ct:fail({closed_while_quiet, Reason})
    after ?QUIET_MS -> ok
    end,
    ok = echo_datagram(Sess, <<"after">>),
    close(Sess).

connect_udp(Config) ->
    connect(Config, {<<"127.0.0.1">>, ?config(udp_port, Config)}, #{}).

count_datagrams(Sess, Payload, N) ->
    receive
        {masque_data, Sess, Payload} -> count_datagrams(Sess, Payload, N + 1);
        {masque_data, Sess, Other} -> ct:fail({corrupt_datagram, byte_size(Other)});
        {masque_closed, Sess, Reason} -> ct:fail({closed, Reason, N})
    after 2000 -> N
    end.

%% Datagrams may be lost, so a few attempts are allowed.
echo_datagram(Sess, Payload) ->
    echo_datagram(Sess, Payload, 20).

echo_datagram(_Sess, Payload, 0) ->
    ct:fail({no_echo, byte_size(Payload)});
echo_datagram(Sess, Payload, N) ->
    ok = masque:send(Sess, Payload),
    receive
        {masque_data, Sess, Payload} -> ok;
        {masque_closed, Sess, Reason} -> ct:fail({closed, Reason})
    after 250 -> echo_datagram(Sess, Payload, N - 1)
    end.

%%====================================================================
%% Connect-UDP-Bind
%%====================================================================

bind_two_peers(Config) ->
    Sess = connect_bind(Config),
    {ok, Ctx} = masque:open_uncompressed_context(Sess),
    await_acked(Sess, Ctx),
    {PeerA, AddrA} = open_peer(),
    {PeerB, AddrB} = open_peer(),
    ok = masque:send_to(Sess, AddrA, <<"to a">>),
    ok = masque:send_to(Sess, AddrB, <<"to b">>),
    From = peer_recv(PeerA, <<"to a">>),
    From = peer_recv(PeerB, <<"to b">>),
    ok = gen_udp:send(PeerA, From, <<"from a">>),
    ok = gen_udp:send(PeerB, From, <<"from b">>),
    await_bind_packet(Sess, AddrA, <<"from a">>),
    await_bind_packet(Sess, AddrB, <<"from b">>),
    close(Sess).

bind_compressed_peer(Config) ->
    Sess = connect_bind(Config),
    {ok, Uncompressed} = masque:open_uncompressed_context(Sess),
    await_acked(Sess, Uncompressed),
    {Peer, Addr} = open_peer(),
    {ok, Ctx} = masque:assign_compression(Sess, Addr),
    await_acked(Sess, Ctx),
    ok = masque:send_to(Sess, Addr, <<"compressed">>),
    From = peer_recv(Peer, <<"compressed">>),
    ok = gen_udp:send(Peer, From, <<"back">>),
    await_bind_packet(Sess, Addr, <<"back">>),
    ok = masque:close_compression(Sess, Ctx),
    timer:sleep(100),
    ok = masque:send_to(Sess, Addr, <<"plain again">>),
    From = peer_recv(Peer, <<"plain again">>),
    close(Sess).

%% By default the proxy only talks to public peers.
bind_peer_filter(Config) ->
    Sess = connect_bind(Config),
    {ok, Ctx} = masque:open_uncompressed_context(Sess),
    await_acked(Sess, Ctx),
    {Peer, Addr} = open_peer(),
    ok = masque:send_to(Sess, Addr, <<"refused">>),
    ?assertEqual({error, timeout}, gen_udp:recv(Peer, 0, 1000)),
    close(Sess).

connect_bind(Config) ->
    #{port := Port} = ?config(server, Config),
    Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
    {ok, Sess} = masque:bind_connect(Uri, unscoped, #{
        transports => [?config(transport, Config)], verify => verify_none, timeout => 5000
    }),
    Sess.

await_acked(Sess, Ctx) ->
    receive
        {masque_compression_acked, Sess, Ctx} -> ok
    after 5000 -> ct:fail({no_ack, Ctx})
    end.

open_peer() ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Sock),
    {Sock, {{127, 0, 0, 1}, Port}}.

peer_recv(Peer, Expected) ->
    {ok, {IP, Port, Expected}} = gen_udp:recv(Peer, 0, 5000),
    {IP, Port}.

await_bind_packet(Sess, Addr, Bytes) ->
    receive
        {masque_bind_packet, Sess, Addr, Bytes} -> ok;
        {masque_closed, Sess, Reason} -> ct:fail({closed, Reason})
    after 5000 -> ct:fail({no_bind_packet, Bytes})
    end.

%%====================================================================
%% CONNECT-IP
%%====================================================================

%% An ICMP echo answered by a gateway address behind `forward_fun'.
ip_gateway_echo(Config) ->
    {Sess, Addr} = connect_ip(Config),
    Request = icmp_echo(Addr, ?IP_GATEWAY, 8),
    ok = masque:send_ip_packet(Sess, Request),
    receive
        {masque_ip_packet, Sess, Reply} ->
            ?assertEqual(?IP_GATEWAY, ipv4_src(Reply)),
            ?assertEqual(Addr, ipv4_dst(Reply)),
            ?assertEqual(0, masque_ip_packet:checksum(ipv4_header(Reply)))
    after 5000 -> ct:fail(no_icmp_reply)
    end,
    close(Sess).

%% Two clients reach each other through the address registry, the way
%% a site-to-site deployment routes between tunnels.
ip_two_clients(Config) ->
    {SessA, AddrA} = connect_ip(Config),
    {SessB, AddrB} = connect_ip(Config),
    ?assertNotEqual(AddrA, AddrB),
    ToB = ipv4_udp(AddrA, AddrB, <<"hello b">>),
    ok = masque:send_ip_packet(SessA, ToB),
    receive
        {masque_ip_packet, SessB, GotB} ->
            ?assertEqual(AddrA, ipv4_src(GotB)),
            ?assertMatch({_, <<"hello b">>}, split_binary(GotB, byte_size(GotB) - 7))
    after 5000 -> ct:fail(b_got_nothing)
    end,
    ToA = ipv4_udp(AddrB, AddrA, <<"hello a">>),
    ok = masque:send_ip_packet(SessB, ToA),
    receive
        {masque_ip_packet, SessA, GotA} -> ?assertEqual(AddrB, ipv4_src(GotA))
    after 5000 -> ct:fail(a_got_nothing)
    end,
    close(SessA),
    close(SessB).

%% RFC 9484 section 4.7.1: each ADDRESS_ASSIGN is the full set the
%% client holds. Asking for IPv6 after IPv4 keeps the IPv4 address.
ip_full_assign_set(Config) ->
    {Sess, V4} = connect_ip(Config),
    {ok, [Id]} = masque:request_addresses(Sess, [{6, {0, 0, 0, 0, 0, 0, 0, 0}, 128}]),
    receive
        {masque_address_assign, Sess, Entries} ->
            ?assertMatch(
                [#ip_assignment{request_id = Id, version = 6}, #ip_assignment{request_id = 0}],
                Entries
            ),
            [_, #ip_assignment{version = 4, address = Kept}] = Entries,
            ?assertEqual(V4, Kept)
    after 5000 -> ct:fail(no_v6_assign)
    end,
    close(Sess).

%% RFC 9484 section 7.2: the TTL is decremented going into the tunnel,
%% not coming out. A TTL of 1 reaches the gateway, and its reply comes
%% back one hop down.
ip_ttl_kept_on_decapsulation(Config) ->
    {Sess, Addr} = connect_ip(Config),
    ok = masque:send_ip_packet(Sess, set_ttl(icmp_echo(Addr, ?IP_GATEWAY, 8), 1)),
    receive
        {masque_ip_packet, Sess, Reply} ->
            ?assertEqual(?IP_GATEWAY, ipv4_src(Reply)),
            ?assertEqual(63, ipv4_ttl(Reply)),
            ?assertEqual(0, masque_ip_packet:checksum(ipv4_header(Reply)))
    after 5000 -> ct:fail(no_icmp_reply)
    end,
    close(Sess).

%% With `ttl_decrement => decapsulation' a TTL of 1 runs out at the
%% proxy, which answers ICMP Time Exceeded.
ip_time_exceeded(Config) ->
    {Sess, Addr} = connect_ip(Config),
    ok = masque:send_ip_packet(Sess, set_ttl(ipv4_udp(Addr, {192, 0, 2, 1}, <<"ttl">>), 1)),
    receive
        {masque_ip_packet, Sess, Icmp} ->
            ?assertEqual(Addr, ipv4_dst(Icmp)),
            ?assertMatch(<<_:20/binary, 11, 0, _/binary>>, Icmp)
    after 5000 -> ct:fail(no_time_exceeded)
    end,
    close(Sess).

%% A packet above the proxy's `mtu' is answered with Fragmentation
%% Needed carrying the MTU.
ip_packet_too_big(Config) ->
    {Sess, Addr} = connect_ip(Config),
    ok = masque:send_ip_packet(Sess, ipv4_udp(Addr, {192, 0, 2, 1}, binary:copy(<<0>>, 600))),
    receive
        {masque_ip_packet, Sess, Icmp} ->
            ?assertMatch(<<_:20/binary, 3, 4, _:16, 0:16, 576:16, _/binary>>, Icmp)
    after 5000 -> ct:fail(no_frag_needed)
    end,
    close(Sess).

%% RFC 9484 section 11 and 7.2.1: a source outside the assignment is
%% dropped (BCP 38) and the drop is signalled with ICMP.
ip_spoofed_source_gets_icmp(Config) ->
    {Sess, _Addr} = connect_ip(Config),
    Spoofed = {198, 51, 100, 7},
    ok = masque:send_ip_packet(Sess, ipv4_udp(Spoofed, {192, 0, 2, 1}, <<"spoof">>)),
    receive
        {masque_ip_packet, Sess, Icmp} ->
            ?assertEqual(Spoofed, ipv4_dst(Icmp)),
            ?assertMatch(<<_:20/binary, 3, 13, _/binary>>, Icmp)
    after 5000 -> ct:fail(no_dest_unreachable)
    end,
    close(Sess).

set_ttl(<<Head:8/binary, _TTL, Proto, _Sum:16, Rest/binary>>, TTL) ->
    <<Addrs:8/binary, Body/binary>> = Rest,
    H0 = <<Head/binary, TTL, Proto, 0:16, Addrs/binary>>,
    Sum = masque_ip_packet:checksum(H0),
    <<Head/binary, TTL, Proto, Sum:16, Addrs/binary, Body/binary>>.

ipv4_ttl(<<_:64, TTL, _/binary>>) -> TTL.

connect_ip(Config) ->
    Sess = connect(Config, {'*', '*'}, #{protocol => ip}),
    {ok, [Id]} = masque:request_addresses(Sess, [{4, {0, 0, 0, 0}, 32}]),
    receive
        {masque_address_assign, Sess, [#ip_assignment{request_id = Id, address = Addr}]} ->
            {Sess, Addr}
    after 5000 -> ct:fail(no_address)
    end.

%% `forward_fun': the proxy's routing decision for an accepted packet.
ip_router(Packet, State) ->
    case ipv4_dst(Packet) of
        ?IP_GATEWAY ->
            {reply, icmp_echo(?IP_GATEWAY, ipv4_src(Packet), 0), State};
        Dst ->
            case masque_ip_session_registry:lookup(Dst) of
                {ok, Pid, _} ->
                    ok = masque_ip:inject_packet(Pid, Packet),
                    {forward, State};
                not_found ->
                    {drop, State}
            end
    end.

ipv4_src(<<_:96, A, B, C, D, _/binary>>) -> {A, B, C, D}.
ipv4_dst(<<_:128, A, B, C, D, _/binary>>) -> {A, B, C, D}.
ipv4_header(<<Header:20/binary, _/binary>>) -> Header.

ipv4(Src, Dst, Proto, Body) ->
    {SA, SB, SC, SD} = Src,
    {DA, DB, DC, DD} = Dst,
    Total = 20 + byte_size(Body),
    H0 =
        <<4:4, 5:4, 0, Total:16, 0:16, 0:16, 64, Proto, 0:16, SA, SB, SC, SD, DA, DB, DC, DD>>,
    Sum = masque_ip_packet:checksum(H0),
    <<Before:10/binary, 0:16, After/binary>> = H0,
    <<Before/binary, Sum:16, After/binary, Body/binary>>.

icmp_echo(Src, Dst, Type) ->
    Body0 = <<Type, 0, 0:16, 1:16, 1:16, "ping">>,
    Sum = masque_ip_packet:checksum(Body0),
    <<Head:2/binary, 0:16, Rest/binary>> = Body0,
    ipv4(Src, Dst, 1, <<Head/binary, Sum:16, Rest/binary>>).

ipv4_udp(Src, Dst, Payload) ->
    Len = 8 + byte_size(Payload),
    ipv4(Src, Dst, 17, <<4000:16, 4001:16, Len:16, 0:16, Payload/binary>>).

%%====================================================================
%% Relay
%%====================================================================

chain_tcp_full_duplex(Config) ->
    with_chain(Config, fun(Cfg) -> full_duplex(Cfg, payload()) end).

%% Bytes refused by a full upstream queue must not be lost.
chain_tcp_upload(Config) ->
    with_chain(Config, fun(Cfg) ->
        Sess = connect_tcp(Cfg),
        ok = masque:send(Sess, <<"sink">>),
        ok = send_all(Sess, payload()),
        Sum = sha(payload()),
        ?assertEqual(Sum, recv_bytes(Sess, byte_size(Sum))),
        close(Sess)
    end).

%% A target slower than the client fills the upstream leg's send queue.
chain_tcp_upload_large(Config) ->
    with_chain(Config, fun(Cfg) ->
        Sess = connect_tcp(Cfg),
        ok = masque:send(Sess, <<"slow">>),
        Payload = binary:copy(<<"0123456789abcdef">>, ?LARGE_BYTES div 16),
        ok = send_all(Sess, Payload),
        Sum = sha(Payload),
        ?assertEqual(Sum, recv_bytes(Sess, byte_size(Sum))),
        close(Sess)
    end).

chain_udp_echo(Config) ->
    with_chain(Config, fun(Cfg) ->
        Sess = connect_udp(Cfg),
        ok = echo_datagram(Sess, <<"over two hops">>),
        close(Sess)
    end).

chain_ip_echo(Config) ->
    with_chain(Config, fun(Cfg) ->
        {Sess, Addr} = connect_ip(Cfg),
        ok = masque:send_ip_packet(Sess, icmp_echo(Addr, ?IP_GATEWAY, 8)),
        receive
            {masque_ip_packet, Sess, Reply} -> ?assertEqual(?IP_GATEWAY, ipv4_src(Reply))
        after 5000 -> ct:fail(no_icmp_reply)
        end,
        close(Sess)
    end).

%% The case's server is the egress; clients dial a chain listener of
%% the same transport in front of it.
with_chain(Config, Fun) ->
    Transport = ?config(transport, Config),
    #{port := EgressPort} = ?config(server, Config),
    Ingress = start_chain(Transport, ?config(certs, Config), EgressPort),
    Cfg = lists:keystore(server, 1, Config, {server, Ingress}),
    try
        Fun(Cfg)
    after
        stop_chain(Transport, Ingress)
    end.

start_chain(Transport, Certs, EgressPort) ->
    Name = unique_name(chain),
    Upstream = #{
        upstream_proxy => iolist_to_binary(["https://127.0.0.1:", integer_to_list(EgressPort)]),
        upstream_opts => #{transports => [Transport], verify => verify_none}
    },
    case Transport of
        h3 ->
            #{cert := Cert, key := Key} = Certs,
            {ok, _} = masque:start_chain_listener(Name, #{
                port => 0, cert => Cert, key => Key, handler_opts => Upstream
            }),
            {ok, Port} = quic:get_server_port(Name),
            #{name => Name, port => Port};
        h2 ->
            #{cert_file := Cert, key_file := Key} = Certs,
            {ok, {_, _, Port}} = masque:start_chain_listener_h2(Name, #{
                port => 0, cert => Cert, key => Key, handler_opts => Upstream
            }),
            #{name => Name, port => Port};
        h1 ->
            #{cert_file := Cert, key_file := Key} = Certs,
            {ok, Ref} = masque:start_chain_listener_h1(Name, #{
                port => 0, cert => Cert, key => Key, handler_opts => Upstream
            }),
            #{name => Name, port => h1:server_port(Ref)}
    end.

stop_chain(h3, #{name := Name}) -> masque:stop_listener(Name);
stop_chain(h2, #{name := Name}) -> masque:stop_listener_h2(Name);
stop_chain(h1, #{name := Name}) -> masque:stop_listener_h1(Name).

%%====================================================================
%% Lifecycle
%%====================================================================

%% Stopping a listener refuses new work. Open tunnels end, or carry on
%% until they finish, but none may be left without an owner.
stop_listener_with_open_tunnels(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"echo">>),
    ok = masque:send(Sess, <<"x">>),
    <<"x">> = recv_bytes(Sess, 1),
    stop_server(?config(transport, Config), ?config(server, Config)),
    Ended =
        receive
            {masque_closed, Sess, Reason} -> {closed, Reason}
        after 5000 -> still_open
        end,
    ct:log("after listener stop: ~p", [Ended]),
    close(Sess),
    await_no_server_sessions(10000).

%% The owner dying ends its tunnels at the target and leaks nothing. A
%% crash is an abort (section 3.5), so the target sees a reset.
owner_crash_cleans_up(Config) ->
    Ports = length(erlang:ports()),
    Parent = self(),
    Owner = spawn(fun() ->
        Sess = connect_tcp(Config),
        ok = masque:send(Sess, <<"wclo">>),
        <<"x">> = recv_bytes(Sess, 1),
        Parent ! connected,
        receive
            never -> ok
        end
    end),
    receive
        connected -> ok
    after 10000 -> ct:fail(owner_never_connected)
    end,
    exit(Owner, kill),
    receive
        {target, closed, Reason} -> ?assertEqual(abort_seen_at_target(Config), Reason)
    after 10000 -> ct:fail(target_not_told)
    end,
    await_no_server_sessions(10000),
    %% Sockets close just after their owners exit.
    timer:sleep(500),
    ?assert(length(erlang:ports()) =< Ports + 1).

%% GOAWAY refuses new streams and leaves running tunnels alone.
goaway_keeps_open_tunnel(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"echo">>),
    ok = masque:send(Sess, <<"before">>),
    <<"before">> = recv_bytes(Sess, 6),
    [Pid | _] = server_sessions(),
    ServerConn = element(2, sys:get_state(Pid)),
    %% `h2:goaway/1' closes the connection after a 100 ms drain, so the
    %% tunnel only has to work inside that window there.
    ok =
        case ?config(transport, Config) of
            h3 -> quic_h3:goaway(ServerConn);
            h2 -> h2:goaway(ServerConn)
        end,
    ok = masque:send(Sess, <<"after">>),
    <<"after">> = recv_bytes(Sess, 5),
    close(Sess).

%% RFC 9114 section 5.2: streams under the GOAWAY id run to completion.
%% A whole transfer in both directions starts after it.
h3_goaway_transfer_continues(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"echo">>),
    ok = masque:send(Sess, <<"before">>),
    <<"before">> = recv_bytes(Sess, 6),
    ok = quic_h3:goaway(server_conn()),
    timer:sleep(500),
    {Sender, MRef} = spawn_monitor(fun() -> exit({sent, send_all(Sess, payload())}) end),
    Got = recv_bytes(Sess, ?TRANSFER_BYTES),
    receive
        {'DOWN', MRef, process, Sender, {sent, ok}} -> ok;
        {'DOWN', MRef, process, Sender, Other} -> ct:fail({sender, Other})
    after ?STALL_MS -> ct:fail(sender_stuck)
    end,
    ?assertEqual(sha(payload()), sha(Got)),
    close(Sess).

%% `h2:goaway/1' closes the connection after its drain. The client has
%% to hear about it and not hang.
h2_goaway_tells_client(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"echo">>),
    ok = masque:send(Sess, <<"x">>),
    <<"x">> = recv_bytes(Sess, 1),
    ok = h2:goaway(server_conn()),
    receive
        {masque_closed, Sess, Reason} -> ct:log("client told ~p", [Reason])
    after 5000 -> ct:fail(client_not_told)
    end.

%% After a GOAWAY the client may not open new streams on the connection.
goaway_refuses_new_requests(Config) ->
    Sess = connect_tcp(Config),
    ok = masque:send(Sess, <<"echo">>),
    ok = masque:send(Sess, <<"x">>),
    <<"x">> = recv_bytes(Sess, 1),
    close(Sess),
    await_no_server_sessions(5000),
    case ?config(transport, Config) of
        h3 -> h3_refused_after_goaway(Config);
        h2 -> h2_refused_after_goaway(Config)
    end.

h3_refused_after_goaway(Config) ->
    Conn = raw_h3_connect(Config),
    {ok, Sid} = quic_h3:request(Conn, tcp_request(Config), #{end_stream => false}),
    receive
        {quic_h3, Conn, {response, Sid, 200, _}} -> ok
    after 5000 -> ct:fail(no_response)
    end,
    ok = quic_h3:goaway(server_conn()),
    receive
        {quic_h3, Conn, {goaway, _}} -> ok
    after 5000 -> ct:fail(no_goaway)
    end,
    ?assertMatch({error, _}, quic_h3:request(Conn, tcp_request(Config), #{end_stream => false})),
    quic_h3:close(Conn).

h2_refused_after_goaway(Config) ->
    Conn = raw_h2_connect(Config),
    {ok, Sid} = h2:request(Conn, tcp_request(Config), #{protocol => <<"connect-tcp">>}),
    receive
        {h2, Conn, {response, Sid, 200, _}} -> ok
    after 5000 -> ct:fail(no_response)
    end,
    ok = h2:goaway(server_conn()),
    receive
        {h2, Conn, {goaway, _, _}} -> ok
    after 5000 -> ct:fail(no_goaway)
    end,
    ?assertMatch(
        {error, _}, h2:request(Conn, tcp_request(Config), #{protocol => <<"connect-tcp">>})
    ),
    h2:close(Conn).

%% The pool stops using a connection that got a GOAWAY: new tunnels get
%% a new connection, and they work.
goaway_pool_moves_on(Config) ->
    Target = {<<"127.0.0.1">>, ?config(target_port, Config)},
    Opts = #{protocol => tcp, upstream_pool => true},
    First = connect(Config, Target, Opts),
    ok = masque:send(First, <<"echo">>),
    ok = masque:send(First, <<"1">>),
    <<"1">> = recv_bytes(First, 1),
    [Before] = server_connections(),
    Goaway =
        case ?config(transport, Config) of
            h3 -> fun quic_h3:goaway/1;
            h2 -> fun h2:goaway/1
        end,
    ok = Goaway(Before),
    timer:sleep(300),
    Second = connect(Config, Target, Opts),
    ok = masque:send(Second, <<"echo">>),
    ok = masque:send(Second, <<"2">>),
    <<"2">> = recv_bytes(Second, 1),
    ?assert(lists:any(fun(C) -> C =/= Before end, server_connections())),
    case ?config(transport, Config) of
        h3 ->
            ok = masque:send(First, <<"3">>),
            <<"3">> = recv_bytes(First, 1);
        h2 ->
            ok
    end,
    close(First),
    close(Second).

server_conn() ->
    [Conn | _] = server_connections(),
    Conn.

server_connections() ->
    lists:usort([element(2, sys:get_state(P)) || P <- server_sessions()]).

%%====================================================================
%% Client helpers
%%====================================================================

connect_tcp(Config) ->
    Target = {<<"127.0.0.1">>, ?config(target_port, Config)},
    connect(Config, Target, #{protocol => tcp}).

connect(Config, Target, Opts0) ->
    Opts =
        case {Opts0, proplists:get_value(tcp_framing, Config)} of
            {#{protocol := tcp}, Framing} when Framing =/= undefined ->
                case proplists:get_value(tcp_protocol, Config) of
                    undefined -> Opts0#{tcp_framing => Framing};
                    Token -> Opts0#{tcp_framing => Framing, tcp_protocol => Token}
                end;
            _ ->
                Opts0
        end,
    #{port := Port} = ?config(server, Config),
    Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
    {ok, Sess} = masque:connect(
        Uri,
        Target,
        Opts#{transports => [?config(transport, Config)], verify => verify_none, timeout => 5000}
    ),
    Sess.

close(Sess) ->
    _ = masque:close(Sess),
    ok.

payload() ->
    binary:copy(<<"0123456789abcdef">>, ?TRANSFER_BYTES div 16).

sha(Bin) -> crypto:hash(sha256, Bin).

%% A refused write wrote nothing, so the caller tries again.
send_all(_Sess, <<>>) ->
    ok;
send_all(Sess, Bin) ->
    Size = min(?CHUNK_BYTES, byte_size(Bin)),
    <<Chunk:Size/binary, Rest/binary>> = Bin,
    case send_chunk(Sess, Chunk, 3000) of
        ok -> send_all(Sess, Rest);
        Err -> Err
    end.

send_chunk(_Sess, _Chunk, 0) ->
    {error, send_stuck};
send_chunk(Sess, Chunk, N) ->
    case masque:send(Sess, Chunk) of
        ok ->
            ok;
        {error, Full} when Full =:= send_queue_full; Full =:= send_buffer_full ->
            timer:sleep(10),
            send_chunk(Sess, Chunk, N - 1);
        Err ->
            Err
    end.

recv_bytes(Sess, Want) ->
    recv_bytes(Sess, Want, [], 0).

recv_bytes(_Sess, Want, Acc, Got) when Got >= Want ->
    iolist_to_binary(lists:reverse(Acc));
recv_bytes(Sess, Want, Acc, Got) ->
    receive
        {masque_data, Sess, Bin} ->
            recv_bytes(Sess, Want, [Bin | Acc], Got + byte_size(Bin));
        {masque_closed, Sess, Reason} ->
            ct:fail({closed, Reason, Got, tunnel_stacks()})
    after ?STALL_MS ->
        ct:fail({stalled, Got, Want, tunnel_stacks()})
    end.

max_session_mailbox() ->
    lists:max([0 | [L || {_, [_, {message_queue_len, L}]} <- tunnel_stacks()]]).

%% Where the server sessions are, for the failure report.
tunnel_stacks() ->
    [
        {Mod, process_info(P, [current_stacktrace, message_queue_len])}
     || P <- processes(),
        Mod <- session_module(P),
        lists:suffix("session", atom_to_list(Mod))
    ].

session_module(P) ->
    case process_info(P, dictionary) of
        {dictionary, Dict} ->
            case lists:keyfind('$initial_call', 1, Dict) of
                {_, {Mod, init, 1}} ->
                    case atom_to_list(Mod) of
                        "masque_" ++ _ -> [Mod];
                        _ -> []
                    end;
                _ ->
                    []
            end;
        _ ->
            []
    end.

%%====================================================================
%% Servers
%%====================================================================

server_opts(Extra) ->
    Handler =
        case Extra of
            #{handler_opts := H} -> H;
            _ -> default_handler_opts()
        end,
    Extra#{accept_bind => true, handler_opts => Handler}.

default_handler_opts() ->
    #{
        allow_private => true,
        allow_self => true,
        bind_address => {127, 0, 0, 1},
        allow_loopback => true,
        address_pool => {4, {10, 200, 0, 0}, 24},
        routes => [
            #ip_route{
                version = 4,
                start_addr = {0, 0, 0, 0},
                end_addr = {255, 255, 255, 255},
                ip_protocol = 0
            }
        ],
        forward_fun => fun ?MODULE:ip_router/2
    }.

start_server(h3, Certs, Extra) ->
    {ok, Srv} = masque_test_helpers:start_masque_server(maps:merge(Certs, server_opts(Extra))),
    Srv;
start_server(h2, #{cert_file := Cert, key_file := Key}, Extra) ->
    Name = unique_name(h2),
    {ok, {_, _, Port}} = masque:start_listener_h2(
        Name, (server_opts(Extra))#{port => 0, cert => Cert, key => Key}
    ),
    #{name => Name, port => Port};
start_server(h1, #{cert_file := Cert, key_file := Key}, Extra) ->
    Name = unique_name(h1),
    {ok, Ref} = masque:start_listener_h1(
        Name, (server_opts(Extra))#{port => 0, cert => Cert, key => Key}
    ),
    #{name => Name, port => h1:server_port(Ref)}.

stop_server(h3, Srv) -> masque_test_helpers:stop_masque_server(Srv);
stop_server(h2, #{name := Name}) -> masque:stop_listener_h2(Name);
stop_server(h1, #{name := Name}) -> masque:stop_listener_h1(Name).

unique_name(Prefix) ->
    list_to_atom(
        "e2e_" ++ atom_to_list(Prefix) ++ "_" ++
            integer_to_list(erlang:unique_integer([positive]))
    ).

%%====================================================================
%% Target
%%====================================================================

start_udp_echo() ->
    {ok, Sock} = gen_udp:open(0, [
        binary, {active, false}, {ip, {127, 0, 0, 1}}, {recbuf, 8 * 1024 * 1024}
    ]),
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

target_accept(Listen) ->
    case gen_tcp:accept(Listen) of
        {ok, Sock} ->
            Pid = spawn(fun() -> target_wait(Sock) end),
            %% A tunnel may already have closed this socket.
            _ = gen_tcp:controlling_process(Sock, Pid),
            Pid ! go,
            target_accept(Listen);
        {error, closed} ->
            ok;
        %% A connection reset before it was accepted (macOS reports it as
        %% `einval', Linux as `econnaborted'): a tunnel that aborts right
        %% after dialing, as one that gets invalid data queued during its
        %% start does. To the case it is a reset like any other.
        {error, Reason} when Reason =:= einval; Reason =:= econnaborted ->
            probe({target, closed, econnreset}),
            target_accept(Listen);
        {error, Reason} ->
            ct:pal("target accept: ~p", [Reason]),
            timer:sleep(10),
            target_accept(Listen)
    end.

target_wait(Sock) ->
    receive
        go ->
            case gen_tcp:recv(Sock, 4) of
                {ok, Mode} ->
                    target_mode(Mode, Sock);
                %% A tunnel aborted before its first bytes were written.
                {error, Reason} ->
                    probe({target, closed, Reason}),
                    gen_tcp:close(Sock)
            end
    end.

target_mode(<<"echo">>, Sock) ->
    target_echo(Sock);
target_mode(<<"down">>, Sock) ->
    ok = gen_tcp:send(Sock, payload()),
    target_hold(Sock);
target_mode(<<"slow">>, Sock) ->
    Sum = target_slow_sink(Sock, ?LARGE_BYTES, crypto:hash_init(sha256)),
    ok = gen_tcp:send(Sock, Sum),
    target_hold(Sock);
target_mode(<<"gath">>, Sock) ->
    Bin = target_read_all(Sock, []),
    ok = gen_tcp:send(Sock, sha(Bin)),
    gen_tcp:close(Sock);
target_mode(<<"fin1">>, Sock) ->
    ok = gen_tcp:send(Sock, <<"bye">>),
    ok = gen_tcp:shutdown(Sock, write),
    {ok, Late} = gen_tcp:recv(Sock, 4, 5000),
    probe({target, got, Late}),
    gen_tcp:close(Sock);
%% Figure 6: everything until the client's FIN, then an answer and ours.
target_mode(<<"grac">>, Sock) ->
    Bin = target_read_all(Sock, []),
    probe({target, got_all, Bin}),
    ok = gen_tcp:send(Sock, <<"xyz">>),
    gen_tcp:close(Sock);
%% After the client's FIN, keep writing: a reset shows as a failed
%% write, a healthy tunnel takes the bytes.
target_mode(<<"fins">>, Sock) ->
    _ = target_read_all(Sock, []),
    probe({target, fin}),
    probe({target, after_fin, target_write_until_error(Sock, 30)}),
    gen_tcp:close(Sock);
%% Read until the client's FIN, then stay quiet (no traffic restarts the
%% handler's eof timer) until told to write, to see whether the tunnel
%% reset the connection meanwhile.
target_mode(<<"eoft">>, Sock) ->
    _ = target_read_all(Sock, []),
    probe({target, fin, self()}),
    receive
        write -> probe({target, after_eof, target_write_until_error(Sock, 10)})
    after 60000 -> ok
    end,
    gen_tcp:close(Sock);
target_mode(<<"rset">>, Sock) ->
    ok = gen_tcp:send(Sock, <<"x">>),
    timer:sleep(200),
    ok = inet:setopts(Sock, [{linger, {true, 0}}]),
    gen_tcp:close(Sock);
target_mode(<<"wclo">>, Sock) ->
    %% A tunnel aborted at once may have reset us already.
    case gen_tcp:send(Sock, <<"x">>) of
        ok -> probe({target, closed, target_recv_error(Sock)});
        {error, Reason} -> probe({target, closed, Reason})
    end,
    gen_tcp:close(Sock);
target_mode(<<"floo">>, Sock) ->
    target_flood(Sock, binary:copy(<<"f">>, 64 * 1024));
target_mode(<<"stal">>, Sock) ->
    receive
    after infinity -> gen_tcp:close(Sock)
    end;
target_mode(<<"sink">>, Sock) ->
    {ok, Bin} = gen_tcp:recv(Sock, ?TRANSFER_BYTES),
    ok = gen_tcp:send(Sock, sha(Bin)),
    target_hold(Sock).

target_slow_sink(_Sock, 0, Ctx) ->
    crypto:hash_final(Ctx);
target_slow_sink(Sock, Left, Ctx) ->
    Size = min(Left, 256 * 1024),
    case gen_tcp:recv(Sock, Size, 20000) of
        {ok, Bin} ->
            timer:sleep(1),
            target_slow_sink(Sock, Left - byte_size(Bin), crypto:hash_update(Ctx, Bin));
        {error, Reason} ->
            probe({target, slow_sink_failed, Reason, Left}),
            exit(normal)
    end.

%% Bytes may still arrive (a capsule cut short is forwarded as far as
%% it went); the end is what counts.
target_recv_error(Sock) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, _} -> target_recv_error(Sock);
        {error, Reason} -> Reason
    end.

target_write_until_error(_Sock, 0) ->
    ok;
target_write_until_error(Sock, N) ->
    timer:sleep(100),
    case gen_tcp:send(Sock, <<"y">>) of
        ok -> target_write_until_error(Sock, N - 1);
        {error, _} = Err -> Err
    end.

target_read_all(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, Bin} -> target_read_all(Sock, [Bin | Acc]);
        {error, closed} -> iolist_to_binary(lists:reverse(Acc))
    end.

target_flood(Sock, Chunk) ->
    case gen_tcp:send(Sock, Chunk) of
        ok -> target_flood(Sock, Chunk);
        {error, _} -> gen_tcp:close(Sock)
    end.

probe(Msg) ->
    try
        ?PROBE ! Msg,
        ok
    catch
        error:badarg -> ok
    end.

target_echo(Sock) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, Bin} ->
            case gen_tcp:send(Sock, Bin) of
                ok -> target_echo(Sock);
                {error, _} -> gen_tcp:close(Sock)
            end;
        {error, _} ->
            gen_tcp:close(Sock)
    end.

target_hold(Sock) ->
    _ = gen_tcp:recv(Sock, 0),
    gen_tcp:close(Sock).

%%====================================================================
%% HTTP framing (RFC 9297, RFC 9298, RFC 9209, RFC 9110)
%%
%% Listener cases drive the listener with hand-built requests; client
%% cases run the real client against a listener whose `fallback' sends
%% the response the case scripts.
%%====================================================================

%% RFC 9297 section 3.2: a capsule-protocol request carrying a body
%% field is malformed (400). h2 and h3 forbid `transfer-encoding'
%% already, so it is sent on h1 only.
udp_body_fields_refused(Config) ->
    Fields =
        [{<<"content-length">>, <<"0">>}, {<<"content-type">>, <<"text/plain">>}] ++
            [{<<"transfer-encoding">>, <<"chunked">>} || ?config(transport, Config) =:= h1],
    lists:foreach(
        fun(Field) ->
            {Status, Hdrs, H} = udp_attempt(Config, udp_target(Config), <<"?1">>, [Field]),
            ?assertEqual({400, <<"masque; error=http_request_error">>}, {
                Status, proplists:get_value(<<"proxy-status">>, Hdrs)
            }),
            attempt_close(H)
        end,
        Fields
    ).

%% RFC 9297 section 3.4: `Capsule-Protocol' is a Boolean and unknown
%% parameters are ignored.
udp_capsule_protocol_parameters(Config) ->
    {Status, Hdrs, H} = udp_attempt(Config, udp_target(Config), <<"?1; foo=bar;x">>, []),
    ?assertEqual(success_status(Config), Status),
    ?assertEqual(<<"?1">>, proplists:get_value(<<"capsule-protocol">>, Hdrs)),
    %% On h3 the reply comes back as a QUIC datagram, not a capsule.
    case H of
        {quic_h3, _, _} ->
            ok;
        _ ->
            ok = attempt_send(H, datagram_capsule(<<"param">>)),
            ?assertEqual({0, <<0, "param">>}, attempt_capsule(H))
    end,
    attempt_close(H).

%% RFC 9297 section 3.3: a stream that ends inside a capsule is
%% malformed; the listener resets it (h3, h2) or the connection is gone
%% (h1), and the session ends.
udp_truncated_capsule_at_fin(Config) ->
    {Status, _, H} = udp_attempt(Config, udp_target(Config), <<"?1">>, []),
    ?assertEqual(success_status(Config), Status),
    ok = attempt_send(H, <<0, 10, "abc">>),
    case H of
        {h1, Sock, _} ->
            ssl:close(Sock);
        {Tag, Conn, Sid} ->
            ok = raw_end(Tag, Conn, Sid),
            receive
                {Tag, Conn, {stream_reset, Sid, _}} -> ok
            after 5000 -> ct:fail(no_reset)
            end,
            raw_close(Tag, Conn)
    end,
    await_no_server_sessions(?LEAK_MS).

%% RFC 9297 section 3.3: capsules of an unknown type are skipped; the
%% DATAGRAM capsule behind one still reaches the target.
udp_unknown_capsule_skipped(Config) ->
    {Status, _, H} = udp_attempt(Config, udp_target(Config), <<"?1">>, []),
    ?assertEqual(success_status(Config), Status),
    Unknown = iolist_to_binary(masque_capsule:encode(16#2a5f, <<"ignore me">>)),
    ok = attempt_send(H, <<Unknown/binary, (datagram_capsule(<<"after">>))/binary>>),
    ?assertEqual({0, <<0, "after">>}, attempt_capsule(H)),
    attempt_close(H).

%% RFC 8441 section 4 and RFC 9220: an Extended CONNECT with a
%% `:protocol' the listener does not implement is a 501.
unknown_protocol_not_implemented(Config) ->
    #{port := Port} = ?config(server, Config),
    Headers = [
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, iolist_to_binary(["127.0.0.1:", integer_to_list(Port)])},
        {<<":path">>, <<"/.well-known/masque/udp/127.0.0.1/9/">>}
    ],
    Token = <<"x-unknown-protocol">>,
    Req =
        case ?config(transport, Config) of
            h3 -> Headers ++ [{<<":protocol">>, Token}];
            h2 -> Headers
        end,
    {Tag, Conn, Sid} = raw_request(Config, Req, Token),
    {Status, Hdrs} = raw_response(Tag, Conn, Sid),
    ?assertEqual({501, <<"masque; error=http_protocol_error">>}, {
        Status, proplists:get_value(<<"proxy-status">>, Hdrs)
    }),
    raw_close(Tag, Conn).

%% RFC 9112 section 3.2 and RFC 9298 section 3.2: one Host field line.
h1_duplicate_host_refused(Config) ->
    {Status, Hdrs, H} = udp_attempt(
        Config, udp_target(Config), <<"?1">>, [{<<"Host">>, <<"other.example">>}]
    ),
    ?assertEqual({400, <<"masque; error=http_request_error">>}, {
        Status, proplists:get_value(<<"proxy-status">>, Hdrs)
    }),
    attempt_close(H).

%% RFC 9209 section 2.3: the most specific error type for each refusal.
ps_request_error(Config) ->
    expect_refusal(Config, {<<"127.0.0.1">>, <<"0">>}, 400, <<"http_request_error">>).

ps_policy_refusal(Config) ->
    expect_refusal(Config, udp_target(Config), 403, <<"destination_ip_prohibited">>).

ps_dns_error(Config) ->
    expect_refusal(Config, {<<"nx.test">>, <<"53">>}, 502, <<"dns_error">>),
    %% The client reports the status on every transport; on h1 since h1
    %% 0.13.1 returns it from a refused upgrade.
    #{port := Port} = ?config(server, Config),
    Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
    {error, Reason} = masque:connect(Uri, {<<"nx.test">>, 53}, #{
        transports => [?config(transport, Config)], verify => verify_none, timeout => 5000
    }),
    ?assertMatch({handshake_rejected, 502}, element_status(Reason)).

element_status({handshake_rejected, Status}) -> {handshake_rejected, Status};
element_status({handshake_rejected, Status, _}) -> {handshake_rejected, Status};
element_status(Other) -> Other.

ps_internal_error(Config) ->
    expect_refusal(Config, udp_target(Config), 502, <<"proxy_internal_error">>).

ps_denied(Config) ->
    expect_refusal(Config, udp_target(Config), 403, <<"http_request_denied">>).

%% A target that refuses the connection, on CONNECT-TCP: classic
%% CONNECT on h1, the raw template on h3 and h2.
ps_connection_refused(Config) ->
    {ok, Closed} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}]),
    {ok, ClosedPort} = inet:port(Closed),
    ok = gen_tcp:close(Closed),
    {Status, Hdrs} =
        case ?config(transport, Config) of
            h1 ->
                Target = iolist_to_binary(["127.0.0.1:", integer_to_list(ClosedPort)]),
                {Sock, Heads, _} = h1_raw(Config, [
                    <<"CONNECT ">>, Target, <<" HTTP/1.1\r\nHost: ">>, Target, <<"\r\n\r\n">>
                ]),
                ssl:close(Sock),
                lists:last(Heads);
            _ ->
                {Tag, Conn, Sid} = raw_request(
                    Config, tcp_request(Config, <<"connect-tcp">>, ClosedPort), <<"connect-tcp">>
                ),
                Result = raw_response(Tag, Conn, Sid),
                raw_close(Tag, Conn),
                Result
        end,
    ?assertEqual({502, <<"masque; error=connection_refused">>}, {
        Status, proplists:get_value(<<"proxy-status">>, Hdrs)
    }).

expect_refusal(Config, Target, Want, Type) ->
    {Status, Hdrs, H} = udp_attempt(Config, Target, <<"?1">>, []),
    attempt_close(H),
    ?assertEqual({Want, <<"masque; error=", Type/binary>>}, {
        Status, proplists:get_value(<<"proxy-status">>, Hdrs)
    }).

%%--------------------------------------------------------------------
%% Clients against a scripted proxy
%%--------------------------------------------------------------------

%% RFC 9297 section 3.4: the client reads the acknowledgement as a
%% Boolean, so parameters do not fail the tunnel.
client_capsule_parameters_accepted(Config) ->
    fake_script(Config, {success_status(Config), [{<<"capsule-protocol">>, <<"?1; foo=bar">>}]}),
    {ok, Sess} = fake_connect(Config, udp),
    close(Sess).

%% RFC 9297 section 3.3: a proxy stream that ends inside a capsule
%% aborts the tunnel (h3 and h2); on h1 the connection just ends.
client_truncated_capsule_at_fin(Config) ->
    fake_script(
        Config,
        {success_status(Config), [{<<"capsule-protocol">>, <<"?1">>}], <<0, 10, "abc">>}
    ),
    {ok, Sess} = fake_connect(Config, udp),
    receive
        {masque_closed, Sess, Reason} ->
            case ?config(transport, Config) of
                h1 -> ok;
                _ -> ?assertEqual(truncated_capsule, Reason)
            end
    after 5000 -> ct:fail(not_closed)
    end.

%% RFC 9297 section 3.2 and RFC 9298 section 3.5: a 2xx that carries a
%% body field, is a 204, 205 or 206, or does not acknowledge the
%% Capsule Protocol fails the tunnel.
client_bad_udp_responses(Config) ->
    Ack = {<<"capsule-protocol">>, <<"?1">>},
    fake_cases(
        Config,
        udp,
        [
            {{200, [Ack, {<<"content-type">>, <<"text/plain">>}]}, {error, malformed_response}},
            {{204, [Ack]}, {error, malformed_response}},
            {{205, [Ack]}, {error, malformed_response}},
            {{206, [Ack]}, {error, malformed_response}},
            {{200, []}, {error, capsule_protocol_not_acknowledged}},
            {
                {200, [{<<"capsule-protocol">>, <<"?0">>}]},
                {error, capsule_protocol_not_acknowledged}
            }
        ]
    ).

client_bad_ip_responses(Config) ->
    Ack = {<<"capsule-protocol">>, <<"?1">>},
    fake_cases(
        Config,
        ip,
        [
            {{204, [Ack]}, {error, malformed_response}},
            {{200, []}, {error, capsule_protocol_missing}}
        ]
    ),
    fake_script(Config, {200, [{<<"capsule-protocol">>, <<"?1;v=2">>}]}),
    {ok, Sess} = fake_connect(Config, ip),
    close(Sess).

%% CONNECT-TCP: a capsule-framed 2xx follows RFC 9297 section 3.2; a
%% raw one must not start the Capsule Protocol, parameters or not.
client_bad_tcp_responses(Config) ->
    Ack = {<<"capsule-protocol">>, <<"?1">>},
    fake_cases(Config, {tcp, capsule}, [
        {{204, [Ack]}, {error, malformed_response}},
        {{200, [Ack, {<<"content-type">>, <<"text/plain">>}]}, {error, malformed_response}}
    ]),
    fake_cases(Config, {tcp, raw}, [
        {{200, [{<<"capsule-protocol">>, <<"?1;x=1">>}]}, {error, {bad_response, capsule_protocol}}}
    ]).

%% A 2xx to CONNECT with `content-length' cannot be scripted: h2 and,
%% since quic 3.2.0, quic_h3 leave it out (RFC 9110 section 8.6). The
%% client check is covered in `masque_http_tests'.

client_h1_transfer_encoding_refused(Config) ->
    fake_cases(Config, udp, [
        {
            {101, [{<<"capsule-protocol">>, <<"?1">>}, {<<"transfer-encoding">>, <<"chunked">>}]},
            {error, malformed_response}
        }
    ]).

fake_cases(Config, Protocol, Cases) ->
    lists:foreach(
        fun({Script, Expected}) ->
            fake_script(Config, Script),
            ?assertEqual(Expected, fake_connect(Config, Protocol), Script)
        end,
        Cases
    ).

fake_script(_Config, Script) ->
    persistent_term:put({?MODULE, fake}, Script).

fake_connect(Config, Protocol) ->
    #{port := Port} = ?config(server, Config),
    Uri = iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
    {Target, Opts} =
        case Protocol of
            udp -> {{<<"fake.test">>, 443}, #{}};
            ip -> {{'*', '*'}, #{protocol => ip}};
            {tcp, Framing} -> {{<<"fake.test">>, 443}, #{protocol => tcp, tcp_framing => Framing}}
        end,
    masque:connect(
        Uri,
        Target,
        Opts#{transports => [?config(transport, Config)], verify => verify_none, timeout => 3000}
    ).

%% The listener's `fallback': the scripted status and headers, then the
%% scripted bytes and the end of the stream (or connection).
fake_reply(Transport, Conn, Sid) ->
    {Status, Headers, Bytes} =
        case persistent_term:get({?MODULE, fake}) of
            {S, H} -> {S, H, none};
            {S, H, B} -> {S, H, B}
        end,
    fake_send(Transport, Conn, Sid, Status, Headers, Bytes).

fake_send(h3, Conn, Sid, Status, Headers, Bytes) ->
    ok = quic_h3:send_response(Conn, Sid, Status, Headers),
    _ = [quic_h3:send_data(Conn, Sid, Bytes, true) || Bytes =/= none],
    ok;
fake_send(h2, Conn, Sid, Status, Headers, Bytes) ->
    ok = h2:send_response(Conn, Sid, Status, Headers),
    _ = [h2:send_data(Conn, Sid, Bytes, true) || Bytes =/= none],
    ok;
fake_send(h1, Conn, Sid, 101, Headers, Bytes) ->
    {ok, Sock, _} = h1:accept_upgrade(Conn, Sid, Headers),
    _ = [ssl:send(Sock, Bytes) || Bytes =/= none],
    %% The client reads the 101 before the connection ends.
    timer:sleep(500),
    ssl:close(Sock).

%%--------------------------------------------------------------------
%% Raw CONNECT-UDP requests on every transport
%%--------------------------------------------------------------------

udp_target(Config) ->
    {<<"127.0.0.1">>, integer_to_binary(?config(udp_port, Config))}.

success_status(Config) ->
    case ?config(transport, Config) of
        h1 -> 101;
        _ -> 200
    end.

%% A CONNECT-UDP request with `Capsule-Protocol: Cap' and `Extra'
%% fields: the final status and headers, and a handle on the stream.
udp_attempt(Config, {Host, Port}, Cap, Extra) ->
    #{port := ProxyPort} = ?config(server, Config),
    Authority = iolist_to_binary(["127.0.0.1:", integer_to_list(ProxyPort)]),
    Path = <<"/.well-known/masque/udp/", Host/binary, "/", Port/binary, "/">>,
    case ?config(transport, Config) of
        h1 ->
            Fields = [{<<"Capsule-Protocol">>, Cap} | Extra],
            {Sock, Heads, Rest} = h1_raw(Config, [
                <<"GET ">>,
                Path,
                <<" HTTP/1.1\r\nHost: ">>,
                Authority,
                <<"\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n">>,
                [[K, <<": ">>, V, <<"\r\n">>] || {K, V} <- Fields],
                <<"\r\n">>
            ]),
            {Status, Hdrs} = lists:last(Heads),
            Ref = make_ref(),
            put({h1_rest, Ref}, Rest),
            {Status, Hdrs, {h1, Sock, Ref}};
        Transport ->
            Base = [
                {<<":method">>, <<"CONNECT">>},
                {<<":scheme">>, <<"https">>},
                {<<":authority">>, Authority},
                {<<":path">>, Path}
            ],
            Proto = [{<<":protocol">>, <<"connect-udp">>} || Transport =:= h3],
            Req = Base ++ Proto ++ [{<<"capsule-protocol">>, Cap} | Extra],
            {Tag, Conn, Sid} = raw_request(Config, Req, <<"connect-udp">>),
            {Status, Hdrs} = raw_response(Tag, Conn, Sid),
            {Status, Hdrs, {Tag, Conn, Sid}}
    end.

attempt_send({h1, Sock, _}, Bin) -> ssl:send(Sock, Bin);
attempt_send({Tag, Conn, Sid}, Bin) -> raw_send(Tag, Conn, Sid, Bin).

%% The next capsule from the listener, as `{Type, Value}'.
attempt_capsule(H) ->
    attempt_capsule(H, <<>>).

attempt_capsule(H, Buf) ->
    case masque_capsule:decode(Buf) of
        {ok, {Type, Value, _Rest}} ->
            {Type, Value};
        {more, _} ->
            attempt_capsule(H, <<Buf/binary, (attempt_recv(H))/binary>>)
    end.

attempt_recv({h1, Sock, Ref}) ->
    case erase({h1_rest, Ref}) of
        Rest when is_binary(Rest), Rest =/= <<>> ->
            Rest;
        _ ->
            {ok, Bin} = ssl:recv(Sock, 0, 5000),
            Bin
    end;
attempt_recv({Tag, Conn, Sid}) ->
    receive
        {Tag, Conn, {data, Sid, Bin, _}} -> Bin
    after 5000 -> ct:fail(no_capsule)
    end.

attempt_close({h1, Sock, _}) -> ssl:close(Sock);
attempt_close({Tag, Conn, _}) -> raw_close(Tag, Conn).

datagram_capsule(Payload) ->
    iolist_to_binary(
        masque_capsule:encode(0, iolist_to_binary(masque_datagram:encode(0, Payload)))
    ).

raw_end(quic_h3, Conn, Sid) -> quic_h3:send_data(Conn, Sid, <<>>, true);
raw_end(h2, Conn, Sid) -> h2:send_data(Conn, Sid, <<>>, true).

%% Any request head on h1: the responses read (interim ones first) and
%% the bytes past the last one.
h1_raw(Config, Request) ->
    #{port := Port} = ?config(server, Config),
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
    ok = ssl:send(Sock, Request),
    {Heads, Rest} = h1_heads(Sock, <<>>, [], fun(_) -> ok end),
    {Sock, Heads, Rest}.
