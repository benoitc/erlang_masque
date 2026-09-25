%%% @doc Client-side CONNECT-IP session (RFC 9484).
%%%
%%% One `gen_statem' per tunnel, transport-generic: the same module
%%% drives both HTTP/3 (`quic_h3', QUIC DATAGRAM frames) and HTTP/2
%%% (`erlang_h2', RFC 9297 DATAGRAM-type capsules on the stream body)
%%% by dispatching on a `transport :: h3 | h2' field — following the
%%% architecture already used by `masque_tcp_client_session'.
%%%
%%% Owner-side events (the process that called `masque:connect/3'):
%%%
%%% <ul>
%%%  <li>`{masque_ip_packet,           Sess, Packet}'</li>
%%%  <li>`{masque_address_assign,      Sess, [ip_assignment()]}'</li>
%%%  <li>`{masque_address_request,     Sess, [ip_prefix_request()]}'</li>
%%%  <li>`{masque_route_advertisement, Sess, [ip_route()]}'</li>
%%%  <li>`{masque_ip_error,            Sess, Reason}'</li>
%%%  <li>`{masque_closed,              Sess, Reason}'</li>
%%% </ul>
-module(masque_ip_client_session).
-behaviour(gen_statem).

-export([start_link/3, start/3, stop/1, info/1]).
-export([send_ip_packet/2, recv/2, set_mode/2]).
-export([
    request_addresses/2,
    assign_addresses/2,
    advertise_routes/2,
    ip_info/1
]).
-export([send_capsule/3]).

-export([init/1, callback_mode/0, terminate/3, code_change/4]).
-export([connecting/3, open/3, closing/3]).

-include("masque.hrl").
-include("masque_ip.hrl").

-dialyzer(
    {nowarn_function, [
        do_connect/2,
        verify_h3_peer_settings/1,
        verify_h2_peer_settings/1,
        request_headers/1,
        build_authority/2,
        is_ipv6_literal/1
    ]}
).

-record(data, {
    owner :: pid(),
    owner_ref :: reference(),
    proxy_host :: binary(),
    proxy_port :: inet:port_number(),
    template :: masque_uri_template:template(),
    target :: masque_uri_ip:ip_target(),
    ipproto :: masque_uri_ip:ip_ipproto(),
    transport :: h3 | h2,
    mtu :: 1280..65535,
    conn :: pid() | undefined,
    stream_id :: non_neg_integer() | undefined,
    handshake_from :: gen_statem:from() | undefined,
    timeout_ref :: reference() | undefined,
    mode :: message | queue,
    rx_buf :: queue:queue(binary()),
    rx_waiters :: queue:queue({gen_statem:from(), reference()}),
    cap_buf = <<>> :: binary(),
    max_cap :: pos_integer(),
    %% Nonzero IDs the client has sent in ADDRESS_REQUEST and not yet
    %% answered locally (used by assign_addresses/2 validation).
    peer_pending = #{} :: #{pos_integer() => true},
    %% Highest nonzero Request ID allocated for our own outbound
    %% ADDRESS_REQUEST (monotonic).
    next_req_id = 1 :: pos_integer(),
    %% Most recent server-advertised state.
    assigned = [] :: [masque_ip_capsule:address_entry()],
    routes = [] :: [masque_ip_capsule:route_entry()],
    %% Extra request headers prepended to the CONNECT-IP request.
    extra_headers = [] :: [{binary(), binary()}],
    %% When set, the conn is owned by a `masque_upstream_owner';
    %% teardown releases the stream back to the pool instead of
    %% closing the conn.
    pool_owner :: pid() | undefined
}).

%%====================================================================
%% API
%%====================================================================

start_link(Target, Opts, Owner) ->
    gen_statem:start_link(?MODULE, {Target, Opts, Owner}, []).

start(Target, Opts, Owner) ->
    gen_statem:start(?MODULE, {Target, Opts, Owner}, []).

stop(Pid) -> gen_statem:call(Pid, stop, 5000).
info(Pid) -> gen_statem:call(Pid, info, 1000).

%% @doc Send a full IP packet through the tunnel.
-spec send_ip_packet(pid(), binary()) -> ok | {error, term()}.
send_ip_packet(Pid, Packet) when is_binary(Packet) ->
    gen_statem:call(Pid, {send_ip_packet, Packet}).

%% @doc Block for the next inbound IP packet when in `queue' mode.
recv(Pid, Timeout) ->
    gen_statem:call(Pid, {recv, Timeout}, Timeout + 500).

set_mode(Pid, Mode) when Mode =:= message; Mode =:= queue ->
    gen_statem:call(Pid, {set_mode, Mode}).

%% @doc Send an ADDRESS_REQUEST capsule asking the server to assign
%% addresses matching the given prefixes. Returns the list of
%% allocated Request IDs (strictly nonzero).
-spec request_addresses(pid(), [{4 | 6, inet:ip_address(), non_neg_integer()}]) ->
    {ok, [pos_integer()]} | {error, term()}.
request_addresses(Pid, Prefixes) ->
    gen_statem:call(Pid, {request_addresses, Prefixes}).

%% @doc Send an ADDRESS_ASSIGN capsule. Nonzero Request IDs must
%% match an outstanding peer ADDRESS_REQUEST (tracked in the
%% session's pending set); ID 0 is unprompted and always accepted.
-spec assign_addresses(pid(), [masque_ip_capsule:address_entry()]) ->
    ok | {error, term()}.
assign_addresses(Pid, Assignments) ->
    gen_statem:call(Pid, {assign_addresses, Assignments}).

%% @doc Send a ROUTE_ADVERTISEMENT capsule.
-spec advertise_routes(pid(), [masque_ip_capsule:route_entry()]) ->
    ok | {error, term()}.
advertise_routes(Pid, Routes) ->
    gen_statem:call(Pid, {advertise_routes, Routes}).

-spec ip_info(pid()) -> map().
ip_info(Pid) ->
    gen_statem:call(Pid, ip_info, 1000).

send_capsule(Pid, Type, Value) ->
    gen_statem:call(Pid, {send_capsule, Type, Value}).

%%====================================================================
%% gen_statem
%%====================================================================

callback_mode() -> state_functions.

init({{Target, IPProto}, Opts, Owner}) ->
    process_flag(trap_exit, true),
    {ProxyHost, ProxyPort} = maps:get(proxy, Opts),
    MRef = erlang:monitor(process, Owner),
    Mode = maps:get(mode, Opts, message),
    Transport = maps:get(transport, Opts, h3),
    MaxCap = maps:get(
        max_capsule_size,
        Opts,
        ?MASQUE_DEFAULT_MAX_CAPSULE_SIZE
    ),
    Mtu = maps:get(mtu, Opts, 1500),
    Template = build_template(Opts, ProxyHost, ProxyPort),
    Data = #data{
        owner = Owner,
        owner_ref = MRef,
        proxy_host = to_bin(ProxyHost),
        proxy_port = ProxyPort,
        template = Template,
        target = Target,
        ipproto = IPProto,
        transport = Transport,
        mtu = Mtu,
        mode = Mode,
        rx_buf = queue:new(),
        rx_waiters = queue:new(),
        max_cap = MaxCap,
        extra_headers = sanitise_extra_headers(
            maps:get(request_headers, Opts, [])
        ),
        pool_owner = maps:get(pool_owner, Opts, undefined)
    },
    {ok, connecting, Data, [{next_event, internal, {do_handshake, Opts}}]}.

build_template(Opts, ProxyHost, ProxyPort) ->
    case maps:find(uri_template, Opts) of
        {ok, Raw} ->
            case masque_uri_ip:parse_client_template(Raw) of
                {ok, T} -> T;
                {error, Err} -> erlang:error({bad_template, Err})
            end;
        error ->
            Authority = build_authority(to_bin(ProxyHost), ProxyPort),
            Raw = <<"https://", Authority/binary, ?MASQUE_DEFAULT_IP_URI_PATH_PATTERN/binary>>,
            {ok, T} = masque_uri_ip:parse_client_template(Raw),
            T
    end.

%%====================================================================
%% States
%%====================================================================

connecting(internal, {do_handshake, Opts}, Data) ->
    case do_connect(Data, Opts) of
        {ok, Conn, StreamId} ->
            Timeout = maps:get(timeout, Opts, 5000),
            TRef = erlang:start_timer(Timeout, self(), handshake_timeout),
            {keep_state, Data#data{
                conn = Conn,
                stream_id = StreamId,
                timeout_ref = TRef
            }};
        {error, Reason} ->
            {stop, {handshake_failed, Reason}}
    end;
connecting({call, From}, handshake_await, Data) ->
    {keep_state, Data#data{handshake_from = From}};
connecting({call, From}, {set_owner, NewOwner}, Data) ->
    {keep_state, swap_owner(NewOwner, Data), [{reply, From, ok}]};
connecting(info, {Tag, _Conn, {closed, _Reason}}, Data) when
    Tag =:= quic_h3; Tag =:= h2
->
    reply_handshake(Data, {error, peer_closed}),
    {stop, peer_closed};
connecting(
    info,
    {quic_h3, _Conn, {goaway, Id}},
    #data{stream_id = StreamId} = Data
) when is_integer(StreamId), StreamId >= Id ->
    reply_handshake(Data, {error, goaway}),
    {stop, goaway};
connecting(
    info,
    {h2, _Conn, {goaway, LastId, _Code}},
    #data{stream_id = StreamId} = Data
) when is_integer(StreamId), StreamId > LastId ->
    reply_handshake(Data, {error, goaway}),
    {stop, goaway};
connecting(
    info,
    {Tag, _Conn, {response, StreamId, Status, Headers}},
    #data{stream_id = StreamId} = Data
) when
    Tag =:= quic_h3; Tag =:= h2
->
    cancel_timer(Data#data.timeout_ref),
    case Status of
        S when S >= 200, S < 300 ->
            case validate_response(Headers) of
                ok ->
                    case check_datagram_mtu(Data) of
                        ok ->
                            reply_handshake(Data, ok),
                            {next_state, open, Data#data{
                                timeout_ref = undefined,
                                handshake_from = undefined
                            }};
                        {error, _} = MtuErr ->
                            reply_handshake(Data, MtuErr),
                            {stop, element(2, MtuErr)}
                    end;
                {error, _} = Err ->
                    reply_handshake(Data, Err),
                    {stop, element(2, Err)}
            end;
        _ ->
            reply_handshake(
                Data,
                {error, {handshake_rejected, Status}}
            ),
            {stop, {handshake_rejected, Status}}
    end;
connecting(
    info,
    {timeout, TRef, handshake_timeout},
    #data{timeout_ref = TRef} = Data
) ->
    reply_handshake(Data, {error, handshake_timeout}),
    {stop, handshake_timeout};
connecting(
    info,
    {'DOWN', Ref, process, _, _},
    #data{owner_ref = Ref}
) ->
    {stop, owner_gone};
connecting(info, _Msg, Data) ->
    {keep_state, Data};
connecting({call, From}, info, Data) ->
    {keep_state, Data, [{reply, From, session_info(Data, connecting)}]};
connecting({call, From}, stop, Data) ->
    {stop_and_reply, normal, [{reply, From, ok}], Data};
connecting({call, From}, _Other, Data) ->
    {keep_state, Data, [{reply, From, {error, not_ready}}]}.

open({call, From}, info, Data) ->
    {keep_state, Data, [{reply, From, session_info(Data, open)}]};
open({call, From}, ip_info, Data) ->
    {keep_state, Data, [
        {reply, From, #{
            assigned => Data#data.assigned,
            routes => Data#data.routes,
            mtu => Data#data.mtu,
            transport => Data#data.transport
        }}
    ]};
open({call, From}, {send_ip_packet, Pkt}, Data) ->
    PktSz = byte_size(Pkt),
    case PktSz > Data#data.mtu of
        true ->
            {keep_state, Data, [{reply, From, {error, {packet_too_large, PktSz, Data#data.mtu}}}]};
        false ->
            Reply = transport_send_datagram(Data, ?MASQUE_CONTEXT_ID_IP, Pkt),
            {keep_state, Data, [{reply, From, Reply}]}
    end;
open({call, From}, {request_addresses, Prefixes}, Data) ->
    handle_request_addresses(From, Prefixes, Data);
open({call, From}, {assign_addresses, Assignments}, Data) ->
    handle_assign_addresses(From, Assignments, Data);
open({call, From}, {advertise_routes, Routes}, Data) ->
    handle_advertise_routes(From, Routes, Data);
open({call, From}, {recv, Timeout}, Data) ->
    handle_recv_call(From, Timeout, Data);
open({call, From}, {set_mode, Mode}, Data) ->
    {keep_state, Data#data{mode = Mode}, [{reply, From, ok}]};
open({call, From}, {set_owner, NewOwner}, Data) ->
    {keep_state, swap_owner(NewOwner, Data), [{reply, From, ok}]};
open({call, From}, {send_capsule, Type, Value}, Data) ->
    Enc = iolist_to_binary(masque_capsule:encode(Type, Value)),
    Reply = transport_send_data(Data, Enc, false),
    {keep_state, Data, [{reply, From, Reply}]};
open({call, From}, stop, Data) ->
    {next_state, closing, Data, [{reply, From, ok}, {next_event, internal, do_close}]};
%% H3 datagram arrival.
open(
    info,
    {quic_h3, _Conn, {datagram, StreamId, Payload}},
    #data{stream_id = StreamId} = Data
) ->
    {keep_state, handle_inbound_datagram(Payload, Data)};
%% H3 or H2 stream body (carries RFC 9297 capsules — and H2 datagrams).
open(
    info,
    {Tag, _Conn, {data, StreamId, Bytes, Fin}},
    #data{stream_id = StreamId, cap_buf = Buf, max_cap = Max} = Data
) when
    Tag =:= quic_h3; Tag =:= h2
->
    New = <<Buf/binary, Bytes/binary>>,
    case byte_size(New) > Max of
        true -> client_stream_abort(capsule_buffer_overflow, Data);
        false -> drain_capsules(New, Fin, Data)
    end;
open(
    info,
    {Tag, _Conn, {stream_reset, StreamId, _ErrorCode}},
    #data{stream_id = StreamId} = Data
) when
    Tag =:= quic_h3; Tag =:= h2
->
    _ = notify_owner_closed(peer_reset, Data),
    {stop, peer_reset, Data};
open(info, {Tag, _Conn, {closed, _Reason}}, Data) when
    Tag =:= quic_h3; Tag =:= h2
->
    _ = notify_owner_closed(peer_closed, Data),
    {stop, peer_closed, Data};
%% GOAWAY: requests the peer did not process (h3: id at or above the
%% GOAWAY id, h2: id above the last-stream-id) end; others keep running.
open(
    info,
    {quic_h3, _Conn, {goaway, Id}},
    #data{stream_id = StreamId} = Data
) when StreamId >= Id ->
    _ = notify_owner_closed(goaway, Data),
    {stop, goaway, Data};
open(
    info,
    {h2, _Conn, {goaway, LastId, _Code}},
    #data{stream_id = StreamId} = Data
) when StreamId > LastId ->
    _ = notify_owner_closed(goaway, Data),
    {stop, goaway, Data};
open(info, {timeout, TRef, {recv_timeout, From}}, Data) ->
    {keep_state, drop_waiter(TRef, From, Data)};
open(
    info,
    {'DOWN', Ref, process, _, _},
    #data{owner_ref = Ref} = Data
) ->
    {next_state, closing, Data, [{next_event, internal, do_close}]};
open(info, _Msg, Data) ->
    {keep_state, Data}.

closing(internal, do_close, Data) ->
    _ =
        try transport_send_data(Data, <<>>, true) of
            ok ->
                ok;
            _ ->
                try
                    transport_cancel(Data)
                catch
                    _:_ -> ok
                end
        catch
            _:_ ->
                try
                    transport_cancel(Data)
                catch
                    _:_ -> ok
                end
        end,
    _ = session_teardown(Data),
    {stop, normal, Data};
closing(_Event, _Msg, Data) ->
    {keep_state, Data}.

terminate(_Reason, _State, #data{conn = undefined} = D) ->
    cancel_all_waiters(D);
terminate(_Reason, _State, Data) ->
    cancel_all_waiters(Data),
    _ = session_teardown(Data),
    ok.

%% Close path abstraction: release the pooled stream back to the
%% owner, or shut down the owned transport connection.
session_teardown(#data{pool_owner = Pool, stream_id = StreamId}) when
    is_pid(Pool), is_integer(StreamId)
->
    masque_upstream_owner:release_stream(Pool, StreamId);
session_teardown(#data{pool_owner = Pool}) when is_pid(Pool) ->
    ok;
session_teardown(#data{conn = Conn} = Data) when is_pid(Conn) ->
    _ =
        (try
            transport_close(Data)
        catch
            _:_ -> ok
        end),
    ok;
session_teardown(_) ->
    ok.

code_change(_OldVsn, State, Data, _Extra) ->
    {ok, State, Data}.

%%====================================================================
%% Transport dispatch
%%====================================================================

do_connect(#data{pool_owner = PoolOwner} = Data, _Opts) when
    is_pid(PoolOwner)
->
    ReqHeaders = request_headers(Data),
    ReqOpts =
        case Data#data.transport of
            h3 -> #{end_stream => false};
            h2 -> #{protocol => ?MASQUE_CONNECT_IP_PROTOCOL}
        end,
    case
        masque_upstream_owner:acquire_stream(
            PoolOwner, ReqHeaders, self(), ReqOpts
        )
    of
        {ok, StreamId, Conn} -> {ok, Conn, StreamId};
        {error, _} = Err -> Err
    end;
do_connect(#data{transport = h3} = Data, Opts) ->
    ConnOpts = maps:with([verify, cacerts], Opts),
    ConnOpts1 = ConnOpts#{
        sync => true,
        settings => #{enable_connect_protocol => 1, h3_datagram => 1},
        h3_datagram_enabled => true,
        quic_opts => #{
            alpn => maps:get(alpn, Opts, [<<"h3">>]),
            max_datagram_frame_size => 65535
        }
    },
    case
        quic_h3:connect(
            Data#data.proxy_host,
            Data#data.proxy_port,
            ConnOpts1
        )
    of
        {ok, Conn} ->
            case verify_h3_peer_settings(Conn) of
                ok ->
                    ReqHeaders = request_headers(Data),
                    case
                        quic_h3:request(
                            Conn,
                            ReqHeaders,
                            #{end_stream => false}
                        )
                    of
                        {ok, StreamId} ->
                            {ok, Conn, StreamId};
                        {error, R} ->
                            quic_h3:close(Conn),
                            {error, {request, R}}
                    end;
                {error, _} = Err ->
                    quic_h3:close(Conn),
                    Err
            end;
        {error, Reason} ->
            {error, {connect, Reason}}
    end;
do_connect(#data{transport = h2} = Data, Opts) ->
    SSLOpts = masque_tls:client_opts(Data#data.proxy_host, Opts, [<<"h2">>]),
    ConnOpts = #{
        transport => ssl,
        ssl_opts => SSLOpts,
        sync => true,
        timeout => maps:get(timeout, Opts, 5000),
        settings => #{enable_connect_protocol => 1}
    },
    case
        h2:connect(
            Data#data.proxy_host,
            Data#data.proxy_port,
            ConnOpts
        )
    of
        {ok, Conn} ->
            case verify_h2_peer_settings(Conn) of
                ok ->
                    ReqHeaders = request_headers(Data),
                    case
                        h2:request(
                            Conn,
                            ReqHeaders,
                            #{
                                protocol =>
                                    ?MASQUE_CONNECT_IP_PROTOCOL
                            }
                        )
                    of
                        {ok, StreamId} ->
                            {ok, Conn, StreamId};
                        {error, R} ->
                            h2:close(Conn),
                            {error, {request, R}}
                    end;
                {error, _} = Err ->
                    h2:close(Conn),
                    Err
            end;
        {error, Reason} ->
            {error, {connect, Reason}}
    end.

verify_h3_peer_settings(Conn) ->
    case quic_h3:get_peer_settings(Conn) of
        undefined ->
            ok;
        Settings when is_map(Settings) ->
            ECP = maps:get(enable_connect_protocol, Settings, 0),
            H3D = maps:get(h3_datagram, Settings, 0),
            if
                ECP =/= 1 -> {error, no_extended_connect};
                H3D =/= 1 -> {error, no_h3_datagram};
                true -> ok
            end
    end.

verify_h2_peer_settings(Conn) ->
    Settings = h2:get_peer_settings(Conn),
    case maps:get(enable_connect_protocol, Settings, false) of
        true -> ok;
        1 -> ok;
        _ -> {error, no_extended_connect}
    end.

transport_send_datagram(
    #data{transport = h3, conn = C, stream_id = S},
    Ctx,
    Payload
) ->
    Enc = masque_datagram:encode(Ctx, Payload),
    quic_h3:send_datagram(C, S, Enc);
transport_send_datagram(
    #data{transport = h2, conn = C, stream_id = S},
    Ctx,
    Payload
) ->
    Inner = iolist_to_binary(masque_datagram:encode(Ctx, Payload)),
    Cap = iolist_to_binary(h2_capsule:encode(datagram, Inner)),
    h2:send_data(C, S, Cap, false).

transport_send_data(
    #data{transport = h3, conn = C, stream_id = S},
    Bytes,
    Fin
) ->
    quic_h3:send_data(C, S, Bytes, Fin);
transport_send_data(
    #data{transport = h2, conn = C, stream_id = S},
    Bytes,
    Fin
) ->
    h2:send_data(C, S, Bytes, Fin).

transport_cancel(#data{transport = h3, conn = C, stream_id = S}) ->
    quic_h3:cancel(C, S, ?MASQUE_H3_MESSAGE_ERROR);
transport_cancel(#data{transport = h2, conn = C, stream_id = S}) ->
    h2:cancel(C, S, protocol_error).

transport_close(#data{transport = h3, conn = C}) -> quic_h3:close(C);
transport_close(#data{transport = h2, conn = C}) -> h2:close(C).

request_headers(#data{
    template = T,
    target = Target,
    ipproto = IPProto,
    extra_headers = Extra
}) ->
    Url = masque_uri_ip:expand(T, #{target => Target, ipproto => IPProto}),
    %% Split the synthesised URI into :authority and :path.
    {Scheme, Authority, Path} = split_url(Url),
    Base = [
        {<<":method">>, <<"CONNECT">>},
        {<<":protocol">>, ?MASQUE_CONNECT_IP_PROTOCOL},
        {<<":scheme">>, Scheme},
        {<<":authority">>, Authority},
        {<<":path">>, Path},
        {<<"capsule-protocol">>, <<"?1">>}
    ],
    Base ++ Extra.

sanitise_extra_headers(List) when is_list(List) ->
    Reserved = [
        <<":method">>,
        <<":scheme">>,
        <<":authority">>,
        <<":path">>,
        <<":protocol">>,
        <<"capsule-protocol">>
    ],
    [
        {K, V}
     || {K, V} <- List,
        is_binary(K),
        is_binary(V),
        not lists:member(K, Reserved)
    ].

split_url(<<"https://", Rest/binary>>) ->
    {Auth, Path} = split_authority(Rest),
    {<<"https">>, Auth, Path};
split_url(<<"http://", Rest/binary>>) ->
    {Auth, Path} = split_authority(Rest),
    {<<"http">>, Auth, Path}.

split_authority(Bin) ->
    case binary:match(Bin, <<"/">>) of
        {Pos, 1} ->
            <<A:Pos/binary, P/binary>> = Bin,
            {A, P};
        nomatch ->
            {Bin, <<"/">>}
    end.

%%====================================================================
%% Inbound handlers
%%====================================================================

handle_inbound_datagram(Payload, Data) ->
    case masque_datagram:decode(Payload) of
        {ok, {?MASQUE_CONTEXT_ID_IP, IPPkt}} ->
            deliver_packet(IPPkt, Data);
        {ok, {_OtherCtx, _}} ->
            %% Unknown context IDs are silently dropped per RFC 9484 §6.
            Data;
        {error, _} ->
            Data
    end.

drain_capsules(Buf, Fin, Data) ->
    drain_capsules_1(Buf, Fin, Data).

drain_capsules_1(Buf, Fin, Data) ->
    case decode_one_capsule(Data, Buf) of
        {ok, {Type, Inner}, Rest} ->
            case deliver_capsule(Type, Inner, Data) of
                {abort, Reason} ->
                    client_stream_abort(Reason, Data);
                Data2 ->
                    drain_capsules_1(Rest, Fin, Data2#data{cap_buf = <<>>})
            end;
        {more, _} when Fin, Buf =/= <<>> ->
            client_stream_abort(truncated_capsule, Data);
        {more, _} when Fin ->
            %% Clean FIN: the proxy ended the tunnel.
            _ = notify_owner_closed(peer_fin, Data),
            {next_state, closing, Data#data{cap_buf = <<>>}, [
                {next_event, internal, do_close}
            ]};
        {more, _} ->
            {keep_state, Data#data{cap_buf = Buf}};
        {error, _} ->
            client_stream_abort(malformed_capsule, Data)
    end.

%% On H3 we use masque_capsule (which delegates to quic_h3_capsule);
%% on H2 we use h2_capsule so the `datagram` type is resolved natively.
decode_one_capsule(#data{transport = h2}, Buf) ->
    case h2_capsule:decode(Buf) of
        {ok, {datagram, Inner}, Rest} ->
            {ok, {datagram, Inner}, Rest};
        {ok, {Type, Inner}, Rest} when is_integer(Type) ->
            {ok, {Type, Inner}, Rest};
        Other ->
            Other
    end;
decode_one_capsule(#data{transport = h3}, Buf) ->
    case masque_capsule:decode(Buf) of
        {ok, {Type, Inner, Rest}} -> {ok, {Type, Inner}, Rest};
        Other -> Other
    end.

deliver_capsule(datagram, Inner, Data) ->
    %% Only reached on H2.
    handle_inbound_datagram(Inner, Data);
deliver_capsule(
    ?MASQUE_CAPSULE_ADDRESS_ASSIGN,
    Inner,
    #data{owner = Owner} = Data
) ->
    case masque_ip_capsule:decode_address_assign(Inner) of
        {ok, Entries} ->
            Owner ! {masque_address_assign, self(), Entries},
            Data#data{assigned = Entries};
        {error, _} ->
            {abort, malformed_capsule}
    end;
deliver_capsule(
    ?MASQUE_CAPSULE_ADDRESS_REQUEST,
    Inner,
    #data{owner = Owner, peer_pending = Pend} = Data
) ->
    case masque_ip_capsule:decode_address_request(Inner) of
        {ok, Entries} ->
            Owner ! {masque_address_request, self(), Entries},
            Pend1 = lists:foldl(
                fun(R, Acc) ->
                    %% #ip_prefix_request.request_id
                    Id = element(2, R),
                    Acc#{Id => true}
                end,
                Pend,
                Entries
            ),
            Data#data{peer_pending = Pend1};
        {error, _} ->
            {abort, malformed_capsule}
    end;
deliver_capsule(
    ?MASQUE_CAPSULE_ROUTE_ADVERTISEMENT,
    Inner,
    #data{owner = Owner} = Data
) ->
    case masque_ip_capsule:decode_route_advertisement(Inner) of
        {ok, Entries} ->
            Owner ! {masque_route_advertisement, self(), Entries},
            Data#data{routes = Entries};
        {error, _} ->
            {abort, malformed_capsule}
    end;
deliver_capsule(Type, Inner, #data{owner = Owner} = Data) when
    is_integer(Type)
->
    Owner ! {masque_capsule, self(), Type, Inner},
    Data.

%%====================================================================
%% Outbound control-plane
%%====================================================================

handle_request_addresses(From, Prefixes, Data) ->
    case build_request_entries(Prefixes, Data) of
        {ok, Entries, Data1} ->
            Body = masque_ip_capsule:encode_address_request(Entries),
            Cap = iolist_to_binary(
                masque_capsule:encode(
                    ?MASQUE_CAPSULE_ADDRESS_REQUEST, Body
                )
            ),
            case transport_send_data(Data1, Cap, false) of
                ok ->
                    Ids = [R#ip_prefix_request.request_id || R <- Entries],
                    {keep_state, Data1, [{reply, From, {ok, Ids}}]};
                {error, _} = Err ->
                    {keep_state, Data, [{reply, From, Err}]}
            end;
        {error, _} = Err ->
            {keep_state, Data, [{reply, From, Err}]}
    end.

build_request_entries(Prefixes, Data) ->
    try
        {Rev, Next} = lists:foldl(
            fun({V, Addr, Pfx}, {Acc, N}) ->
                ok = check_prefix(V, Addr, Pfx),
                R = #ip_prefix_request{
                    request_id = N,
                    version = V,
                    address = Addr,
                    prefix_len = Pfx
                },
                {[R | Acc], N + 1}
            end,
            {[], Data#data.next_req_id},
            Prefixes
        ),
        {ok, lists:reverse(Rev), Data#data{next_req_id = Next}}
    catch
        throw:Err -> {error, Err};
        error:_ -> {error, bad_prefix}
    end.

handle_assign_addresses(
    From,
    Assignments,
    #data{peer_pending = Pend} = Data
) ->
    case validate_assignments(Assignments, Pend) of
        {ok, Pend1} ->
            Body = masque_ip_capsule:encode_address_assign(Assignments),
            Cap = iolist_to_binary(
                masque_capsule:encode(
                    ?MASQUE_CAPSULE_ADDRESS_ASSIGN, Body
                )
            ),
            case transport_send_data(Data, Cap, false) of
                ok ->
                    {keep_state, Data#data{peer_pending = Pend1}, [{reply, From, ok}]};
                {error, _} = Err ->
                    {keep_state, Data, [{reply, From, Err}]}
            end;
        {error, _} = Err ->
            {keep_state, Data, [{reply, From, Err}]}
    end.

validate_assignments(Assignments, Pend) ->
    try
        Pend1 = lists:foldl(
            fun
                (
                    #ip_assignment{
                        request_id = 0,
                        version = V,
                        address = A,
                        prefix_len = P
                    },
                    Acc
                ) ->
                    ok = check_prefix(V, A, P),
                    Acc;
                (
                    #ip_assignment{
                        request_id = Id,
                        version = V,
                        address = A,
                        prefix_len = P
                    },
                    Acc
                ) ->
                    ok = check_prefix(V, A, P),
                    case maps:is_key(Id, Acc) of
                        true -> maps:remove(Id, Acc);
                        false -> throw({no_such_pending_request, Id})
                    end
            end,
            Pend,
            Assignments
        ),
        {ok, Pend1}
    catch
        throw:Err -> {error, Err};
        error:_ -> {error, bad_prefix}
    end.

handle_advertise_routes(From, Routes, Data) ->
    try masque_ip_capsule:encode_route_advertisement(Routes) of
        Body ->
            Cap = iolist_to_binary(
                masque_capsule:encode(
                    ?MASQUE_CAPSULE_ROUTE_ADVERTISEMENT, Body
                )
            ),
            case transport_send_data(Data, Cap, false) of
                ok -> {keep_state, Data, [{reply, From, ok}]};
                {error, _} = Err -> {keep_state, Data, [{reply, From, Err}]}
            end
    catch
        error:Reason ->
            {keep_state, Data, [{reply, From, {error, Reason}}]}
    end.

check_prefix(4, {A, B, C, D}, P) when
    P >= 0,
    P =< 32,
    A >= 0,
    A =< 255,
    B >= 0,
    B =< 255,
    C >= 0,
    C =< 255,
    D >= 0,
    D =< 255
->
    ok;
check_prefix(6, Addr, P) when P >= 0, P =< 128, tuple_size(Addr) =:= 8 ->
    true = lists:all(
        fun(X) -> is_integer(X) andalso X >= 0 andalso X =< 16#FFFF end,
        tuple_to_list(Addr)
    ),
    ok;
check_prefix(V, _, P) ->
    throw({bad_prefix_length, P, V}).

%%====================================================================
%% RFC 9484 §8 — negotiated datagram size check
%%====================================================================

%% An IPv6 CONNECT-IP tunnel requires the HTTP datagram channel to
%% carry a full 1280-byte IPv6 packet (plus the 1-byte context-id
%% varint). On H3 we check the effective max datagram size after
%% the 2xx response; on H2 there is no per-datagram size limit
%% (capsules bound only by max_capsule_size) so the check is a
%% no-op. Returns `{error, {mtu_too_low, Got, Min}}` on failure.
check_datagram_mtu(#data{transport = h3, conn = C, stream_id = S}) ->
    case quic_h3:max_datagram_size(C, S) of
        N when is_integer(N), N >= ?MASQUE_IPV6_MIN_MTU + 1 ->
            ok;
        N when is_integer(N), N > 0 ->
            {error, {mtu_too_low, N, ?MASQUE_IPV6_MIN_MTU}};
        _ ->
            %% 0 or undefined — datagrams unavailable; this was
            %% already caught in verify_h3_peer_settings.
            ok
    end;
check_datagram_mtu(#data{transport = h2}) ->
    ok.

%%====================================================================
%% Response validation
%%====================================================================

%% RFC 9297 §3.4 forbids `content-length` / `content-type` on a
%% capsule-protocol response. RFC 9484 §4 mandates
%% `capsule-protocol: ?1` echoed in the 2xx response.
validate_response(Headers) ->
    HasCL = header_present(<<"content-length">>, Headers),
    HasCT = header_present(<<"content-type">>, Headers),
    case header_value(<<"capsule-protocol">>, Headers) of
        <<"?1">> when not HasCL, not HasCT -> ok;
        <<"?1">> -> {error, malformed_response};
        _ -> {error, capsule_protocol_missing}
    end.

header_present(Name, Headers) ->
    lists:keyfind(Name, 1, Headers) =/= false.

header_value(Name, Headers) ->
    case lists:keyfind(Name, 1, Headers) of
        {_, V} -> V;
        false -> undefined
    end.

%%====================================================================
%% Misc
%%====================================================================

client_stream_abort(
    Reason,
    #data{
        pool_owner = Pool,
        stream_id = StreamId
    } = Data
) ->
    case is_pid(Pool) of
        true ->
            masque_upstream_owner:release_stream(Pool, StreamId);
        false ->
            _ =
                (try
                    transport_cancel(Data)
                catch
                    _:_ -> ok
                end),
            ok
    end,
    _ = notify_owner_closed(Reason, Data),
    {stop, Reason, Data}.

notify_owner_closed(Reason, #data{owner = Owner, mode = message}) ->
    Owner ! {masque_closed, self(), Reason};
notify_owner_closed(_, _) ->
    ok.

reply_handshake(#data{handshake_from = undefined}, _Reply) -> ok;
reply_handshake(#data{handshake_from = From}, Reply) -> gen_statem:reply(From, Reply).

session_info(
    #data{
        target = T,
        ipproto = P,
        proxy_host = PH,
        proxy_port = PP,
        transport = Transport
    },
    State
) ->
    #{
        state => State,
        protocol => ip,
        transport => Transport,
        proxy => {PH, PP},
        target => T,
        ipproto => P
    }.

cancel_timer(undefined) ->
    ok;
cancel_timer(Ref) ->
    _ = erlang:cancel_timer(Ref),
    ok.

swap_owner(NewOwner, #data{owner_ref = OldRef} = Data) ->
    _ = erlang:demonitor(OldRef, [flush]),
    NewRef = erlang:monitor(process, NewOwner),
    Data#data{owner = NewOwner, owner_ref = NewRef}.

handle_recv_call(From, Timeout, #data{rx_buf = Buf} = Data) ->
    case queue:out(Buf) of
        {{value, Bytes}, Buf2} ->
            {keep_state, Data#data{rx_buf = Buf2}, [{reply, From, {ok, Bytes}}]};
        {empty, _} ->
            TRef = erlang:start_timer(Timeout, self(), {recv_timeout, From}),
            {keep_state, Data#data{
                rx_waiters =
                    queue:in({From, TRef}, Data#data.rx_waiters)
            }}
    end.

deliver_packet(Pkt, #data{mode = message, owner = Owner} = Data) ->
    Owner ! {masque_ip_packet, self(), Pkt},
    Data;
deliver_packet(
    Pkt,
    #data{
        mode = queue,
        rx_waiters = Ws,
        rx_buf = Buf
    } = Data
) ->
    case queue:out(Ws) of
        {{value, {From, TRef}}, Ws2} ->
            _ = erlang:cancel_timer(TRef),
            gen_statem:reply(From, {ok, Pkt}),
            Data#data{rx_waiters = Ws2};
        {empty, _} ->
            case queue:len(Buf) < 1000 of
                true -> Data#data{rx_buf = queue:in(Pkt, Buf)};
                false -> Data
            end
    end.

drop_waiter(TRef, From, #data{rx_waiters = Ws} = Data) ->
    Ws2 = queue:filter(
        fun
            ({F, T}) when F =:= From, T =:= TRef ->
                gen_statem:reply(F, {error, timeout}),
                false;
            (_) ->
                true
        end,
        Ws
    ),
    Data#data{rx_waiters = Ws2}.

cancel_all_waiters(#data{rx_waiters = Ws}) ->
    _ = queue:fold(
        fun({From, TRef}, _) ->
            _ = erlang:cancel_timer(TRef),
            gen_statem:reply(From, {error, closed}),
            ok
        end,
        ok,
        Ws
    ),
    ok.

to_bin(X) when is_binary(X) -> X;
to_bin(X) when is_list(X) -> list_to_binary(X);
to_bin(X) when is_atom(X) -> atom_to_binary(X, utf8).

build_authority(Host, Port) ->
    HostPart =
        case is_ipv6_literal(Host) of
            true -> <<"[", Host/binary, "]">>;
            false -> Host
        end,
    iolist_to_binary([HostPart, ":", integer_to_binary(Port)]).

is_ipv6_literal(Host) ->
    case inet:parse_address(binary_to_list(Host)) of
        {ok, {_, _, _, _, _, _, _, _}} -> true;
        _ -> false
    end.
