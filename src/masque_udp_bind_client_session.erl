%%% @doc Connect-UDP-Bind client session for h2 / h3
%%% (draft-ietf-masque-connect-udp-listen-11). Sibling of
%%% `masque_client_session' / `masque_ip_client_session'; one module
%%% serves both transports by dispatching on a `transport' field.
%%%
%%% Public API surfaced via `masque':
%%%
%%% <ul>
%%%   <li>`masque:bind_connect/3' opens the tunnel.</li>
%%%   <li>`masque:send_to/3' sends a UDP payload to a peer.</li>
%%%   <li>`masque:assign_compression/2',
%%%       `masque:open_uncompressed_context/1',
%%%       `masque:close_compression/2' drive the compression-table
%%%       lifecycle.</li>
%%%   <li>`masque:proxy_public_address/1' reads the parsed
%%%       `Proxy-Public-Address' list.</li>
%%% </ul>
%%%
%%% Owner messages (sent to the `owner' pid passed in opts):
%%%
%%% <ul>
%%%   <li>`{masque_bind_packet, Sess, {IP, Port}, UdpPayload}'</li>
%%%   <li>`{masque_compression_assigned, Sess, ContextId, Peer}'</li>
%%%   <li>`{masque_compression_acked, Sess, ContextId}'</li>
%%%   <li>`{masque_compression_closed, Sess, ContextId}'</li>
%%%   <li>`{masque_closed, Sess, Reason}'</li>
%%% </ul>
-module(masque_udp_bind_client_session).
-behaviour(gen_statem).

-export([start_link/3, start/3, stop/1, info/1]).
-export([send_to/3, recv/2, set_mode/2]).
-export([
    assign_compression/2,
    open_uncompressed_context/1,
    close_compression/2,
    proxy_public_address/1
]).
-export([send_capsule/3]).

-export([init/1, callback_mode/0, terminate/3, code_change/4]).
-export([connecting/3, open/3, closing/3]).

-include("masque.hrl").
-include("masque_udp_bind.hrl").

-dialyzer({nowarn_function, [do_connect/2, build_authority/2]}).

-record(data, {
    owner :: pid(),
    owner_ref :: reference(),
    proxy_host :: binary(),
    proxy_port :: inet:port_number(),
    template :: masque_uri_template:template(),
    bind_target :: unscoped | {Host :: binary(), Port :: 1..65535},
    bind_scope :: scoped | unscoped,
    transport :: h2 | h3,
    conn :: pid() | undefined,
    stream_id :: non_neg_integer() | undefined,
    handshake_from :: gen_statem:from() | undefined,
    timeout_ref :: reference() | undefined,
    mode :: message | queue,
    rx_buf :: queue:queue({inet:ip_address(), inet:port_number(), binary()}),
    rx_waiters :: queue:queue({gen_statem:from(), reference()}),
    cap_buf = <<>> :: binary(),
    max_cap :: pos_integer(),
    extra_headers = [] :: [{binary(), binary()}],
    public_addresses :: [{inet:ip_address(), inet:port_number()}],
    own_table :: masque_compression_table:state() | undefined,
    peer_table :: masque_compression_table:state() | undefined
}).

-define(CLIENT_ROLE, client).

%%====================================================================
%% Public API
%%====================================================================

%% Target shape:
%%   unscoped              - bind socket can talk to any peer the
%%                           proxy's policy allows.
%%   {Host :: binary(), Port :: 1..65535}
%%                         - scoped bind: proxy enforces the peer.
start_link(Target, Opts, Owner) ->
    gen_statem:start_link(?MODULE, {Target, Opts, Owner}, []).

start(Target, Opts, Owner) ->
    gen_statem:start(?MODULE, {Target, Opts, Owner}, []).

stop(Pid) -> gen_statem:call(Pid, stop, 5000).
info(Pid) -> gen_statem:call(Pid, info, 1000).

send_to(Pid, {IP, Port}, Bytes) when
    is_binary(Bytes),
    is_integer(Port),
    Port >= 0,
    Port =< 65535
->
    gen_statem:call(Pid, {send_to, {IP, Port}, Bytes}).

recv(Pid, Timeout) ->
    gen_statem:call(Pid, {recv, Timeout}, Timeout + 500).

set_mode(Pid, Mode) when Mode =:= message; Mode =:= queue ->
    gen_statem:call(Pid, {set_mode, Mode}).

assign_compression(Pid, Peer) ->
    gen_statem:call(Pid, {assign_compression, Peer}).

open_uncompressed_context(Pid) ->
    gen_statem:call(Pid, open_uncompressed_context).

close_compression(Pid, ContextId) ->
    gen_statem:call(Pid, {close_compression, ContextId}).

proxy_public_address(Pid) ->
    gen_statem:call(Pid, proxy_public_address).

send_capsule(Pid, Type, Value) ->
    gen_statem:call(Pid, {send_capsule, Type, Value}).

%%====================================================================
%% gen_statem
%%====================================================================

callback_mode() -> state_functions.

init({Target, Opts, Owner}) ->
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
    Template = build_template(Opts, ProxyHost, ProxyPort),
    Scope =
        case Target of
            unscoped -> unscoped;
            {_, _} -> scoped
        end,
    Data = #data{
        owner = Owner,
        owner_ref = MRef,
        proxy_host = to_bin(ProxyHost),
        proxy_port = ProxyPort,
        template = Template,
        bind_target = Target,
        bind_scope = Scope,
        transport = Transport,
        mode = Mode,
        rx_buf = queue:new(),
        rx_waiters = queue:new(),
        max_cap = MaxCap,
        extra_headers = maps:get(request_headers, Opts, []),
        public_addresses = []
    },
    {ok, connecting, Data, [{next_event, internal, {do_handshake, Opts}}]}.

build_template(Opts, ProxyHost, ProxyPort) ->
    case maps:find(uri_template, Opts) of
        {ok, Raw} ->
            case masque_uri_template:parse_absolute(Raw) of
                {ok, T} -> T;
                {error, _} -> erlang:error(bad_template)
            end;
        error ->
            Authority = build_authority(to_bin(ProxyHost), ProxyPort),
            Raw = <<"https://", Authority/binary, ?MASQUE_DEFAULT_URI_TEMPLATE/binary>>,
            {ok, T} = masque_uri_template:parse_absolute(Raw),
            T
    end.

%%====================================================================
%% State: connecting
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
connecting({call, From}, _Other, Data) ->
    %% No outbound API works before the handshake completes.
    {keep_state, Data, [{reply, From, {error, not_ready}}]};
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
                {ok, Addrs} ->
                    Families = lists:usort([
                        family_of(IP)
                     || {IP, _} <- Addrs
                    ]),
                    TableOpts = #{advertised_families => Families},
                    Data1 = Data#data{
                        timeout_ref = undefined,
                        handshake_from = undefined,
                        public_addresses = Addrs,
                        own_table = masque_compression_table:new_own(
                            ?CLIENT_ROLE, TableOpts
                        ),
                        peer_table = masque_compression_table:new_peer(
                            ?CLIENT_ROLE, TableOpts
                        )
                    },
                    reply_handshake(Data, ok),
                    {next_state, open, Data1};
                {error, Reason} ->
                    reply_handshake(Data, {error, Reason}),
                    {stop, {handshake_failed, Reason}}
            end;
        _ ->
            reply_handshake(Data, {error, {bad_status, Status}}),
            {stop, {handshake_failed, {bad_status, Status}}}
    end;
connecting(info, {Tag, _Conn, {closed, _Reason}}, Data) when
    Tag =:= quic_h3; Tag =:= h2
->
    reply_handshake(Data, {error, peer_closed}),
    {stop, peer_closed, Data};
connecting(
    info,
    {quic_h3, _Conn, {goaway, Id}},
    #data{stream_id = StreamId} = Data
) when is_integer(StreamId), StreamId >= Id ->
    reply_handshake(Data, {error, goaway}),
    {stop, goaway, Data};
connecting(
    info,
    {h2, _Conn, {goaway, LastId, _Code}},
    #data{stream_id = StreamId} = Data
) when is_integer(StreamId), StreamId > LastId ->
    reply_handshake(Data, {error, goaway}),
    {stop, goaway, Data};
connecting(
    info,
    {timeout, TRef, handshake_timeout},
    #data{timeout_ref = TRef} = Data
) ->
    reply_handshake(Data, {error, handshake_timeout}),
    {stop, handshake_timeout, Data};
connecting(
    info,
    {'DOWN', Ref, process, _, _},
    #data{owner_ref = Ref}
) ->
    {stop, owner_gone};
connecting(info, _Msg, Data) ->
    {keep_state, Data}.

%%====================================================================
%% State: open
%%====================================================================

open({call, From}, handshake_await, Data) ->
    {keep_state, Data, [{reply, From, ok}]};
open({call, From}, info, Data) ->
    {keep_state, Data, [{reply, From, session_info(Data, open)}]};
open({call, From}, {send_to, Peer, Bytes}, Data) ->
    {Reply, Data1} = handle_send_to(Peer, Bytes, Data),
    {keep_state, Data1, [{reply, From, Reply}]};
open({call, From}, {recv, Timeout}, Data) ->
    handle_recv_call(From, Timeout, Data);
open({call, From}, {set_mode, Mode}, Data) ->
    {keep_state, Data#data{mode = Mode}, [{reply, From, ok}]};
open({call, From}, {assign_compression, {IP, Port}}, Data) ->
    handle_assign_compression(From, {IP, Port}, Data);
open({call, From}, open_uncompressed_context, Data) ->
    handle_open_uncompressed_context(From, Data);
open({call, From}, {close_compression, Id}, Data) ->
    handle_close_compression(From, Id, Data);
open({call, From}, proxy_public_address, Data) ->
    {keep_state, Data, [{reply, From, {ok, Data#data.public_addresses}}]};
open({call, From}, {send_capsule, Type, Value}, Data) ->
    Bytes = iolist_to_binary(masque_capsule:encode(Type, Value)),
    Reply = transport_send_data(Data, Bytes, false),
    {keep_state, Data, [{reply, From, Reply}]};
open({call, From}, stop, Data) ->
    {next_state, closing, Data, [
        {reply, From, ok},
        {next_event, internal, do_close}
    ]};
open(
    info,
    {h2_datagram, _Conn, StreamId, Payload},
    #data{transport = h2, stream_id = StreamId} = Data
) ->
    {keep_state, handle_inbound_datagram(Payload, Data)};
open(
    info,
    {quic_h3, _Conn, {datagram, StreamId, Payload}},
    #data{transport = h3, stream_id = StreamId} = Data
) ->
    {keep_state, handle_inbound_datagram(Payload, Data)};
open(
    info,
    {Tag, _Conn, {data, StreamId, Bytes, Fin}},
    #data{
        stream_id = StreamId,
        cap_buf = Buf,
        max_cap = Max
    } = Data
) when
    Tag =:= quic_h3; Tag =:= h2
->
    New = <<Buf/binary, Bytes/binary>>,
    case byte_size(New) > Max of
        true -> {stop, capsule_buffer_overflow};
        false -> drain_capsules(New, Fin, Data)
    end;
open(
    info,
    {Tag, _Conn, {stream_reset, StreamId, _Code}},
    #data{stream_id = StreamId}
) when
    Tag =:= quic_h3; Tag =:= h2
->
    {stop, peer_reset};
open(info, {Tag, _Conn, {closed, _Reason}}, _Data) when
    Tag =:= h2; Tag =:= quic_h3
->
    {stop, peer_closed};
%% GOAWAY: requests the peer did not process (h3: id at or above the
%% GOAWAY id, h2: id above the last-stream-id) end; others keep running.
open(info, {quic_h3, _Conn, {goaway, Id}}, #data{stream_id = StreamId}) when
    StreamId >= Id
->
    {stop, goaway};
open(
    info,
    {h2, _Conn, {goaway, LastId, _Code}},
    #data{stream_id = StreamId}
) when StreamId > LastId ->
    {stop, goaway};
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

%%====================================================================
%% State: closing
%%====================================================================

closing(
    internal,
    do_close,
    #data{
        transport = h3,
        conn = Conn,
        stream_id = StreamId
    } = Data
) ->
    _ =
        (try
            quic_h3:send_data(Conn, StreamId, <<>>, true)
        catch
            _:_ -> ok
        end),
    {stop, normal, Data};
closing(
    internal,
    do_close,
    #data{
        transport = h2,
        conn = Conn,
        stream_id = StreamId
    } = Data
) ->
    _ =
        (try
            h2:send_data(Conn, StreamId, <<>>, true)
        catch
            _:_ -> ok
        end),
    {stop, normal, Data};
closing(_, _, Data) ->
    {keep_state, Data}.

%%====================================================================
%% terminate / code_change
%%====================================================================

terminate(Reason, _State, #data{owner = Owner, mode = message}) ->
    Owner ! {masque_closed, self(), Reason},
    ok;
terminate(_Reason, _State, _Data) ->
    ok.

code_change(_OldVsn, State, Data, _Extra) ->
    {ok, State, Data}.

%%====================================================================
%% Send path
%%====================================================================

handle_send_to({IP, Port}, Bytes, Data) ->
    Tuple = {family_of(IP), IP, Port},
    case
        masque_compression_table:lookup_by_tuple(
            Data#data.own_table, Tuple
        )
    of
        {ok, #compression_entry{
            state = installed,
            ip_version = 0
        }} ->
            send_uncompressed(Tuple, Bytes, Data);
        {ok, #compression_entry{
            state = installed,
            context_id = Id,
            ip_version = V
        }} when
            V =:= 4; V =:= 6
        ->
            send_compressed_inline(Id, Bytes, Data);
        _ ->
            try_uncompressed_fallback(Tuple, Bytes, Data)
    end.

try_uncompressed_fallback(Tuple, Bytes, Data) ->
    case find_peer_uncompressed(Data#data.peer_table) of
        {ok, Id} ->
            case
                masque_udp_bind_payload:encode_uncompressed(
                    Tuple, Bytes, advertised_families(Data)
                )
            of
                {ok, Inner} ->
                    {ok, send_datagram(Id, Inner, Data)};
                {error, _} = E ->
                    {E, Data}
            end;
        not_found ->
            {{error, no_compression_context}, Data}
    end.

find_peer_uncompressed(Table) ->
    case
        [
            E
         || E <- masque_compression_table:entries(Table),
            E#compression_entry.ip_version =:= 0
        ]
    of
        [#compression_entry{context_id = Id} | _] -> {ok, Id};
        [] -> not_found
    end.

send_uncompressed(Tuple, Bytes, Data) ->
    case find_own_uncompressed(Data#data.own_table) of
        {ok, Id} ->
            case
                masque_udp_bind_payload:encode_uncompressed(
                    Tuple, Bytes, advertised_families(Data)
                )
            of
                {ok, Inner} ->
                    {ok, send_datagram(Id, Inner, Data)};
                {error, _} = E ->
                    {E, Data}
            end;
        not_found ->
            {{error, no_uncompressed_context}, Data}
    end.

find_own_uncompressed(Table) ->
    case
        [
            E
         || E <- masque_compression_table:entries(Table),
            E#compression_entry.ip_version =:= 0,
            E#compression_entry.state =:= installed
        ]
    of
        [#compression_entry{context_id = Id} | _] -> {ok, Id};
        [] -> not_found
    end.

send_compressed_inline(Id, Bytes, Data) ->
    Inner = masque_udp_bind_payload:encode_compressed(Bytes),
    {ok, send_datagram(Id, Inner, Data)}.

send_datagram(
    Ctx,
    Inner,
    #data{
        transport = h3,
        conn = C,
        stream_id = Sid
    } = Data
) ->
    Enc = masque_datagram:encode(Ctx, Inner),
    _ = quic_h3:send_datagram(C, Sid, Enc),
    Data;
send_datagram(Ctx, Inner, #data{transport = h2} = Data) ->
    Inner1 = iolist_to_binary(masque_datagram:encode(Ctx, Inner)),
    Cap = h2_capsule:encode(datagram, Inner1),
    _ = transport_send_data(Data, iolist_to_binary(Cap), false),
    Data.

%%====================================================================
%% Compression API handlers
%%====================================================================

handle_assign_compression(From, {IP, Port}, Data) ->
    Tuple = {family_of(IP), IP, Port},
    case
        masque_compression_table:open_compressed(
            Data#data.own_table, Tuple
        )
    of
        {ok, Entry, T2} ->
            Bytes = iolist_to_binary(
                masque_compression_capsule:encode(
                    #compression_assign{
                        context_id = Entry#compression_entry.context_id,
                        ip_version = Entry#compression_entry.ip_version,
                        address = Entry#compression_entry.address,
                        port = Entry#compression_entry.port
                    }
                )
            ),
            _ = transport_send_data(Data, Bytes, false),
            {keep_state, Data#data{own_table = T2}, [
                {reply, From, {ok, Entry#compression_entry.context_id}}
            ]};
        {error, Reason} ->
            {keep_state, Data, [{reply, From, {error, Reason}}]}
    end.

handle_open_uncompressed_context(From, Data) ->
    case
        masque_compression_table:open_uncompressed(
            Data#data.own_table
        )
    of
        {ok, Entry, T2} ->
            Bytes = iolist_to_binary(
                masque_compression_capsule:encode(
                    #compression_assign{
                        context_id = Entry#compression_entry.context_id,
                        ip_version = 0,
                        address = undefined,
                        port = undefined
                    }
                )
            ),
            _ = transport_send_data(Data, Bytes, false),
            {keep_state, Data#data{own_table = T2}, [
                {reply, From, {ok, Entry#compression_entry.context_id}}
            ]};
        {error, Reason} ->
            {keep_state, Data, [{reply, From, {error, Reason}}]}
    end.

handle_close_compression(From, Id, Data) ->
    %% Close on whichever side owns the ID. Try the own table first.
    case
        masque_compression_table:install_close(
            Data#data.own_table, #compression_close{context_id = Id}
        )
    of
        {ok, OT2} ->
            _ = send_close_capsule(Id, Data),
            {keep_state, Data#data{own_table = OT2}, [{reply, From, ok}]};
        {error, unknown_context} ->
            case
                masque_compression_table:install_close(
                    Data#data.peer_table,
                    #compression_close{context_id = Id}
                )
            of
                {ok, PT2} ->
                    _ = send_close_capsule(Id, Data),
                    {keep_state, Data#data{peer_table = PT2}, [{reply, From, ok}]};
                {error, _} = E ->
                    {keep_state, Data, [{reply, From, E}]}
            end
    end.

send_close_capsule(Id, Data) ->
    Bytes = iolist_to_binary(
        masque_compression_capsule:encode(
            #compression_close{context_id = Id}
        )
    ),
    transport_send_data(Data, Bytes, false).

%%====================================================================
%% Inbound datagram + capsule paths
%%====================================================================

handle_inbound_datagram(Payload, Data) ->
    case masque_datagram:decode(Payload) of
        {ok, {0, Inner}} ->
            handle_context_zero(Inner, Data);
        {ok, {Ctx, Inner}} when is_integer(Ctx), Ctx > 0 ->
            handle_known_context(Ctx, Inner, Data);
        {error, _} ->
            Data
    end.

handle_context_zero(Inner, #data{bind_scope = scoped} = Data) ->
    %% Scoped bind: context-id 0 is raw UDP to the scoped peer; we
    %% don't have the peer tuple in-band so we surface the bytes
    %% with a `scoped' marker.
    deliver_bind_packet({Data#data.bind_target, scoped}, Inner, Data);
handle_context_zero(_Inner, Data) ->
    Data.

handle_known_context(Ctx, Inner, Data) ->
    case lookup_context(Ctx, Data) of
        {ok, #compression_entry{ip_version = 0}} ->
            case masque_udp_bind_payload:decode_uncompressed(Inner) of
                {ok, {_V, IP, Port}, UdpPayload} ->
                    deliver_bind_packet({IP, Port}, UdpPayload, Data);
                {error, _} ->
                    Data
            end;
        {ok, #compression_entry{ip_version = V, address = A, port = P}} when
            V =:= 4; V =:= 6
        ->
            deliver_bind_packet({A, P}, Inner, Data);
        not_found ->
            Data
    end.

%% A context carries datagrams both ways: the proxy replies on the
%% contexts we opened (own table) as well as on its own (peer table).
lookup_context(Ctx, #data{peer_table = PT, own_table = OT}) ->
    case masque_compression_table:lookup_by_id(PT, Ctx) of
        not_found ->
            case masque_compression_table:lookup_by_id(OT, Ctx) of
                {ok, #compression_entry{state = installed}} = Found -> Found;
                _ -> not_found
            end;
        Found ->
            Found
    end.

deliver_bind_packet(
    PeerOrTagged,
    Bytes,
    #data{mode = message, owner = Owner} = Data
) ->
    Peer =
        case PeerOrTagged of
            {T, scoped} -> T;
            T -> T
        end,
    Owner ! {masque_bind_packet, self(), Peer, Bytes},
    Data;
deliver_bind_packet(
    PeerOrTagged,
    Bytes,
    #data{mode = queue, rx_buf = Q, rx_waiters = Ws} = Data
) ->
    Peer =
        case PeerOrTagged of
            {T, scoped} -> T;
            T -> T
        end,
    case queue:out(Ws) of
        {{value, {From, TRef}}, Ws2} ->
            _ = erlang:cancel_timer(TRef),
            gen_statem:reply(From, {ok, Peer, Bytes}),
            Data#data{rx_waiters = Ws2};
        {empty, _} ->
            Data#data{rx_buf = queue:in({Peer, Bytes}, Q)}
    end.

drain_capsules(Buf, Fin, Data) ->
    case masque_capsule:decode(Buf) of
        {ok, {Type, Value, Rest}} ->
            case dispatch_capsule(Type, Value, Data) of
                {ok, Data2} ->
                    drain_capsules(Rest, Fin, Data2#data{cap_buf = <<>>});
                {stop, R} ->
                    {stop, R, Data}
            end;
        {more, _} when Fin, Buf =/= <<>> ->
            {stop, truncated_capsule, Data};
        {more, _} when Fin ->
            %% Clean FIN: the proxy ended the tunnel. Send ours back.
            {next_state, closing, Data#data{cap_buf = <<>>}, [
                {next_event, internal, do_close}
            ]};
        {more, _} ->
            {keep_state, Data#data{cap_buf = Buf}};
        {error, _} ->
            {stop, malformed_capsule}
    end.

dispatch_capsule(?MASQUE_CAPSULE_COMPRESSION_ASSIGN, Body, Data) ->
    case masque_compression_capsule:decode_assign(Body) of
        {ok, A} ->
            case masque_compression_table:install(Data#data.peer_table, A) of
                {ok, T2} ->
                    Owner = Data#data.owner,
                    Owner !
                        {masque_compression_assigned, self(), A#compression_assign.context_id, {
                            A#compression_assign.address, A#compression_assign.port
                        }},
                    %% Send ACK for the new mapping.
                    Bytes = iolist_to_binary(
                        masque_compression_capsule:encode(
                            #compression_ack{
                                context_id =
                                    A#compression_assign.context_id
                            }
                        )
                    ),
                    _ = transport_send_data(Data, Bytes, false),
                    {ok, Data#data{peer_table = T2}};
                {error, _} ->
                    {stop, malformed_capsule}
            end;
        {error, _} ->
            {stop, malformed_capsule}
    end;
dispatch_capsule(?MASQUE_CAPSULE_COMPRESSION_ACK, Body, Data) ->
    case masque_compression_capsule:decode_ack(Body) of
        {ok, Ack} ->
            case
                masque_compression_table:install_ack(
                    Data#data.own_table, Ack
                )
            of
                {ok, T2} ->
                    Owner = Data#data.owner,
                    Owner ! {masque_compression_acked, self(), Ack#compression_ack.context_id},
                    {ok, Data#data{own_table = T2}};
                {error, _} ->
                    {stop, malformed_capsule}
            end;
        {error, _} ->
            {stop, malformed_capsule}
    end;
dispatch_capsule(?MASQUE_CAPSULE_COMPRESSION_CLOSE, Body, Data) ->
    case masque_compression_capsule:decode_close(Body) of
        {ok, C} ->
            Id = C#compression_close.context_id,
            %% Try peer table first (server-originated mapping).
            case
                masque_compression_table:install_close(
                    Data#data.peer_table, C
                )
            of
                {ok, T2} ->
                    Data#data.owner !
                        {masque_compression_closed, self(), Id},
                    {ok, Data#data{peer_table = T2}};
                {error, unknown_context} ->
                    case
                        masque_compression_table:install_close(
                            Data#data.own_table, C
                        )
                    of
                        {ok, T2} ->
                            Data#data.owner !
                                {masque_compression_closed, self(), Id},
                            {ok, Data#data{own_table = T2}};
                        {error, _} ->
                            {stop, malformed_capsule}
                    end
            end;
        {error, _} ->
            {stop, malformed_capsule}
    end;
dispatch_capsule(0, Value, #data{transport = h2} = Data) ->
    %% h2 carries HTTP datagrams as RFC 9297 DATAGRAM capsules (type 0).
    {ok, handle_inbound_datagram(Value, Data)};
dispatch_capsule(_Type, _Value, Data) ->
    %% Unknown / unrelated capsules: silently drop per RFC 9297.
    {ok, Data}.

%%====================================================================
%% Recv (queue mode)
%%====================================================================

handle_recv_call(
    From,
    Timeout,
    #data{
        rx_buf = Q,
        rx_waiters = Ws
    } = Data
) ->
    case queue:out(Q) of
        {{value, {Peer, Bytes}}, Q2} ->
            {keep_state, Data#data{rx_buf = Q2}, [{reply, From, {ok, Peer, Bytes}}]};
        {empty, _} ->
            TRef = erlang:start_timer(
                Timeout,
                self(),
                {recv_timeout, From}
            ),
            {keep_state, Data#data{rx_waiters = queue:in({From, TRef}, Ws)}}
    end.

drop_waiter(TRef, From, #data{rx_waiters = Ws} = Data) ->
    Filtered = queue:filter(
        fun({F, T}) -> not (F =:= From andalso T =:= TRef) end,
        Ws
    ),
    gen_statem:reply(From, {error, timeout}),
    Data#data{rx_waiters = Filtered}.

%%====================================================================
%% Handshake helpers
%%====================================================================

do_connect(#data{transport = h3} = Data, Opts) ->
    ConnOpts0 = maps:with([verify, cacerts], Opts),
    ConnOpts = ConnOpts0#{
        sync => true,
        timeout => maps:get(timeout, Opts, 5000),
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
            ConnOpts
        )
    of
        {ok, Conn} ->
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
                    _ =
                        (try
                            quic_h3:close(Conn)
                        catch
                            _:_ -> ok
                        end),
                    {error, {request, R}}
            end;
        {error, R} ->
            {error, {connect, R}}
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
            ReqHeaders = request_headers(Data),
            case
                h2:request(
                    Conn,
                    ReqHeaders,
                    #{protocol => ?MASQUE_CONNECT_UDP_PROTOCOL}
                )
            of
                {ok, StreamId} ->
                    {ok, Conn, StreamId};
                {error, R} ->
                    _ =
                        (try
                            h2:close(Conn)
                        catch
                            _:_ -> ok
                        end),
                    {error, {request, R}}
            end;
        {error, R} ->
            {error, {connect, R}}
    end.

request_headers(#data{} = Data) ->
    Path = expand_path(Data#data.bind_target),
    Authority = build_authority(
        Data#data.proxy_host,
        Data#data.proxy_port
    ),
    Base = [
        {<<":method">>, <<"CONNECT">>},
        {<<":protocol">>, ?MASQUE_CONNECT_UDP_PROTOCOL},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, Authority},
        {<<":path">>, Path},
        {<<"capsule-protocol">>, <<"?1">>},
        masque_uri_udp_bind:format_bind_header()
    ],
    Base ++ Data#data.extra_headers.

expand_path(unscoped) ->
    masque_uri_udp_bind:expand(default_template_bin(), unscoped);
expand_path({Host, Port}) ->
    masque_uri_udp_bind:expand(
        default_template_bin(),
        {to_bin(Host), Port}
    ).

default_template_bin() ->
    <<"https://h", ?MASQUE_DEFAULT_URI_TEMPLATE/binary>>.

%%====================================================================
%% Response validation: both Connect-UDP-Bind: ?1 AND
%% Proxy-Public-Address are required per draft-11.
%%====================================================================

validate_response(Headers) ->
    case masque_uri_udp_bind:parse_bind_header(Headers) of
        bind ->
            case masque_uri_udp_bind:parse_proxy_public_address(Headers) of
                {ok, Addrs} -> {ok, Addrs};
                {error, _} -> {error, missing_proxy_public_address}
            end;
        _ ->
            {error, missing_bind_response_header}
    end.

%%====================================================================
%% Misc
%%====================================================================

advertised_families(#data{public_addresses = Addrs}) ->
    lists:usort([family_of(IP) || {IP, _} <- Addrs]).

family_of({_, _, _, _}) -> 4;
family_of({_, _, _, _, _, _, _, _}) -> 6.

reply_handshake(#data{handshake_from = undefined}, _Reply) -> ok;
reply_handshake(#data{handshake_from = From}, Reply) -> gen_statem:reply(From, Reply).

cancel_timer(undefined) ->
    ok;
cancel_timer(Ref) ->
    _ = erlang:cancel_timer(Ref),
    ok.

session_info(#data{transport = T, bind_scope = Scope}, State) ->
    #{
        state => State,
        protocol => udp_bind,
        transport => T,
        bind => Scope
    }.

transport_send_data(
    #data{transport = h3, conn = C, stream_id = Sid},
    Bytes,
    Fin
) ->
    case quic_h3:send_data(C, Sid, Bytes, Fin) of
        ok -> ok;
        Err -> Err
    end;
transport_send_data(
    #data{transport = h2, conn = C, stream_id = Sid},
    Bytes,
    _Fin
) ->
    case h2:send_data(C, Sid, Bytes) of
        ok -> ok;
        Err -> Err
    end.

build_authority(Host, Port) ->
    iolist_to_binary([Host, ":", integer_to_binary(Port)]).

to_bin(B) when is_binary(B) -> B;
to_bin(L) when is_list(L) -> iolist_to_binary(L).
