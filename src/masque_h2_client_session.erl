%%% @doc Client-side MASQUE CONNECT-UDP session over HTTP/2.
%%%
%%% Mirrors `masque_client_session' but uses `erlang_h2' as the
%%% transport. HTTP/2 has no native datagram channel, so every UDP
%%% payload is wrapped in a DATAGRAM capsule (RFC 9297 §3.2) and
%%% carried on the CONNECT request stream body alongside any
%%% extension capsules.
-module(masque_h2_client_session).
-behaviour(gen_statem).

-export([start_link/3, start/3, stop/1, info/1]).
-export([send/2, send/3, recv/2, set_mode/2]).
-export([send_capsule/3]).

-export([init/1, callback_mode/0, terminate/3, code_change/4]).
-export([connecting/3, open/3, closing/3]).

-include("masque.hrl").

%% `h2:connect/3' has `sync' / `verify' / `ssl_opts' keys that
%% dialyzer does not see in its published `connect_opts()' type.
%% The scope of the suppression is exactly the single call site
%% (plus the headers builder that feeds it), keeping every other
%% check strict.
-dialyzer(
    {nowarn_function, [
        do_connect/2,
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
    target_host :: binary(),
    target_port :: 1..65535,
    uri_template :: binary(),
    capsule_proto :: boolean(),
    conn :: pid() | undefined,
    stream_id :: non_neg_integer() | undefined,
    handshake_from :: gen_statem:from() | undefined,
    timeout_ref :: reference() | undefined,
    mode :: message | queue,
    rx_buf = queue:new() :: queue:queue(binary()),
    rx_waiters = queue:new() :: queue:queue({gen_statem:from(), reference()}),
    cap_buf = <<>> :: binary(),
    max_cap :: pos_integer(),
    %% Extra request headers prepended to the CONNECT request.
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

send(Pid, Data) ->
    send(Pid, ?MASQUE_CONTEXT_ID_UDP, Data).
send(Pid, ContextId, Data) ->
    gen_statem:call(Pid, {send, ContextId, Data}).

recv(Pid, Timeout) ->
    gen_statem:call(Pid, {recv, Timeout}, Timeout + 500).

set_mode(Pid, Mode) when Mode =:= message; Mode =:= queue ->
    gen_statem:call(Pid, {set_mode, Mode}).

send_capsule(Pid, Type, Value) ->
    gen_statem:call(Pid, {send_capsule, Type, Value}).

%%====================================================================
%% gen_statem
%%====================================================================

callback_mode() -> state_functions.

init({Target, Opts, Owner}) ->
    process_flag(trap_exit, true),
    {ProxyHost, ProxyPort} = maps:get(proxy, Opts),
    {TargetHost, TargetPort} = Target,
    MRef = erlang:monitor(process, Owner),
    Mode = maps:get(mode, Opts, message),
    MaxCap = maps:get(
        max_capsule_size,
        Opts,
        ?MASQUE_DEFAULT_MAX_CAPSULE_SIZE
    ),
    Data = #data{
        owner = Owner,
        owner_ref = MRef,
        proxy_host = to_bin(ProxyHost),
        proxy_port = ProxyPort,
        target_host = to_bin(TargetHost),
        target_port = TargetPort,
        uri_template = maps:get(
            uri_template,
            Opts,
            ?MASQUE_DEFAULT_URI_TEMPLATE
        ),
        capsule_proto = maps:get(capsule_protocol, Opts, true),
        mode = Mode,
        max_cap = MaxCap,
        extra_headers = sanitise_extra_headers(
            maps:get(request_headers, Opts, [])
        ),
        pool_owner = maps:get(pool_owner, Opts, undefined)
    },
    {ok, connecting, Data, [{next_event, internal, {do_handshake, Opts}}]}.

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
connecting({call, From}, shutdown_write, Data) ->
    {keep_state, Data, [{reply, From, {error, not_ready}}]};
connecting({call, From}, {set_owner, NewOwner}, Data) ->
    {keep_state, swap_owner(NewOwner, Data), [{reply, From, ok}]};
connecting(info, {h2, _Conn, {closed, _Reason}}, Data) ->
    reply_handshake(Data, {error, peer_closed}),
    {stop, peer_closed};
connecting(
    info,
    {h2, _Conn, {goaway, LastId, _Code}},
    #data{stream_id = StreamId} = Data
) when is_integer(StreamId), StreamId > LastId ->
    reply_handshake(Data, {error, goaway}),
    {stop, goaway};
connecting(
    info,
    {h2, _Conn, {response, StreamId, Status, Headers}},
    #data{stream_id = StreamId} = Data
) ->
    cancel_timer(Data#data.timeout_ref),
    case Status of
        S when S >= 200, S < 300 ->
            case validate_response(Headers, Data) of
                ok ->
                    reply_handshake(Data, ok),
                    {next_state, open, Data#data{
                        timeout_ref = undefined,
                        handshake_from = undefined
                    }};
                {error, _} = Err ->
                    reply_handshake(Data, Err),
                    {stop, element(2, Err)}
            end;
        _ ->
            reply_handshake(Data, {error, {handshake_rejected, Status}}),
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
    {stop_and_reply, normal, [{reply, From, ok}], Data}.

open({call, From}, info, Data) ->
    {keep_state, Data, [{reply, From, session_info(Data, open)}]};
open({call, From}, {send, Payload}, Data) ->
    Reply = send_out(Data, ?MASQUE_CONTEXT_ID_UDP, Payload),
    {keep_state, Data, [{reply, From, Reply}]};
open({call, From}, {send, Ctx, Payload}, Data) ->
    Reply = send_out(Data, Ctx, Payload),
    {keep_state, Data, [{reply, From, Reply}]};
open({call, From}, {recv, Timeout}, Data) ->
    handle_recv_call(From, Timeout, Data);
open({call, From}, {set_mode, Mode}, Data) ->
    {keep_state, Data#data{mode = Mode}, [{reply, From, ok}]};
open({call, From}, shutdown_write, Data) ->
    {keep_state, Data, [{reply, From, {error, not_supported}}]};
open({call, From}, {set_owner, NewOwner}, Data) ->
    {keep_state, swap_owner(NewOwner, Data), [{reply, From, ok}]};
open({call, From}, {send_capsule, Type, Value}, Data) ->
    %% Outbound extension capsules travel on the stream as-is.
    Enc = iolist_to_binary(masque_capsule:encode(Type, Value)),
    Reply = h2:send_data(
        Data#data.conn,
        Data#data.stream_id,
        Enc,
        false
    ),
    {keep_state, Data, [{reply, From, Reply}]};
open({call, From}, stop, Data) ->
    {next_state, closing, Data, [
        {reply, From, ok},
        {next_event, internal, do_close}
    ]};
open(
    info,
    {h2, _Conn, {data, StreamId, Bytes, Fin}},
    #data{stream_id = StreamId, cap_buf = Buf, max_cap = Max} = Data
) ->
    New = <<Buf/binary, Bytes/binary>>,
    case byte_size(New) > Max of
        true -> client_stream_abort(capsule_buffer_overflow, Data);
        false -> drain_capsules(New, Fin, Data)
    end;
open(info, {timeout, TRef, {recv_timeout, From}}, Data) ->
    {keep_state, drop_waiter(TRef, From, Data)};
open(
    info,
    {h2, _Conn, {stream_reset, StreamId, _ErrorCode}},
    #data{stream_id = StreamId} = Data
) ->
    _ = notify_owner_closed(peer_reset, Data),
    {stop, peer_reset, Data};
open(info, {h2, _Conn, {closed, _Reason}}, Data) ->
    _ = notify_owner_closed(peer_closed, Data),
    {stop, peer_closed, Data};
%% RFC 9113 sec 6.8: streams above the GOAWAY last-stream-id were not
%% processed; lower ids keep running.
open(
    info,
    {h2, _Conn, {goaway, LastId, _Code}},
    #data{stream_id = StreamId} = Data
) when StreamId > LastId ->
    _ = notify_owner_closed(goaway, Data),
    {stop, goaway, Data};
open(
    info,
    {'DOWN', Ref, process, _, _},
    #data{owner_ref = Ref} = Data
) ->
    {next_state, closing, Data, [{next_event, internal, do_close}]};
open(info, _Msg, Data) ->
    {keep_state, Data}.

closing(internal, do_close, #data{conn = Conn, stream_id = StreamId} = Data) ->
    _ =
        try h2:send_data(Conn, StreamId, <<>>, true) of
            ok ->
                ok;
            _ ->
                try
                    h2:cancel(Conn, StreamId)
                catch
                    _:_ -> ok
                end
        catch
            _:_ ->
                try
                    h2:cancel(Conn, StreamId)
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
terminate(_Reason, _State, #data{} = D) ->
    cancel_all_waiters(D),
    _ = session_teardown(D),
    ok.

%% Close path abstraction: release the pooled stream back to the
%% owner, or shut down the owned h2 connection.
session_teardown(#data{pool_owner = Pool, stream_id = StreamId}) when
    is_pid(Pool), is_integer(StreamId)
->
    masque_upstream_owner:release_stream(Pool, StreamId);
session_teardown(#data{pool_owner = Pool}) when is_pid(Pool) ->
    ok;
session_teardown(#data{conn = Conn}) when is_pid(Conn) ->
    _ =
        (try
            h2:close(Conn)
        catch
            _:_ -> ok
        end),
    ok;
session_teardown(_) ->
    ok.

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

code_change(_OldVsn, State, Data, _Extra) ->
    {ok, State, Data}.

%%====================================================================
%% Transport-specific (h2)
%%====================================================================

do_connect(#data{pool_owner = PoolOwner} = Data, _Opts) when
    is_pid(PoolOwner)
->
    ReqHeaders = request_headers(Data),
    case
        masque_upstream_owner:acquire_stream(
            PoolOwner,
            ReqHeaders,
            self(),
            #{protocol => ?MASQUE_CONNECT_UDP_PROTOCOL}
        )
    of
        {ok, StreamId, Conn} -> {ok, Conn, StreamId};
        {error, _} = Err -> Err
    end;
do_connect(Data, Opts) ->
    SSLOpts = build_ssl_opts(Opts),
    ConnOpts = #{
        transport => ssl,
        ssl_opts => SSLOpts,
        sync => true,
        verify => maps:get(verify, Opts, verify_none),
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
                                    ?MASQUE_CONNECT_UDP_PROTOCOL
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

verify_h2_peer_settings(Conn) ->
    Settings = h2:get_peer_settings(Conn),
    case maps:get(enable_connect_protocol, Settings, false) of
        true -> ok;
        1 -> ok;
        _ -> {error, no_extended_connect}
    end.

%% `h2:connect/3' merges `verify'/`cacerts' and `ssl_opts' into the
%% TLS socket options. We build the SNI + ALPN bits here and leave
%% user-supplied overrides intact.
build_ssl_opts(Opts) ->
    Base = [{server_name_indication, host_to_sni(Opts)}],
    UserOpts = maps:get(ssl_opts, Opts, []),
    Base ++ UserOpts.

host_to_sni(Opts) ->
    case maps:get(proxy, Opts) of
        {H, _} when is_binary(H) -> binary_to_list(H);
        {H, _} when is_list(H) -> H;
        _ -> "localhost"
    end.

request_headers(#data{
    proxy_host = ProxyHost,
    proxy_port = ProxyPort,
    target_host = TargetHost,
    target_port = TargetPort,
    uri_template = Template,
    capsule_proto = CapProto,
    extra_headers = Extra
}) ->
    Path = masque_uri:expand(Template, #{
        target_host => TargetHost,
        target_port => TargetPort
    }),
    Authority = build_authority(ProxyHost, ProxyPort),
    Base = [
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, Authority},
        {<<":path">>, Path}
    ],
    WithCap =
        case CapProto of
            true -> Base ++ [{<<"capsule-protocol">>, <<"?1">>}];
            false -> Base
        end,
    WithCap ++ Extra.

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

%% Outbound: UDP payloads become DATAGRAM capsules whose inner
%% payload is `ContextId (varint) || UdpBytes'. Oversize payloads are
%% refused at the API boundary; capsule headers are a few extra bytes
%% and we size-check before framing.
send_out(#data{conn = Conn, stream_id = StreamId}, Ctx, Payload) when
    is_integer(Ctx), Ctx >= 0
->
    PayloadSize = iolist_size(Payload),
    case
        Ctx =:= ?MASQUE_CONTEXT_ID_UDP andalso
            PayloadSize > ?MASQUE_MAX_UDP_PAYLOAD
    of
        true ->
            {error, {payload_too_large, PayloadSize, ?MASQUE_MAX_UDP_PAYLOAD}};
        false ->
            %% Context-ID varint || UDP bytes -> DATAGRAM capsule ->
            %% stream body.
            InnerIoData = masque_datagram:encode(Ctx, Payload),
            Inner = iolist_to_binary(InnerIoData),
            Capsule = iolist_to_binary(h2_capsule:encode(datagram, Inner)),
            h2:send_data(Conn, StreamId, Capsule, false)
    end.

%%====================================================================
%% Capsule decode loop (covers both DATAGRAM and extension capsules)
%%====================================================================

drain_capsules(Buf, Fin, #data{} = Data) ->
    case h2_capsule:decode(Buf) of
        {ok, {Type, Inner}, Rest} ->
            Data2 = deliver_capsule(Type, Inner, Data),
            drain_capsules(Rest, Fin, Data2#data{cap_buf = <<>>});
        {more, _} when Fin, Buf =/= <<>> ->
            client_stream_abort(truncated_capsule, Data);
        {more, _} when Fin ->
            %% Clean END_STREAM: the proxy ended the tunnel.
            _ = notify_owner_closed(peer_fin, Data),
            {next_state, closing, Data#data{cap_buf = <<>>}, [
                {next_event, internal, do_close}
            ]};
        {more, _} ->
            {keep_state, Data#data{cap_buf = Buf}}
    end.

deliver_capsule(datagram, Inner, Data) ->
    case masque_datagram:decode(Inner) of
        {ok, {?MASQUE_CONTEXT_ID_UDP, UdpBytes}} when
            byte_size(UdpBytes) =< ?MASQUE_MAX_UDP_PAYLOAD
        ->
            deliver_packet(UdpBytes, Data);
        _ ->
            Data
    end;
deliver_capsule(Type, Inner, #data{owner = Owner} = Data) when
    is_integer(Type)
->
    Owner ! {masque_capsule, self(), Type, Inner},
    Data.

client_stream_abort(
    Reason,
    #data{
        conn = Conn,
        stream_id = StreamId,
        pool_owner = Pool
    } = Data
) ->
    case is_pid(Pool) of
        true ->
            masque_upstream_owner:release_stream(Pool, StreamId);
        false ->
            %% HTTP/2 has no `H3_MESSAGE_ERROR'; use `protocol_error' (0x1).
            _ =
                (try
                    h2:cancel(Conn, StreamId, protocol_error)
                catch
                    _:_ -> ok
                end),
            ok
    end,
    _ = notify_owner_closed(Reason, Data),
    {stop, Reason, Data}.

%%====================================================================
%% Response validation (mirrors the h3 session)
%%====================================================================

validate_response(Headers, #data{capsule_proto = CapsuleRequested}) ->
    HasContentLength = header_present(<<"content-length">>, Headers),
    HasContentType = header_present(<<"content-type">>, Headers),
    CapsuleAck =
        case header_value(<<"capsule-protocol">>, Headers) of
            <<"?1">> -> true;
            _ -> false
        end,
    if
        HasContentLength ->
            {error, malformed_response};
        HasContentType ->
            {error, malformed_response};
        CapsuleRequested andalso not CapsuleAck ->
            {error, capsule_protocol_not_acknowledged};
        true ->
            ok
    end.

header_present(Name, Headers) ->
    lists:keyfind(Name, 1, Headers) =/= false.

header_value(Name, Headers) ->
    case lists:keyfind(Name, 1, Headers) of
        {_, V} -> V;
        false -> undefined
    end.

%%====================================================================
%% Rx buffering (identical to the h3 session)
%%====================================================================

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

deliver_packet(UdpBytes, #data{mode = message, owner = Owner} = Data) ->
    Owner ! {masque_data, self(), UdpBytes},
    Data;
deliver_packet(
    UdpBytes,
    #data{
        mode = queue,
        rx_waiters = Ws,
        rx_buf = Buf
    } = Data
) ->
    case queue:out(Ws) of
        {{value, {From, TRef}}, Ws2} ->
            _ = erlang:cancel_timer(TRef),
            gen_statem:reply(From, {ok, UdpBytes}),
            Data#data{rx_waiters = Ws2};
        {empty, _} ->
            case queue:len(Buf) < 1000 of
                true -> Data#data{rx_buf = queue:in(UdpBytes, Buf)};
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

%%====================================================================
%% Misc
%%====================================================================

reply_handshake(#data{handshake_from = undefined}, _Reply) -> ok;
reply_handshake(#data{handshake_from = From}, Reply) -> gen_statem:reply(From, Reply).

session_info(
    #data{
        target_host = H,
        target_port = P,
        proxy_host = PH,
        proxy_port = PP
    },
    State
) ->
    #{
        state => State,
        transport => h2,
        proxy => {PH, PP},
        target => {H, P}
    }.

cancel_timer(undefined) ->
    ok;
cancel_timer(Ref) ->
    _ = erlang:cancel_timer(Ref),
    ok.

notify_owner_closed(Reason, #data{owner = Owner, mode = message}) ->
    Owner ! {masque_closed, self(), Reason};
notify_owner_closed(_Reason, _Data) ->
    ok.

swap_owner(NewOwner, #data{owner_ref = OldRef} = Data) ->
    _ = erlang:demonitor(OldRef, [flush]),
    NewRef = erlang:monitor(process, NewOwner),
    Data#data{owner = NewOwner, owner_ref = NewRef}.

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
