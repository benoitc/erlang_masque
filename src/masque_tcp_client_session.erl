%%% @doc Client-side MASQUE CONNECT-TCP session.
%%%
%%% TCP data travels as raw bytes on the HTTP request/response stream
%%% body - no datagrams, no context-IDs, no capsule wrapping for the
%%% base case. Stream END_STREAM = TCP FIN.
%%%
%%% Supports both HTTP/3 (quic_h3) and HTTP/2 (h2) as the outer
%%% transport, selected by `transport => h3 | h2' in opts.
-module(masque_tcp_client_session).
-behaviour(gen_statem).

-export([start_link/3, start/3, stop/1, info/1]).
-export([send/2, recv/2, set_mode/2]).
-export([send_capsule/3]).

-export([init/1, callback_mode/0, terminate/3, code_change/4]).
-export([connecting/3, failed/3, open/3, closing/3]).

-include("masque.hrl").

%% quic_h3:connect_opts() is missing sync key. Fix tracked upstream.
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
    target_host :: binary(),
    target_port :: 1..65535,
    uri_template :: binary(),
    transport :: h3 | h2,
    conn :: pid() | undefined,
    stream_id :: non_neg_integer() | undefined,
    handshake_from :: gen_statem:from() | undefined,
    %% Dial error parked in the `failed' state.
    failure :: term(),
    timeout_ref :: reference() | undefined,
    mode :: message | queue,
    rx_buf = queue:new() :: queue:queue(binary()),
    rx_waiters = queue:new() :: queue:queue({gen_statem:from(), reference()}),
    write_closed = false :: boolean(),
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
    gen_statem:call(Pid, {send, Data}).

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
    Transport = maps:get(transport, Opts, h3),
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
            ?MASQUE_DEFAULT_TCP_URI_TEMPLATE
        ),
        transport = Transport,
        mode = Mode,
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
    case masque_client_failed:guard(fun() -> do_connect(Data, Opts) end) of
        {ok, Conn, StreamId} ->
            Timeout = maps:get(timeout, Opts, 5000),
            TRef = erlang:start_timer(Timeout, self(), handshake_timeout),
            {keep_state, Data#data{
                conn = Conn,
                stream_id = StreamId,
                timeout_ref = TRef
            }};
        {error, Reason} ->
            %% The caller's `handshake_await' is not processed yet.
            {next_state, failed, Data#data{failure = Reason}, masque_client_failed:enter(Opts)}
    end;
connecting({call, From}, handshake_await, Data) ->
    {keep_state, Data#data{handshake_from = From}};
connecting({call, From}, shutdown_write, Data) ->
    {keep_state, Data, [{reply, From, {error, not_ready}}]};
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
    {Tag, _Conn, {response, StreamId, Status, _Headers}},
    #data{stream_id = StreamId} = Data
) when
    Tag =:= quic_h3; Tag =:= h2
->
    cancel_timer(Data#data.timeout_ref),
    case Status of
        S when S >= 200, S < 300 ->
            reply_handshake(Data, ok),
            {next_state, open, Data#data{
                timeout_ref = undefined,
                handshake_from = undefined
            }};
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

%%====================================================================
%% State: failed (dial error parked for `handshake_await')
%%====================================================================

failed(Type, Event, #data{failure = Reason, owner_ref = Ref}) ->
    masque_client_failed:handle(Type, Event, Reason, Ref).

open({call, From}, info, Data) ->
    {keep_state, Data, [{reply, From, session_info(Data, open)}]};
open({call, From}, {send, _}, #data{write_closed = true} = Data) ->
    {keep_state, Data, [{reply, From, {error, write_closed}}]};
open({call, From}, {send, Payload}, Data) ->
    Reply = send_out(Data, Payload),
    {keep_state, Data, [{reply, From, Reply}]};
open({call, From}, {recv, Timeout}, Data) ->
    handle_recv_call(From, Timeout, Data);
open({call, From}, {set_mode, Mode}, Data) ->
    {keep_state, Data#data{mode = Mode}, [{reply, From, ok}]};
open({call, From}, {set_owner, NewOwner}, Data) ->
    {keep_state, swap_owner(NewOwner, Data), [{reply, From, ok}]};
open({call, From}, {send_capsule, _, _}, #data{write_closed = true} = Data) ->
    {keep_state, Data, [{reply, From, {error, write_closed}}]};
open({call, From}, {send_capsule, Type, Value}, Data) ->
    Enc = iolist_to_binary(masque_capsule:encode(Type, Value)),
    Reply = transport_send_data(Data, Enc, false),
    {keep_state, Data, [{reply, From, Reply}]};
open({call, From}, shutdown_write, #data{write_closed = true} = Data) ->
    {keep_state, Data, [{reply, From, {error, already_closed}}]};
open({call, From}, shutdown_write, Data) ->
    case transport_send_data(Data, <<>>, true) of
        ok ->
            {keep_state, Data#data{write_closed = true}, [{reply, From, ok}]};
        Err ->
            {keep_state, Data, [{reply, From, Err}]}
    end;
open({call, From}, stop, Data) ->
    {next_state, closing, Data, [
        {reply, From, ok},
        {next_event, internal, do_close}
    ]};
%% Incoming stream data - raw TCP bytes (no capsule decoding)
open(
    info,
    {Tag, _Conn, {data, StreamId, Bytes, Fin}},
    #data{stream_id = StreamId} = Data
) when
    Tag =:= quic_h3; Tag =:= h2
->
    Data2 = deliver(Bytes, Data),
    case Fin of
        true ->
            _ = notify_owner_closed(peer_fin, Data2),
            {stop, normal, Data2};
        false ->
            {keep_state, Data2}
    end;
open(
    info,
    {Tag, _Conn, {stream_reset, StreamId, _}},
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

closing({call, From}, shutdown_write, Data) ->
    {keep_state, Data, [{reply, From, {error, closing}}]};
closing(internal, do_close, #data{write_closed = true} = Data) ->
    %% Write FIN already sent. Just close the connection.
    _ = session_teardown(Data),
    {stop, normal, Data};
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
%% Transport dispatch (h3 vs h2)
%%====================================================================

do_connect(#data{pool_owner = PoolOwner} = Data, _Opts) when
    is_pid(PoolOwner)
->
    ReqHeaders = request_headers(Data),
    ReqOpts =
        case Data#data.transport of
            h3 -> #{end_stream => false};
            h2 -> #{protocol => ?MASQUE_CONNECT_TCP_PROTOCOL}
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
        connect_timeout => maps:get(timeout, Opts, 5000),
        settings => #{enable_connect_protocol => 1},
        quic_opts => #{
            alpn => maps:get(alpn, Opts, [<<"h3">>])
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
                                    ?MASQUE_CONNECT_TCP_PROTOCOL
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
            case maps:get(enable_connect_protocol, Settings, 0) of
                1 -> ok;
                _ -> {error, no_extended_connect}
            end
    end.

verify_h2_peer_settings(Conn) ->
    Settings = h2:get_peer_settings(Conn),
    case maps:get(enable_connect_protocol, Settings, false) of
        true -> ok;
        1 -> ok;
        _ -> {error, no_extended_connect}
    end.

send_out(#data{} = Data, Payload) ->
    transport_send_data(Data, iolist_to_binary(Payload), false).

transport_send_data(#data{transport = h3, conn = C, stream_id = S}, Bytes, Fin) ->
    quic_h3:send_data(C, S, Bytes, Fin);
transport_send_data(#data{transport = h2, conn = C, stream_id = S}, Bytes, Fin) ->
    h2:send_data(C, S, Bytes, Fin).

transport_cancel(#data{transport = h3, conn = C, stream_id = S}) ->
    quic_h3:cancel(C, S);
transport_cancel(#data{transport = h2, conn = C, stream_id = S}) ->
    h2:cancel(C, S).

transport_close(#data{transport = h3, conn = C}) -> quic_h3:close(C);
transport_close(#data{transport = h2, conn = C}) -> h2:close(C).

request_headers(#data{
    proxy_host = ProxyHost,
    proxy_port = ProxyPort,
    target_host = TargetHost,
    target_port = TargetPort,
    uri_template = Template,
    extra_headers = Extra
}) ->
    Path = masque_uri:expand(Template, #{
        target_host => TargetHost,
        target_port => TargetPort
    }),
    Authority = build_authority(ProxyHost, ProxyPort),
    [
        {<<":method">>, <<"CONNECT">>},
        {<<":protocol">>, ?MASQUE_CONNECT_TCP_PROTOCOL},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, Authority},
        {<<":path">>, Path},
        {<<"capsule-protocol">>, <<"?1">>}
    ] ++ Extra.

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

%%====================================================================
%% Rx buffering
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

deliver(Bytes, #data{mode = message, owner = Owner} = Data) ->
    Owner ! {masque_data, self(), Bytes},
    Data;
deliver(Bytes, #data{mode = queue, rx_waiters = Ws, rx_buf = Buf} = Data) ->
    case queue:out(Ws) of
        {{value, {From, TRef}}, Ws2} ->
            _ = erlang:cancel_timer(TRef),
            gen_statem:reply(From, {ok, Bytes}),
            Data#data{rx_waiters = Ws2};
        {empty, _} ->
            case queue:len(Buf) < 1000 of
                true -> Data#data{rx_buf = queue:in(Bytes, Buf)};
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
        proxy_port = PP,
        transport = T
    },
    State
) ->
    #{
        state => State,
        protocol => tcp,
        transport => T,
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
