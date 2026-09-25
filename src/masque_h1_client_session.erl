%%% @doc Client-side MASQUE CONNECT-UDP session over HTTP/1.1.
%%%
%%% Runs the RFC 9298 handshake as an HTTP/1.1 Upgrade
%%% (`Upgrade: connect-udp') and, after the 101 response, drives
%%% RFC 9297 capsules directly on the raw TLS socket. DATAGRAM
%%% capsules carry the UDP payload; extension capsules are opaque.
%%%
%%% The on-wire shape of a DATAGRAM capsule is identical to the h2
%%% and h3 paths, so `masque_datagram' and `masque_capsule' are
%%% reused unchanged; only the transport plumbing differs.
-module(masque_h1_client_session).
-behaviour(gen_statem).

-export([start_link/3, start/3, stop/1, info/1]).
-export([send/2, send/3, recv/2, set_mode/2]).
-export([send_capsule/3]).

-export([init/1, callback_mode/0, terminate/3, code_change/4]).
-export([connecting/3, open/3, closing/3]).

-ifdef(TEST).
-export([
    request_headers/1,
    validate_response/2,
    build_authority/2,
    classify_upgrade_error/1
]).
-export([build_data/1]).
-endif.

-include("masque.hrl").

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
    socket :: ssl:sslsocket() | undefined,
    handshake_from :: gen_statem:from() | undefined,
    mode :: message | queue,
    rx_buf = queue:new() :: queue:queue(binary()),
    rx_waiters = queue:new() :: queue:queue({gen_statem:from(), reference()}),
    cap_buf = <<>> :: binary(),
    max_cap :: pos_integer(),
    %% Extra request headers prepended to the GET+Upgrade request.
    extra_headers = [] :: [{binary(), binary()}]
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
        )
    },
    {ok, connecting, Data, [{next_event, internal, {do_handshake, Opts}}]}.

%%====================================================================
%% States
%%====================================================================

connecting(internal, {do_handshake, Opts}, Data) ->
    case do_connect(Data, Opts) of
        {ok, Socket, Buffer} ->
            case setopts_active_once(Socket) of
                ok ->
                    reply_handshake(Data, ok),
                    {next_state, open,
                        Data#data{
                            socket = Socket,
                            cap_buf = <<>>,
                            handshake_from = undefined
                        },
                        drain_leftover(Socket, Buffer)};
                {error, Reason} ->
                    _ =
                        (try
                            ssl:close(Socket)
                        catch
                            _:_ -> ok
                        end),
                    reply_handshake(Data, {error, {setopts, Reason}}),
                    {stop, {setopts, Reason}}
            end;
        {error, Reason} ->
            reply_handshake(Data, {error, Reason}),
            {stop, {handshake_failed, Reason}}
    end;
connecting({call, From}, handshake_await, Data) ->
    {keep_state, Data#data{handshake_from = From}};
connecting({call, From}, shutdown_write, Data) ->
    {keep_state, Data, [{reply, From, {error, not_ready}}]};
connecting({call, From}, {set_owner, NewOwner}, Data) ->
    {keep_state, swap_owner(NewOwner, Data), [{reply, From, ok}]};
connecting({call, From}, info, Data) ->
    {keep_state, Data, [{reply, From, session_info(Data, connecting)}]};
connecting({call, From}, stop, Data) ->
    {stop_and_reply, normal, [{reply, From, ok}], Data};
connecting({call, From}, _Other, Data) ->
    %% RFC 9931: no UDP datagram (or any other operation) is permitted
    %% before the HTTP/1.1 Upgrade handshake completes.
    {keep_state, Data, [{reply, From, {error, not_ready}}]};
connecting(
    info,
    {'DOWN', Ref, process, _, _},
    #data{owner_ref = Ref}
) ->
    {stop, owner_gone};
connecting(info, _Msg, Data) ->
    {keep_state, Data}.

open({call, From}, handshake_await, Data) ->
    %% Handshake is synchronous on h1; by the time we're in `open'
    %% it has already succeeded. Reply ok to any late caller.
    {keep_state, Data, [{reply, From, ok}]};
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
open({call, From}, {send_capsule, Type, Value}, #data{socket = Socket} = Data) ->
    Reply = h1_upgrade:send_capsule(ssl, Socket, Type, Value),
    {keep_state, Data, [{reply, From, Reply}]};
open({call, From}, stop, Data) ->
    {next_state, closing, Data, [
        {reply, From, ok},
        {next_event, internal, do_close}
    ]};
open(
    info,
    {ssl, Socket, Bytes},
    #data{socket = Socket, cap_buf = Buf, max_cap = Max} = Data
) ->
    New = <<Buf/binary, Bytes/binary>>,
    case byte_size(New) > Max of
        true -> abort(capsule_buffer_overflow, Data);
        false -> drain_capsules(New, Data)
    end;
open(info, {ssl_closed, Socket}, #data{socket = Socket} = Data) ->
    _ = notify_owner_closed(peer_closed, Data),
    {stop, peer_closed, Data};
open(info, {ssl_error, Socket, Reason}, #data{socket = Socket} = Data) ->
    _ = notify_owner_closed({ssl_error, Reason}, Data),
    {stop, {ssl_error, Reason}, Data};
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

closing(internal, do_close, #data{socket = Socket} = Data) ->
    _ =
        case Socket of
            undefined ->
                ok;
            _ ->
                try
                    ssl:close(Socket)
                catch
                    _:_ -> ok
                end
        end,
    {stop, normal, Data};
closing(_Event, _Msg, Data) ->
    {keep_state, Data}.

terminate(_Reason, _State, #data{socket = undefined} = D) ->
    _ = erlang:demonitor(D#data.owner_ref, [flush]),
    cancel_all_waiters(D);
terminate(_Reason, _State, #data{socket = Socket} = D) ->
    _ = erlang:demonitor(D#data.owner_ref, [flush]),
    cancel_all_waiters(D),
    _ =
        (try
            ssl:close(Socket)
        catch
            _:_ -> ok
        end),
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
%% Transport-specific (h1)
%%====================================================================

do_connect(Data, Opts) ->
    Timeout = maps:get(timeout, Opts, 5000),
    SSLOpts = masque_tls:client_opts(Data#data.proxy_host, Opts),
    ConnOpts = #{
        transport => ssl,
        ssl_opts => SSLOpts,
        connect_timeout => Timeout,
        timeout => Timeout
    },
    case
        h1_client:connect(
            binary_to_list(Data#data.proxy_host),
            Data#data.proxy_port,
            ConnOpts
        )
    of
        {ok, Conn} ->
            case h1:wait_connected(Conn, Timeout) of
                ok ->
                    do_upgrade(Conn, Data, Timeout);
                {error, Reason} ->
                    _ =
                        (try
                            h1:close(Conn)
                        catch
                            _:_ -> ok
                        end),
                    {error, {connect, Reason}}
            end;
        {error, Reason} ->
            {error, {connect, Reason}}
    end.

do_upgrade(Conn, Data, Timeout) ->
    Headers = request_headers(Data),
    case h1:upgrade(Conn, ?MASQUE_CONNECT_UDP_PROTOCOL, Headers, Timeout) of
        {ok, _StreamId, Socket, Buffer, RespHeaders} ->
            case validate_response(RespHeaders, Data) of
                ok ->
                    {ok, Socket, Buffer};
                {error, _} = Err ->
                    _ =
                        (try
                            ssl:close(Socket)
                        catch
                            _:_ -> ok
                        end),
                    Err
            end;
        {error, Reason} ->
            _ =
                (try
                    h1:close(Conn)
                catch
                    _:_ -> ok
                end),
            {error, classify_upgrade_error(Reason)}
    end.

classify_upgrade_error({http_status, Code, _} = R) -> {handshake_rejected, Code, R};
classify_upgrade_error(timeout) -> handshake_timeout;
classify_upgrade_error(Other) -> {upgrade, Other}.

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
        {<<":path">>, Path},
        {<<"host">>, Authority}
    ],
    WithCap =
        case CapProto of
            true -> Base ++ [{<<"capsule-protocol">>, <<"?1">>}];
            false -> Base
        end,
    WithCap ++ Extra.

sanitise_extra_headers(List) when is_list(List) ->
    Reserved = [
        <<":path">>,
        <<"host">>,
        <<"capsule-protocol">>,
        <<"upgrade">>,
        <<"connection">>
    ],
    [
        {K, V}
     || {K, V} <- List,
        is_binary(K),
        is_binary(V),
        not lists:member(lowercase_bin(K), Reserved)
    ].

lowercase_bin(B) when is_binary(B) ->
    list_to_binary(string:to_lower(binary_to_list(B))).

setopts_active_once(Socket) ->
    ssl:setopts(Socket, [{active, once}, {mode, binary}]).

%% Outbound: UDP payloads become DATAGRAM capsules whose inner
%% payload is `ContextId (varint) || UdpBytes'.
send_out(#data{socket = Socket}, Ctx, Payload) when
    is_integer(Ctx), Ctx >= 0, Socket =/= undefined
->
    PayloadSize = iolist_size(Payload),
    case
        Ctx =:= ?MASQUE_CONTEXT_ID_UDP andalso
            PayloadSize > ?MASQUE_MAX_UDP_PAYLOAD
    of
        true ->
            {error, {payload_too_large, PayloadSize, ?MASQUE_MAX_UDP_PAYLOAD}};
        false ->
            InnerIoData = masque_datagram:encode(Ctx, Payload),
            Inner = iolist_to_binary(InnerIoData),
            h1_upgrade:send_capsule(ssl, Socket, datagram, Inner)
    end.

%%====================================================================
%% Capsule decode loop
%%====================================================================

drain_capsules(Buf, #data{socket = Socket} = Data) ->
    case h1_capsule:decode(Buf) of
        {ok, {Type, Inner}, Rest} ->
            Data2 = deliver_capsule(Type, Inner, Data),
            drain_capsules(Rest, Data2#data{cap_buf = <<>>});
        {more, _} ->
            _ = setopts_active_once(Socket),
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

abort(Reason, #data{socket = Socket} = Data) ->
    _ =
        case Socket of
            undefined ->
                ok;
            _ ->
                try
                    ssl:close(Socket)
                catch
                    _:_ -> ok
                end
        end,
    _ = notify_owner_closed(Reason, Data),
    {stop, Reason, Data}.

%%====================================================================
%% Response validation (mirrors the h2 session)
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
    lists:any(fun({N, _}) -> ci_eq(N, Name) end, Headers).

header_value(Name, Headers) ->
    case lists:search(fun({N, _}) -> ci_eq(N, Name) end, Headers) of
        {value, {_, V}} -> V;
        false -> undefined
    end.

ci_eq(A, B) ->
    string:to_lower(binary_to_list(iolist_to_binary(A))) =:=
        string:to_lower(binary_to_list(iolist_to_binary(B))).

%%====================================================================
%% Rx buffering (identical to the h2 / h3 sessions)
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
        transport => h1,
        proxy => {PH, PP},
        target => {H, P}
    }.

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

%% Capsules the proxy sent right behind the 101 arrive in the upgrade
%% leftover; feed them through the `open' decode path immediately
%% instead of waiting for the next socket read.
drain_leftover(_Socket, <<>>) ->
    [];
drain_leftover(Socket, Buffer) ->
    [{next_event, info, {ssl, Socket, Buffer}}].

-ifdef(TEST).
%% Test-only helper: build a `#data{}' record from a map for driving
%% the pure helpers (`request_headers/1', `validate_response/2') from
%% eunit without standing up a gen_statem.
build_data(M) ->
    #data{
        owner = maps:get(owner, M, self()),
        owner_ref = make_ref(),
        proxy_host = maps:get(proxy_host, M, <<"proxy.example">>),
        proxy_port = maps:get(proxy_port, M, 443),
        target_host = maps:get(target_host, M, <<"10.0.0.1">>),
        target_port = maps:get(target_port, M, 1234),
        uri_template = maps:get(
            uri_template,
            M,
            ?MASQUE_DEFAULT_URI_TEMPLATE
        ),
        capsule_proto = maps:get(capsule_protocol, M, true),
        mode = maps:get(mode, M, message),
        max_cap = maps:get(
            max_capsule_size,
            M,
            ?MASQUE_DEFAULT_MAX_CAPSULE_SIZE
        )
    }.
-endif.
