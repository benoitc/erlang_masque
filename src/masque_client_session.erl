%%% @doc Client-side MASQUE CONNECT-UDP session.
%%%
%%% One gen_statem per tunnel. Owns the `quic_h3' connection, sends
%%% the Extended CONNECT request and drives it to 2xx, then holds the
%%% request stream open for subsequent datagrams / capsules.
%%%
%%% States:
%%% <ul>
%%%   <li>`connecting' - waiting for the CONNECT-UDP response.</li>
%%%   <li>`open' - tunnel is live; datagram plumbing lands in Step 5.</li>
%%%   <li>`closing' - graceful shutdown in progress.</li>
%%% </ul>
-module(masque_client_session).
-behaviour(gen_statem).

-export([start_link/3, start/3, stop/1, info/1]).
-export([send/2, send/3, recv/2, set_mode/2]).
-export([send_capsule/3]).

-export([init/1, callback_mode/0, terminate/3, code_change/4]).
-export([connecting/3, open/3, closing/3]).

-include("masque.hrl").

%% `quic_h3:connect/3' has a narrower published type than its
%% implementation accepts (e.g. `sync' and `h3_datagram_enabled' are
%% used by the code but omitted from `quic_h3:connect_opts()'). The
%% suppression is scoped to the single call site so every other
%% type-check in this module remains strict.
-dialyzer({nowarn_function, [do_connect/2, request_headers/1,
                              build_authority/2, is_ipv6_literal/1]}).

-record(data, {
    owner         :: pid(),
    owner_ref     :: reference(),
    proxy_host    :: binary(),
    proxy_port    :: inet:port_number(),
    target_host   :: binary(),
    target_port   :: 1..65535,
    uri_template  :: binary(),
    capsule_proto :: boolean(),
    conn          :: pid() | undefined,
    stream_id     :: non_neg_integer() | undefined,
    handshake_from :: gen_statem:from() | undefined,
    timeout_ref   :: reference() | undefined,
    %% Delivery mode: `message' delivers incoming UDP payloads to the
    %% owner as `{masque_data, Sess, Data}', `queue' buffers them
    %% for sync `recv/2'.
    mode          :: message | queue,
    %% Pending sync receivers and buffered datagrams (when mode=queue).
    rx_buf = queue:new() :: queue:queue(binary()),
    rx_waiters = queue:new() :: queue:queue({gen_statem:from(), reference()}),
    %% Incoming capsule bytes buffered from stream body data.
    cap_buf = <<>> :: binary(),
    %% Ceiling on `cap_buf' (resets the stream with H3_MESSAGE_ERROR).
    max_cap :: pos_integer()
}).

%%====================================================================
%% API
%%====================================================================

start_link(Target, Opts, Owner) ->
    gen_statem:start_link(?MODULE, {Target, Opts, Owner}, []).

start(Target, Opts, Owner) ->
    gen_statem:start(?MODULE, {Target, Opts, Owner}, []).

stop(Pid) ->
    gen_statem:call(Pid, stop, 5000).

info(Pid) ->
    gen_statem:call(Pid, info, 1000).

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
%% gen_statem callbacks
%%====================================================================

callback_mode() -> state_functions.

init({Target, Opts, Owner}) ->
    process_flag(trap_exit, true),
    {ProxyHost, ProxyPort} = maps:get(proxy, Opts),
    {TargetHost, TargetPort} = Target,
    MRef = erlang:monitor(process, Owner),
    Mode = maps:get(mode, Opts, message),
    MaxCap = maps:get(max_capsule_size, Opts,
                      ?MASQUE_DEFAULT_MAX_CAPSULE_SIZE),
    Data = #data{
        owner = Owner,
        owner_ref = MRef,
        proxy_host = to_bin(ProxyHost),
        proxy_port = ProxyPort,
        target_host = to_bin(TargetHost),
        target_port = TargetPort,
        uri_template = maps:get(uri_template, Opts,
                                ?MASQUE_DEFAULT_URI_TEMPLATE),
        capsule_proto = maps:get(capsule_protocol, Opts, true),
        mode = Mode,
        max_cap = MaxCap
    },
    {ok, connecting, Data,
     [{next_event, internal, {do_handshake, Opts}}]}.

%%====================================================================
%% States
%%====================================================================

connecting(internal, {do_handshake, Opts}, Data) ->
    case do_connect(Data, Opts) of
        {ok, Conn, StreamId} ->
            Timeout = maps:get(timeout, Opts, 5000),
            TRef = erlang:start_timer(Timeout, self(), handshake_timeout),
            {keep_state,
             Data#data{conn = Conn, stream_id = StreamId,
                       timeout_ref = TRef}};
        {error, Reason} ->
            {stop, {handshake_failed, Reason}}
    end;
connecting({call, From}, handshake_await, Data) ->
    {keep_state, Data#data{handshake_from = From}};
connecting({call, From}, shutdown_write, Data) ->
    {keep_state, Data, [{reply, From, {error, not_ready}}]};
connecting({call, From}, {set_owner, NewOwner}, Data) ->
    {keep_state, swap_owner(NewOwner, Data), [{reply, From, ok}]};
connecting(info, {quic_h3, _Conn, {response, StreamId, Status, Headers}},
           #data{stream_id = StreamId} = Data) ->
    cancel_timer(Data#data.timeout_ref),
    case Status of
        S when S >= 200, S < 300 ->
            case validate_response(Headers, Data) of
                ok ->
                    reply_handshake(Data, ok),
                    {next_state, open,
                     Data#data{timeout_ref = undefined,
                               handshake_from = undefined}};
                {error, _} = Err ->
                    reply_handshake(Data, Err),
                    {stop, element(2, Err)}
            end;
        _ ->
            reply_handshake(Data,
                            {error, {handshake_rejected, Status}}),
            {stop, {handshake_rejected, Status}}
    end;
connecting(info, {timeout, TRef, handshake_timeout},
           #data{timeout_ref = TRef} = Data) ->
    reply_handshake(Data, {error, handshake_timeout}),
    {stop, handshake_timeout};
connecting(info, {'DOWN', Ref, process, _, _},
           #data{owner_ref = Ref}) ->
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
    Enc = iolist_to_binary(masque_capsule:encode(Type, Value)),
    Reply = quic_h3:send_data(Data#data.conn, Data#data.stream_id,
                              Enc, false),
    {keep_state, Data, [{reply, From, Reply}]};
open({call, From}, stop, Data) ->
    {next_state, closing, Data,
     [{reply, From, ok},
      {next_event, internal, do_close}]};
open(info, {quic_h3, _Conn, {datagram, StreamId, Payload}},
     #data{stream_id = StreamId} = Data) ->
    case masque_datagram:decode(Payload) of
        {ok, {?MASQUE_CONTEXT_ID_UDP, UdpBytes}}
          when byte_size(UdpBytes) =< ?MASQUE_MAX_UDP_PAYLOAD ->
            {keep_state, deliver_packet(UdpBytes, Data)};
        _ ->
            {keep_state, Data}
    end;
open(info, {quic_h3, _Conn, {data, StreamId, Bytes, Fin}},
     #data{stream_id = StreamId, cap_buf = Buf, max_cap = Max} = Data) ->
    New = <<Buf/binary, Bytes/binary>>,
    case byte_size(New) > Max of
        true  -> client_stream_abort(capsule_buffer_overflow, Data);
        false -> drain_client_capsules(New, Fin, Data)
    end;
open(info, {timeout, TRef, {recv_timeout, From}}, Data) ->
    {keep_state, drop_waiter(TRef, From, Data)};
open(info, {quic_h3, _Conn, {stream_reset, StreamId, _ErrorCode}},
     #data{stream_id = StreamId} = Data) ->
    _ = notify_owner_closed(peer_reset, Data),
    {stop, peer_reset, Data};
open(info, {'DOWN', Ref, process, _, _},
     #data{owner_ref = Ref} = Data) ->
    {next_state, closing, Data, [{next_event, internal, do_close}]};
open(info, _Msg, Data) ->
    {keep_state, Data}.

send_out(#data{conn = Conn, stream_id = StreamId}, Ctx, Payload)
  when is_integer(Ctx), Ctx >= 0 ->
    PayloadSize = iolist_size(Payload),
    %% RFC 9298 §5: UDP payloads capped at 65527 regardless of the
    %% QUIC datagram budget.
    UDPLimit = Ctx =:= ?MASQUE_CONTEXT_ID_UDP
               andalso PayloadSize > ?MASQUE_MAX_UDP_PAYLOAD,
    Max = quic_h3:max_datagram_size(Conn, StreamId),
    CtxOverhead = quic_varint_size(Ctx),
    QUICLimit = Max > 0 andalso (PayloadSize + CtxOverhead) > Max,
    if
        UDPLimit ->
            {error, {payload_too_large, PayloadSize,
                     ?MASQUE_MAX_UDP_PAYLOAD}};
        QUICLimit ->
            {error, {datagram_too_large, PayloadSize,
                     Max - CtxOverhead}};
        true ->
            Enc = masque_datagram:encode(Ctx, Payload),
            quic_h3:send_datagram(Conn, StreamId, Enc)
    end.

%% Bytes needed to encode a non-negative integer as a QUIC varint.
quic_varint_size(V) when V < 64        -> 1;
quic_varint_size(V) when V < 16384     -> 2;
quic_varint_size(V) when V < 1073741824 -> 4;
quic_varint_size(_)                    -> 8.

%% RFC 9297 §3.4: responses carrying the Capsule Protocol must not
%% also carry `content-length' / `content-type' indicating a regular
%% body. We also reject a response that drops the `capsule-protocol'
%% header when we advertised it on the request, since that signals a
%% peer that did not actually opt in.
validate_response(Headers, #data{capsule_proto = CapsuleRequested}) ->
    HasContentLength = header_present(<<"content-length">>, Headers),
    HasContentType   = header_present(<<"content-type">>, Headers),
    CapsuleAck = case header_value(<<"capsule-protocol">>, Headers) of
                     <<"?1">> -> true;
                     _        -> false
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
        false  -> undefined
    end.

notify_owner_closed(Reason, #data{owner = Owner, mode = message}) ->
    Owner ! {masque_closed, self(), Reason};
notify_owner_closed(_Reason, _Data) ->
    ok.

%% Used by the transport racer to flip ownership from the race worker
%% to the real caller after a winning handshake.
swap_owner(NewOwner, #data{owner_ref = OldRef} = Data) ->
    _ = erlang:demonitor(OldRef, [flush]),
    NewRef = erlang:monitor(process, NewOwner),
    Data#data{owner = NewOwner, owner_ref = NewRef}.

handle_recv_call(From, Timeout, #data{rx_buf = Buf, rx_waiters = Ws} = Data) ->
    case queue:out(Buf) of
        {{value, Bytes}, Buf2} ->
            {keep_state, Data#data{rx_buf = Buf2},
             [{reply, From, {ok, Bytes}}]};
        {empty, _} ->
            TRef = erlang:start_timer(Timeout, self(), {recv_timeout, From}),
            {keep_state, Data#data{rx_waiters = queue:in({From, TRef}, Ws)}}
    end.

deliver_packet(UdpBytes, #data{mode = message, owner = Owner} = Data) ->
    Owner ! {masque_data, self(), UdpBytes},
    Data;
deliver_packet(UdpBytes, #data{mode = queue,
                                rx_waiters = Ws,
                                rx_buf = Buf} = Data) ->
    case queue:out(Ws) of
        {{value, {From, TRef}}, Ws2} ->
            _ = erlang:cancel_timer(TRef),
            gen_statem:reply(From, {ok, UdpBytes}),
            Data#data{rx_waiters = Ws2};
        {empty, _} ->
            case queue:len(Buf) < 1000 of
                true  -> Data#data{rx_buf = queue:in(UdpBytes, Buf)};
                false -> Data
            end
    end.

drain_client_capsules(Buf, Fin, #data{owner = Owner} = Data) ->
    case masque_capsule:decode(Buf) of
        {ok, {Type, Value, Rest}} ->
            Owner ! {masque_capsule, self(), Type, Value},
            drain_client_capsules(Rest, Fin, Data#data{cap_buf = <<>>});
        {more, _} when Fin, Buf =/= <<>> ->
            %% Stream closed mid-capsule.
            client_stream_abort(truncated_capsule, Data);
        {more, _} ->
            {keep_state, Data#data{cap_buf = Buf}};
        {error, _} ->
            client_stream_abort(malformed_capsule, Data)
    end.

client_stream_abort(Reason, #data{conn = Conn, stream_id = StreamId} = Data) ->
    _ = (catch quic_h3:cancel(Conn, StreamId, ?MASQUE_H3_MESSAGE_ERROR)),
    _ = notify_owner_closed(Reason, Data),
    {stop, Reason, Data}.

drop_waiter(TRef, From, #data{rx_waiters = Ws} = Data) ->
    %% The timer fired; if the waiter is still in the queue, reply with
    %% timeout and evict.
    Ws2 = queue:filter(
        fun({F, T}) when F =:= From, T =:= TRef ->
                gen_statem:reply(F, {error, timeout}),
                false;
           (_) -> true
        end, Ws),
    Data#data{rx_waiters = Ws2}.

closing(internal, do_close, #data{conn = Conn, stream_id = StreamId} = Data) ->
    %% Prefer a graceful half-close (FIN on an empty DATA frame) to
    %% signal end-of-tunnel per HTTP semantics. Fall back to cancel
    %% if the stream is already gone.
    case (catch quic_h3:send_data(Conn, StreamId, <<>>, true)) of
        ok  -> ok;
        _   -> catch quic_h3:cancel(Conn, StreamId)
    end,
    _ = (catch quic_h3:close(Conn)),
    {stop, normal, Data};
closing(_Event, _Msg, Data) ->
    {keep_state, Data}.

terminate(_Reason, _State, #data{conn = undefined} = D) ->
    cancel_all_waiters(D);
terminate(_Reason, _State, #data{conn = Conn} = D) ->
    cancel_all_waiters(D),
    _ = (catch quic_h3:close(Conn)),
    ok.

cancel_all_waiters(#data{rx_waiters = Ws}) ->
    _ = queue:fold(fun({From, TRef}, _) ->
        _ = erlang:cancel_timer(TRef),
        gen_statem:reply(From, {error, closed}),
        ok
    end, ok, Ws),
    ok.

code_change(_OldVsn, State, Data, _Extra) ->
    {ok, State, Data}.

%%====================================================================
%% Internal
%%====================================================================

do_connect(Data, Opts) ->
    ConnOpts0 = maps:with([verify, cacerts], Opts),
    ConnOpts = ConnOpts0#{
        sync => true,
        settings => #{enable_connect_protocol => 1, h3_datagram => 1},
        h3_datagram_enabled => true,
        quic_opts => #{
            alpn => maps:get(alpn, Opts, [<<"h3">>]),
            max_datagram_frame_size => 65535
        }
    },
    case quic_h3:connect(Data#data.proxy_host,
                         Data#data.proxy_port,
                         ConnOpts) of
        {ok, Conn} ->
            ReqHeaders = request_headers(Data),
            %% RFC 9298 tunnels - the request stream must remain open
            %% for subsequent capsules, so suppress the default FIN.
            case quic_h3:request(Conn, ReqHeaders, #{end_stream => false}) of
                {ok, StreamId} -> {ok, Conn, StreamId};
                {error, R}     -> quic_h3:close(Conn), {error, {request, R}}
            end;
        {error, Reason} ->
            {error, {connect, Reason}}
    end.

request_headers(#data{proxy_host = ProxyHost, proxy_port = ProxyPort,
                      target_host = TargetHost, target_port = TargetPort,
                      uri_template = Template,
                      capsule_proto = CapProto}) ->
    Path = masque_uri:expand(Template, #{
        target_host => TargetHost,
        target_port => TargetPort
    }),
    Authority = build_authority(ProxyHost, ProxyPort),
    Base = [
        {<<":method">>, <<"CONNECT">>},
        {<<":protocol">>, ?MASQUE_CONNECT_UDP_PROTOCOL},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, Authority},
        {<<":path">>, Path}
    ],
    case CapProto of
        true  -> Base ++ [{<<"capsule-protocol">>, <<"?1">>}];
        false -> Base
    end.

reply_handshake(#data{handshake_from = undefined}, _Reply) ->
    ok;
reply_handshake(#data{handshake_from = From}, Reply) ->
    gen_statem:reply(From, Reply).

session_info(#data{target_host = H, target_port = P,
                   proxy_host = PH, proxy_port = PP}, State) ->
    #{
        state => State,
        proxy => {PH, PP},
        target => {H, P}
    }.

cancel_timer(undefined) -> ok;
cancel_timer(Ref) ->
    _ = erlang:cancel_timer(Ref),
    ok.

to_bin(X) when is_binary(X) -> X;
to_bin(X) when is_list(X)   -> list_to_binary(X);
to_bin(X) when is_atom(X)   -> atom_to_binary(X, utf8).

%% IPv6 literals must be bracketed in a URI authority
%% (RFC 3986 §3.2.2). IPv4 literals and hostnames go through bare.
build_authority(Host, Port) ->
    HostPart = case is_ipv6_literal(Host) of
                   true  -> <<"[", Host/binary, "]">>;
                   false -> Host
               end,
    iolist_to_binary([HostPart, ":", integer_to_binary(Port)]).

is_ipv6_literal(Host) ->
    case inet:parse_address(binary_to_list(Host)) of
        {ok, {_, _, _, _, _, _, _, _}} -> true;
        _ -> false
    end.
