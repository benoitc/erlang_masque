%%% @doc Per-tunnel server session for Connect-UDP-Bind
%%% (draft-ietf-masque-connect-udp-listen-11). Sibling of
%%% `masque_server_session' / `masque_h2_server_session'; one module
%%% serves both h2 and h3 by dispatching on a `transport' field, the
%%% same shape used by `masque_ip_server_session'.
%%%
%%% Responsibilities:
%%%
%%% <ul>
%%%   <li>Run the handler's `init/2' and splice the resulting
%%%       `{response_headers, _}' action into the 2xx response so the
%%%       proxy emits `Connect-UDP-Bind: ?1' and `Proxy-Public-Address'.</li>
%%%   <li>Own the per-session compression tables (own + peer, via
%%%       `masque_compression_table').</li>
%%%   <li>Drain capsules off the request stream and dispatch
%%%       `COMPRESSION_ASSIGN' / `ACK' / `CLOSE' to the table; pass
%%%       any other capsule to the handler's `handle_capsule/3'.</li>
%%%   <li>Decode incoming HTTP datagrams: extract context-id, look up
%%%       the compression-table entry, decode the inner Bound UDP
%%%       Proxying Payload via `masque_udp_bind_payload', and call
%%%       `masque_udp_bind_proxy_handler:handle_bind_packet/3'.</li>
%%%   <li>Apply handler actions (`{send_bind_packet, Peer, Bytes}',
%%%       `{compression_assign, _}', `{compression_ack, _}',
%%%       `{compression_close, _}', plus the legacy `send_capsule' /
%%%       `close_session').</li>
%%% </ul>
%%%
%%% Deliberately minimal in this first PR:
%%%
%%% <ul>
%%%   <li>Wait-for-ACK on send is implemented via the table's
%%%       `state' field; an outbound mapping is `pending_ack' until
%%%       `COMPRESSION_ACK' arrives. The session emits compressed
%%%       payloads only against `installed' entries; otherwise it
%%%       falls through to the uncompressed channel if open, or
%%%       drops the packet.</li>
%%%   <li>The `max_pending_compression_responses' bound and the
%%%       post-close prohibition are deferred to a follow-up PR; the
%%%       hooks are in place but the policy is permissive.</li>
%%% </ul>
-module(masque_udp_bind_server_session).
-behaviour(gen_server).

-export([start_link/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include("masque.hrl").
-include("masque_udp_bind.hrl").

-record(state, {
    transport     :: h2 | h3,
    conn          :: pid(),
    stream_id     :: non_neg_integer(),
    router        :: pid() | undefined,
    handler       :: module(),
    h_state       :: term(),
    req           :: map(),
    %% Bind classification + advertised public address list.
    bind_scope    :: scoped | unscoped,
    public_addresses :: [{inet:ip_address(), inet:port_number()}],
    %% Per-session compression tables.
    own_table     :: masque_compression_table:state(),
    peer_table    :: masque_compression_table:state(),
    cap_buf = <<>> :: binary(),
    max_cap       :: pos_integer(),
    cap_fin_seen  = false :: boolean(),
    %% Actions returned by handler init, applied after response
    %% headers have been emitted.
    pending_actions :: [term()] | undefined,
    start_time    :: integer() | undefined
}).

-define(PROXY_ROLE, proxy).

%%====================================================================
%% API
%%====================================================================

-spec start_link(map()) -> {ok, pid()} | ignore | {error, term()}.
start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

%%====================================================================
%% gen_server
%%====================================================================

init(#{conn := Conn, stream_id := StreamId, transport := Transport,
       router := Router,
       handler := Handler, handler_opts := HOpts, req := Req}) ->
    process_flag(trap_exit, true),
    erlang:monitor(process, Router),
    MaxCap = maps:get(max_capsule_size, HOpts,
                      ?MASQUE_DEFAULT_MAX_CAPSULE_SIZE),
    BindScope = maps:get(bind, Req, unscoped),
    case init_handler(Handler, Req, HOpts) of
        {ok, HState, Actions} ->
            {Headers, OtherActions} = take_response_headers(Actions),
            PublicAddrs = read_public_addresses(Headers),
            Families = lists:usort([family_of(IP)
                                     || {IP, _P} <- PublicAddrs]),
            TableOpts = #{advertised_families => Families,
                          max_entries =>
                              maps:get(max_compression_contexts, HOpts,
                                       1024)},
            State = #state{
                transport       = Transport,
                conn            = Conn,
                stream_id       = StreamId,
                router          = Router,
                handler         = Handler,
                h_state         = HState,
                req             = Req,
                bind_scope      = BindScope,
                public_addresses = PublicAddrs,
                own_table  = masque_compression_table:new_own(?PROXY_ROLE,
                                                              TableOpts),
                peer_table = masque_compression_table:new_peer(?PROXY_ROLE,
                                                               TableOpts),
                max_cap         = MaxCap,
                pending_actions = OtherActions
            },
            {ok, {State, Headers}};
        {stop, Reason} ->
            {stop, Reason}
    end.

handle_call(finalize, _From,
            {#state{pending_actions = Actions} = State, Headers})
  when Actions =/= undefined ->
    case send_response(State, 200, base_response_headers() ++ Headers) of
        ok ->
            case claim_stream(State#state{pending_actions = undefined}) of
                {ok, S2} ->
                    masque_metrics:tunnel_opened(
                      #{protocol => udp_bind,
                        transport => State#state.transport}),
                    {reply, ok,
                     run_init_actions(Actions,
                       S2#state{start_time =
                                  erlang:monotonic_time(millisecond)})};
                {error, _} = Err ->
                    {reply, Err, State}
            end;
        {error, _} = Err ->
            {reply, Err, State}
    end;
handle_call(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

handle_cast(connection_closed, S) ->
    {stop, connection_closed, S};
handle_cast(_Msg, S) ->
    {noreply, S}.

handle_info({masque_datagram_in, StreamId, Payload},
            #state{transport = h3, stream_id = StreamId} = S) ->
    masque_metrics:bytes_in(byte_size(Payload),
                            #{protocol => udp_bind, transport => h3}),
    handle_inbound_datagram(Payload, S);
handle_info({masque_stream_data, StreamId, Data, Fin},
            #state{stream_id = StreamId} = S) ->
    handle_stream_bytes(Data, Fin, S);
handle_info({quic_h3, _Conn, {data, StreamId, Data, Fin}},
            #state{transport = h3, stream_id = StreamId} = S) ->
    handle_stream_bytes(Data, Fin, S);
handle_info({masque_stream_reset, StreamId, _ErrorCode},
            #state{stream_id = StreamId} = S) ->
    {stop, peer_reset, S};
handle_info({'DOWN', _MRef, process, _Pid, _Reason}, S) ->
    {stop, router_gone, S};
handle_info(Msg, S) ->
    %% Hand all other messages (notably {udp, ...} from the bind
    %% handler's gen_udp socket) through the handler's handle_info/2.
    dispatch(handle_info, [Msg], S).

terminate(Reason, #state{} = S) ->
    emit_tunnel_closed(S),
    terminate_transport(Reason, S),
    _ = case S#state.router of
            undefined -> ok;
            R -> catch masque_server_connection:unregister_session(
                          R, S#state.stream_id)
        end,
    try_callback(S#state.handler, terminate,
                 [Reason, S#state.h_state]),
    ok.

code_change(_OldVsn, S, _Extra) ->
    {ok, S}.

emit_tunnel_closed(#state{start_time = undefined}) -> ok;
emit_tunnel_closed(#state{start_time = T, transport = Transport}) ->
    Duration = erlang:monotonic_time(millisecond) - T,
    masque_metrics:tunnel_closed(Duration,
                                 #{protocol => udp_bind,
                                   transport => Transport}).

%%====================================================================
%% Inbound datagram path
%%====================================================================

handle_inbound_datagram(Payload, #state{} = S) ->
    case masque_datagram:decode(Payload) of
        {ok, {0, Inner}} ->
            handle_context_zero(Inner, S);
        {ok, {Ctx, Inner}} when is_integer(Ctx), Ctx > 0 ->
            handle_known_context(Ctx, Inner, S);
        {error, _} ->
            {noreply, S}
    end.

%% Scoped bind: context-id 0 keeps RFC 9298 CONNECT-UDP semantics.
%% Unscoped bind: context-id 0 is reserved (drop).
handle_context_zero(Inner, #state{bind_scope = scoped} = S) ->
    %% Treat as a raw UDP payload to the scoped peer. The scoped peer
    %% lives in `req()' under target_host / target_port; for v1 we
    %% defer to handle_packet/2 if exported (legacy UDP semantics).
    dispatch(handle_packet, [Inner], S);
handle_context_zero(_Inner, S) ->
    %% Unscoped: malformed; per draft-11 we drop. Counter bump goes
    %% in a follow-up PR.
    {noreply, S}.

handle_known_context(Ctx, Inner, #state{} = S) ->
    case masque_compression_table:lookup_by_id(S#state.peer_table, Ctx) of
        {ok, #compression_entry{ip_version = 0}} ->
            handle_uncompressed_payload(Inner, S);
        {ok, #compression_entry{ip_version = V,
                                address    = A,
                                port       = P}}
          when V =:= 4; V =:= 6 ->
            Peer = {A, P},
            handle_bind_to_peer(Peer, Inner, S);
        not_found ->
            %% Unknown context ID. Per draft-11 sections 4 and 5
            %% these arrive on a context the peer never installed:
            %% drop. (Telemetry attribution lands in a follow-up.)
            {noreply, S}
    end.

handle_uncompressed_payload(Inner, S) ->
    case masque_udp_bind_payload:decode_uncompressed(Inner) of
        {ok, {_V, IP, Port}, UdpPayload} ->
            handle_bind_to_peer({IP, Port}, UdpPayload, S);
        {error, _} ->
            {noreply, S}
    end.

handle_bind_to_peer(Peer, UdpPayload, #state{handler = Handler,
                                             h_state = HS} = S) ->
    case erlang:function_exported(Handler, handle_bind_packet, 3) of
        true ->
            case Handler:handle_bind_packet(Peer, UdpPayload, HS) of
                {ok, HS2} ->
                    {noreply, S#state{h_state = HS2}};
                {ok, HS2, Actions} ->
                    apply_actions_noreply(Actions,
                                          S#state{h_state = HS2});
                {drop, _Reason, HS2} ->
                    {noreply, S#state{h_state = HS2}};
                {stop, R, HS2} ->
                    {stop, R, S#state{h_state = HS2}}
            end;
        false ->
            {noreply, S}
    end.

%%====================================================================
%% Capsule path
%%====================================================================

handle_stream_bytes(Data, Fin,
                    #state{cap_buf = Buf, max_cap = Max} = S) ->
    New = <<Buf/binary, Data/binary>>,
    case byte_size(New) > Max of
        true ->
            reset_and_stop(capsule_buffer_overflow, S);
        false ->
            drain_capsules(New, Fin, S#state{cap_fin_seen = Fin})
    end.

drain_capsules(Buf, Fin, S) ->
    case masque_capsule:decode(Buf) of
        {ok, {Type, Value, Rest}} ->
            case dispatch_capsule(Type, Value, S) of
                {noreply, S2} ->
                    drain_capsules(Rest, Fin, S2#state{cap_buf = <<>>});
                Stop ->
                    Stop
            end;
        {more, _} when Fin, Buf =/= <<>> ->
            reset_and_stop(truncated_capsule, S);
        {more, _} ->
            {noreply, S#state{cap_buf = Buf}};
        {error, _Reason} ->
            reset_and_stop(malformed_capsule, S)
    end.

dispatch_capsule(?MASQUE_CAPSULE_COMPRESSION_ASSIGN, Body, S) ->
    case masque_compression_capsule:decode_assign(Body) of
        {ok, Assign} ->
            handle_peer_assign(Assign, S);
        {error, _} ->
            reset_and_stop(malformed_capsule, S)
    end;
dispatch_capsule(?MASQUE_CAPSULE_COMPRESSION_ACK, Body, S) ->
    case masque_compression_capsule:decode_ack(Body) of
        {ok, Ack} -> handle_peer_ack(Ack, S);
        {error, _} -> reset_and_stop(malformed_capsule, S)
    end;
dispatch_capsule(?MASQUE_CAPSULE_COMPRESSION_CLOSE, Body, S) ->
    case masque_compression_capsule:decode_close(Body) of
        {ok, Close} -> handle_peer_close(Close, S);
        {error, _} -> reset_and_stop(malformed_capsule, S)
    end;
dispatch_capsule(Type, Value, S) ->
    %% Unknown capsule: defer to handler's handle_capsule/3, otherwise
    %% silently drop per RFC 9297.
    dispatch(handle_capsule, [Type, Value], S).

handle_peer_assign(Assign, S) ->
    case masque_compression_table:install(S#state.peer_table, Assign) of
        {ok, T2} ->
            ack_peer_assign(Assign#compression_assign.context_id,
                            S#state{peer_table = T2});
        {error, _} ->
            reset_and_stop(malformed_capsule, S)
    end.

ack_peer_assign(Id, S) ->
    Bytes = iolist_to_binary(
              masque_compression_capsule:encode(
                #compression_ack{context_id = Id})),
    send_capsule_bytes(Bytes, S).

handle_peer_ack(Ack, S) ->
    case masque_compression_table:install_ack(S#state.own_table, Ack) of
        {ok, T2} ->
            {noreply, S#state{own_table = T2}};
        {error, _} ->
            reset_and_stop(malformed_capsule, S)
    end.

handle_peer_close(Close, #state{own_table = OT, peer_table = PT} = S) ->
    %% A close can refer to a context owned by either side. Try the
    %% own table first; fall through to the peer table.
    case masque_compression_table:install_close(OT, Close) of
        {ok, OT2} ->
            {noreply, S#state{own_table = OT2}};
        {error, unknown_context} ->
            case masque_compression_table:install_close(PT, Close) of
                {ok, PT2} -> {noreply, S#state{peer_table = PT2}};
                {error, _} -> reset_and_stop(malformed_capsule, S)
            end
    end.

%%====================================================================
%% Action interpreter
%%====================================================================

apply_actions_noreply(Actions, State) ->
    case do_actions(Actions, State) of
        {ok, S2}            -> {noreply, S2};
        {stop, Reason, S2}  -> {stop, Reason, S2}
    end.

run_init_actions([], S) -> S;
run_init_actions(Actions, S) ->
    case do_actions(Actions, S) of
        {ok, S2}           -> S2;
        {stop, Reason, _}  -> exit(Reason)
    end.

do_actions([], S) -> {ok, S};
do_actions([{send_bind_packet, Peer, Bytes} | Rest], S) ->
    do_actions(Rest, send_bind_payload(Peer, Bytes, S));
do_actions([{compression_assign, Entry} | Rest], S) ->
    do_actions(Rest, send_compression_assign(Entry, S));
do_actions([{compression_ack, Id} | Rest], S) ->
    Bytes = masque_compression_capsule:encode(
              #compression_ack{context_id = Id}),
    do_actions(Rest, send_capsule_bytes_or_state(Bytes, S));
do_actions([{compression_close, Id} | Rest], S) ->
    Bytes = masque_compression_capsule:encode(
              #compression_close{context_id = Id}),
    do_actions(Rest, send_capsule_bytes_or_state(Bytes, S));
do_actions([{send_capsule, Type, Value} | Rest], S) ->
    Enc = masque_capsule:encode(Type, Value),
    do_actions(Rest, send_capsule_bytes_or_state(Enc, S));
do_actions([close_session | _Rest], S) ->
    {stop, normal, S};
do_actions([{close_session, _Code, _Msg} | _Rest], S) ->
    {stop, normal, S};
do_actions([_Unknown | Rest], S) ->
    do_actions(Rest, S).

%% Ignore the response_headers action if it leaks past init - those
%% have already been spliced into the 2xx and reapplying them is a
%% no-op on the wire.
%% (Handled implicitly by the fall-through clause above.)

%%====================================================================
%% Outbound datagram + capsule emit
%%====================================================================

send_bind_payload({IP, Port}, UdpPayload, S) ->
    Tuple = {family_of(IP), IP, Port},
    case masque_compression_table:lookup_by_tuple(S#state.own_table,
                                                  Tuple) of
        {ok, #compression_entry{state = installed,
                                ip_version = 0}} ->
            %% The own-table uncompressed mapping is open and ACKed:
            %% emit the payload on its context-id, with the inner
            %% peer tuple.
            send_uncompressed(Tuple, UdpPayload, S);
        {ok, #compression_entry{state = installed, context_id = Id,
                                ip_version = V}} when V =:= 4; V =:= 6 ->
            send_compressed(Id, UdpPayload, S);
        _ ->
            %% No mapping yet (or not yet ACKed). Try the
            %% uncompressed channel if the peer opened one for us;
            %% otherwise drop.
            try_uncompressed_fallback(Tuple, UdpPayload, S)
    end.

try_uncompressed_fallback(Tuple, UdpPayload, S) ->
    case find_peer_uncompressed(S#state.peer_table) of
        {ok, Id} ->
            case masque_udp_bind_payload:encode_uncompressed(
                   Tuple, UdpPayload, advertised_families(S)) of
                {ok, Inner} ->
                    send_datagram(Id, Inner, S);
                {error, _} -> S
            end;
        not_found ->
            S
    end.

find_peer_uncompressed(Table) ->
    case [Entry || Entry <- masque_compression_table:entries(Table),
                   Entry#compression_entry.ip_version =:= 0] of
        [#compression_entry{context_id = Id} | _] -> {ok, Id};
        []                                         -> not_found
    end.

send_uncompressed(Tuple, UdpPayload, S) ->
    case find_own_uncompressed(S#state.own_table) of
        {ok, Id} ->
            case masque_udp_bind_payload:encode_uncompressed(
                   Tuple, UdpPayload, advertised_families(S)) of
                {ok, Inner} -> send_datagram(Id, Inner, S);
                {error, _}  -> S
            end;
        not_found -> S
    end.

find_own_uncompressed(Table) ->
    case [Entry || Entry <- masque_compression_table:entries(Table),
                   Entry#compression_entry.ip_version =:= 0,
                   Entry#compression_entry.state =:= installed] of
        [#compression_entry{context_id = Id} | _] -> {ok, Id};
        []                                         -> not_found
    end.

send_compressed(Id, UdpPayload, S) ->
    Inner = masque_udp_bind_payload:encode_compressed(UdpPayload),
    send_datagram(Id, Inner, S).

send_datagram(Ctx, Inner, #state{transport = h3, conn = C,
                                 stream_id = Sid} = S) ->
    Enc = masque_datagram:encode(Ctx, Inner),
    _ = quic_h3:send_datagram(C, Sid, Enc),
    masque_metrics:bytes_out(iolist_size(Inner),
                             #{protocol => udp_bind, transport => h3}),
    S;
send_datagram(Ctx, Inner, #state{transport = h2} = S) ->
    %% h2 carries datagrams as RFC 9297 DATAGRAM-type capsules.
    %% h2_capsule:encode/2 builds the type+length frame for the
    %% `datagram' atom internally (matches the existing UDP / IP
    %% session pattern).
    Inner1 = iolist_to_binary(masque_datagram:encode(Ctx, Inner)),
    Cap = h2_capsule:encode(datagram, Inner1),
    {noreply, S2} = send_capsule_bytes(Cap, S),
    S2.

send_compression_assign(Entry, S) ->
    Bytes = masque_compression_capsule:encode(
              #compression_assign{
                context_id = Entry#compression_entry.context_id,
                ip_version = Entry#compression_entry.ip_version,
                address    = Entry#compression_entry.address,
                port       = Entry#compression_entry.port}),
    send_capsule_bytes_or_state(Bytes, S).

send_capsule_bytes_or_state(Bytes, S) ->
    {noreply, S2} = send_capsule_bytes(iolist_to_binary(Bytes), S),
    S2.

send_capsule_bytes(Bytes, #state{transport = h3, conn = C,
                                 stream_id = Sid} = S) ->
    _ = quic_h3:send_data(C, Sid, Bytes, false),
    masque_metrics:bytes_out(byte_size(Bytes),
                             #{protocol => udp_bind, transport => h3}),
    {noreply, S};
send_capsule_bytes(Bytes, #state{transport = h2, conn = C,
                                 stream_id = Sid} = S) ->
    _ = h2:send_data(C, Sid, Bytes),
    masque_metrics:bytes_out(byte_size(Bytes),
                             #{protocol => udp_bind, transport => h2}),
    {noreply, S}.

%%====================================================================
%% Transport-specific glue
%%====================================================================

send_response(#state{transport = h3, conn = C, stream_id = S}, Status, Hdrs) ->
    quic_h3:send_response(C, S, Status, Hdrs);
send_response(#state{transport = h2, conn = C, stream_id = S}, Status, Hdrs) ->
    h2:send_response(C, S, Status, Hdrs).

claim_stream(#state{transport = h3, conn = C, stream_id = Sid,
                    cap_buf = Buf} = S) ->
    case quic_h3:set_stream_handler(C, Sid, self()) of
        ok ->
            {ok, S};
        {ok, Chunks} ->
            More = iolist_to_binary([D || {D, _Fin} <- Chunks]),
            {ok, S#state{cap_buf = <<Buf/binary, More/binary>>}};
        {error, _} = Err ->
            Err
    end;
claim_stream(#state{transport = h2} = S) ->
    {ok, S}.

reset_and_stop(Reason, #state{transport = h3, conn = C,
                              stream_id = Sid} = S) ->
    _ = (catch quic_h3:cancel(C, Sid, ?MASQUE_H3_MESSAGE_ERROR)),
    {stop, Reason, S};
reset_and_stop(Reason, #state{transport = h2, conn = C,
                              stream_id = Sid} = S) ->
    _ = (catch h2:cancel(C, Sid, protocol_error)),
    {stop, Reason, S}.

terminate_transport(normal, #state{transport = h3, conn = C,
                                   stream_id = Sid}) ->
    _ = (catch quic_h3:send_data(C, Sid, <<>>, true)),
    ok;
terminate_transport(_Reason, _S) ->
    ok.

%%====================================================================
%% Handler / opts plumbing
%%====================================================================

init_handler(Handler, Req, HOpts) ->
    case erlang:function_exported(Handler, init, 2) of
        true ->
            case Handler:init(Req, HOpts) of
                {ok, HState}           -> {ok, HState, []};
                {ok, HState, Actions}  -> {ok, HState, Actions};
                {stop, Reason}         -> {stop, Reason};
                Other                  -> {stop, {bad_init, Other}}
            end;
        false ->
            {ok, undefined, []}
    end.

dispatch(CB, Extra, #state{handler = Handler, h_state = HS} = S) ->
    case erlang:function_exported(Handler, CB, length(Extra) + 1) of
        true ->
            case apply(Handler, CB, Extra ++ [HS]) of
                {ok, HS2}          -> {noreply, S#state{h_state = HS2}};
                {ok, HS2, Actions} -> apply_actions_noreply(
                                         Actions, S#state{h_state = HS2});
                {stop, R, HS2}     -> {stop, R, S#state{h_state = HS2}};
                _                  -> {noreply, S}
            end;
        false ->
            {noreply, S}
    end.

try_callback(Mod, Fun, Args) ->
    Arity = length(Args),
    case erlang:function_exported(Mod, Fun, Arity) of
        true  -> (catch apply(Mod, Fun, Args));
        false -> ok
    end.

%%====================================================================
%% Helpers
%%====================================================================

base_response_headers() ->
    [{<<"capsule-protocol">>, <<"?1">>}].

%% Pull the {response_headers, _} action out of the init action list
%% so the session can splice it into the 2xx; everything else stays
%% to be applied after the response.
take_response_headers(Actions) ->
    take_response_headers(Actions, [], []).

take_response_headers([], Hdrs, Other) ->
    {lists:reverse(Hdrs), lists:reverse(Other)};
take_response_headers([{response_headers, Pairs} | Rest], Hdrs, Other) ->
    take_response_headers(Rest, lists:reverse(Pairs) ++ Hdrs, Other);
take_response_headers([X | Rest], Hdrs, Other) ->
    take_response_headers(Rest, Hdrs, [X | Other]).

read_public_addresses(Headers) ->
    case masque_uri_udp_bind:parse_proxy_public_address(Headers) of
        {ok, Addrs} -> Addrs;
        {error, _}  -> []
    end.

advertised_families(#state{public_addresses = Addrs}) ->
    lists:usort([family_of(IP) || {IP, _} <- Addrs]).

family_of({_,_,_,_})             -> 4;
family_of({_,_,_,_,_,_,_,_})     -> 6.
