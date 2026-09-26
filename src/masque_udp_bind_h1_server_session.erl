%%% Per-tunnel server session for Connect-UDP-Bind
%%% (draft-ietf-masque-connect-udp-listen-11) over HTTP/1.1.
%%%
%%% Sibling of `masque_udp_bind_server_session` (h2/h3); the wire
%%% format above the transport is identical, so capsule and payload
%%% logic is reused unchanged. Only the transport plumbing differs:
%%% h1 takes ownership of the upgraded TLS socket via
%%% `h1:accept_upgrade/3` and reads / writes capsules directly on
%%% it through `h1_capsule:encode/2` and `h1_capsule:decode/1`.
-module(masque_udp_bind_h1_server_session).
-moduledoc false.
-behaviour(gen_server).

-export([start_link/1]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-include("masque.hrl").
-include("masque_udp_bind.hrl").

-record(state, {
    transport :: gen_tcp | ssl,
    socket :: ssl:sslsocket() | gen_tcp:socket(),
    handler :: module(),
    h_state :: term(),
    req :: map(),
    bind_scope :: scoped | unscoped,
    public_addresses :: [{inet:ip_address(), inet:port_number()}],
    own_table :: masque_compression_table:state(),
    peer_table :: masque_compression_table:state(),
    cap_buf = <<>> :: binary(),
    max_cap :: pos_integer(),
    start_time :: integer() | undefined,
    idle_ms :: non_neg_integer() | infinity,
    idle_ref :: reference() | undefined,
    max_pending :: non_neg_integer()
}).

-define(DEFAULT_MAX_PENDING_RESPONSES, 16).

%%====================================================================
%% API
%%====================================================================

start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

%%====================================================================
%% Lifecycle
%%====================================================================

%% A tunnel counts as open once `init_session/1' succeeded: the 2xx is
%% sent and the stream (or socket) is ours. `terminate/2' closes it.
init(Args) ->
    case init_session(Args) of
        {ok, S} ->
            masque_metrics:tunnel_opened(#{protocol => udp_bind, transport => h1}),
            {ok, S#state{start_time = erlang:monotonic_time(millisecond)}};
        Other ->
            Other
    end.

init_session(#{
    conn := Conn,
    stream_id := StreamId,
    handler := Handler,
    handler_opts := HOpts,
    req := Req
}) ->
    process_flag(trap_exit, true),
    MaxCap = maps:get(
        max_capsule_size,
        HOpts,
        ?MASQUE_DEFAULT_MAX_CAPSULE_SIZE
    ),
    IdleMs = maps:get(idle_timeout_ms, HOpts, 300000),
    case init_handler(Handler, Req, HOpts) of
        {ok, HState, Actions} ->
            {Headers, OtherActions} = take_response_headers(Actions),
            BaseHeaders = [{<<"capsule-protocol">>, <<"?1">>}],
            UpgradeHeaders = BaseHeaders ++ Headers,
            case h1:accept_upgrade(Conn, StreamId, UpgradeHeaders) of
                {ok, Socket, Buffer} ->
                    Transport = socket_transport(Socket),
                    PublicAddrs = read_public_addresses(Headers),
                    Families = lists:usort([
                        family_of(IP)
                     || {IP, _} <- PublicAddrs
                    ]),
                    TableOpts = #{
                        advertised_families => Families,
                        max_entries =>
                            maps:get(
                                max_compression_contexts,
                                HOpts,
                                1024
                            )
                    },
                    State0 = arm_idle(#state{
                        transport = Transport,
                        socket = Socket,
                        handler = Handler,
                        h_state = HState,
                        req = Req,
                        bind_scope = maps:get(bind, Req, unscoped),
                        public_addresses = PublicAddrs,
                        own_table = masque_compression_table:new_own(
                            proxy, TableOpts
                        ),
                        peer_table = masque_compression_table:new_peer(
                            proxy, TableOpts
                        ),
                        cap_buf = Buffer,
                        max_cap = MaxCap,
                        start_time = erlang:monotonic_time(millisecond),
                        idle_ms = IdleMs,
                        max_pending = maps:get(
                            max_pending_compression_responses,
                            HOpts,
                            ?DEFAULT_MAX_PENDING_RESPONSES
                        )
                    }),
                    case drain_and_arm(State0) of
                        {ok, State1} ->
                            apply_init_actions(OtherActions, State1);
                        {stop, Reason, _S} ->
                            _ = close_socket(State0),
                            {stop, Reason}
                    end;
                {error, Reason} ->
                    try_callback(
                        Handler,
                        terminate,
                        [{accept_upgrade, Reason}, HState]
                    ),
                    {stop, {accept_upgrade, Reason}}
            end;
        {stop, Reason} ->
            {stop, Reason}
    end.

handle_call(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

handle_cast(_Msg, S) ->
    {noreply, S}.

handle_info(
    {ssl, Sock, Bytes},
    #state{socket = Sock, cap_buf = Buf, max_cap = Max} = S
) ->
    S1 = arm_idle(S),
    New = <<Buf/binary, Bytes/binary>>,
    case byte_size(New) > Max of
        true -> {stop, capsule_buffer_overflow, S1};
        false -> step(S1#state{cap_buf = New})
    end;
handle_info(
    {tcp, Sock, Bytes},
    #state{socket = Sock, cap_buf = Buf, max_cap = Max} = S
) ->
    S1 = arm_idle(S),
    New = <<Buf/binary, Bytes/binary>>,
    case byte_size(New) > Max of
        true -> {stop, capsule_buffer_overflow, S1};
        false -> step(S1#state{cap_buf = New})
    end;
handle_info({timeout, Ref, idle}, #state{idle_ref = Ref} = S) ->
    {stop, idle_timeout, S};
handle_info({ssl_closed, Sock}, #state{socket = Sock} = S) ->
    {stop, peer_closed, S};
handle_info({tcp_closed, Sock}, #state{socket = Sock} = S) ->
    {stop, peer_closed, S};
handle_info({ssl_error, Sock, Reason}, #state{socket = Sock} = S) ->
    {stop, {ssl_error, Reason}, S};
handle_info({tcp_error, Sock, Reason}, #state{socket = Sock} = S) ->
    {stop, {tcp_error, Reason}, S};
handle_info({'EXIT', _Pid, _Reason}, S) ->
    {noreply, S};
handle_info(Msg, S) ->
    dispatch(handle_info, [Msg], S).

terminate(
    Reason,
    #state{
        handler = Handler,
        h_state = HState,
        start_time = Start
    } = S
) ->
    _ = cancel_idle(S),
    _ = close_socket(S),
    try_callback(Handler, terminate, [Reason, HState]),
    _ = emit_tunnel_closed(Start),
    ok.

code_change(_OldVsn, S, _Extra) -> {ok, S}.

emit_tunnel_closed(undefined) ->
    ok;
emit_tunnel_closed(T) ->
    Duration = erlang:monotonic_time(millisecond) - T,
    masque_metrics:tunnel_closed(
        Duration,
        #{protocol => udp_bind, transport => h1}
    ).

%%====================================================================
%% Capsule loop
%%====================================================================

step(#state{cap_buf = Buf} = S) ->
    case h1_capsule:decode(Buf) of
        {ok, {Type, Inner}, Rest} ->
            case dispatch_capsule(Type, Inner, S#state{cap_buf = Rest}) of
                {noreply, S2} -> step(S2);
                Stop -> Stop
            end;
        {more, _} ->
            _ = arm_once(S),
            {noreply, S}
    end.

drain_and_arm(S) ->
    case step(S) of
        {noreply, S2} -> {ok, S2};
        {stop, R, S2} -> {stop, R, S2}
    end.

apply_init_actions(Actions, State) ->
    case do_actions(Actions, State) of
        {ok, S2} -> {ok, S2};
        {stop, R, _} -> {stop, R}
    end.

dispatch_capsule(datagram, Inner, S) ->
    handle_inbound_datagram(Inner, S);
dispatch_capsule(?MASQUE_CAPSULE_COMPRESSION_ASSIGN, Body, S) ->
    case masque_compression_capsule:decode_assign(Body) of
        {ok, A} -> handle_peer_assign(A, S);
        {error, _} -> {stop, malformed_capsule, S}
    end;
dispatch_capsule(?MASQUE_CAPSULE_COMPRESSION_ACK, Body, S) ->
    case masque_compression_capsule:decode_ack(Body) of
        {ok, A} -> handle_peer_ack(A, S);
        {error, _} -> {stop, malformed_capsule, S}
    end;
dispatch_capsule(?MASQUE_CAPSULE_COMPRESSION_CLOSE, Body, S) ->
    case masque_compression_capsule:decode_close(Body) of
        {ok, C} -> handle_peer_close(C, S);
        {error, _} -> {stop, malformed_capsule, S}
    end;
dispatch_capsule(Type, Value, S) when is_integer(Type) ->
    dispatch(handle_capsule, [Type, Value], S);
dispatch_capsule(_Other, _Value, S) ->
    {noreply, S}.

%%====================================================================
%% Inbound datagram path
%%====================================================================

handle_inbound_datagram(Payload, S) ->
    case masque_datagram:decode(Payload) of
        {ok, {0, Inner}} -> handle_context_zero(Inner, S);
        {ok, {Ctx, Inner}} when Ctx > 0 -> handle_known_context(Ctx, Inner, S);
        {error, _} -> drop(malformed, S)
    end.

handle_context_zero(Inner, #state{bind_scope = scoped} = S) ->
    dispatch(handle_packet, [Inner], S);
handle_context_zero(_Inner, S) ->
    drop(context_zero, S).

handle_known_context(Ctx, Inner, S) ->
    case masque_compression_table:lookup_by_id(S#state.peer_table, Ctx) of
        {ok, #compression_entry{ip_version = 0}} ->
            case masque_udp_bind_payload:decode_uncompressed(Inner) of
                {ok, {_V, IP, Port}, Pkt} ->
                    handle_bind_to_peer({IP, Port}, Pkt, S);
                {error, _} ->
                    drop(malformed, S)
            end;
        {ok, #compression_entry{ip_version = V, address = A, port = P}} when
            V =:= 4; V =:= 6
        ->
            handle_bind_to_peer({A, P}, Inner, S);
        not_found ->
            drop(unknown_context, S)
    end.

drop(Reason, S) ->
    masque_metrics:bind_drop_inc(Reason),
    {noreply, S}.

handle_bind_to_peer(Peer, Pkt, #state{handler = H, h_state = HS} = S) ->
    case exported(H, handle_bind_packet, 3) of
        true ->
            case safe_apply(H, handle_bind_packet, [Peer, Pkt, HS]) of
                {ok, HS2} ->
                    {noreply, S#state{h_state = HS2}};
                {ok, HS2, Actions} ->
                    apply_actions_noreply(
                        Actions,
                        S#state{h_state = HS2}
                    );
                {drop, R, HS2} ->
                    masque_metrics:bind_drop_inc(R),
                    {noreply, S#state{h_state = HS2}};
                {stop, R, HS2} ->
                    {stop, R, S#state{h_state = HS2}};
                {stop, R} ->
                    {stop, R, S};
                _ ->
                    {noreply, S}
            end;
        false ->
            {noreply, S}
    end.

handle_peer_assign(Assign, #state{own_table = OT} = S) ->
    Id = Assign#compression_assign.context_id,
    case masque_compression_table:install(S#state.peer_table, Assign, OT) of
        {ok, T2} ->
            send_capsule(#compression_ack{context_id = Id}, S),
            {noreply, S#state{peer_table = T2}};
        {ok, {conflict, close_proxy_id, OwnId}, T2} ->
            %% The client assigned a tuple we already opened: keep
            %% theirs, close ours.
            {ok, OT2} = masque_compression_table:install_close(
                OT, #compression_close{context_id = OwnId}
            ),
            send_capsule(#compression_ack{context_id = Id}, S),
            send_capsule(#compression_close{context_id = OwnId}, S),
            {noreply, S#state{peer_table = T2, own_table = OT2}};
        {error, _} ->
            {stop, malformed_capsule, S}
    end.

handle_peer_ack(Ack, S) ->
    case masque_compression_table:install_ack(S#state.own_table, Ack) of
        {ok, T2} -> {noreply, S#state{own_table = T2}};
        {error, _} -> {stop, malformed_capsule, S}
    end.

handle_peer_close(Close, #state{own_table = OT, peer_table = PT} = S) ->
    case masque_compression_table:install_close(OT, Close) of
        {ok, OT2} ->
            {noreply, S#state{own_table = OT2}};
        {error, unknown_context} ->
            Closed = is_uncompressed(PT, Close#compression_close.context_id),
            case masque_compression_table:install_close(PT, Close) of
                {ok, PT2} when Closed ->
                    %% Post-close prohibition: no new compressed
                    %% contexts from now on.
                    {noreply, S#state{
                        peer_table = PT2,
                        own_table = masque_compression_table:mark_uncompressed_closed(OT)
                    }};
                {ok, PT2} ->
                    {noreply, S#state{peer_table = PT2}};
                {error, _} ->
                    {stop, malformed_capsule, S}
            end
    end.

is_uncompressed(Table, Id) ->
    case masque_compression_table:lookup_by_id(Table, Id) of
        {ok, #compression_entry{ip_version = 0}} -> true;
        _ -> false
    end.

%%====================================================================
%% Action interpreter
%%====================================================================

apply_actions_noreply(Actions, S) ->
    case do_actions(Actions, S) of
        {ok, S2} -> {noreply, S2};
        {stop, R, S2} -> {stop, R, S2}
    end.

do_actions([], S) ->
    {ok, S};
do_actions([{send_bind_packet, Peer, Bytes} | Rest], S) ->
    do_actions(Rest, send_bind_payload(Peer, Bytes, S));
do_actions([{compression_assign, {IP, Port}} | Rest], S) ->
    do_actions(Rest, open_compression(IP, Port, S));
do_actions([{compression_assign, Entry} | Rest], S) ->
    send_compression_assign(Entry, S),
    do_actions(Rest, S);
do_actions([{compression_ack, Id} | Rest], S) ->
    send_capsule(#compression_ack{context_id = Id}, S),
    do_actions(Rest, S);
do_actions([{compression_close, Id} | Rest], S) ->
    send_capsule(#compression_close{context_id = Id}, S),
    do_actions(Rest, S);
do_actions([{send_capsule, Type, Value} | Rest], S) ->
    Bytes = iolist_to_binary(masque_capsule:encode(Type, Value)),
    send_bytes(Bytes, S),
    do_actions(Rest, S);
do_actions([close_session | _], S) ->
    {stop, normal, S};
do_actions([{close_session, _, _} | _], S) ->
    {stop, normal, S};
do_actions([_Other | Rest], S) ->
    do_actions(Rest, S).

%% Open an own-table mapping for a peer and announce it. Dropped when
%% `max_pending' assigns already wait for a response, or after the
%% client closed its uncompressed context (post-close prohibition).
open_compression(IP, Port, #state{own_table = OT} = S) ->
    case pending_responses(OT) >= S#state.max_pending of
        true ->
            masque_metrics:bind_drop_inc(pending_limit),
            S;
        false ->
            case
                masque_compression_table:open_compressed(
                    OT, {family_of(IP), IP, Port}
                )
            of
                {ok, Entry, OT2} ->
                    send_compression_assign(Entry, S),
                    S#state{own_table = OT2};
                {error, uncompressed_closed} ->
                    masque_metrics:bind_drop_inc(uncompressed_closed),
                    S;
                {error, _} ->
                    masque_metrics:bind_drop_inc(other),
                    S
            end
    end.

pending_responses(Table) ->
    length([
        E
     || #compression_entry{state = pending_ack} = E <-
            masque_compression_table:entries(Table)
    ]).

send_compression_assign(Entry, S) ->
    send_capsule(
        #compression_assign{
            context_id = Entry#compression_entry.context_id,
            ip_version = Entry#compression_entry.ip_version,
            address = Entry#compression_entry.address,
            port = Entry#compression_entry.port
        },
        S
    ).

send_capsule(Capsule, S) ->
    send_bytes(iolist_to_binary(masque_compression_capsule:encode(Capsule)), S).

%%====================================================================
%% Outbound datagram emit
%%====================================================================

send_bind_payload({IP, Port}, UdpPayload, S) ->
    Tuple = {family_of(IP), IP, Port},
    case
        masque_compression_table:lookup_by_tuple(
            S#state.own_table,
            Tuple
        )
    of
        {ok, #compression_entry{
            state = installed,
            ip_version = 0
        }} ->
            send_uncompressed(Tuple, UdpPayload, S);
        {ok, #compression_entry{
            state = installed,
            context_id = Id,
            ip_version = V
        }} when
            V =:= 4; V =:= 6
        ->
            send_compressed_inline(Id, UdpPayload, S);
        _ ->
            try_uncompressed_fallback(Tuple, UdpPayload, S)
    end.

try_uncompressed_fallback(Tuple, UdpPayload, S) ->
    case find_peer_uncompressed(S#state.peer_table) of
        {ok, Id} ->
            case
                masque_udp_bind_payload:encode_uncompressed(
                    Tuple, UdpPayload, advertised_families(S)
                )
            of
                {ok, Inner} -> send_dgram(Id, Inner, S);
                {error, _} -> S
            end;
        not_found ->
            S
    end.

find_peer_uncompressed(T) ->
    case
        [
            E
         || E <- masque_compression_table:entries(T),
            E#compression_entry.ip_version =:= 0
        ]
    of
        [#compression_entry{context_id = Id} | _] -> {ok, Id};
        [] -> not_found
    end.

send_uncompressed(Tuple, UdpPayload, S) ->
    case find_own_uncompressed(S#state.own_table) of
        {ok, Id} ->
            case
                masque_udp_bind_payload:encode_uncompressed(
                    Tuple, UdpPayload, advertised_families(S)
                )
            of
                {ok, Inner} -> send_dgram(Id, Inner, S);
                {error, _} -> S
            end;
        not_found ->
            S
    end.

find_own_uncompressed(T) ->
    case
        [
            E
         || E <- masque_compression_table:entries(T),
            E#compression_entry.ip_version =:= 0,
            E#compression_entry.state =:= installed
        ]
    of
        [#compression_entry{context_id = Id} | _] -> {ok, Id};
        [] -> not_found
    end.

send_compressed_inline(Id, UdpPayload, S) ->
    Inner = masque_udp_bind_payload:encode_compressed(UdpPayload),
    send_dgram(Id, Inner, S).

send_dgram(Ctx, Inner, S) ->
    Inner1 = iolist_to_binary(masque_datagram:encode(Ctx, Inner)),
    Cap = h1_capsule:encode(datagram, Inner1),
    send_bytes(iolist_to_binary(Cap), S),
    S.

send_bytes(Bytes, #state{transport = ssl, socket = Sock}) ->
    _ = ssl:send(Sock, Bytes),
    masque_metrics:bytes_out(
        byte_size(Bytes),
        #{protocol => udp_bind, transport => h1}
    ),
    ok;
send_bytes(Bytes, #state{transport = gen_tcp, socket = Sock}) ->
    _ = gen_tcp:send(Sock, Bytes),
    masque_metrics:bytes_out(
        byte_size(Bytes),
        #{protocol => udp_bind, transport => h1}
    ),
    ok.

%%====================================================================
%% Handler dispatch
%%====================================================================

init_handler(Handler, Req, HOpts) ->
    case exported(Handler, init, 2) of
        true ->
            case safe_apply(Handler, init, [Req, HOpts]) of
                {ok, HState} -> {ok, HState, []};
                {ok, HState, Actions} -> {ok, HState, Actions};
                {stop, Reason} -> {stop, Reason};
                Other -> {stop, {bad_init, Other}}
            end;
        false ->
            {ok, undefined, []}
    end.

dispatch(CB, Extra, #state{handler = H, h_state = HS} = S) ->
    case exported(H, CB, length(Extra) + 1) of
        true ->
            case safe_apply(H, CB, Extra ++ [HS]) of
                {ok, HS2} ->
                    {noreply, S#state{h_state = HS2}};
                {ok, HS2, Actions} ->
                    apply_actions_noreply(
                        Actions, S#state{h_state = HS2}
                    );
                {stop, R, HS2} ->
                    {stop, R, S#state{h_state = HS2}};
                {stop, R} ->
                    {stop, R, S};
                _ ->
                    {noreply, S}
            end;
        false ->
            {noreply, S}
    end.

%% `erlang:function_exported/3' is `false' for a module not loaded yet.
exported(Mod, Fun, Arity) ->
    _ = code:ensure_loaded(Mod),
    erlang:function_exported(Mod, Fun, Arity).

safe_apply(M, F, A) ->
    try
        apply(M, F, A)
    catch
        Class:Reason:Stack ->
            logger:error(
                "masque udp-bind-h1 handler ~p:~p/~p failed: ~p:~p~n~p",
                [M, F, length(A), Class, Reason, Stack]
            ),
            {stop, {handler_crash, Reason}}
    end.

try_callback(Mod, Fun, Args) ->
    Arity = length(Args),
    case erlang:function_exported(Mod, Fun, Arity) of
        true ->
            (try
                apply(Mod, Fun, Args)
            catch
                _:_ -> ok
            end);
        false ->
            ok
    end.

%%====================================================================
%% Idle timer + socket plumbing
%%====================================================================

arm_idle(#state{idle_ms = infinity} = S) ->
    S;
arm_idle(#state{idle_ms = Ms, idle_ref = Old} = S) ->
    _ =
        case Old of
            undefined -> ok;
            R -> erlang:cancel_timer(R)
        end,
    Ref = erlang:start_timer(Ms, self(), idle),
    S#state{idle_ref = Ref}.

cancel_idle(#state{idle_ref = undefined}) ->
    ok;
cancel_idle(#state{idle_ref = R}) ->
    _ = erlang:cancel_timer(R),
    ok.

arm_once(#state{transport = ssl, socket = S}) ->
    _ = ssl:setopts(S, [{active, once}]),
    ok;
arm_once(#state{transport = gen_tcp, socket = S}) ->
    _ = inet:setopts(S, [{active, once}]),
    ok.

close_socket(#state{transport = ssl, socket = S}) ->
    _ =
        (try
            ssl:close(S)
        catch
            _:_ -> ok
        end),
    ok;
close_socket(#state{transport = gen_tcp, socket = S}) ->
    _ =
        (try
            gen_tcp:close(S)
        catch
            _:_ -> ok
        end),
    ok.

socket_transport(Sock) when is_tuple(Sock), element(1, Sock) =:= sslsocket -> ssl;
socket_transport(_) -> gen_tcp.

%%====================================================================
%% Helpers
%%====================================================================

take_response_headers(Actions) ->
    take_response_headers(Actions, [], []).
take_response_headers([], Hdrs, Other) ->
    {lists:reverse(Hdrs), lists:reverse(Other)};
take_response_headers([{response_headers, Pairs} | Rest], H, O) ->
    take_response_headers(Rest, lists:reverse(Pairs) ++ H, O);
take_response_headers([X | Rest], H, O) ->
    take_response_headers(Rest, H, [X | O]).

read_public_addresses(Headers) ->
    case masque_uri_udp_bind:parse_proxy_public_address(Headers) of
        {ok, A} -> A;
        {error, _} -> []
    end.

advertised_families(#state{public_addresses = A}) ->
    lists:usort([family_of(IP) || {IP, _} <- A]).

family_of({_, _, _, _}) -> 4;
family_of({_, _, _, _, _, _, _, _}) -> 6.
