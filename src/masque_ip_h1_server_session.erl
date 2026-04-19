%%% @doc Per-tunnel server session for CONNECT-IP (RFC 9484) over
%%% HTTP/1.1.
%%%
%%% Spawned by `masque_h1_server' after a `GET' with
%%% `Upgrade: connect-ip' passes validation. The session calls
%%% `h1:accept_upgrade/3' in `init/1' so socket ownership lands on
%%% this gen_server. After the 101 response, the raw TLS socket
%%% becomes the tunnel; datagrams and control capsules are framed
%%% via RFC 9297 capsules on that socket.
%%%
%%% Wire format is identical to the h2 / h3 paths, so
%%% `masque_ip_capsule' + `masque_datagram' are reused unchanged;
%%% only the transport plumbing differs.
-module(masque_ip_h1_server_session).
-behaviour(gen_server).

-export([start_link/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include("masque.hrl").
-include("masque_ip.hrl").

-record(state, {
    transport  :: gen_tcp | ssl,
    socket     :: ssl:sslsocket() | gen_tcp:socket(),
    handler    :: module(),
    h_state    :: term(),
    req        :: map(),
    cap_buf = <<>>       :: binary(),
    max_cap              :: pos_integer(),
    peer_pending = #{}   :: #{pos_integer() => true},
    start_time           :: integer() | undefined
}).

%%====================================================================
%% API
%%====================================================================

-spec start_link(map()) -> {ok, pid()} | ignore | {error, term()}.
start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

%%====================================================================
%% gen_server
%%====================================================================

init(#{conn := Conn, stream_id := StreamId,
       handler := Handler, handler_opts := HOpts, req := Req}) ->
    process_flag(trap_exit, true),
    MaxCap = maps:get(max_capsule_size, HOpts,
                      ?MASQUE_DEFAULT_MAX_CAPSULE_SIZE),
    %% init_handler before accept_upgrade: a handler rejection (e.g.
    %% address pool exhausted) becomes a 502 on the as-yet-unupgraded
    %% connection, not a "101 + immediate close".
    case init_handler(Handler, Req, HOpts) of
        {ok, HState, Actions} ->
            case h1:accept_upgrade(Conn, StreamId,
                                    [{<<"capsule-protocol">>, <<"?1">>}]) of
                {ok, Socket, Buffer} ->
                    Transport = socket_transport(Socket),
                    State0 = #state{
                        transport = Transport,
                        socket    = Socket,
                        handler   = Handler,
                        h_state   = HState,
                        req       = Req,
                        cap_buf   = Buffer,
                        max_cap   = MaxCap,
                        start_time = erlang:monotonic_time(millisecond)
                    },
                    case drain_and_arm(State0) of
                        {ok, State1} ->
                            apply_init_actions(Actions, State1);
                        {stop, Reason, _State} ->
                            _ = close_socket(State0),
                            {stop, Reason}
                    end;
                {error, Reason} ->
                    try_callback(Handler, terminate,
                                  [{accept_upgrade, Reason}, HState]),
                    {stop, {accept_upgrade, Reason}}
            end;
        {stop, Reason} ->
            {stop, Reason}
    end.

handle_call(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

handle_cast(_Msg, S) ->
    {noreply, S}.

handle_info({ssl, Sock, Bytes},
            #state{socket = Sock, cap_buf = Buf, max_cap = Max} = S) ->
    New = <<Buf/binary, Bytes/binary>>,
    case byte_size(New) > Max of
        true  -> {stop, capsule_buffer_overflow, S};
        false -> step(S#state{cap_buf = New})
    end;
handle_info({tcp, Sock, Bytes},
            #state{socket = Sock, cap_buf = Buf, max_cap = Max} = S) ->
    New = <<Buf/binary, Bytes/binary>>,
    case byte_size(New) > Max of
        true  -> {stop, capsule_buffer_overflow, S};
        false -> step(S#state{cap_buf = New})
    end;
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

terminate(Reason, #state{handler = Handler, h_state = HState,
                          start_time = Start} = S) ->
    _ = close_socket(S),
    try_callback(Handler, terminate, [Reason, HState]),
    _ = emit_tunnel_closed(Start),
    ok.

code_change(_OldVsn, S, _Extra) ->
    {ok, S}.

emit_tunnel_closed(undefined) -> ok;
emit_tunnel_closed(T) ->
    Duration = erlang:monotonic_time(millisecond) - T,
    masque_metrics:tunnel_closed(Duration,
                                 #{protocol => ip, transport => h1}).

%%====================================================================
%% Capsule decode loop
%%====================================================================

step(#state{cap_buf = Buf} = S) ->
    case h1_capsule:decode(Buf) of
        {ok, {Type, Inner}, Rest} ->
            case dispatch_capsule(Type, Inner, S#state{cap_buf = Rest}) of
                {noreply, S2} -> step(S2);
                Stop          -> Stop
            end;
        {more, _} ->
            _ = arm_once(S),
            {noreply, S}
    end.

drain_and_arm(S) ->
    case step(S) of
        {noreply, S2}        -> {ok, S2};
        {stop, Reason, S2}   -> {stop, Reason, S2}
    end.

apply_init_actions(Actions, State) ->
    case do_actions(Actions, State) of
        {ok, S2}           -> {ok, S2};
        {stop, Reason, _S} -> {stop, Reason}
    end.

dispatch_capsule(datagram, Inner, S) ->
    dispatch_datagram(Inner, S);
dispatch_capsule(?MASQUE_CAPSULE_ADDRESS_REQUEST, Body,
                 #state{peer_pending = Pend} = S) ->
    case masque_ip_capsule:decode_address_request(Body) of
        {ok, Entries} ->
            Pend1 = lists:foldl(
                      fun(#ip_prefix_request{request_id = Id}, Acc) ->
                          Acc#{Id => true}
                      end, Pend, Entries),
            dispatch(handle_address_request, [Entries],
                     S#state{peer_pending = Pend1});
        {error, _} ->
            {stop, malformed_capsule, S}
    end;
dispatch_capsule(?MASQUE_CAPSULE_ADDRESS_ASSIGN, Body, S) ->
    case masque_ip_capsule:decode_address_assign(Body) of
        {ok, Entries} ->
            dispatch(handle_address_assign, [Entries], S);
        {error, _} ->
            {stop, malformed_capsule, S}
    end;
dispatch_capsule(?MASQUE_CAPSULE_ROUTE_ADVERTISEMENT, Body, S) ->
    case masque_ip_capsule:decode_route_advertisement(Body) of
        {ok, Entries} ->
            dispatch(handle_route_advertisement, [Entries], S);
        {error, _} ->
            {stop, malformed_capsule, S}
    end;
dispatch_capsule(Type, Inner, S) when is_integer(Type) ->
    dispatch(handle_capsule, [Type, Inner], S).

dispatch_datagram(Payload, S) ->
    case masque_datagram:decode(Payload) of
        {ok, {?MASQUE_CONTEXT_ID_IP, IPPkt}} ->
            dispatch(handle_ip_packet, [IPPkt], S);
        {ok, {_OtherCtx, _}} ->
            {noreply, S};
        {error, _} ->
            {noreply, S}
    end.

%%====================================================================
%% Handler dispatch (mirrors masque_ip_server_session)
%%====================================================================

init_handler(Handler, Req, HOpts) ->
    case exported(Handler, init, 2) of
        true ->
            case safe_apply(Handler, init, [Req, HOpts]) of
                {ok, HState}          -> {ok, HState, []};
                {ok, HState, Actions} -> {ok, HState, Actions};
                {stop, Reason}        -> {stop, Reason};
                Other                 -> {stop, {bad_init, Other}}
            end;
        false ->
            {ok, undefined, []}
    end.

dispatch(CB, Extra, #state{handler = Handler, h_state = HS} = S) ->
    case exported(Handler, CB, length(Extra) + 1) of
        true ->
            case safe_apply(Handler, CB, Extra ++ [HS]) of
                {ok, HS2}           -> {noreply, S#state{h_state = HS2}};
                {ok, HS2, Actions}  -> apply_actions_noreply(
                                         Actions, S#state{h_state = HS2});
                {stop, Reason, HS2} -> {stop, Reason,
                                              S#state{h_state = HS2}};
                _                   -> {noreply, S}
            end;
        false ->
            {noreply, S}
    end.

exported(Mod, Fun, Arity) ->
    _ = code:ensure_loaded(Mod),
    erlang:function_exported(Mod, Fun, Arity).

apply_actions_noreply(Actions, State) ->
    case do_actions(Actions, State) of
        {ok, S2}           -> {noreply, S2};
        {stop, Reason, S2} -> {stop, Reason, S2}
    end.

%%====================================================================
%% Action interpreter (matches masque_ip_server_session's surface so
%% user handlers work unchanged across transports).
%%====================================================================

do_actions([], S) ->
    {ok, S};
do_actions([{send_ip_packet, Pkt} | Rest], S) ->
    _ = send_datagram(S, ?MASQUE_CONTEXT_ID_IP, Pkt),
    do_actions(Rest, S);
do_actions([{assign, Entries} | Rest], S) ->
    case send_assign(Entries, S) of
        {ok, S2}   -> do_actions(Rest, S2);
        {error, _} -> do_actions(Rest, S)
    end;
do_actions([{advertise, Routes} | Rest], S) ->
    _ = send_advertise(Routes, S),
    do_actions(Rest, S);
do_actions([{request_addresses, Prefixes} | Rest], S) ->
    _ = send_request(Prefixes, S),
    do_actions(Rest, S);
do_actions([{icmp_error, {Kind, Spec, Invoking}} | Rest], S)
  when is_binary(Invoking) ->
    Pkt = masque_icmp:apply_action(Kind, Spec, Invoking),
    _ = send_datagram(S, ?MASQUE_CONTEXT_ID_IP, Pkt),
    do_actions(Rest, S);
do_actions([{icmp_error, _Bad} | Rest], S) ->
    do_actions(Rest, S);
do_actions([{send_capsule, Type, Value} | Rest], S) ->
    _ = h1_upgrade:send_capsule(S#state.transport, S#state.socket,
                                 Type, Value),
    do_actions(Rest, S);
do_actions([{close, _Reason} | _Rest], S) ->
    {stop, normal, S};
do_actions([close_session | _Rest], S) ->
    {stop, normal, S};
do_actions([_Unknown | Rest], S) ->
    do_actions(Rest, S).

send_datagram(#state{transport = T, socket = Sock}, Ctx, Payload) ->
    Inner = iolist_to_binary(masque_datagram:encode(Ctx, Payload)),
    h1_upgrade:send_capsule(T, Sock, datagram, Inner).

send_assign(Entries, #state{peer_pending = Pend} = S) ->
    case consume_pending(Entries, Pend) of
        {ok, Pend1} ->
            try masque_ip_capsule:encode_address_assign(Entries) of
                Body ->
                    case h1_upgrade:send_capsule(S#state.transport,
                                                   S#state.socket,
                                                   ?MASQUE_CAPSULE_ADDRESS_ASSIGN,
                                                   Body) of
                        ok -> {ok, S#state{peer_pending = Pend1}};
                        {error, _} = Err -> Err
                    end
            catch
                error:Reason -> {error, Reason}
            end;
        {error, _} = Err -> Err
    end.

consume_pending([], Pend) -> {ok, Pend};
consume_pending([#ip_assignment{request_id = 0} | Rest], Pend) ->
    consume_pending(Rest, Pend);
consume_pending([#ip_assignment{request_id = Id} | Rest], Pend) ->
    case maps:is_key(Id, Pend) of
        true  -> consume_pending(Rest, maps:remove(Id, Pend));
        false -> {error, {no_such_pending_request, Id}}
    end.

send_advertise(Routes, S) ->
    try masque_ip_capsule:encode_route_advertisement(Routes) of
        Body ->
            h1_upgrade:send_capsule(S#state.transport, S#state.socket,
                                     ?MASQUE_CAPSULE_ROUTE_ADVERTISEMENT,
                                     Body)
    catch
        error:Reason -> {error, Reason}
    end.

send_request(Prefixes, S) ->
    Ids = allocate_request_ids(length(Prefixes)),
    Entries = lists:zipwith(
        fun(Id, {V, A, P}) ->
            #ip_prefix_request{request_id = Id, version = V,
                               address = A, prefix_len = P}
        end, Ids, Prefixes),
    try masque_ip_capsule:encode_address_request(Entries) of
        Body ->
            h1_upgrade:send_capsule(S#state.transport, S#state.socket,
                                     ?MASQUE_CAPSULE_ADDRESS_REQUEST,
                                     Body)
    catch
        error:Reason -> {error, Reason}
    end.

allocate_request_ids(N) ->
    Base = erlang:unique_integer([positive, monotonic]),
    [Base + I || I <- lists:seq(0, N - 1)].

%%====================================================================
%% Socket helpers
%%====================================================================

arm_once(#state{transport = ssl, socket = Sock}) ->
    ssl:setopts(Sock, [{active, once}, {mode, binary}]);
arm_once(#state{transport = gen_tcp, socket = Sock}) ->
    inet:setopts(Sock, [{active, once}, {mode, binary}]).

close_socket(#state{transport = T, socket = S}) ->
    close_transport(T, S).

close_transport(ssl, S)     -> catch ssl:close(S);
close_transport(gen_tcp, S) -> catch gen_tcp:close(S).

socket_transport(Socket) when is_tuple(Socket),
                               element(1, Socket) =:= sslsocket ->
    ssl;
socket_transport(_) ->
    gen_tcp.

%%====================================================================
%% Misc
%%====================================================================

safe_apply(M, F, A) ->
    try apply(M, F, A)
    catch
        Class:Reason:Stack ->
            error_logger:error_msg(
                "masque ip-h1 handler ~p:~p/~p failed: ~p:~p~n~p~n",
                [M, F, length(A), Class, Reason, Stack]),
            {stop, {handler_crash, Reason}}
    end.

try_callback(Mod, Fun, Args) ->
    Arity = length(Args),
    case erlang:function_exported(Mod, Fun, Arity) of
        true  -> (catch apply(Mod, Fun, Args));
        false -> ok
    end.
