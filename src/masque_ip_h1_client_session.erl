%%% @doc Client-side CONNECT-IP session (RFC 9484) over HTTP/1.1.
%%%
%%% Runs the handshake as an HTTP/1.1 Upgrade (`Upgrade: connect-ip')
%%% and, after the 101 response, drives RFC 9297 capsules directly on
%%% the raw TLS socket.
%%%
%%% Control-plane capsules (ADDRESS_ASSIGN, ADDRESS_REQUEST,
%%% ROUTE_ADVERTISEMENT) are encoded via `masque_ip_capsule'. IP
%%% packets ride the DATAGRAM capsule with `masque_datagram' carrying
%%% the `context-id || IP bytes' payload. Wire format is identical to
%%% the h2 / h3 paths so `masque_ip_capsule' + `masque_datagram' are
%%% reused unchanged; only the transport plumbing differs.
%%%
%%% Sibling module of `masque_ip_client_session'; they do not share
%%% state. Keeping them separate avoids leaking the socket-ownership
%%% and active-once read model back into the h2/h3 session.
-module(masque_ip_h1_client_session).
-behaviour(gen_statem).

-export([start_link/3, start/3, stop/1, info/1]).
-export([send_ip_packet/2, recv/2, set_mode/2]).
-export([request_addresses/2, assign_addresses/2,
         advertise_routes/2, ip_info/1]).
-export([send_capsule/3]).

-export([init/1, callback_mode/0, terminate/3, code_change/4]).
-export([connecting/3, open/3, closing/3]).

-include("masque.hrl").
-include("masque_ip.hrl").

-dialyzer({nowarn_function, [do_connect/2, do_upgrade/3, request_headers/1,
                              build_authority/2, is_ipv6_literal/1]}).

-record(data, {
    owner            :: pid(),
    owner_ref        :: reference(),
    proxy_host       :: binary(),
    proxy_port       :: inet:port_number(),
    template         :: masque_uri_template:template(),
    target           :: masque_uri_ip:ip_target(),
    ipproto          :: masque_uri_ip:ip_ipproto(),
    mtu              :: 1280..65535,
    socket           :: ssl:sslsocket() | undefined,
    handshake_from   :: gen_statem:from() | undefined,
    mode             :: message | queue,
    rx_buf           :: queue:queue(binary()),
    rx_waiters       :: queue:queue({gen_statem:from(), reference()}),
    cap_buf = <<>>   :: binary(),
    max_cap          :: pos_integer(),
    peer_pending = #{} :: #{pos_integer() => true},
    next_req_id = 1   :: pos_integer(),
    assigned = []     :: [masque_ip_capsule:address_entry()],
    routes   = []     :: [masque_ip_capsule:route_entry()],
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

-spec send_ip_packet(pid(), binary()) -> ok | {error, term()}.
send_ip_packet(Pid, Packet) when is_binary(Packet) ->
    gen_statem:call(Pid, {send_ip_packet, Packet}).

recv(Pid, Timeout) ->
    gen_statem:call(Pid, {recv, Timeout}, Timeout + 500).

set_mode(Pid, Mode) when Mode =:= message; Mode =:= queue ->
    gen_statem:call(Pid, {set_mode, Mode}).

-spec request_addresses(pid(), [{4 | 6, inet:ip_address(), non_neg_integer()}]) ->
    {ok, [pos_integer()]} | {error, term()}.
request_addresses(Pid, Prefixes) ->
    gen_statem:call(Pid, {request_addresses, Prefixes}).

-spec assign_addresses(pid(), [masque_ip_capsule:address_entry()]) ->
    ok | {error, term()}.
assign_addresses(Pid, Assignments) ->
    gen_statem:call(Pid, {assign_addresses, Assignments}).

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
    MaxCap = maps:get(max_capsule_size, Opts,
                      ?MASQUE_DEFAULT_MAX_CAPSULE_SIZE),
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
        mtu = Mtu,
        mode = Mode,
        rx_buf = queue:new(),
        rx_waiters = queue:new(),
        max_cap = MaxCap,
        extra_headers = sanitise_extra_headers(
                          maps:get(request_headers, Opts, []))
    },
    {ok, connecting, Data,
     [{next_event, internal, {do_handshake, Opts}}]}.

build_template(Opts, ProxyHost, ProxyPort) ->
    case maps:find(uri_template, Opts) of
        {ok, Raw} ->
            case masque_uri_ip:parse_client_template(Raw) of
                {ok, T} -> T;
                {error, Err} ->
                    erlang:error({bad_template, Err})
            end;
        error ->
            Authority = build_authority(to_bin(ProxyHost), ProxyPort),
            Raw = <<"https://", Authority/binary,
                    ?MASQUE_DEFAULT_IP_URI_PATH_PATTERN/binary>>,
            {ok, T} = masque_uri_ip:parse_client_template(Raw),
            T
    end.

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
                     Data#data{socket = Socket,
                               cap_buf = Buffer,
                               handshake_from = undefined}};
                {error, Reason} ->
                    _ = catch ssl:close(Socket),
                    reply_handshake(Data, {error, {setopts, Reason}}),
                    {stop, {setopts, Reason}}
            end;
        {error, Reason} ->
            reply_handshake(Data, {error, Reason}),
            {stop, {handshake_failed, Reason}}
    end;
connecting({call, From}, handshake_await, Data) ->
    {keep_state, Data#data{handshake_from = From}};
connecting({call, From}, {set_owner, NewOwner}, Data) ->
    {keep_state, swap_owner(NewOwner, Data), [{reply, From, ok}]};
connecting({call, From}, info, Data) ->
    {keep_state, Data, [{reply, From, session_info(Data, connecting)}]};
connecting({call, From}, stop, Data) ->
    {stop_and_reply, normal, [{reply, From, ok}], Data};
connecting({call, From}, _Other, Data) ->
    {keep_state, Data, [{reply, From, {error, not_ready}}]};
connecting(info, {'DOWN', Ref, process, _, _},
           #data{owner_ref = Ref}) ->
    {stop, owner_gone};
connecting(info, _Msg, Data) ->
    {keep_state, Data}.

open({call, From}, handshake_await, Data) ->
    {keep_state, Data, [{reply, From, ok}]};
open({call, From}, info, Data) ->
    {keep_state, Data, [{reply, From, session_info(Data, open)}]};
open({call, From}, ip_info, Data) ->
    {keep_state, Data,
     [{reply, From, #{assigned  => Data#data.assigned,
                      routes    => Data#data.routes,
                      mtu       => Data#data.mtu,
                      transport => h1}}]};
open({call, From}, {send_ip_packet, Pkt}, Data) ->
    PktSz = byte_size(Pkt),
    case PktSz > Data#data.mtu of
        true ->
            {keep_state, Data,
             [{reply, From,
               {error, {packet_too_large, PktSz, Data#data.mtu}}}]};
        false ->
            Reply = send_datagram(Data, ?MASQUE_CONTEXT_ID_IP, Pkt),
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
open({call, From}, {send_capsule, Type, Value}, #data{socket = Sock} = Data) ->
    Reply = h1_upgrade:send_capsule(ssl, Sock, Type, Value),
    {keep_state, Data, [{reply, From, Reply}]};
open({call, From}, stop, Data) ->
    {next_state, closing, Data,
     [{reply, From, ok}, {next_event, internal, do_close}]};
open(info, {ssl, Sock, Bytes},
     #data{socket = Sock, cap_buf = Buf, max_cap = Max} = Data) ->
    New = <<Buf/binary, Bytes/binary>>,
    case byte_size(New) > Max of
        true  -> abort(capsule_buffer_overflow, Data);
        false -> drain_capsules(New, Data)
    end;
open(info, {ssl_closed, Sock}, #data{socket = Sock} = Data) ->
    _ = notify_owner_closed(peer_closed, Data),
    {stop, peer_closed, Data};
open(info, {ssl_error, Sock, Reason}, #data{socket = Sock} = Data) ->
    _ = notify_owner_closed({ssl_error, Reason}, Data),
    {stop, {ssl_error, Reason}, Data};
open(info, {timeout, TRef, {recv_timeout, From}}, Data) ->
    {keep_state, drop_waiter(TRef, From, Data)};
open(info, {'DOWN', Ref, process, _, _},
     #data{owner_ref = Ref} = Data) ->
    {next_state, closing, Data, [{next_event, internal, do_close}]};
open(info, _Msg, Data) ->
    {keep_state, Data}.

closing(internal, do_close, #data{socket = Socket} = Data) ->
    _ = case Socket of
        undefined -> ok;
        _         -> catch ssl:close(Socket)
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
    _ = (catch ssl:close(Socket)),
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
        ssl_opts  => SSLOpts,
        connect_timeout => Timeout,
        timeout   => Timeout
    },
    case h1_client:connect(binary_to_list(Data#data.proxy_host),
                            Data#data.proxy_port,
                            ConnOpts) of
        {ok, Conn} ->
            case h1:wait_connected(Conn, Timeout) of
                ok ->
                    do_upgrade(Conn, Data, Timeout);
                {error, Reason} ->
                    _ = catch h1:close(Conn),
                    {error, {connect, Reason}}
            end;
        {error, Reason} ->
            {error, {connect, Reason}}
    end.

do_upgrade(Conn, Data, Timeout) ->
    Headers = request_headers(Data),
    case h1:upgrade(Conn, ?MASQUE_CONNECT_IP_PROTOCOL, Headers, Timeout) of
        {ok, _StreamId, Socket, Buffer, RespHeaders} ->
            case validate_response(RespHeaders) of
                ok ->
                    {ok, Socket, Buffer};
                {error, _} = Err ->
                    _ = catch ssl:close(Socket),
                    Err
            end;
        {error, Reason} ->
            _ = catch h1:close(Conn),
            {error, classify_upgrade_error(Reason)}
    end.

classify_upgrade_error({http_status, Code, _} = R) -> {handshake_rejected, Code, R};
classify_upgrade_error(timeout)                    -> handshake_timeout;
classify_upgrade_error(Other)                      -> {upgrade, Other}.

request_headers(#data{template = T, target = Target, ipproto = IPProto,
                      proxy_host = ProxyHost, proxy_port = ProxyPort,
                      extra_headers = Extra}) ->
    Url = masque_uri_ip:expand(T, #{target => Target, ipproto => IPProto}),
    {_Scheme, _Authority, Path} = split_url(Url),
    Authority = build_authority(ProxyHost, ProxyPort),
    [
        {<<":path">>, Path},
        {<<"host">>, Authority},
        {<<"capsule-protocol">>, <<"?1">>}
    ] ++ Extra.

sanitise_extra_headers(List) when is_list(List) ->
    Reserved = [<<":path">>, <<"host">>, <<"capsule-protocol">>,
                <<"upgrade">>, <<"connection">>],
    [{K, V} || {K, V} <- List,
               is_binary(K), is_binary(V),
               not lists:member(lowercase_bin(K), Reserved)].

lowercase_bin(B) when is_binary(B) ->
    list_to_binary(string:to_lower(binary_to_list(B))).

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

setopts_active_once(Socket) ->
    ssl:setopts(Socket, [{active, once}, {mode, binary}]).

send_datagram(#data{socket = Sock}, Ctx, Payload) ->
    Inner = iolist_to_binary(masque_datagram:encode(Ctx, Payload)),
    h1_upgrade:send_capsule(ssl, Sock, datagram, Inner).

%%====================================================================
%% Capsule decode loop
%%====================================================================

drain_capsules(Buf, #data{socket = Socket} = Data) ->
    case h1_capsule:decode(Buf) of
        {ok, {Type, Inner}, Rest} ->
            case deliver_capsule(Type, Inner, Data) of
                {abort, Reason} ->
                    abort(Reason, Data);
                Data2 ->
                    drain_capsules(Rest, Data2#data{cap_buf = <<>>})
            end;
        {more, _} ->
            _ = setopts_active_once(Socket),
            {keep_state, Data#data{cap_buf = Buf}}
    end.

deliver_capsule(datagram, Inner, Data) ->
    case masque_datagram:decode(Inner) of
        {ok, {?MASQUE_CONTEXT_ID_IP, IPPkt}} ->
            deliver_packet(IPPkt, Data);
        {ok, {_OtherCtx, _}} ->
            Data;
        {error, _} ->
            Data
    end;
deliver_capsule(?MASQUE_CAPSULE_ADDRESS_ASSIGN, Inner,
                #data{owner = Owner} = Data) ->
    case masque_ip_capsule:decode_address_assign(Inner) of
        {ok, Entries} ->
            Owner ! {masque_address_assign, self(), Entries},
            Data#data{assigned = Entries};
        {error, _} ->
            {abort, malformed_capsule}
    end;
deliver_capsule(?MASQUE_CAPSULE_ADDRESS_REQUEST, Inner,
                #data{owner = Owner, peer_pending = Pend} = Data) ->
    case masque_ip_capsule:decode_address_request(Inner) of
        {ok, Entries} ->
            Owner ! {masque_address_request, self(), Entries},
            Pend1 = lists:foldl(
                      fun(R, Acc) ->
                          Id = element(2, R),
                          Acc#{Id => true}
                      end, Pend, Entries),
            Data#data{peer_pending = Pend1};
        {error, _} ->
            {abort, malformed_capsule}
    end;
deliver_capsule(?MASQUE_CAPSULE_ROUTE_ADVERTISEMENT, Inner,
                #data{owner = Owner} = Data) ->
    case masque_ip_capsule:decode_route_advertisement(Inner) of
        {ok, Entries} ->
            Owner ! {masque_route_advertisement, self(), Entries},
            Data#data{routes = Entries};
        {error, _} ->
            {abort, malformed_capsule}
    end;
deliver_capsule(Type, Inner, #data{owner = Owner} = Data)
  when is_integer(Type) ->
    Owner ! {masque_capsule, self(), Type, Inner},
    Data.

abort(Reason, #data{socket = Socket} = Data) ->
    _ = case Socket of
        undefined -> ok;
        _         -> catch ssl:close(Socket)
    end,
    _ = notify_owner_closed(Reason, Data),
    {stop, Reason, Data}.

%%====================================================================
%% Control-plane senders
%%====================================================================

handle_request_addresses(From, Prefixes, Data) ->
    case build_request_entries(Prefixes, Data) of
        {ok, Entries, Data1} ->
            Body = masque_ip_capsule:encode_address_request(Entries),
            case send_wrapped_capsule(Data1,
                   ?MASQUE_CAPSULE_ADDRESS_REQUEST, Body) of
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
                       request_id = N, version = V,
                       address = Addr, prefix_len = Pfx},
                {[R | Acc], N + 1}
            end, {[], Data#data.next_req_id}, Prefixes),
        {ok, lists:reverse(Rev), Data#data{next_req_id = Next}}
    catch
        throw:Err -> {error, Err};
        error:_   -> {error, bad_prefix}
    end.

handle_assign_addresses(From, Assignments,
                        #data{peer_pending = Pend} = Data) ->
    case validate_assignments(Assignments, Pend) of
        {ok, Pend1} ->
            Body = masque_ip_capsule:encode_address_assign(Assignments),
            case send_wrapped_capsule(Data,
                   ?MASQUE_CAPSULE_ADDRESS_ASSIGN, Body) of
                ok ->
                    {keep_state, Data#data{peer_pending = Pend1},
                     [{reply, From, ok}]};
                {error, _} = Err ->
                    {keep_state, Data, [{reply, From, Err}]}
            end;
        {error, _} = Err ->
            {keep_state, Data, [{reply, From, Err}]}
    end.

validate_assignments(Assignments, Pend) ->
    try
        Pend1 = lists:foldl(
            fun(#ip_assignment{request_id = 0, version = V,
                               address = A, prefix_len = P}, Acc) ->
                    ok = check_prefix(V, A, P),
                    Acc;
               (#ip_assignment{request_id = Id, version = V,
                               address = A, prefix_len = P}, Acc) ->
                    ok = check_prefix(V, A, P),
                    case maps:is_key(Id, Acc) of
                        true  -> maps:remove(Id, Acc);
                        false -> throw({no_such_pending_request, Id})
                    end
            end, Pend, Assignments),
        {ok, Pend1}
    catch
        throw:Err -> {error, Err};
        error:_   -> {error, bad_prefix}
    end.

handle_advertise_routes(From, Routes, Data) ->
    try masque_ip_capsule:encode_route_advertisement(Routes) of
        Body ->
            case send_wrapped_capsule(Data,
                   ?MASQUE_CAPSULE_ROUTE_ADVERTISEMENT, Body) of
                ok -> {keep_state, Data, [{reply, From, ok}]};
                {error, _} = Err ->
                    {keep_state, Data, [{reply, From, Err}]}
            end
    catch
        error:Reason ->
            {keep_state, Data, [{reply, From, {error, Reason}}]}
    end.

send_wrapped_capsule(#data{socket = Sock}, Type, Body) ->
    %% Control-plane capsules are plain RFC 9297 framing with the
    %% RFC 9484 capsule type as-is (no outer wrapping).
    h1_upgrade:send_capsule(ssl, Sock, Type, Body).

check_prefix(4, {A,B,C,D}, P)
  when P >= 0, P =< 32,
       A >= 0, A =< 255, B >= 0, B =< 255,
       C >= 0, C =< 255, D >= 0, D =< 255 -> ok;
check_prefix(6, Addr, P) when P >= 0, P =< 128, tuple_size(Addr) =:= 8 ->
    true = lists:all(fun(X) -> is_integer(X) andalso X >= 0 andalso X =< 16#FFFF end,
                     tuple_to_list(Addr)),
    ok;
check_prefix(V, _, P) -> throw({bad_prefix_length, P, V}).

%%====================================================================
%% Response validation
%%====================================================================

validate_response(Headers) ->
    HasCL = header_present(<<"content-length">>, Headers),
    HasCT = header_present(<<"content-type">>, Headers),
    case header_value(<<"capsule-protocol">>, Headers) of
        <<"?1">> when not HasCL, not HasCT -> ok;
        <<"?1">>                           -> {error, malformed_response};
        _                                  -> {error, capsule_protocol_missing}
    end.

header_present(Name, Headers) ->
    lists:any(fun({N, _}) -> ci_eq(N, Name) end, Headers).

header_value(Name, Headers) ->
    case lists:search(fun({N, _}) -> ci_eq(N, Name) end, Headers) of
        {value, {_, V}} -> V;
        false           -> undefined
    end.

ci_eq(A, B) ->
    string:to_lower(binary_to_list(iolist_to_binary(A))) =:=
    string:to_lower(binary_to_list(iolist_to_binary(B))).

%%====================================================================
%% Rx buffering
%%====================================================================

handle_recv_call(From, Timeout, #data{rx_buf = Buf} = Data) ->
    case queue:out(Buf) of
        {{value, Bytes}, Buf2} ->
            {keep_state, Data#data{rx_buf = Buf2},
             [{reply, From, {ok, Bytes}}]};
        {empty, _} ->
            TRef = erlang:start_timer(Timeout, self(), {recv_timeout, From}),
            {keep_state, Data#data{rx_waiters =
                queue:in({From, TRef}, Data#data.rx_waiters)}}
    end.

deliver_packet(Pkt, #data{mode = message, owner = Owner} = Data) ->
    Owner ! {masque_ip_packet, self(), Pkt},
    Data;
deliver_packet(Pkt, #data{mode = queue,
                          rx_waiters = Ws,
                          rx_buf = Buf} = Data) ->
    case queue:out(Ws) of
        {{value, {From, TRef}}, Ws2} ->
            _ = erlang:cancel_timer(TRef),
            gen_statem:reply(From, {ok, Pkt}),
            Data#data{rx_waiters = Ws2};
        {empty, _} ->
            case queue:len(Buf) < 1000 of
                true  -> Data#data{rx_buf = queue:in(Pkt, Buf)};
                false -> Data
            end
    end.

drop_waiter(TRef, From, #data{rx_waiters = Ws} = Data) ->
    Ws2 = queue:filter(
        fun({F, T}) when F =:= From, T =:= TRef ->
                gen_statem:reply(F, {error, timeout}),
                false;
           (_) -> true
        end, Ws),
    Data#data{rx_waiters = Ws2}.

cancel_all_waiters(#data{rx_waiters = Ws}) ->
    _ = queue:fold(fun({From, TRef}, _) ->
        _ = erlang:cancel_timer(TRef),
        gen_statem:reply(From, {error, closed}),
        ok
    end, ok, Ws),
    ok.

%%====================================================================
%% Misc
%%====================================================================

reply_handshake(#data{handshake_from = undefined}, _Reply) -> ok;
reply_handshake(#data{handshake_from = From}, Reply) ->
    gen_statem:reply(From, Reply).

notify_owner_closed(Reason, #data{owner = Owner, mode = message}) ->
    Owner ! {masque_closed, self(), Reason};
notify_owner_closed(_Reason, _Data) -> ok.

swap_owner(NewOwner, #data{owner_ref = OldRef} = Data) ->
    _ = erlang:demonitor(OldRef, [flush]),
    NewRef = erlang:monitor(process, NewOwner),
    Data#data{owner = NewOwner, owner_ref = NewRef}.

session_info(#data{target = T, ipproto = P, proxy_host = PH,
                   proxy_port = PP}, State) ->
    #{state => State, protocol => ip, transport => h1,
      proxy => {PH, PP}, target => T, ipproto => P}.

to_bin(X) when is_binary(X) -> X;
to_bin(X) when is_list(X)   -> list_to_binary(X);
to_bin(X) when is_atom(X)   -> atom_to_binary(X, utf8).

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
