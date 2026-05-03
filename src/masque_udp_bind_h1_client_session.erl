%%% @doc Connect-UDP-Bind client session over HTTP/1.1
%%% (draft-ietf-masque-connect-udp-listen-11). Sibling of
%%% `masque_udp_bind_client_session' for the h2/h3 paths.
%%%
%%% Public API and owner-message shape match the h2/h3 client; only
%%% the transport plumbing differs.
-module(masque_udp_bind_h1_client_session).
-behaviour(gen_statem).

-export([start_link/3, start/3, stop/1, info/1]).
-export([send_to/3, recv/2, set_mode/2]).
-export([assign_compression/2, open_uncompressed_context/1,
         close_compression/2, proxy_public_address/1]).
-export([send_capsule/3]).

-export([init/1, callback_mode/0, terminate/3, code_change/4]).
-export([connecting/3, open/3, closing/3]).

-include("masque.hrl").
-include("masque_udp_bind.hrl").

-dialyzer({nowarn_function, [do_connect/2, build_authority/2]}).

-record(data, {
    owner             :: pid(),
    owner_ref         :: reference(),
    proxy_host        :: binary(),
    proxy_port        :: inet:port_number(),
    bind_target       :: unscoped | {Host :: binary(), Port :: 1..65535},
    bind_scope        :: scoped | unscoped,
    socket            :: ssl:sslsocket() | undefined,
    handshake_from    :: gen_statem:from() | undefined,
    mode              :: message | queue,
    rx_buf            :: queue:queue({inet:ip_address(),
                                       inet:port_number(), binary()}),
    rx_waiters        :: queue:queue({gen_statem:from(), reference()}),
    cap_buf = <<>>    :: binary(),
    max_cap           :: pos_integer(),
    extra_headers = []:: [{binary(), binary()}],
    public_addresses  :: [{inet:ip_address(), inet:port_number()}],
    own_table         :: masque_compression_table:state() | undefined,
    peer_table        :: masque_compression_table:state() | undefined
}).

-define(CLIENT_ROLE, client).

start_link(Target, Opts, Owner) ->
    gen_statem:start_link(?MODULE, {Target, Opts, Owner}, []).
start(Target, Opts, Owner) ->
    gen_statem:start(?MODULE, {Target, Opts, Owner}, []).

stop(Pid) -> gen_statem:call(Pid, stop, 5000).
info(Pid) -> gen_statem:call(Pid, info, 1000).

send_to(Pid, {IP, Port}, Bytes) when is_binary(Bytes) ->
    gen_statem:call(Pid, {send_to, {IP, Port}, Bytes}).

recv(Pid, Timeout) ->
    gen_statem:call(Pid, {recv, Timeout}, Timeout + 500).

set_mode(Pid, Mode) when Mode =:= message; Mode =:= queue ->
    gen_statem:call(Pid, {set_mode, Mode}).

assign_compression(Pid, Peer) ->
    gen_statem:call(Pid, {assign_compression, Peer}).

open_uncompressed_context(Pid) ->
    gen_statem:call(Pid, open_uncompressed_context).

close_compression(Pid, Id) ->
    gen_statem:call(Pid, {close_compression, Id}).

proxy_public_address(Pid) ->
    gen_statem:call(Pid, proxy_public_address).

send_capsule(Pid, Type, Value) ->
    gen_statem:call(Pid, {send_capsule, Type, Value}).

callback_mode() -> state_functions.

init({Target, Opts, Owner}) ->
    process_flag(trap_exit, true),
    {ProxyHost, ProxyPort} = maps:get(proxy, Opts),
    MRef = erlang:monitor(process, Owner),
    Mode = maps:get(mode, Opts, message),
    MaxCap = maps:get(max_capsule_size, Opts,
                      ?MASQUE_DEFAULT_MAX_CAPSULE_SIZE),
    Scope = case Target of unscoped -> unscoped; {_,_} -> scoped end,
    Data = #data{
        owner = Owner,
        owner_ref = MRef,
        proxy_host = to_bin(ProxyHost),
        proxy_port = ProxyPort,
        bind_target = Target,
        bind_scope = Scope,
        mode = Mode,
        rx_buf = queue:new(),
        rx_waiters = queue:new(),
        max_cap = MaxCap,
        extra_headers = maps:get(request_headers, Opts, []),
        public_addresses = []
    },
    {ok, connecting, Data,
     [{next_event, internal, {do_handshake, Opts}}]}.

%%====================================================================
%% State: connecting
%%====================================================================

connecting(internal, {do_handshake, Opts}, Data) ->
    case do_connect(Data, Opts) of
        {ok, Socket, Buffer, RespHeaders} ->
            case validate_response(RespHeaders) of
                {ok, Addrs} ->
                    Families = lists:usort([family_of(IP)
                                             || {IP, _} <- Addrs]),
                    TableOpts = #{advertised_families => Families},
                    Data1 = Data#data{
                        socket = Socket,
                        cap_buf = Buffer,
                        public_addresses = Addrs,
                        own_table  = masque_compression_table:new_own(
                                       ?CLIENT_ROLE, TableOpts),
                        peer_table = masque_compression_table:new_peer(
                                       ?CLIENT_ROLE, TableOpts)},
                    _ = setopts_active_once(Socket),
                    reply_handshake(Data, ok),
                    {next_state, open, Data1};
                {error, Reason} ->
                    _ = (catch ssl:close(Socket)),
                    reply_handshake(Data, {error, Reason}),
                    {stop, {handshake_failed, Reason}}
            end;
        {error, Reason} ->
            reply_handshake(Data, {error, Reason}),
            {stop, {handshake_failed, Reason}}
    end;
connecting({call, From}, handshake_await, Data) ->
    {keep_state, Data#data{handshake_from = From}};
connecting({call, From}, _Other, Data) ->
    {keep_state, Data, [{reply, From, {error, not_ready}}]};
connecting(info, {'DOWN', Ref, process, _, _},
           #data{owner_ref = Ref}) ->
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
open({call, From}, {assign_compression, Peer}, Data) ->
    handle_assign_compression(From, Peer, Data);
open({call, From}, open_uncompressed_context, Data) ->
    handle_open_uncompressed_context(From, Data);
open({call, From}, {close_compression, Id}, Data) ->
    handle_close_compression(From, Id, Data);
open({call, From}, proxy_public_address, Data) ->
    {keep_state, Data,
     [{reply, From, {ok, Data#data.public_addresses}}]};
open({call, From}, {send_capsule, Type, Value}, Data) ->
    Bytes = iolist_to_binary(masque_capsule:encode(Type, Value)),
    Reply = ssl_send(Data, Bytes),
    {keep_state, Data, [{reply, From, Reply}]};
open({call, From}, stop, Data) ->
    {next_state, closing, Data,
     [{reply, From, ok}, {next_event, internal, do_close}]};
open(info, {ssl, Sock, Bytes},
     #data{socket = Sock, cap_buf = Buf, max_cap = Max} = Data) ->
    New = <<Buf/binary, Bytes/binary>>,
    case byte_size(New) > Max of
        true  -> {stop, capsule_buffer_overflow};
        false -> drain_capsules(New, Data)
    end;
open(info, {ssl_closed, Sock}, #data{socket = Sock}) ->
    {stop, peer_closed};
open(info, {ssl_error, Sock, Reason}, #data{socket = Sock}) ->
    {stop, {ssl_error, Reason}};
open(info, {timeout, TRef, {recv_timeout, From}}, Data) ->
    {keep_state, drop_waiter(TRef, From, Data)};
open(info, {'DOWN', Ref, process, _, _},
     #data{owner_ref = Ref} = Data) ->
    {next_state, closing, Data, [{next_event, internal, do_close}]};
open(info, _Msg, Data) ->
    {keep_state, Data}.

closing(internal, do_close, #data{socket = Socket} = Data) ->
    _ = case Socket of undefined -> ok; _ -> catch ssl:close(Socket) end,
    {stop, normal, Data};
closing(_, _, Data) ->
    {keep_state, Data}.

terminate(Reason, _State, #data{owner = Owner, mode = message,
                                socket = Socket}) ->
    _ = case Socket of undefined -> ok; _ -> catch ssl:close(Socket) end,
    Owner ! {masque_closed, self(), Reason},
    ok;
terminate(_Reason, _State, #data{socket = Socket}) ->
    _ = case Socket of undefined -> ok; _ -> catch ssl:close(Socket) end,
    ok.

code_change(_OldVsn, State, Data, _Extra) ->
    {ok, State, Data}.

%%====================================================================
%% Send path
%%====================================================================

handle_send_to({IP, Port}, Bytes, Data) ->
    Tuple = {family_of(IP), IP, Port},
    case masque_compression_table:lookup_by_tuple(
           Data#data.own_table, Tuple) of
        {ok, #compression_entry{state = installed,
                                ip_version = 0}} ->
            send_uncompressed(Tuple, Bytes, Data);
        {ok, #compression_entry{state = installed, context_id = Id,
                                ip_version = V}}
          when V =:= 4; V =:= 6 ->
            send_compressed_inline(Id, Bytes, Data);
        _ ->
            try_uncompressed_fallback(Tuple, Bytes, Data)
    end.

try_uncompressed_fallback(Tuple, Bytes, Data) ->
    case find_peer_uncompressed(Data#data.peer_table) of
        {ok, Id} ->
            case masque_udp_bind_payload:encode_uncompressed(
                   Tuple, Bytes, advertised_families(Data)) of
                {ok, Inner} ->
                    {ok, send_datagram(Id, Inner, Data)};
                {error, _} = E ->
                    {E, Data}
            end;
        not_found ->
            {{error, no_compression_context}, Data}
    end.

find_peer_uncompressed(T) ->
    case [E || E <- masque_compression_table:entries(T),
               E#compression_entry.ip_version =:= 0] of
        [#compression_entry{context_id = Id} | _] -> {ok, Id};
        []                                        -> not_found
    end.

send_uncompressed(Tuple, Bytes, Data) ->
    case find_own_uncompressed(Data#data.own_table) of
        {ok, Id} ->
            case masque_udp_bind_payload:encode_uncompressed(
                   Tuple, Bytes, advertised_families(Data)) of
                {ok, Inner} -> {ok, send_datagram(Id, Inner, Data)};
                {error, _} = E -> {E, Data}
            end;
        not_found ->
            {{error, no_uncompressed_context}, Data}
    end.

find_own_uncompressed(T) ->
    case [E || E <- masque_compression_table:entries(T),
               E#compression_entry.ip_version =:= 0,
               E#compression_entry.state =:= installed] of
        [#compression_entry{context_id = Id} | _] -> {ok, Id};
        []                                        -> not_found
    end.

send_compressed_inline(Id, Bytes, Data) ->
    Inner = masque_udp_bind_payload:encode_compressed(Bytes),
    {ok, send_datagram(Id, Inner, Data)}.

send_datagram(Ctx, Inner, Data) ->
    Inner1 = iolist_to_binary(masque_datagram:encode(Ctx, Inner)),
    Cap = h1_capsule:encode(datagram, Inner1),
    _ = ssl_send(Data, iolist_to_binary(Cap)),
    Data.

%%====================================================================
%% Compression API
%%====================================================================

handle_assign_compression(From, {IP, Port}, Data) ->
    Tuple = {family_of(IP), IP, Port},
    case masque_compression_table:open_compressed(
           Data#data.own_table, Tuple) of
        {ok, Entry, T2} ->
            Bytes = iolist_to_binary(
                      masque_compression_capsule:encode(
                        #compression_assign{
                          context_id = Entry#compression_entry.context_id,
                          ip_version = Entry#compression_entry.ip_version,
                          address    = Entry#compression_entry.address,
                          port       = Entry#compression_entry.port})),
            _ = ssl_send(Data, Bytes),
            {keep_state, Data#data{own_table = T2},
             [{reply, From,
               {ok, Entry#compression_entry.context_id}}]};
        {error, R} ->
            {keep_state, Data, [{reply, From, {error, R}}]}
    end.

handle_open_uncompressed_context(From, Data) ->
    case masque_compression_table:open_uncompressed(
           Data#data.own_table) of
        {ok, Entry, T2} ->
            Bytes = iolist_to_binary(
                      masque_compression_capsule:encode(
                        #compression_assign{
                          context_id = Entry#compression_entry.context_id,
                          ip_version = 0,
                          address    = undefined,
                          port       = undefined})),
            _ = ssl_send(Data, Bytes),
            {keep_state, Data#data{own_table = T2},
             [{reply, From,
               {ok, Entry#compression_entry.context_id}}]};
        {error, R} ->
            {keep_state, Data, [{reply, From, {error, R}}]}
    end.

handle_close_compression(From, Id, Data) ->
    Close = #compression_close{context_id = Id},
    case masque_compression_table:install_close(
           Data#data.own_table, Close) of
        {ok, OT2} ->
            send_close(Id, Data),
            {keep_state, Data#data{own_table = OT2},
             [{reply, From, ok}]};
        {error, unknown_context} ->
            case masque_compression_table:install_close(
                   Data#data.peer_table, Close) of
                {ok, PT2} ->
                    send_close(Id, Data),
                    {keep_state, Data#data{peer_table = PT2},
                     [{reply, From, ok}]};
                {error, _} = E ->
                    {keep_state, Data, [{reply, From, E}]}
            end
    end.

send_close(Id, Data) ->
    Bytes = iolist_to_binary(
              masque_compression_capsule:encode(
                #compression_close{context_id = Id})),
    _ = ssl_send(Data, Bytes),
    ok.

%%====================================================================
%% Inbound capsule + datagram path
%%====================================================================

drain_capsules(Buf, Data) ->
    case h1_capsule:decode(Buf) of
        {ok, {Type, Inner}, Rest} ->
            case dispatch_capsule(Type, Inner, Data) of
                {ok, Data2} ->
                    drain_capsules(Rest, Data2#data{cap_buf = <<>>});
                {stop, R} ->
                    {stop, R, Data}
            end;
        {more, _} ->
            _ = setopts_active_once(Data#data.socket),
            {keep_state, Data#data{cap_buf = Buf}}
    end.

dispatch_capsule(datagram, Inner, Data) ->
    Data1 = handle_inbound_datagram(Inner, Data),
    {ok, Data1};
dispatch_capsule(?MASQUE_CAPSULE_COMPRESSION_ASSIGN, Body, Data) ->
    case masque_compression_capsule:decode_assign(Body) of
        {ok, A} ->
            case masque_compression_table:install(
                   Data#data.peer_table, A) of
                {ok, T2} ->
                    Owner = Data#data.owner,
                    Owner ! {masque_compression_assigned, self(),
                             A#compression_assign.context_id,
                             {A#compression_assign.address,
                              A#compression_assign.port}},
                    %% Send ACK
                    Bytes = iolist_to_binary(
                              masque_compression_capsule:encode(
                                #compression_ack{
                                  context_id =
                                    A#compression_assign.context_id})),
                    _ = ssl_send(Data, Bytes),
                    {ok, Data#data{peer_table = T2}};
                {error, _} -> {stop, malformed_capsule}
            end;
        {error, _} -> {stop, malformed_capsule}
    end;
dispatch_capsule(?MASQUE_CAPSULE_COMPRESSION_ACK, Body, Data) ->
    case masque_compression_capsule:decode_ack(Body) of
        {ok, Ack} ->
            case masque_compression_table:install_ack(
                   Data#data.own_table, Ack) of
                {ok, T2} ->
                    Data#data.owner !
                        {masque_compression_acked, self(),
                         Ack#compression_ack.context_id},
                    {ok, Data#data{own_table = T2}};
                {error, _} -> {stop, malformed_capsule}
            end;
        {error, _} -> {stop, malformed_capsule}
    end;
dispatch_capsule(?MASQUE_CAPSULE_COMPRESSION_CLOSE, Body, Data) ->
    case masque_compression_capsule:decode_close(Body) of
        {ok, C} ->
            Id = C#compression_close.context_id,
            case masque_compression_table:install_close(
                   Data#data.peer_table, C) of
                {ok, T2} ->
                    Data#data.owner !
                        {masque_compression_closed, self(), Id},
                    {ok, Data#data{peer_table = T2}};
                {error, unknown_context} ->
                    case masque_compression_table:install_close(
                           Data#data.own_table, C) of
                        {ok, T2} ->
                            Data#data.owner !
                                {masque_compression_closed, self(),
                                 Id},
                            {ok, Data#data{own_table = T2}};
                        {error, _} -> {stop, malformed_capsule}
                    end
            end;
        {error, _} -> {stop, malformed_capsule}
    end;
dispatch_capsule(_Type, _Value, Data) ->
    {ok, Data}.

handle_inbound_datagram(Payload, Data) ->
    case masque_datagram:decode(Payload) of
        {ok, {0, Inner}}                  -> handle_context_zero(Inner, Data);
        {ok, {Ctx, Inner}} when Ctx > 0   -> handle_known_context(Ctx, Inner, Data);
        {error, _}                        -> Data
    end.

handle_context_zero(Inner, #data{bind_scope = scoped} = Data) ->
    deliver_bind_packet(Data#data.bind_target, Inner, Data);
handle_context_zero(_Inner, Data) ->
    Data.

handle_known_context(Ctx, Inner, Data) ->
    case masque_compression_table:lookup_by_id(Data#data.peer_table, Ctx) of
        {ok, #compression_entry{ip_version = 0}} ->
            case masque_udp_bind_payload:decode_uncompressed(Inner) of
                {ok, {_V, IP, Port}, Pkt} ->
                    deliver_bind_packet({IP, Port}, Pkt, Data);
                {error, _} -> Data
            end;
        {ok, #compression_entry{ip_version = V, address = A, port = P}}
          when V =:= 4; V =:= 6 ->
            deliver_bind_packet({A, P}, Inner, Data);
        not_found ->
            Data
    end.

deliver_bind_packet(Peer, Bytes,
                    #data{mode = message, owner = Owner} = Data) ->
    Owner ! {masque_bind_packet, self(), Peer, Bytes},
    Data;
deliver_bind_packet(Peer, Bytes,
                    #data{mode = queue, rx_buf = Q,
                          rx_waiters = Ws} = Data) ->
    case queue:out(Ws) of
        {{value, {From, TRef}}, Ws2} ->
            _ = erlang:cancel_timer(TRef),
            gen_statem:reply(From, {ok, Peer, Bytes}),
            Data#data{rx_waiters = Ws2};
        {empty, _} ->
            Data#data{rx_buf = queue:in({Peer, Bytes}, Q)}
    end.

%%====================================================================
%% Recv
%%====================================================================

handle_recv_call(From, Timeout, #data{rx_buf = Q,
                                      rx_waiters = Ws} = Data) ->
    case queue:out(Q) of
        {{value, {Peer, Bytes}}, Q2} ->
            {keep_state, Data#data{rx_buf = Q2},
             [{reply, From, {ok, Peer, Bytes}}]};
        {empty, _} ->
            TRef = erlang:start_timer(Timeout, self(),
                                       {recv_timeout, From}),
            {keep_state,
             Data#data{rx_waiters = queue:in({From, TRef}, Ws)}}
    end.

drop_waiter(TRef, From, #data{rx_waiters = Ws} = Data) ->
    Filtered = queue:filter(
                 fun({F, T}) -> not (F =:= From andalso T =:= TRef) end,
                 Ws),
    gen_statem:reply(From, {error, timeout}),
    Data#data{rx_waiters = Filtered}.

%%====================================================================
%% Handshake
%%====================================================================

do_connect(Data, Opts) ->
    SslOpts = build_ssl_opts(Opts),
    Host = binary_to_list(Data#data.proxy_host),
    Port = Data#data.proxy_port,
    case ssl:connect(Host, Port, SslOpts) of
        {ok, Socket} ->
            ReqBin = build_request(Data),
            case ssl:send(Socket, ReqBin) of
                ok ->
                    case read_response(Socket) of
                        {ok, RespHeaders, Buffer} ->
                            {ok, Socket, Buffer, RespHeaders};
                        {error, R} ->
                            _ = ssl:close(Socket),
                            {error, R}
                    end;
                {error, R} ->
                    _ = ssl:close(Socket),
                    {error, R}
            end;
        {error, R} ->
            {error, R}
    end.

build_ssl_opts(Opts) ->
    Defaults = [{verify, verify_none}, {active, false},
                {alpn_advertised_protocols, [<<"http/1.1">>]}],
    Custom = maps:get(ssl_opts, Opts, []),
    lists:keymerge(1, Custom, Defaults).

build_request(Data) ->
    Path = expand_path(Data#data.bind_target),
    Authority = build_authority(Data#data.proxy_host,
                                 Data#data.proxy_port),
    HostHdr = [<<"Host: ">>, Authority, <<"\r\n">>],
    Lines = [
        [<<"GET ">>, Path, <<" HTTP/1.1\r\n">>],
        HostHdr,
        [<<"Connection: Upgrade\r\n">>],
        [<<"Upgrade: connect-udp\r\n">>],
        [<<"Capsule-Protocol: ?1\r\n">>],
        [<<"Connect-UDP-Bind: ?1\r\n">>],
        [render_header(N, V) || {N, V} <- Data#data.extra_headers],
        [<<"\r\n">>]
    ],
    iolist_to_binary(Lines).

render_header(N, V) -> [N, <<": ">>, V, <<"\r\n">>].

expand_path(unscoped) ->
    masque_uri_udp_bind:expand(?MASQUE_DEFAULT_URI_TEMPLATE,
                                unscoped);
expand_path({Host, Port}) ->
    masque_uri_udp_bind:expand(?MASQUE_DEFAULT_URI_TEMPLATE,
                                {Host, Port}).

read_response(Socket) ->
    read_response_lines(Socket, <<>>).

read_response_lines(Socket, Acc) ->
    case ssl:recv(Socket, 0, 5000) of
        {ok, Bytes} ->
            New = <<Acc/binary, Bytes/binary>>,
            case binary:match(New, <<"\r\n\r\n">>) of
                nomatch ->
                    read_response_lines(Socket, New);
                {Pos, 4} ->
                    Header = binary:part(New, 0, Pos),
                    Buffer = binary:part(New, Pos + 4,
                                         byte_size(New) - Pos - 4),
                    parse_response_header(Header, Buffer)
            end;
        {error, R} ->
            {error, R}
    end.

parse_response_header(HeaderBin, Buffer) ->
    Lines = binary:split(HeaderBin, <<"\r\n">>, [global]),
    case Lines of
        [StatusLine | HdrLines] ->
            case parse_status(StatusLine) of
                {ok, 101} ->
                    Headers = [parse_header_line(L) || L <- HdrLines,
                                                       L =/= <<>>],
                    {ok, Headers, Buffer};
                {ok, S} -> {error, {bad_status, S}};
                {error, R} -> {error, R}
            end;
        _ -> {error, malformed_response}
    end.

parse_status(<<"HTTP/1.1 ", Status:3/binary, _/binary>>) ->
    {ok, binary_to_integer(Status)};
parse_status(_) -> {error, bad_status_line}.

parse_header_line(Line) ->
    case binary:split(Line, <<":">>) of
        [Name, Rest] ->
            {string:lowercase(string:trim(Name, both, " \t\r\n")),
             string:trim(Rest, both, " \t\r\n")};
        _ -> {Line, <<>>}
    end.

%%====================================================================
%% Response validation
%%====================================================================

validate_response(Headers) ->
    Headers1 = [{iolist_to_binary(N), iolist_to_binary(V)}
                 || {N, V} <- Headers],
    case masque_uri_udp_bind:parse_bind_header(Headers1) of
        bind ->
            case masque_uri_udp_bind:parse_proxy_public_address(Headers1) of
                {ok, Addrs} -> {ok, Addrs};
                {error, _}  -> {error, missing_proxy_public_address}
            end;
        _ ->
            {error, missing_bind_response_header}
    end.

%%====================================================================
%% Helpers
%%====================================================================

advertised_families(#data{public_addresses = A}) ->
    lists:usort([family_of(IP) || {IP, _} <- A]).

family_of({_,_,_,_})         -> 4;
family_of({_,_,_,_,_,_,_,_}) -> 6.

reply_handshake(#data{handshake_from = undefined}, _Reply) -> ok;
reply_handshake(#data{handshake_from = From}, Reply) ->
    gen_statem:reply(From, Reply).

session_info(#data{bind_scope = Scope}, State) ->
    #{state => State, protocol => udp_bind, transport => h1,
      bind => Scope}.

ssl_send(#data{socket = Socket}, Bytes) ->
    case ssl:send(Socket, Bytes) of
        ok -> ok;
        Err -> Err
    end.

setopts_active_once(undefined) -> ok;
setopts_active_once(Socket) ->
    _ = ssl:setopts(Socket, [{active, once}]),
    ok.

build_authority(Host, Port) ->
    iolist_to_binary([Host, ":", integer_to_binary(Port)]).

to_bin(B) when is_binary(B) -> B;
to_bin(L) when is_list(L)   -> iolist_to_binary(L).
