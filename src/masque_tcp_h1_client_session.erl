%%% Client-side MASQUE CONNECT-TCP session over HTTP/1.1.
%%%
%%% Classic HTTP CONNECT (RFC 9110 §9.3.6 / RFC 9112 §3.2.3). This is
%%% the method every HTTPS proxy has spoken for decades: the client
%%% writes `CONNECT host:port HTTP/1.1` with a `Host` header, the
%%% server replies `200 Connection Established`, and the raw TLS
%%% socket then carries arbitrary TCP bytes both ways. Not Extended
%%% CONNECT, no `:protocol`, no capsules.
%%%
%%% Intentionally bypasses `h1_connection`: after the 200, the
%%% connection is no longer HTTP, so driving it through the h1 state
%%% machine gains nothing and actively conflicts with the tunnel
%%% handoff (`h1:accept_connect/3` is the server-side analogue
%%% the listener uses).
%%%
%%% Cleartext is out of scope: we only open `ssl:connect/4` with
%%% ALPN `http/1.1`. This matches the TLS-only contract documented in
%%% the h1 fallback plan.
-module(masque_tcp_h1_client_session).
-moduledoc false.
-behaviour(gen_statem).

-export([start_link/3, start/3, stop/1, info/1]).
-export([send/2, recv/2, set_mode/2, shutdown_write/1]).
-export([send_capsule/3]).

-export([init/1, callback_mode/0, terminate/3, code_change/4]).
-export([connecting/3, open/3, closing/3, closed/3]).

-include("masque.hrl").

-record(data, {
    owner :: pid(),
    owner_ref :: reference(),
    proxy_host :: binary(),
    proxy_port :: inet:port_number(),
    target_host :: binary(),
    target_port :: 1..65535,
    proxy_auth :: binary() | undefined,
    connect_opts :: map(),
    socket :: ssl:sslsocket() | undefined,
    mode :: message | queue,
    rx_buf = queue:new() :: queue:queue(binary()),
    rx_waiters = queue:new() :: queue:queue({gen_statem:from(), reference()}),
    %% Bound on `rx_buf' (`rx_queue_limit'); past it the tunnel ends
    %% with `rx_overflow' rather than dropping bytes.
    rx_limit = ?MASQUE_DEFAULT_RX_QUEUE_LIMIT :: pos_integer(),
    write_closed = false :: boolean(),
    %% Extra request headers prepended to the CONNECT line.
    extra_headers = [] :: [{binary(), binary()}],
    %% Writes run here so a full TLS send buffer never stops this
    %% process reading: the peer may be blocked writing to us.
    writer :: pid() | undefined,
    %% `raw': classic CONNECT. `capsule': GET with `Upgrade: connect-tcp'
    %% and DATA / FINAL_DATA capsules (draft-ietf-httpbis-connect-tcp-18),
    %% from the `tcp_framing' option.
    framing = raw :: raw | capsule,
    %% The `Upgrade' token and capsule codes (`tcp_protocol' option),
    %% and the decoder of the proxy's capsules.
    token = ?MASQUE_CONNECT_TCP_PROTOCOL :: binary(),
    %% Template variables other than the target (`uri_vars' option).
    uri_vars :: map() | undefined,
    version = final :: masque_tcp_capsule:version(),
    dec :: masque_tcp_capsule:decoder() | undefined,
    uri_template = ?MASQUE_DEFAULT_TCP_URI_TEMPLATE :: binary(),
    %% Capsule mode: the proxy sent FINAL_DATA.
    final_in = false :: boolean()
}).

%%====================================================================
%% API
%%====================================================================

-spec start_link(masque:target(), map(), pid()) -> gen_statem:start_ret().
start_link(Target, Opts, Owner) ->
    gen_statem:start_link(?MODULE, {Target, Opts, Owner}, []).

-spec start(masque:target(), map(), pid()) -> gen_statem:start_ret().
start(Target, Opts, Owner) ->
    gen_statem:start(?MODULE, {Target, Opts, Owner}, []).

-spec stop(pid()) -> ok.
stop(Pid) -> gen_statem:call(Pid, stop, 5000).
-spec info(pid()) -> map().
info(Pid) -> gen_statem:call(Pid, info, 1000).

-spec send(pid(), iodata()) -> ok | {error, term()}.
send(Pid, Data) ->
    gen_statem:call(Pid, {send, Data}).

-spec recv(pid(), non_neg_integer()) -> {ok, binary()} | {error, term()}.
recv(Pid, Timeout) ->
    gen_statem:call(Pid, {recv, Timeout}, Timeout + 500).

-spec set_mode(pid(), message | queue) -> ok | {error, term()}.
set_mode(Pid, Mode) when Mode =:= message; Mode =:= queue ->
    gen_statem:call(Pid, {set_mode, Mode}).

-spec shutdown_write(pid()) -> ok | {error, term()}.
shutdown_write(Pid) ->
    gen_statem:call(Pid, shutdown_write).

%% CONNECT-TCP has no capsule channel; accept the call for API
%% symmetry and surface a clear error.
-spec send_capsule(pid(), non_neg_integer(), iodata()) -> ok | {error, term()}.
send_capsule(_Pid, _Type, _Value) ->
    {error, not_supported}.

%%====================================================================
%% gen_statem
%%====================================================================

callback_mode() -> state_functions.

init({Target, Opts, Owner}) ->
    process_flag(trap_exit, true),
    {ProxyHost, ProxyPort} = maps:get(proxy, Opts),
    {TargetHost, TargetPort} = Target,
    MRef = erlang:monitor(process, Owner),
    ok = masque_client_owner:init(Opts),
    Mode = maps:get(mode, Opts, message),
    ProxyAuth = maps:get(proxy_authorization, Opts, undefined),
    {Framing, Token, Version} = masque_tcp_capsule:client_protocol(Opts),
    ok = validate_proxy_auth(ProxyAuth),
    Data = #data{
        owner = Owner,
        owner_ref = MRef,
        rx_limit = masque_client_rx:limit(Opts),
        proxy_host = to_bin(ProxyHost),
        proxy_port = ProxyPort,
        target_host = to_bin(TargetHost),
        target_port = TargetPort,
        proxy_auth = ProxyAuth,
        connect_opts = Opts,
        mode = Mode,
        extra_headers = sanitise_extra_headers(
            maps:get(request_headers, Opts, [])
        ),
        framing = Framing,
        token = Token,
        version = Version,
        dec = masque_tcp_capsule:decoder(Version),
        uri_template = maps:get(uri_template, Opts, ?MASQUE_DEFAULT_TCP_URI_TEMPLATE),
        uri_vars = maps:get(uri_vars, Opts, undefined)
    },
    %% Defer `do_handshake' until `handshake_await' arrives so the
    %% reply can be delivered synchronously (classic CONNECT is a
    %% blocking handshake; we have no async response event to hang an
    %% error reply off).
    {ok, connecting, Data}.

%%====================================================================
%% States
%%====================================================================

connecting(Type, Event, Data) ->
    masque_quiet:stop(connecting_inner(Type, Event, Data)).

connecting_inner(
    {call, From},
    handshake_await,
    #data{connect_opts = Opts} = Data
) ->
    case do_connect(Data, Opts) of
        {ok, Socket, InitialBuffer, DataC} ->
            case setopts_active_once(Socket) of
                ok ->
                    Data1 = DataC#data{socket = Socket},
                    Data2 =
                        case incoming(InitialBuffer, Data1) of
                            {error, _} -> Data1;
                            {{overflow, D}, _} -> D;
                            {D, _} -> D
                        end,
                    {next_state, open, Data2, [{reply, From, ok}]};
                {error, Reason} ->
                    _ =
                        (try
                            ssl:close(Socket)
                        catch
                            _:_ -> ok
                        end),
                    {stop_and_reply, normal, [{reply, From, {error, {setopts, Reason}}}], Data}
            end;
        {error, Reason} ->
            {stop_and_reply, normal, [{reply, From, {error, Reason}}], Data}
    end;
connecting_inner({call, From}, {set_owner, NewOwner}, Data) ->
    {keep_state, swap_owner(NewOwner, Data), [{reply, From, ok}]};
connecting_inner({call, From}, info, Data) ->
    {keep_state, Data, [{reply, From, session_info(Data, connecting)}]};
connecting_inner({call, From}, stop, Data) ->
    {stop_and_reply, normal, [{reply, From, ok}], Data};
connecting_inner({call, From}, _Other, Data) ->
    {keep_state, Data, [{reply, From, {error, not_ready}}]};
connecting_inner(
    info,
    {'DOWN', Ref, process, _, _},
    #data{owner_ref = Ref}
) ->
    {stop, owner_gone};
connecting_inner(info, _Msg, Data) ->
    {keep_state, Data}.

open(Type, Event, Data) ->
    masque_quiet:stop(open_inner(Type, Event, Data)).

open_inner({call, From}, handshake_await, Data) ->
    {keep_state, Data, [{reply, From, ok}]};
open_inner({call, From}, info, Data) ->
    {keep_state, Data, [{reply, From, session_info(Data, open)}]};
open_inner({call, From}, {send, _Data}, #data{write_closed = true} = Data) ->
    {keep_state, Data, [{reply, From, {error, write_closed}}]};
open_inner({call, From}, {send, Payload}, Data) ->
    Data2 = ensure_writer(Data),
    Data2#data.writer ! {send, From, frame(Data2, Payload, false)},
    {keep_state, Data2};
open_inner({call, From}, {recv, Timeout}, Data) ->
    handle_recv_call(From, Timeout, Data);
open_inner({call, From}, {send_capsule, _, _}, Data) ->
    {keep_state, Data, [{reply, From, {error, not_supported}}]};
open_inner({call, From}, {set_mode, Mode}, Data) ->
    {keep_state, Data#data{mode = Mode}, [{reply, From, ok}]};
%% Capsule mode ends the write side with FINAL_DATA, which TLS cannot
%% do with a half-close.
open_inner({call, From}, shutdown_write, #data{framing = capsule} = Data) ->
    Data2 = ensure_writer(Data),
    Data2#data.writer ! {send, From, frame(Data2, <<>>, true)},
    {keep_state, Data2#data{write_closed = true}};
open_inner({call, From}, shutdown_write, Data) ->
    Data2 = ensure_writer(Data),
    Data2#data.writer ! {shutdown_write, From},
    {keep_state, Data2#data{write_closed = true}};
open_inner({call, From}, {set_owner, NewOwner}, Data) ->
    {keep_state, swap_owner(NewOwner, Data), [{reply, From, ok}]};
open_inner({call, From}, stop, Data) ->
    {next_state, closing, Data, [{reply, From, ok}, {next_event, internal, do_close}]};
open_inner(info, {ssl, Sock, Bytes}, #data{socket = Sock} = Data) ->
    case incoming(Bytes, Data) of
        {error, Reason} ->
            end_tunnel(Reason, {stop, Reason, Data}, Data);
        {{overflow, Data1}, _} ->
            park_unread(rx_overflow, Data1);
        {#data{write_closed = true} = Data1, true} ->
            end_tunnel(peer_fin, {stop, normal, Data1}, Data1);
        {Data1, true} ->
            %% Half-close: the proxy is done sending, our side stays open.
            _ = notify_owner_closed(peer_fin, Data1),
            _ = setopts_active_once(Sock),
            {keep_state, Data1};
        {Data1, false} ->
            _ = setopts_active_once(Sock),
            {keep_state, Data1}
    end;
%% Capsule mode: the connection closing after FINAL_DATA is the end of
%% a finished tunnel; without it the tunnel was aborted.
open_inner(
    info, {ssl_closed, Sock}, #data{socket = Sock, framing = capsule, final_in = true} = Data
) ->
    case masque_tcp_capsule:end_of_stream(Data#data.dec) of
        ok ->
            {stop, normal, Data};
        {error, Why} ->
            Reason = {bad_capsule, Why},
            end_tunnel(Reason, {stop, Reason, Data}, Data)
    end;
open_inner(info, {ssl_closed, Sock}, #data{socket = Sock, framing = capsule} = Data) ->
    end_tunnel(peer_reset, {stop, peer_reset, Data}, Data);
open_inner(info, {ssl_closed, Sock}, #data{socket = Sock} = Data) ->
    end_tunnel(peer_closed, {stop, peer_closed, Data}, Data);
open_inner(info, {ssl_error, Sock, Reason}, #data{socket = Sock} = Data) ->
    end_tunnel({ssl_error, Reason}, {stop, {ssl_error, Reason}, Data}, Data);
open_inner(info, {timeout, TRef, {recv_timeout, From}}, Data) ->
    {keep_state, drop_waiter(TRef, From, Data)};
open_inner(
    info,
    {'DOWN', Ref, process, _, _},
    #data{owner_ref = Ref} = Data
) ->
    {next_state, closing, Data, [{next_event, internal, do_close}]};
open_inner(info, _Msg, Data) ->
    {keep_state, Data};
open_inner({call, From}, _Other, Data) ->
    {keep_state, Data, [{reply, From, {error, not_supported}}]}.

closing(Type, Event, Data) ->
    masque_quiet:stop(closing_inner(Type, Event, Data)).

closing_inner(internal, do_close, #data{socket = Socket} = Data) ->
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
closing_inner({call, From}, _Other, Data) ->
    {keep_state, Data, [{reply, From, {error, closing}}]};
closing_inner(_Event, _Msg, Data) ->
    {keep_state, Data}.

%%====================================================================
%% Writer
%%====================================================================

ensure_writer(#data{writer = undefined, socket = Sock} = Data) ->
    Session = self(),
    Writer = spawn(fun() ->
        Ref = erlang:monitor(process, Session),
        writer_loop(Sock, Ref, Session)
    end),
    Data#data{writer = Writer};
ensure_writer(Data) ->
    Data.

%% The caller's `send/2' returns once its write has landed, in order.
writer_loop(Sock, Ref, Session) ->
    receive
        {send, From, Payload} ->
            Result = ssl:send(Sock, Payload),
            gen_statem:reply(From, Result),
            report_failure(Result, Sock, Session),
            writer_loop(Sock, Ref, Session);
        {shutdown_write, From} ->
            gen_statem:reply(From, ssl:shutdown(Sock, write)),
            writer_loop(Sock, Ref, Session);
        {'DOWN', Ref, process, _, _} ->
            ok
    after infinity ->
        ok
    end.

%% A write timeout closes the socket without telling the process that
%% reads it, so the session has to hear it from here.
report_failure(ok, _Sock, _Session) ->
    ok;
report_failure({error, Reason}, Sock, Session) ->
    Session ! {ssl_error, Sock, Reason},
    ok.

%%====================================================================
%% State: closed (peer ended the tunnel, queue-mode data unread)
%%====================================================================

closed(Type, Event, Data) ->
    masque_quiet:stop(closed_inner(Type, Event, Data)).

closed_inner({call, From}, info, Data) ->
    {keep_state_and_data, [{reply, From, session_info(Data, closed)}]};
closed_inner(Type, Event, #data{rx_buf = Buf, owner_ref = Ref} = Data) ->
    masque_client_rx:closed(Type, Event, Buf, Ref, fun(B) -> Data#data{rx_buf = B} end).

terminate(Reason, StateName, Data) ->
    terminate_inner(masque_quiet:reason(Reason), StateName, Data).

terminate_inner(_Reason, _State, #data{socket = undefined} = D) ->
    _ = erlang:demonitor(D#data.owner_ref, [flush]),
    cancel_all_waiters(D);
terminate_inner(_Reason, _State, #data{socket = Socket} = D) ->
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
%% Transport
%%====================================================================

do_connect(Data0, Opts) ->
    %% One deadline covers connect, TLS and the CONNECT exchange, the
    %% fallback included.
    Timeout = maps:get(timeout, Opts, 5000),
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    Data = preferred(Data0),
    case dial(Data, Opts, Deadline) of
        {ok, Socket, Leftover} ->
            {ok, Socket, Leftover, Data};
        {fallback, Rejected} ->
            %% draft-ietf-httpbis-connect-tcp-18 section 5.2: a proxy
            %% that refuses classic CONNECT this way may only speak
            %% connect-tcp, so retry on the default template.
            Upgrade = upgrade(Data),
            case dial(Upgrade, Opts, Deadline) of
                {ok, Socket, Leftover} ->
                    ok = remember(Upgrade),
                    {ok, Socket, Leftover, Upgrade};
                {fallback, _} ->
                    {error, Rejected};
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

dial(Data, Opts, Deadline) ->
    SSLOpts = masque_tls:client_opts(Data#data.proxy_host, Opts),
    case
        ssl:connect(
            binary_to_list(Data#data.proxy_host),
            Data#data.proxy_port,
            SSLOpts,
            remaining(Deadline)
        )
    of
        {ok, Socket} ->
            _ = masque_tls:bound_sends(ssl, Socket),
            Req = connect_request(Data),
            case ssl:send(Socket, Req) of
                ok ->
                    case read_status_line(Socket, remaining(Deadline)) of
                        {ok, 101, _Phrase, _Hdrs, Leftover} when
                            Data#data.framing =:= capsule
                        ->
                            {ok, Socket, Leftover};
                        {ok, Code, _Phrase, _Hdrs, Leftover} when
                            Data#data.framing =:= raw, Code >= 200, Code < 300
                        ->
                            %% RFC 9110 §9.3.6: any 2xx establishes
                            %% the tunnel. Most proxies send 200
                            %% "Connection Established" but 201 / 202
                            %% are conformant too.
                            {ok, Socket, Leftover};
                        {ok, Code, Phrase, Hdrs, _Leftover} ->
                            _ = ssl:close(Socket),
                            Rejected = {handshake_rejected, Code, Phrase},
                            case wants_upgrade(Data, Code, Hdrs) of
                                true -> {fallback, Rejected};
                                false -> {error, Rejected}
                            end;
                        {error, Reason} ->
                            _ = ssl:close(Socket),
                            {error, Reason}
                    end;
                {error, Reason} ->
                    _ = ssl:close(Socket),
                    {error, {send, Reason}}
            end;
        {error, Reason} ->
            {error, {connect, Reason}}
    end.

%% A classic CONNECT refused with `501', or with `426' offering
%% `Upgrade: connect-tcp'.
wants_upgrade(#data{framing = raw}, 501, _Hdrs) ->
    true;
wants_upgrade(#data{framing = raw}, 426, Hdrs) ->
    Offered = [
        string:trim(T)
     || {<<"upgrade">>, V} <- Hdrs, T <- binary:split(lowercase_bin(V), <<",">>, [global])
    ],
    lists:member(?MASQUE_CONNECT_TCP_PROTOCOL, Offered) orelse
        lists:member(?MASQUE_CONNECT_TCP_07_PROTOCOL, Offered);
wants_upgrade(_Data, _Code, _Hdrs) ->
    false.

upgrade(Data) ->
    {capsule, Token, Version} = masque_tcp_capsule:client_protocol(#{tcp_framing => capsule}),
    Data#data{
        framing = capsule,
        token = Token,
        version = Version,
        dec = masque_tcp_capsule:decoder(Version),
        uri_template = ?MASQUE_DEFAULT_TCP_URI_TEMPLATE
    }.

%% Section 5.2 also asks the client to remember a proxy that only
%% speaks connect-tcp, so later tunnels skip the refused CONNECT.
preferred(#data{framing = raw, proxy_host = Host, proxy_port = Port} = Data) ->
    case ets:member(?MASQUE_TCP_UPGRADE_PROXIES, {Host, Port}) of
        true -> upgrade(Data);
        false -> Data
    end;
preferred(Data) ->
    Data.

remember(#data{proxy_host = Host, proxy_port = Port}) ->
    true = ets:insert(?MASQUE_TCP_UPGRADE_PROXIES, {{Host, Port}}),
    ok.

%% Milliseconds left before the overall handshake deadline.
remaining(Deadline) ->
    max(0, Deadline - erlang:monotonic_time(millisecond)).

connect_request(#data{framing = capsule} = Data) ->
    upgrade_request(Data);
connect_request(#data{
    target_host = Host,
    target_port = Port,
    proxy_auth = Auth,
    extra_headers = Extra
}) ->
    Authority = masque_uri:build_authority(Host, Port),
    %% The facade validates the host; refuse anything that could still
    %% break the request line.
    nomatch = binary:match(Authority, [<<"\r">>, <<"\n">>, <<" ">>]),
    AuthLine =
        case Auth of
            undefined ->
                <<>>;
            V when is_binary(V) ->
                <<"Proxy-Authorization: ", V/binary, "\r\n">>
        end,
    ExtraLines = iolist_to_binary(
        [[N, <<": ">>, Val, <<"\r\n">>] || {N, Val} <- Extra]
    ),
    <<"CONNECT ", Authority/binary, " HTTP/1.1\r\n", "Host: ", Authority/binary, "\r\n",
        AuthLine/binary, ExtraLines/binary, "\r\n">>.

%% draft-ietf-httpbis-connect-tcp-18 section 3.2: the target goes in the
%% path of a `GET' that upgrades to `connect-tcp', or the draft's
%% interop token.
upgrade_request(#data{
    token = Token,
    proxy_host = ProxyHost,
    proxy_port = ProxyPort,
    target_host = Host,
    target_port = Port,
    uri_template = Template,
    uri_vars = UriVars,
    proxy_auth = Auth,
    extra_headers = Extra
}) ->
    Path = request_path(Template, UriVars, Host, Port),
    ProxyAuthority = masque_uri:build_authority(ProxyHost, ProxyPort),
    nomatch = binary:match(Path, [<<"\r">>, <<"\n">>, <<" ">>]),
    AuthLine =
        case Auth of
            undefined -> <<>>;
            V when is_binary(V) -> <<"Proxy-Authorization: ", V/binary, "\r\n">>
        end,
    ExtraLines = iolist_to_binary([[N, <<": ">>, Val, <<"\r\n">>] || {N, Val} <- Extra]),
    <<"GET ", Path/binary, " HTTP/1.1\r\n", "Host: ", ProxyAuthority/binary, "\r\n",
        "Connection: Upgrade\r\n", "Upgrade: ", Token/binary, "\r\n", "Capsule-Protocol: ?1\r\n",
        AuthLine/binary, ExtraLines/binary, "\r\n">>.

%% The request path. `uri_vars' replaces the target variables for a
%% template that has others, such as a reverse connect accept's
%% `request_id'.
request_path(Template, undefined, Host, Port) ->
    masque_uri:expand(Template, #{target_host => Host, target_port => Port});
request_path(Template, Vars, _Host, _Port) ->
    {ok, T} = masque_uri_template:parse_pattern(masque_uri:to_path(Template)),
    masque_uri_template:expand(T, Vars).

%% Bytes from the proxy: as they are in raw mode, the DATA and
%% FINAL_DATA payloads in capsule mode. Also says whether they end the
%% proxy's side.
incoming(Bytes, #data{framing = raw} = Data) ->
    {deliver_bytes(Bytes, Data), false};
incoming(Bytes, #data{dec = Dec} = Data) ->
    case masque_tcp_capsule:decode(Dec, Bytes) of
        {ok, Items, Dec2} ->
            Payload = iolist_to_binary([P || {_, P} <- Items]),
            Final = lists:keymember(final, 1, Items),
            Data1 = Data#data{dec = Dec2, final_in = Data#data.final_in orelse Final},
            {deliver_bytes(Payload, Data1), Final};
        {error, Why} ->
            {error, {bad_capsule, Why}}
    end.

frame(#data{framing = capsule, version = V}, Bytes, Fin) ->
    masque_tcp_capsule:encode(V, Bytes, Fin);
frame(_Data, Bytes, _Fin) ->
    Bytes.

sanitise_extra_headers(List) when is_list(List) ->
    %% Strip CR/LF to prevent header injection on the raw CONNECT
    %% line. Reserved names (Host, Proxy-Authorization, CONNECT
    %% request line itself) are dropped so the library stays in
    %% control of the wire format.
    Reserved = [<<"host">>, <<"proxy-authorization">>],
    [
        {K, V}
     || {K, V} <- List,
        is_binary(K),
        is_binary(V),
        binary:match(K, [<<"\r">>, <<"\n">>]) =:= nomatch,
        binary:match(V, [<<"\r">>, <<"\n">>]) =:= nomatch,
        not lists:member(lowercase_bin(K), Reserved)
    ].

lowercase_bin(B) when is_binary(B) ->
    list_to_binary(string:to_lower(binary_to_list(B))).

%% Read bytes until we have a full status line + headers (CRLFCRLF).
%% Returns `{ok, StatusCode, Phrase, Leftover}' where Leftover is any
%% extra bytes past the blank line (the tunnel's initial inbound
%% payload). Timeout is an absolute budget: an attacker trickling
%% bytes cannot stretch the handshake past the caller's deadline.
read_status_line(Socket, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    read_headers_loop(Socket, <<>>, Deadline).

read_headers_loop(_Socket, Acc, _Deadline) when byte_size(Acc) > 64 * 1024 ->
    {error, headers_too_large};
read_headers_loop(Socket, Acc, Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining =< 0 of
        true ->
            {error, handshake_timeout};
        false ->
            case ssl:recv(Socket, 0, Remaining) of
                {ok, Bin} ->
                    New = <<Acc/binary, Bin/binary>>,
                    read_response(Socket, New, Deadline);
                {error, timeout} ->
                    {error, handshake_timeout};
                {error, Reason} ->
                    {error, {recv, Reason}}
            end
    end.

%% Interim responses other than 101 (a `100 Continue' the caller asked
%% for with `Expect') are skipped.
read_response(Socket, Acc, Deadline) ->
    case binary:split(Acc, <<"\r\n\r\n">>) of
        [HdrBlock, Rest] ->
            case parse_status(HdrBlock) of
                {ok, Code, _Phrase} when Code >= 100, Code < 200, Code =/= 101 ->
                    read_response(Socket, Rest, Deadline);
                {ok, Code, Phrase} ->
                    {ok, Code, Phrase, parse_headers(HdrBlock), Rest};
                Err ->
                    Err
            end;
        [_] ->
            read_headers_loop(Socket, Acc, Deadline)
    end.

parse_headers(HdrBlock) ->
    [_ | Lines] = binary:split(HdrBlock, <<"\r\n">>, [global]),
    [
        {lowercase_bin(string:trim(K)), string:trim(V)}
     || Line <- Lines, [K, V] <- [binary:split(Line, <<":">>)]
    ].

parse_status(HdrBlock) ->
    case binary:split(HdrBlock, <<"\r\n">>) of
        [StatusLine | _] ->
            case binary:split(StatusLine, <<" ">>, []) of
                [_Ver, Rest] ->
                    case binary:split(Rest, <<" ">>, []) of
                        [CodeBin, Phrase] ->
                            try binary_to_integer(CodeBin) of
                                C when is_integer(C) -> {ok, C, Phrase}
                            catch
                                _:_ -> {error, bad_status}
                            end;
                        [CodeBin] ->
                            try binary_to_integer(CodeBin) of
                                C when is_integer(C) -> {ok, C, <<>>}
                            catch
                                _:_ -> {error, bad_status}
                            end
                    end;
                _ ->
                    {error, bad_status}
            end;
        _ ->
            {error, bad_status}
    end.

setopts_active_once(Socket) ->
    ssl:setopts(Socket, [{active, once}, {mode, binary}]).

%%====================================================================
%% Owner delivery + Rx buffering
%%====================================================================

deliver_bytes(<<>>, Data) ->
    Data;
deliver_bytes(Bin, #data{mode = message, owner = Owner} = Data) ->
    masque_client_owner:send(Owner, {masque_data, self(), Bin}),
    Data;
deliver_bytes(
    Bin,
    #data{
        mode = queue,
        rx_waiters = Ws,
        rx_buf = Buf
    } = Data
) ->
    case queue:out(Ws) of
        {{value, {From, TRef}}, Ws2} ->
            _ = erlang:cancel_timer(TRef),
            gen_statem:reply(From, {ok, Bin}),
            Data#data{rx_waiters = Ws2};
        {empty, _} ->
            case masque_client_rx:is_full(Buf, Data#data.rx_limit) of
                false -> Data#data{rx_buf = queue:in(Bin, Buf)};
                true -> {overflow, Data}
            end
    end.

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

notify_owner_closed(Reason, #data{owner = Owner, mode = message}) ->
    masque_client_owner:send(Owner, {masque_closed, self(), Reason});
notify_owner_closed(_Reason, _Data) ->
    ok.

%% The peer ended the tunnel. Queue-mode data the owner has not read
%% yet stays available to `recv/2' (see `masque_client_rx');
%% otherwise notify the owner and return `Result'.
end_tunnel(Reason, Result, #data{mode = Mode, rx_buf = Buf} = Data) ->
    case masque_client_rx:keep_unread(Mode, Buf) of
        true ->
            park_unread(closed, Data);
        false ->
            _ = notify_owner_closed(Reason, Data),
            Result
    end.

%% Close the socket and keep the queue for `recv/2', which returns
%% it and then `{error, EndReason}'. `rx_overflow': the owner did not
%% keep up and dropping bytes would corrupt the stream.
park_unread(EndReason, #data{rx_buf = Buf, socket = Socket} = Data) ->
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
    {next_state, closed,
        Data#data{
            socket = undefined,
            rx_buf = masque_client_rx:close_queue(Buf, EndReason)
        },
        masque_client_rx:closed_enter()}.

swap_owner(NewOwner, #data{owner_ref = OldRef} = Data) ->
    _ = erlang:demonitor(OldRef, [flush]),
    NewRef = erlang:monitor(process, NewOwner),
    ok = masque_client_owner:release(NewOwner),
    Data#data{owner = NewOwner, owner_ref = NewRef}.

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
        protocol => tcp,
        transport => h1,
        proxy => {PH, PP},
        target => {H, P}
    }.

to_bin(X) when is_binary(X) -> X;
to_bin(X) when is_list(X) -> list_to_binary(X);
to_bin(X) when is_atom(X) -> atom_to_binary(X, utf8).

%% Defence in depth: `masque:validate_connect_opts/2' already rejects
%% CRLF here, but callers that bypass the facade should not be able to
%% inject headers either.
validate_proxy_auth(undefined) ->
    ok;
validate_proxy_auth(V) when is_binary(V) ->
    case binary:match(V, [<<"\r">>, <<"\n">>]) of
        nomatch -> ok;
        _ -> erlang:error({invalid_opts, proxy_authorization_contains_crlf})
    end;
validate_proxy_auth(_) ->
    erlang:error({invalid_opts, proxy_authorization_must_be_binary}).
