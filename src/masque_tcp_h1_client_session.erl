%%% @doc Client-side MASQUE CONNECT-TCP session over HTTP/1.1.
%%%
%%% Classic HTTP CONNECT (RFC 9110 §9.3.6 / RFC 9112 §3.2.3). This is
%%% the method every HTTPS proxy has spoken for decades: the client
%%% writes `CONNECT host:port HTTP/1.1' with a `Host' header, the
%%% server replies `200 Connection Established', and the raw TLS
%%% socket then carries arbitrary TCP bytes both ways. Not Extended
%%% CONNECT, no `:protocol', no capsules.
%%%
%%% Intentionally bypasses `h1_connection': after the 200, the
%%% connection is no longer HTTP, so driving it through the h1 state
%%% machine gains nothing and actively conflicts with the tunnel
%%% handoff ({@link h1:accept_connect/3} is the server-side analogue
%%% the listener uses).
%%%
%%% Cleartext is out of scope: we only open `ssl:connect/4' with
%%% ALPN `http/1.1'. This matches the TLS-only contract documented in
%%% the h1 fallback plan.
-module(masque_tcp_h1_client_session).
-behaviour(gen_statem).

-export([start_link/3, start/3, stop/1, info/1]).
-export([send/2, recv/2, set_mode/2, shutdown_write/1]).
-export([send_capsule/3]).

-export([init/1, callback_mode/0, terminate/3, code_change/4]).
-export([connecting/3, open/3, closing/3]).

-include("masque.hrl").

-record(data, {
    owner          :: pid(),
    owner_ref      :: reference(),
    proxy_host     :: binary(),
    proxy_port     :: inet:port_number(),
    target_host    :: binary(),
    target_port    :: 1..65535,
    proxy_auth     :: binary() | undefined,
    connect_opts   :: map(),
    socket         :: ssl:sslsocket() | undefined,
    mode           :: message | queue,
    rx_buf = queue:new() :: queue:queue(binary()),
    rx_waiters = queue:new() :: queue:queue({gen_statem:from(), reference()}),
    write_closed = false :: boolean()
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

shutdown_write(Pid) ->
    gen_statem:call(Pid, shutdown_write).

%% CONNECT-TCP has no capsule channel; accept the call for API
%% symmetry and surface a clear error.
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
    Mode = maps:get(mode, Opts, message),
    ProxyAuth = maps:get(proxy_authorization, Opts, undefined),
    Data = #data{
        owner      = Owner,
        owner_ref  = MRef,
        proxy_host = to_bin(ProxyHost),
        proxy_port = ProxyPort,
        target_host = to_bin(TargetHost),
        target_port = TargetPort,
        proxy_auth = ProxyAuth,
        connect_opts = Opts,
        mode       = Mode
    },
    %% Defer `do_handshake' until `handshake_await' arrives so the
    %% reply can be delivered synchronously (classic CONNECT is a
    %% blocking handshake; we have no async response event to hang an
    %% error reply off).
    {ok, connecting, Data}.

%%====================================================================
%% States
%%====================================================================

connecting({call, From}, handshake_await,
           #data{connect_opts = Opts} = Data) ->
    case do_connect(Data, Opts) of
        {ok, Socket, InitialBuffer} ->
            case setopts_active_once(Socket) of
                ok ->
                    Data1 = Data#data{socket = Socket},
                    Data2 = deliver_bytes(InitialBuffer, Data1),
                    {next_state, open, Data2, [{reply, From, ok}]};
                {error, Reason} ->
                    _ = catch ssl:close(Socket),
                    {stop_and_reply, normal,
                     [{reply, From, {error, {setopts, Reason}}}],
                     Data}
            end;
        {error, Reason} ->
            {stop_and_reply, normal,
             [{reply, From, {error, Reason}}],
             Data}
    end;
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
open({call, From}, {send, _Data}, #data{write_closed = true} = Data) ->
    {keep_state, Data, [{reply, From, {error, write_closed}}]};
open({call, From}, {send, Payload}, #data{socket = Sock} = Data) ->
    Reply = ssl:send(Sock, Payload),
    {keep_state, Data, [{reply, From, Reply}]};
open({call, From}, {recv, Timeout}, Data) ->
    handle_recv_call(From, Timeout, Data);
open({call, From}, {set_mode, Mode}, Data) ->
    {keep_state, Data#data{mode = Mode}, [{reply, From, ok}]};
open({call, From}, shutdown_write, #data{socket = Sock} = Data) ->
    Reply = ssl:shutdown(Sock, write),
    {keep_state, Data#data{write_closed = true}, [{reply, From, Reply}]};
open({call, From}, {set_owner, NewOwner}, Data) ->
    {keep_state, swap_owner(NewOwner, Data), [{reply, From, ok}]};
open({call, From}, stop, Data) ->
    {next_state, closing, Data,
     [{reply, From, ok}, {next_event, internal, do_close}]};
open(info, {ssl, Sock, Bytes}, #data{socket = Sock} = Data) ->
    Data1 = deliver_bytes(Bytes, Data),
    _ = setopts_active_once(Sock),
    {keep_state, Data1};
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
    cancel_all_waiters(D);
terminate(_Reason, _State, #data{socket = Socket} = D) ->
    cancel_all_waiters(D),
    _ = (catch ssl:close(Socket)),
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
%% Transport
%%====================================================================

do_connect(Data, Opts) ->
    Timeout = maps:get(timeout, Opts, 5000),
    SSLOpts = build_ssl_opts(Data, Opts),
    case ssl:connect(binary_to_list(Data#data.proxy_host),
                     Data#data.proxy_port, SSLOpts, Timeout) of
        {ok, Socket} ->
            Req = connect_request(Data),
            case ssl:send(Socket, Req) of
                ok ->
                    case read_status_line(Socket, Timeout) of
                        {ok, 200, _Phrase, Leftover} ->
                            {ok, Socket, Leftover};
                        {ok, Code, Phrase, _Leftover} ->
                            _ = ssl:close(Socket),
                            {error, {handshake_rejected, Code, Phrase}};
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

build_ssl_opts(Data, Opts) ->
    UserOpts = maps:get(ssl_opts, Opts, []),
    Base = [
        binary,
        {active, false},
        {alpn_advertised_protocols, [<<"http/1.1">>]},
        {verify, maps:get(verify, Opts, verify_none)}
    ] ++ sni_opt(Data#data.proxy_host),
    Base ++ UserOpts.

sni_opt(Host) ->
    case inet:parse_address(binary_to_list(Host)) of
        {ok, _} -> [];
        _       -> [{server_name_indication, binary_to_list(Host)}]
    end.

connect_request(#data{target_host = Host, target_port = Port,
                       proxy_auth = Auth}) ->
    Authority = masque_uri:build_authority(Host, Port),
    AuthLine = case Auth of
        undefined -> <<>>;
        V when is_binary(V) ->
            <<"Proxy-Authorization: ", V/binary, "\r\n">>
    end,
    <<"CONNECT ", Authority/binary, " HTTP/1.1\r\n",
      "Host: ", Authority/binary, "\r\n",
      AuthLine/binary,
      "\r\n">>.

%% Read bytes until we have a full status line + headers (CRLFCRLF).
%% Returns `{ok, StatusCode, Leftover}' where Leftover is any extra
%% bytes past the blank line (the tunnel's initial inbound payload).
read_status_line(Socket, Timeout) ->
    read_headers_loop(Socket, <<>>, Timeout).

read_headers_loop(_Socket, Acc, _Timeout) when byte_size(Acc) > 64 * 1024 ->
    {error, headers_too_large};
read_headers_loop(Socket, Acc, Timeout) ->
    case ssl:recv(Socket, 0, Timeout) of
        {ok, Bin} ->
            New = <<Acc/binary, Bin/binary>>,
            case binary:split(New, <<"\r\n\r\n">>) of
                [HdrBlock, Rest] ->
                    case parse_status(HdrBlock) of
                        {ok, Code, Phrase} -> {ok, Code, Phrase, Rest};
                        Err                -> Err
                    end;
                [_] ->
                    read_headers_loop(Socket, New, Timeout)
            end;
        {error, Reason} ->
            {error, {recv, Reason}}
    end.

parse_status(HdrBlock) ->
    case binary:split(HdrBlock, <<"\r\n">>) of
        [StatusLine | _] ->
            case binary:split(StatusLine, <<" ">>, []) of
                [_Ver, Rest] ->
                    case binary:split(Rest, <<" ">>, []) of
                        [CodeBin, Phrase] ->
                            case catch binary_to_integer(CodeBin) of
                                C when is_integer(C) -> {ok, C, Phrase};
                                _ -> {error, bad_status}
                            end;
                        [CodeBin] ->
                            case catch binary_to_integer(CodeBin) of
                                C when is_integer(C) -> {ok, C, <<>>};
                                _ -> {error, bad_status}
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
    Owner ! {masque_data, self(), Bin},
    Data;
deliver_bytes(Bin, #data{mode = queue, rx_waiters = Ws,
                          rx_buf = Buf} = Data) ->
    case queue:out(Ws) of
        {{value, {From, TRef}}, Ws2} ->
            _ = erlang:cancel_timer(TRef),
            gen_statem:reply(From, {ok, Bin}),
            Data#data{rx_waiters = Ws2};
        {empty, _} ->
            Data#data{rx_buf = queue:in(Bin, Buf)}
    end.

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

drop_waiter(TRef, From, #data{rx_waiters = Ws} = Data) ->
    Ws2 = queue:filter(
        fun({F, T}) when F =:= From, T =:= TRef ->
                gen_statem:reply(F, {error, timeout}),
                false;
           (_) -> true
        end, Ws),
    Data#data{rx_waiters = Ws2}.

%%====================================================================
%% Misc
%%====================================================================

notify_owner_closed(Reason, #data{owner = Owner, mode = message}) ->
    Owner ! {masque_closed, self(), Reason};
notify_owner_closed(_Reason, _Data) -> ok.

swap_owner(NewOwner, #data{owner_ref = OldRef} = Data) ->
    _ = erlang:demonitor(OldRef, [flush]),
    NewRef = erlang:monitor(process, NewOwner),
    Data#data{owner = NewOwner, owner_ref = NewRef}.

session_info(#data{target_host = H, target_port = P,
                   proxy_host = PH, proxy_port = PP}, State) ->
    #{state => State, protocol => tcp, transport => h1,
      proxy => {PH, PP}, target => {H, P}}.

to_bin(X) when is_binary(X) -> X;
to_bin(X) when is_list(X)   -> list_to_binary(X);
to_bin(X) when is_atom(X)   -> atom_to_binary(X, utf8).
