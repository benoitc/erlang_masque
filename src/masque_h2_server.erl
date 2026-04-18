%%% @doc MASQUE CONNECT-UDP listener over HTTP/2.
%%%
%%% Wraps `h2:start_server/3' with a handler fun that validates the
%%% Extended CONNECT envelope (RFC 8441 + RFC 9298), matches the
%%% request path against the configured URI template, and spawns a
%%% per-tunnel `masque_h2_server_session' on acceptance.
%%%
%%% For the cert/key config this follows `erlang_h2' conventions:
%%% both are PEM file paths (string or binary). `quic_h3' takes DER
%%% binaries, so the `masque' facade exposes two distinct start
%%% functions and the test helpers keep both forms around.
-module(masque_h2_server).

-export([
    start_listener/2,
    stop_listener/1,
    h2_handlers/1,
    try_reserve_tunnel/2,
    release_tunnel/1
]).

-include("masque.hrl").

-type listener_name() :: atom().
-type listener_opts() :: map().

-export_type([listener_name/0, listener_opts/0]).

%%====================================================================
%% API
%%====================================================================

-spec start_listener(listener_name(), listener_opts()) ->
    {ok, h2:server_ref()} | {error, term()}.
start_listener(Name, Opts0) when is_atom(Name), is_map(Opts0) ->
    Opts = defaults(Opts0),
    Port = maps:get(port, Opts),
    #{handler := Handler} = h2_handlers(Opts),
    ServerOpts = #{
        cert => maps:get(cert, Opts),
        key  => maps:get(key, Opts),
        handler => Handler,
        enable_connect_protocol => true,
        settings => merged_settings(Opts)
    },
    ServerOpts1 = case maps:find(acceptors, Opts) of
        {ok, N} -> ServerOpts#{acceptors => N};
        error   -> ServerOpts
    end,
    h2:start_server(Name, Port, ServerOpts1).

-spec stop_listener(h2:server_ref() | listener_name()) -> ok | {error, term()}.
stop_listener({_, _, _} = Ref) ->
    h2:stop_server(Ref);
stop_listener(Name) when is_atom(Name) ->
    %% h2:stop_server takes the server_ref, not an atom. Callers that
    %% started with a name should hold onto the ref returned by
    %% start_listener/2. Accept atoms anyway for symmetry with the h3
    %% facade and return a clear error when we don't have a handle.
    {error, {no_ref_for_name, Name}}.

-spec h2_handlers(map()) ->
    #{handler := fun((pid(), non_neg_integer(), binary(), binary(),
                      list()) -> any())}.
h2_handlers(Opts0) ->
    Opts = defaults(Opts0),
    Dispatch = build_dispatch(Opts),
    #{handler => make_dispatch_fun(Dispatch)}.

%%====================================================================
%% Internal
%%====================================================================

defaults(Opts) ->
    D = #{
        uri_template     => ?MASQUE_DEFAULT_URI_TEMPLATE,
        tcp_uri_template => ?MASQUE_DEFAULT_TCP_URI_TEMPLATE,
        handler          => masque_udp_proxy_handler,
        tcp_handler      => masque_tcp_proxy_handler
    },
    maps:merge(D, Opts).

%% RFC 9298 requires `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1'.
%% `h2:start_server/3' also honors `enable_connect_protocol => true'
%% directly; merging into `settings' is a no-op for those paths but
%% keeps user-supplied tuning (e.g. SETTINGS_MAX_FRAME_SIZE).
merged_settings(Opts) ->
    User = maps:get(settings, Opts, #{}),
    User#{enable_connect_protocol => 1}.

build_dispatch(Opts) ->
    #{udp_template => maps:get(uri_template, Opts),
      tcp_template => maps:get(tcp_uri_template, Opts),
      udp_handler  => maps:get(handler, Opts),
      tcp_handler  => maps:get(tcp_handler, Opts),
      handler_opts => maps:get(handler_opts, Opts, #{}),
      fallback     => maps:get(fallback, Opts, undefined),
      max_tunnels  => maps:get(max_tunnels_per_connection, Opts, 0)}.

make_dispatch_fun(Dispatch) ->
    fun(Conn, StreamId, Method, Path, Headers) ->
        dispatch_request(Conn, StreamId, Method, Path, Headers, Dispatch)
    end.

dispatch_request(Conn, StreamId, Method, Path, Headers, Dispatch) ->
    #{udp_template := UdpTpl, tcp_template := TcpTpl,
      udp_handler := UdpHandler, tcp_handler := TcpHandler,
      handler_opts := HandlerOpts, fallback := Fallback} = Dispatch,
    case validate(Method, Path, Headers, UdpTpl, TcpTpl) of
        {ok, Req0} ->
            Protocol = maps:get(protocol, Req0),
            HandlerMod = case Protocol of
                udp -> UdpHandler;
                tcp -> TcpHandler
            end,
            Req = Req0#{handler_opts => HandlerOpts},
            MaxT = maps:get(max_tunnels, Dispatch, 0),
            case accept_request(HandlerMod, Req) of
                accept when MaxT > 0 ->
                    case try_reserve_tunnel(Conn, MaxT) of
                        true ->
                            spawn_session(Conn, StreamId, Protocol,
                                          HandlerMod, HandlerOpts, Req);
                        false ->
                            reject(Conn, StreamId, overload)
                    end;
                accept ->
                    spawn_session(Conn, StreamId, Protocol,
                                  HandlerMod, HandlerOpts, Req);
                {reject, Reason} ->
                    reject(Conn, StreamId, Reason)
            end;
        {error, Reason} ->
            case Fallback of
                undefined ->
                    reject(Conn, StreamId, Reason);
                Fun when is_function(Fun, 5) ->
                    Fun(Conn, StreamId, Method, Path, Headers)
            end
    end.

spawn_session(Conn, StreamId, Protocol, Handler, HOpts, Req) ->
    Args = #{conn => Conn, stream_id => StreamId,
             protocol => Protocol, transport => h2,
             handler => Handler, handler_opts => HOpts, req => Req},
    case masque_h2_session_sup:start_session(Args) of
        {ok, _Pid} -> ok;
        {error, Reason} -> reject(Conn, StreamId, map_init_error(Reason))
    end.

map_init_error({resolution_failed, _}) -> resolution_failed;
map_init_error({reject, Err})          -> Err;
map_init_error(_)                      -> resolution_failed.

validate(Method, Path, Headers, UdpTemplate, TcpTemplate) ->
    case Method of
        <<"CONNECT">> ->
            Protocol = header(<<":protocol">>, Headers),
            case Protocol of
                ?MASQUE_CONNECT_UDP_PROTOCOL ->
                    match_path(Path, Headers, UdpTemplate, udp);
                ?MASQUE_CONNECT_TCP_PROTOCOL ->
                    match_path(Path, Headers, TcpTemplate, tcp);
                _ ->
                    {error, bad_protocol}
            end;
        _ ->
            {error, bad_method}
    end.

%% h2_connection strips `:scheme' and `:authority' from the handler
%% headers (they stay in the stream record but are not exposed). We
%% still populate the Req map with best-effort values so the handler
%% callback sees a consistent shape on both transports.
match_path(Path, Headers, Template, Protocol) ->
    case masque_uri:match(Template, Path) of
        {ok, #{target_host := Host, target_port := Port}} ->
            Authority = case header(<<":authority">>, Headers) of
                            undefined -> header(<<"host">>, Headers, <<>>);
                            A         -> A
                        end,
            {ok, #{
                method => <<"CONNECT">>,
                protocol => Protocol,
                path => Path,
                authority => Authority,
                scheme => <<"https">>,
                target_host => Host,
                target_port => Port,
                headers => Headers
            }};
        {error, bad_port} -> {error, bad_port};
        {error, bad_host} -> {error, bad_host};
        {error, _}        -> {error, bad_path}
    end.

header(Name, Headers, Default) ->
    case lists:keyfind(Name, 1, Headers) of
        {_, V} -> V;
        false  -> Default
    end.

accept_request(HandlerMod, Req) ->
    _ = code:ensure_loaded(HandlerMod),
    case erlang:function_exported(HandlerMod, accept, 1) of
        true  -> HandlerMod:accept(Req);
        false -> masque_handler:default_accept(Req)
    end.

reject(Conn, StreamId, Reason) ->
    masque_metrics:tunnel_rejected(#{reason => Reason}),
    Status = masque_errors:handshake_status(Reason),
    Phrase = masque_errors:status_reason(Reason),
    Body = <<Phrase/binary, "\n">>,
    Headers = [
        {<<"content-type">>, <<"text/plain; charset=utf-8">>},
        {<<"content-length">>, integer_to_binary(byte_size(Body))},
        {<<"proxy-status">>, proxy_status_field(Reason)}
    ],
    ok = h2:send_response(Conn, StreamId, Status, Headers),
    ok = h2:send_data(Conn, StreamId, Body, true).

proxy_status_field(Reason) ->
    Error = proxy_status_error(Reason),
    <<"masque; error=", Error/binary>>.

proxy_status_error(bad_method)        -> <<"http_protocol_error">>;
proxy_status_error(bad_protocol)      -> <<"http_protocol_error">>;
proxy_status_error(bad_path)          -> <<"http_protocol_error">>;
proxy_status_error(bad_port)          -> <<"http_protocol_error">>;
proxy_status_error(bad_host)          -> <<"http_protocol_error">>;
proxy_status_error(resolution_failed) -> <<"dns_error">>;
proxy_status_error(upstream_timeout)  -> <<"connection_timeout">>;
proxy_status_error(forbidden)         -> <<"destination_ip_prohibited">>;
proxy_status_error(loop_detected)     -> <<"proxy_loop_detected">>;
proxy_status_error(overload)          -> <<"proxy_internal_error">>;
proxy_status_error(_)                 -> <<"proxy_internal_error">>.

header(Name, Headers) ->
    case lists:keyfind(Name, 1, Headers) of
        {_, V} -> V;
        false  -> undefined
    end.

%%====================================================================
%% Per-connection tunnel counting
%%====================================================================

-spec try_reserve_tunnel(pid(), pos_integer()) -> boolean().
try_reserve_tunnel(Conn, Max) ->
    _ = ets:insert_new(masque_h2_tunnel_counts, {Conn, 0}),
    New = ets:update_counter(masque_h2_tunnel_counts, Conn, {2, 1}),
    case New > Max of
        true ->
            _ = ets:update_counter(masque_h2_tunnel_counts, Conn, {2, -1}),
            false;
        false ->
            true
    end.

-spec release_tunnel(pid()) -> ok.
release_tunnel(Conn) ->
    _ = try ets:update_counter(masque_h2_tunnel_counts, Conn, {2, -1, 0, 0})
        catch error:badarg -> ok
        end,
    ok.
