%%% @doc MASQUE CONNECT-UDP proxy listener.
%%%
%%% Two public entry points:
%%%
%%% <ul>
%%%   <li>{@link start_listener/2} starts a dedicated `quic_h3' server
%%%       that handles MASQUE end-to-end; the usual case for a pure
%%%       MASQUE proxy.</li>
%%%   <li>{@link h3_handlers/1} returns the `handler' and
%%%       `connection_handler' functions that a caller can splat into
%%%       their own `quic_h3:start_server/3' opts. This lets users who
%%%       already run an HTTP/3 service add CONNECT-UDP support without
%%%       giving up ownership of the listener; non-MASQUE requests can
%%%       be routed to a `fallback' fun.</li>
%%% </ul>
%%%
%%% For each inbound request the handler validates the Extended
%%% CONNECT envelope per RFC 9298, matches the `:path' against the
%%% configured URI template, and either accepts the tunnel (2xx
%%% response, stream left open for subsequent datagrams) or rejects
%%% with the HTTP status selected by `masque_errors:handshake_status/1'
%%% (or defers to the caller's `fallback' fun when provided).
-module(masque_server).

-export([
    start_listener/2,
    stop_listener/1,
    h3_handlers/1
]).

-include("masque.hrl").
-include("masque_ip.hrl").

-type listener_name() :: atom().
-type listener_opts() :: masque:listener_opts().

-type h3_handler_fun() ::
    fun(
        (
            Conn :: pid(),
            StreamId :: non_neg_integer(),
            Method :: binary(),
            Path :: binary(),
            Headers :: [{binary(), binary()}]
        ) -> any()
    ).

-type connection_handler_fun() :: fun((pid()) -> map()).

-export_type([
    listener_name/0,
    listener_opts/0,
    h3_handler_fun/0,
    connection_handler_fun/0
]).

%%====================================================================
%% API
%%====================================================================

%% @doc Start a MASQUE listener as a dedicated `quic_h3' server.
%%
%% Required keys: `port', `cert', `key' (DER-encoded, same shape as
%% `quic_h3:start_server/3' expects). Optional `uri_template' defaults
%% to RFC 9298's well-known path; optional `handler' defaults to
%% `masque_udp_proxy_handler'; optional `fallback' is invoked for
%% requests that are not CONNECT-UDP tunnels (see `h3_handlers/1').
-spec start_listener(listener_name(), listener_opts()) ->
    {ok, pid()} | {error, term()}.
start_listener(Name, Opts0) when is_atom(Name), is_map(Opts0) ->
    persistent_term:erase({masque_drain, Name}),
    Opts = defaults(Opts0),
    Port = maps:get(port, Opts),
    #{
        handler := Handler,
        connection_handler := ConnectionHandler
    } =
        h3_handlers(Opts#{drain_key => Name}),
    ServerOpts = #{
        cert => maps:get(cert, Opts),
        key => maps:get(key, Opts),
        settings => merged_settings(Opts),
        %% `alpn' and `max_datagram_frame_size' are not declared keys
        %% on `quic_h3:server_opts()' - they belong in `quic_opts'.
        quic_opts => build_quic_opts(Opts),
        handler => Handler,
        connection_handler => ConnectionHandler
    },
    quic_h3:start_server(Name, Port, ServerOpts).

build_quic_opts(Opts) ->
    Base = #{
        alpn => maps:get(alpn, Opts, [<<"h3">>]),
        max_datagram_frame_size =>
            maps:get(max_datagram_frame_size, Opts, 65535)
    },
    %% SO_REUSEPORT lets the OS spread incoming packets across N
    %% listener processes for kernel-level scaling.
    case maps:get(reuseport, Opts, false) of
        true -> Base#{reuseport => true};
        false -> Base
    end.

%% @doc Stop a MASQUE listener.
-spec stop_listener(listener_name()) -> ok | {error, term()}.
stop_listener(Name) ->
    persistent_term:erase({masque_drain, Name}),
    quic_h3:stop_server(Name).

%% @doc Return the `handler' and `connection_handler' functions for a
%% MASQUE proxy, in a shape that can be dropped into a user-owned
%% `quic_h3:start_server/3' call.
%%
%% Accepted keys (all optional unless noted):
%% <ul>
%%   <li>`uri_template' - RFC 6570 template, default the RFC 9298
%%       well-known path template.</li>
%%   <li>`handler' - module implementing the {@link masque_handler}
%%       behaviour, default `masque_udp_proxy_handler'.</li>
%%   <li>`handler_opts' - arbitrary term passed to the handler module's
%%       `init/2' callback.</li>
%%   <li>`fallback' - `fun(Conn, StreamId, Method, Path, Headers) -> any()'
%%       invoked when the request is not a CONNECT-UDP tunnel. Absent
%%       → non-MASQUE requests are rejected with 405/501/404 as
%%       appropriate.</li>
%% </ul>
%%
%% Caveat: MASQUE must be the H3 connection's `owner' (HTTP Datagrams
%% are delivered to that pid), so the returned `connection_handler'
%% overrides the listener-wide owner. Sharing a single `quic_h3'
%% connection with another extension that also needs the `owner' slot
%% (e.g. WebTransport) is not supported in v0.1; run those on separate
%% listeners.
-spec h3_handlers(map()) ->
    #{
        handler := h3_handler_fun(),
        connection_handler := connection_handler_fun()
    }.
h3_handlers(Opts0) ->
    Opts = defaults(Opts0),
    UdpTemplate = maps:get(uri_template, Opts),
    TcpTemplate = maps:get(tcp_uri_template, Opts),
    IpTemplate = maps:get(ip_uri_template, Opts),
    UdpHandler = maps:get(handler, Opts),
    TcpHandler = maps:get(tcp_handler, Opts),
    IpHandler = maps:get(ip_handler, Opts),
    BindHandler = maps:get(bind_handler, Opts),
    AcceptBind = maps:get(accept_bind, Opts),
    Resolver = maps:get(resolver, Opts, fun default_resolver/1),
    %% Lift IP-scoped listener options into handler_opts so the
    %% default IP handler (and user handlers that follow the same
    %% convention) see them without callers having to duplicate.
    IpExtra = maps:with(
        [
            address_pool,
            routes,
            mtu,
            resolver,
            allow,
            family,
            allow_private,
            connect_timeout,
            socket_opts
        ],
        Opts
    ),
    %% Same for bind-scoped opts.
    BindExtra = maps:with(
        [
            bind_address,
            bind_port,
            bind_socket_opts,
            public_addresses,
            public_address_fun,
            peer_filter_fun,
            scrub_fun,
            allow_private,
            allow_loopback,
            max_compression_contexts,
            max_compression_contexts_in,
            max_compression_contexts_out,
            max_pending_compression_responses
        ],
        Opts
    ),
    UserHOpts = maps:get(handler_opts, Opts, #{}),
    HandlerOpts = maps:merge(maps:merge(IpExtra, BindExtra), UserHOpts),
    Fallback = maps:get(fallback, Opts, undefined),
    DrainKey = maps:get(drain_key, Opts, undefined),
    Dispatch = #{
        udp_template => UdpTemplate,
        tcp_template => TcpTemplate,
        ip_template => IpTemplate,
        udp_handler => UdpHandler,
        tcp_handler => TcpHandler,
        ip_handler => IpHandler,
        bind_handler => BindHandler,
        accept_bind => AcceptBind,
        resolver => Resolver,
        handler_opts => HandlerOpts,
        fallback => Fallback,
        name => DrainKey
    },
    MaxTunnels = maps:get(max_tunnels_per_connection, Opts, 0),
    ConnectionHandler = fun(ConnPid) ->
        {ok, Router} = masque_server_connection:start_link(MaxTunnels, ConnPid),
        #{
            owner => Router,
            handler => make_dispatch_fun(Dispatch, Router),
            h3_datagram_enabled => true
        }
    end,
    #{
        handler => make_dispatch_fun(Dispatch, undefined),
        connection_handler => ConnectionHandler
    }.

%%====================================================================
%% Internal
%%====================================================================

defaults(Opts) ->
    D = #{
        uri_template => ?MASQUE_DEFAULT_URI_TEMPLATE,
        tcp_uri_template => ?MASQUE_DEFAULT_TCP_URI_TEMPLATE,
        ip_uri_template => ?MASQUE_DEFAULT_IP_URI_PATH_PATTERN,
        handler => masque_udp_proxy_handler,
        tcp_handler => masque_tcp_proxy_handler,
        ip_handler => masque_ip_proxy_handler,
        bind_handler => masque_udp_bind_proxy_handler,
        accept_bind => false
    },
    maps:merge(D, Opts).

%% Default resolver: resolve A and AAAA, merge results.
default_resolver(Host) when is_binary(Host) ->
    default_resolver(binary_to_list(Host));
default_resolver(Host) when is_list(Host) ->
    V4 =
        case inet_res:lookup(Host, in, a) of
            [] -> [];
            Xs -> Xs
        end,
    V6 =
        case inet_res:lookup(Host, in, aaaa) of
            [] -> [];
            Ys -> Ys
        end,
    case V4 ++ V6 of
        [] -> {error, nxdomain};
        Addrs -> {ok, Addrs}
    end.

%% MASQUE requires `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1' and
%% `SETTINGS_H3_DATAGRAM = 1'. Merge these on top of any user-supplied
%% settings rather than clobbering them.
merged_settings(Opts) ->
    User = maps:get(settings, Opts, #{}),
    maps:merge(User, #{
        enable_connect_protocol => 1,
        h3_datagram => 1
    }).

make_dispatch_fun(Dispatch, Router) ->
    fun(Conn, StreamId, Method, Path, Headers) ->
        dispatch_request(
            Conn,
            StreamId,
            Method,
            Path,
            Headers,
            Dispatch,
            Router
        )
    end.

dispatch_request(Conn, StreamId, Method, Path, Headers, Dispatch, Router) ->
    case masque:is_draining(maps:get(name, Dispatch, undefined)) of
        true ->
            reject(Conn, StreamId, overload);
        false ->
            dispatch_request_1(
                Conn,
                StreamId,
                Method,
                Path,
                Headers,
                Dispatch,
                Router
            )
    end.

dispatch_request_1(Conn, StreamId, Method, Path, Headers, Dispatch, Router) ->
    #{
        udp_template := UdpTpl,
        tcp_template := TcpTpl,
        ip_template := IpTpl,
        udp_handler := UdpHandler,
        tcp_handler := TcpHandler,
        ip_handler := IpHandler,
        bind_handler := BindHandler,
        accept_bind := AcceptBind,
        resolver := Resolver,
        handler_opts := HandlerOpts,
        fallback := Fallback
    } = Dispatch,
    case
        validate(
            Method,
            Path,
            Headers,
            UdpTpl,
            TcpTpl,
            IpTpl,
            AcceptBind
        )
    of
        {ok, Req0} ->
            Protocol = maps:get(protocol, Req0),
            HandlerMod =
                case Protocol of
                    udp -> UdpHandler;
                    tcp -> TcpHandler;
                    ip -> IpHandler;
                    udp_bind -> BindHandler
                end,
            Req1 = add_peer_info(Conn, Req0),
            Req2 = Req1#{handler_opts => HandlerOpts},
            case masque_ip:resolve_target(Protocol, Req2, Resolver) of
                {ok, Req3} ->
                    case accept_request(HandlerMod, Req3) of
                        accept ->
                            spawn_session(
                                Conn,
                                StreamId,
                                Router,
                                Protocol,
                                HandlerMod,
                                HandlerOpts,
                                Req3
                            );
                        {reject, Reason} ->
                            reject(Conn, StreamId, Reason);
                        {reject, Reason, Extra} when is_list(Extra) ->
                            reject(Conn, StreamId, Reason, Extra)
                    end;
                {error, Reason} ->
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

spawn_session(Conn, StreamId, undefined, _Proto, _Handler, _HOpts, _Req) ->
    reject(Conn, StreamId, resolution_failed);
spawn_session(Conn, StreamId, Router, Protocol, Handler, HOpts, Req) ->
    Args = #{
        conn => Conn,
        stream_id => StreamId,
        router => Router,
        protocol => Protocol,
        transport => h3,
        handler => Handler,
        handler_opts => HOpts,
        req => Req
    },
    try masque_server_connection:start_session(Router, Args) of
        {ok, _Pid} -> ok;
        %% The session already answered (or the stream is gone): a
        %% reject here would follow a 2xx.
        {error, stream_dead} -> ok;
        {error, Reason} -> reject(Conn, StreamId, map_init_error(Reason))
    catch
        exit:{timeout, _} ->
            case masque_server_connection:cancel_pending(Router, StreamId) of
                ok ->
                    reject(Conn, StreamId, resolution_failed);
                {error, already_activated} ->
                    %% Session started after timeout. Tunnel is live.
                    ok
            end
    end.

add_peer_info(Conn, Req) ->
    QuicConn = quic_h3:get_quic_conn(Conn),
    Req1 =
        case quic:peername(QuicConn) of
            {ok, PeerAddr} -> Req#{peer => PeerAddr};
            _ -> Req
        end,
    case quic:peercert(QuicConn) of
        {ok, Cert} -> Req1#{peer_cert => Cert};
        _ -> Req1
    end.

map_init_error(too_many_tunnels) -> overload;
map_init_error({resolution_failed, _}) -> resolution_failed;
map_init_error({reject, Err}) -> Err;
map_init_error(_) -> resolution_failed.

%% `AcceptBind' is the listener-level switch for Connect-UDP-Bind
%% (draft-ietf-masque-connect-udp-listen-11). When true, the
%% `connect-udp' branch additionally inspects the
%% `Connect-UDP-Bind' request header and routes to the bind matcher
%% on `?1'. When false (the default), the header is ignored and
%% legacy CONNECT-UDP behaviour is unchanged.
validate(
    Method,
    Path,
    Headers,
    UdpTemplate,
    TcpTemplate,
    IpTemplate,
    AcceptBind
) ->
    case Method of
        <<"CONNECT">> ->
            Protocol = header(<<":protocol">>, Headers),
            case Protocol of
                ?MASQUE_CONNECT_UDP_PROTOCOL when AcceptBind ->
                    match_udp_or_bind(Path, Headers, UdpTemplate);
                ?MASQUE_CONNECT_UDP_PROTOCOL ->
                    match_path(Path, Headers, UdpTemplate, udp);
                ?MASQUE_CONNECT_TCP_PROTOCOL ->
                    match_path(Path, Headers, TcpTemplate, tcp);
                ?MASQUE_CONNECT_IP_PROTOCOL ->
                    match_ip_path(Path, Headers, IpTemplate);
                _ ->
                    {error, bad_protocol}
            end;
        _ ->
            {error, bad_method}
    end.

%% Read `Connect-UDP-Bind' first; on `?1' use the bind matcher
%% which accepts the percent-encoded `*' wildcard. Otherwise fall
%% through to the existing CONNECT-UDP path. Per draft-11, an
%% invalid value is treated as absent.
match_udp_or_bind(Path, Headers, Template) ->
    case masque_uri_udp_bind:parse_bind_header(Headers) of
        bind ->
            case masque_uri_udp_bind:match(Template, Path) of
                {ok, #{
                    target_host := Host,
                    target_port := Port,
                    bind := Scope
                }} ->
                    case {header(<<":scheme">>, Headers), header(<<":authority">>, Headers)} of
                        {Scheme, Authority} when
                            Scheme =/= undefined,
                            Authority =/= undefined
                        ->
                            {ok, #{
                                method => <<"CONNECT">>,
                                protocol => udp_bind,
                                bind => Scope,
                                path => Path,
                                authority => Authority,
                                scheme => Scheme,
                                target_host => Host,
                                target_port => Port,
                                headers => Headers
                            }};
                        _ ->
                            {error, bad_path}
                    end;
                {error, bad_port} ->
                    {error, bad_port};
                {error, bad_host} ->
                    {error, bad_host};
                {error, _} ->
                    {error, bad_path}
            end;
        _ ->
            match_path(Path, Headers, Template, udp)
    end.

match_path(Path, Headers, Template, Protocol) ->
    case masque_uri:match(Template, Path) of
        {ok, #{target_host := Host, target_port := Port}} ->
            %% `:scheme' and `:authority' presence is enforced by
            %% `quic_h3' for Extended CONNECT; we surface whatever it
            %% delivers without silently substituting defaults.
            case {header(<<":scheme">>, Headers), header(<<":authority">>, Headers)} of
                {Scheme, Authority} when
                    Scheme =/= undefined,
                    Authority =/= undefined
                ->
                    {ok, #{
                        method => <<"CONNECT">>,
                        protocol => Protocol,
                        path => Path,
                        authority => Authority,
                        scheme => Scheme,
                        target_host => Host,
                        target_port => Port,
                        headers => Headers
                    }};
                _ ->
                    {error, bad_path}
            end;
        {error, bad_port} ->
            {error, bad_port};
        {error, bad_host} ->
            {error, bad_host};
        {error, _} ->
            {error, bad_path}
    end.

match_ip_path(Path, Headers, Template) ->
    case masque_uri_ip:parse_server_template(Template) of
        {ok, T} ->
            case masque_uri_ip:match(T, Path) of
                {ok, #{target := Target, ipproto := IPProto}} ->
                    case {header(<<":scheme">>, Headers), header(<<":authority">>, Headers)} of
                        {Scheme, Authority} when
                            Scheme =/= undefined,
                            Authority =/= undefined
                        ->
                            {ok, #{
                                method => <<"CONNECT">>,
                                protocol => ip,
                                path => Path,
                                authority => Authority,
                                scheme => Scheme,
                                ip_target => Target,
                                ip_ipproto => IPProto,
                                headers => Headers
                            }};
                        _ ->
                            {error, bad_path}
                    end;
                {error, bad_target} ->
                    {error, bad_host};
                {error, bad_ipproto} ->
                    {error, bad_port};
                {error, _} ->
                    {error, bad_path}
            end;
        {error, _} ->
            {error, bad_path}
    end.

accept_request(HandlerMod, Req) ->
    _ = code:ensure_loaded(HandlerMod),
    case erlang:function_exported(HandlerMod, accept, 1) of
        true -> HandlerMod:accept(Req);
        false -> masque_handler:default_accept(Req)
    end.

reject(Conn, StreamId, Reason) ->
    reject(Conn, StreamId, Reason, []).

reject(Conn, StreamId, Reason, ExtraHeaders) ->
    masque_metrics:tunnel_rejected(#{reason => Reason}),
    Status = masque_errors:handshake_status(Reason),
    Phrase = masque_errors:status_reason(Reason),
    Body = <<Phrase/binary, "\n">>,
    Base = [
        {<<"content-type">>, <<"text/plain; charset=utf-8">>},
        {<<"content-length">>, integer_to_binary(byte_size(Body))},
        %% RFC 9209 structured field - gives clients a machine-readable
        %% tag for the failure beyond the numeric status (RFC 9298 §3
        %% recommendation).
        {<<"proxy-status">>, proxy_status_field(Reason)}
    ],
    Headers = merge_extra_headers(Base, ExtraHeaders),
    ok = quic_h3:send_response(Conn, StreamId, Status, Headers),
    ok = quic_h3:send_data(Conn, StreamId, Body, true).

%% Caller-supplied headers win on collision so apps can override the
%% proxy-status / content-type defaults. Order: ExtraHeaders first
%% (caller-visible), then whatever base entries remain.
merge_extra_headers(Base, []) ->
    Base;
merge_extra_headers(Base, Extra) ->
    Keys = [K || {K, _} <- Extra],
    Kept = [Pair || {K, _} = Pair <- Base, not lists:member(K, Keys)],
    Extra ++ Kept.

%% Map MASQUE handshake errors to a minimal Proxy-Status structured
%% field value. We use `masque' as the proxy identifier and attach an
%% RFC 9209 `error' parameter naming the failure class.
proxy_status_field(Reason) ->
    Error = proxy_status_error(Reason),
    <<"masque; error=", Error/binary>>.

proxy_status_error(bad_method) -> <<"http_protocol_error">>;
proxy_status_error(bad_protocol) -> <<"http_protocol_error">>;
proxy_status_error(bad_path) -> <<"http_protocol_error">>;
proxy_status_error(bad_port) -> <<"http_protocol_error">>;
proxy_status_error(bad_host) -> <<"http_protocol_error">>;
proxy_status_error(resolution_failed) -> <<"dns_error">>;
proxy_status_error(upstream_timeout) -> <<"connection_timeout">>;
proxy_status_error(forbidden) -> <<"destination_ip_prohibited">>;
proxy_status_error(loop_detected) -> <<"proxy_loop_detected">>;
proxy_status_error(overload) -> <<"proxy_internal_error">>;
proxy_status_error(_) -> <<"proxy_internal_error">>.

header(Name, Headers) ->
    header(Name, Headers, undefined).

header(Name, Headers, Default) ->
    case lists:keyfind(Name, 1, Headers) of
        {_, V} -> V;
        false -> Default
    end.
