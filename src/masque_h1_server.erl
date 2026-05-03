%%% @doc MASQUE CONNECT-UDP listener over HTTP/1.1.
%%%
%%% Wraps `h1:start_server/3' with a request handler that validates
%%% the RFC 9298 Upgrade envelope (`GET' + `Upgrade: connect-udp' +
%%% `Capsule-Protocol: ?1'), matches the path against the configured
%%% URI template, and spawns a per-tunnel `masque_h1_server_session'
%%% on acceptance. The session itself calls `h1:accept_upgrade/3' so
%%% socket ownership lands on the session gen_server.
%%%
%%% No per-connection tunnel accounting: h1 Upgrade inherently tops
%%% out at one tunnel per TCP/TLS connection (the state machine
%%% shuts down and hands off the socket on 101).
%%%
%%% Handles CONNECT-UDP, CONNECT-IP, and classic CONNECT-TCP (the
%%% RFC 9110 §9.3.6 tunnel). The first two use HTTP Upgrade + RFC 9297
%%% capsules; CONNECT-TCP uses the classic `CONNECT host:port HTTP/1.1'
%%% method and becomes a raw byte pipe after the 200 response.
-module(masque_h1_server).

-export([
    start_listener/2,
    stop_listener/1,
    h1_handlers/1
]).

-include("masque.hrl").
-include("masque_ip.hrl").

-type listener_name() :: atom().
-type listener_opts() :: map().

-export_type([listener_name/0, listener_opts/0]).

%%====================================================================
%% API
%%====================================================================

-spec start_listener(listener_name(), listener_opts()) ->
    {ok, h1:server_ref()} | {error, term()}.
start_listener(Name, Opts0) when is_atom(Name), is_map(Opts0) ->
    persistent_term:erase({masque_drain, Name}),
    Opts = defaults(Opts0),
    Port = maps:get(port, Opts),
    #{handler := Handler} = h1_handlers(Opts#{drain_key => Name}),
    ServerOpts0 = #{
        transport => ssl,
        cert => maps:get(cert, Opts),
        key  => maps:get(key, Opts),
        handler => Handler
    },
    ServerOpts = maybe_add(acceptors, Opts, ServerOpts0),
    case h1:start_server(Name, Port, ServerOpts) of
        {ok, Ref} ->
            persistent_term:put({masque_h1_ref, Name}, Ref),
            persistent_term:put({masque_h1_name, Ref}, Name),
            {ok, Ref};
        Error -> Error
    end.

-spec stop_listener(h1:server_ref() | listener_name()) -> ok | {error, term()}.
stop_listener({_, _, _} = Ref) ->
    case persistent_term:get({masque_h1_name, Ref}, undefined) of
        undefined -> ok;
        Name ->
            persistent_term:erase({masque_drain, Name}),
            persistent_term:erase({masque_h1_ref, Name}),
            persistent_term:erase({masque_h1_name, Ref})
    end,
    h1:stop_server(Ref);
stop_listener(Name) when is_atom(Name) ->
    case persistent_term:get({masque_h1_ref, Name}, undefined) of
        undefined -> {error, {no_ref_for_name, Name}};
        Ref -> stop_listener(Ref)
    end.

-spec h1_handlers(map()) -> #{handler := module() | fun()}.
h1_handlers(Opts0) ->
    Opts = defaults(Opts0),
    Dispatch = build_dispatch(Opts),
    #{handler => make_dispatch_fun(Dispatch)}.

%%====================================================================
%% Internal
%%====================================================================

defaults(Opts) ->
    D = #{
        uri_template    => ?MASQUE_DEFAULT_URI_TEMPLATE,
        ip_uri_template => ?MASQUE_DEFAULT_IP_URI_PATH_PATTERN,
        handler         => masque_udp_proxy_handler,
        ip_handler      => masque_ip_proxy_handler,
        tcp_handler     => masque_tcp_proxy_handler,
        bind_handler    => masque_udp_bind_proxy_handler,
        accept_bind     => false
    },
    maps:merge(D, Opts).

maybe_add(Key, From, Into) ->
    case maps:find(Key, From) of
        {ok, V} -> Into#{Key => V};
        error   -> Into
    end.

build_dispatch(Opts) ->
    #{udp_template => maps:get(uri_template, Opts),
      udp_handler  => maps:get(handler, Opts),
      ip_template  => maps:get(ip_uri_template, Opts),
      ip_handler   => maps:get(ip_handler, Opts),
      tcp_handler  => maps:get(tcp_handler, Opts),
      bind_handler => maps:get(bind_handler, Opts),
      accept_bind  => maps:get(accept_bind, Opts),
      resolver     => maps:get(resolver, Opts, fun default_resolver/1),
      handler_opts => maps:merge(
                        maps:with([address_pool, routes, mtu,
                                   resolver, allow, family,
                                   allow_private, connect_timeout,
                                   socket_opts,
                                   bind_address, bind_port,
                                   bind_socket_opts,
                                   public_addresses, public_address_fun,
                                   peer_filter_fun, scrub_fun,
                                   allow_loopback,
                                   max_compression_contexts,
                                   max_compression_contexts_in,
                                   max_compression_contexts_out,
                                   max_pending_compression_responses],
                                  Opts),
                        maps:get(handler_opts, Opts, #{})),
      name         => maps:get(drain_key, Opts, undefined)}.

default_resolver(Host) when is_binary(Host) ->
    default_resolver(binary_to_list(Host));
default_resolver(Host) when is_list(Host) ->
    V4 = case inet_res:lookup(Host, in, a) of
             [] -> []; Xs -> Xs
         end,
    V6 = case inet_res:lookup(Host, in, aaaa) of
             [] -> []; Ys -> Ys
         end,
    case V4 ++ V6 of
        []    -> {error, nxdomain};
        Addrs -> {ok, Addrs}
    end.

make_dispatch_fun(Dispatch) ->
    fun(Conn, StreamId, Method, Path, Headers) ->
        dispatch_request(Conn, StreamId, Method, Path, Headers, Dispatch)
    end.

dispatch_request(Conn, StreamId, Method, Path, Headers, Dispatch) ->
    case masque:is_draining(maps:get(name, Dispatch, undefined)) of
        true ->
            reject(Conn, StreamId, overload);
        false ->
            dispatch_request_1(Conn, StreamId, Method, Path, Headers,
                               Dispatch)
    end.

dispatch_request_1(Conn, StreamId, Method, Path, Headers, Dispatch) ->
    #{udp_template := UdpTpl,
      udp_handler  := UdpHandler,
      ip_template  := IpTpl,
      ip_handler   := IpHandler,
      tcp_handler  := TcpHandler,
      handler_opts := HandlerOpts} = Dispatch,
    BindHandler = maps:get(bind_handler, Dispatch,
                           masque_udp_bind_proxy_handler),
    AcceptBind = maps:get(accept_bind, Dispatch, false),
    case validate(Method, Path, Headers, UdpTpl, IpTpl, AcceptBind) of
        {ok, Req0} ->
            Protocol = maps:get(protocol, Req0),
            HandlerMod = case Protocol of
                udp      -> UdpHandler;
                ip       -> IpHandler;
                tcp      -> TcpHandler;
                udp_bind -> BindHandler
            end,
            Req = Req0#{handler_opts => HandlerOpts},
            case accept_request(HandlerMod, Req) of
                accept ->
                    spawn_session(Conn, StreamId, Protocol, HandlerMod,
                                  HandlerOpts, Req);
                {reject, Reason} ->
                    reject(Conn, StreamId, Reason);
                {reject, Reason, Extra} when is_list(Extra) ->
                    reject(Conn, StreamId, Reason, Extra)
            end;
        {error, Reason} ->
            reject(Conn, StreamId, Reason)
    end.

spawn_session(Conn, StreamId, Protocol, Handler, HOpts, Req) ->
    Args = #{conn => Conn, stream_id => StreamId,
             protocol => Protocol, transport => h1,
             handler => Handler, handler_opts => HOpts, req => Req},
    case masque_h1_session_sup:start_session(Args) of
        {ok, _Pid} ->
            ok;
        {error, Reason} ->
            reject(Conn, StreamId, map_init_error(Reason))
    end.

map_init_error({reject, Err}) -> Err;
map_init_error(_)             -> resolution_failed.

validate(<<"GET">>, Path, Headers, UdpTemplate, IpTemplate) ->
    validate_get(Path, Headers, UdpTemplate, IpTemplate, false);
validate(<<"CONNECT">>, Path, Headers, _UdpTemplate, _IpTemplate) ->
    %% RFC 9110 §9.3.6 + RFC 9112 §3.2.3: CONNECT request-target is
    %% authority-form (`host:port' / `[ipv6]:port').
    case masque_uri:parse_authority_form(Path) of
        {ok, Host, Port} ->
            case check_connect_host(Headers, Path) of
                ok ->
                    Authority = header(<<"host">>, Headers, Path),
                    {ok, #{
                        method      => <<"CONNECT">>,
                        protocol    => tcp,
                        path        => Path,
                        authority   => Authority,
                        scheme      => <<"https">>,
                        target_host => Host,
                        target_port => Port,
                        headers     => Headers
                    }};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, bad_port} -> {error, bad_port};
        {error, bad_host} -> {error, bad_host};
        {error, _}        -> {error, bad_path}
    end;
validate(_, _Path, _Headers, _UdpTemplate, _IpTemplate) ->
    {error, bad_method}.

%% Same shape as `validate/5' plus the listener-level `AcceptBind'
%% switch. When true, the GET branch additionally inspects the
%% `Connect-UDP-Bind' request header and routes to the bind matcher.
validate(<<"GET">>, Path, Headers, UdpTemplate, IpTemplate, AcceptBind) ->
    validate_get(Path, Headers, UdpTemplate, IpTemplate, AcceptBind);
validate(Method, Path, Headers, UdpTemplate, IpTemplate, _AcceptBind) ->
    validate(Method, Path, Headers, UdpTemplate, IpTemplate).

validate_get(Path, Headers, UdpTemplate, IpTemplate, AcceptBind) ->
    case header(<<"host">>, Headers) of
        undefined ->
            {error, bad_host};
        _ ->
            Upgrade = header(<<"upgrade">>, Headers),
            Capsule = header(<<"capsule-protocol">>, Headers),
            UpgradeLc = lowercase_bin(Upgrade),
            case {UpgradeLc, Capsule} of
                {?MASQUE_CONNECT_UDP_PROTOCOL, <<"?1">>}
                  when AcceptBind ->
                    match_udp_or_bind_path(Path, Headers, UdpTemplate);
                {?MASQUE_CONNECT_UDP_PROTOCOL, <<"?1">>} ->
                    match_path(Path, Headers, UdpTemplate);
                {?MASQUE_CONNECT_IP_PROTOCOL, <<"?1">>} ->
                    match_ip_path(Path, Headers, IpTemplate);
                {Upgrade1, _} when Upgrade1 =:= ?MASQUE_CONNECT_UDP_PROTOCOL;
                                   Upgrade1 =:= ?MASQUE_CONNECT_IP_PROTOCOL ->
                    {error, bad_protocol};
                {undefined, _} ->
                    {error, bad_protocol};
                _ ->
                    {error, bad_protocol}
            end
    end.

%% When the listener has bind enabled, the bind matcher is tried
%% against the same UDP template (per draft-11 the URI is shared)
%% only when the Connect-UDP-Bind: ?1 header is present.
match_udp_or_bind_path(Path, Headers, Template) ->
    case masque_uri_udp_bind:parse_bind_header(Headers) of
        bind ->
            case masque_uri_udp_bind:match(Template, Path) of
                {ok, #{target_host := Host, target_port := Port,
                       bind        := Scope}} ->
                    {ok, #{
                        method      => <<"GET">>,
                        protocol    => udp_bind,
                        bind        => Scope,
                        path        => Path,
                        authority   => header(<<"host">>, Headers, <<"">>),
                        scheme      => <<"https">>,
                        target_host => Host,
                        target_port => Port,
                        headers     => Headers
                    }};
                {error, bad_port} -> {error, bad_port};
                {error, bad_host} -> {error, bad_host};
                {error, _}        -> {error, bad_path}
            end;
        _ ->
            match_path(Path, Headers, Template)
    end.

%% Host header on a CONNECT request must be present and parse to the
%% same host:port as the request-target (RFC 9112 §3.2.3). Case-
%% insensitive comparison on the host part; ports compare as integers.
check_connect_host(Headers, Path) ->
    case header(<<"host">>, Headers) of
        undefined ->
            {error, bad_host};
        HostHeader ->
            case {masque_uri:parse_authority_form(Path),
                  masque_uri:parse_authority_form(HostHeader)} of
                {{ok, H1, P1}, {ok, H2, P2}} ->
                    case ci_eq(H1, H2) andalso P1 =:= P2 of
                        true  -> ok;
                        false -> {error, bad_host}
                    end;
                _ ->
                    {error, bad_host}
            end
    end.

match_path(Path, Headers, Template) ->
    case masque_uri:match(Template, Path) of
        {ok, #{target_host := Host, target_port := Port}} ->
            Authority = header(<<"host">>, Headers, <<>>),
            {ok, #{
                method      => <<"GET">>,
                protocol    => udp,
                path        => Path,
                authority   => Authority,
                scheme      => <<"https">>,
                target_host => Host,
                target_port => Port,
                headers     => Headers
            }};
        {error, bad_port} -> {error, bad_port};
        {error, bad_host} -> {error, bad_host};
        {error, _}        -> {error, bad_path}
    end.

match_ip_path(Path, Headers, Template) ->
    case masque_uri_ip:parse_server_template(Template) of
        {ok, T} ->
            case masque_uri_ip:match(T, Path) of
                {ok, #{target := Target, ipproto := IPProto}} ->
                    Authority = header(<<"host">>, Headers, <<>>),
                    {ok, #{
                        method     => <<"GET">>,
                        protocol   => ip,
                        path       => Path,
                        authority  => Authority,
                        scheme     => <<"https">>,
                        ip_target  => Target,
                        ip_ipproto => IPProto,
                        headers    => Headers
                    }};
                {error, bad_target}  -> {error, bad_host};
                {error, bad_ipproto} -> {error, bad_port};
                {error, _}           -> {error, bad_path}
            end;
        {error, _} ->
            {error, bad_path}
    end.

accept_request(HandlerMod, Req) ->
    _ = code:ensure_loaded(HandlerMod),
    case erlang:function_exported(HandlerMod, accept, 1) of
        true  -> HandlerMod:accept(Req);
        false -> masque_handler:default_accept(Req)
    end.

header(Name, Headers) ->
    case lists:search(fun({N, _}) -> ci_eq(N, Name) end, Headers) of
        {value, {_, V}} -> V;
        false           -> undefined
    end.

header(Name, Headers, Default) ->
    case header(Name, Headers) of
        undefined -> Default;
        V         -> V
    end.

ci_eq(A, B) ->
    lowercase_bin(A) =:= lowercase_bin(B).

lowercase_bin(undefined) -> undefined;
lowercase_bin(B) when is_binary(B) ->
    list_to_binary(string:to_lower(binary_to_list(B)));
lowercase_bin(L) when is_list(L) ->
    lowercase_bin(iolist_to_binary(L)).

reject(Conn, StreamId, Reason) ->
    reject(Conn, StreamId, Reason, []).

reject(Conn, StreamId, Reason, ExtraHeaders) ->
    masque_metrics:tunnel_rejected(#{reason => Reason}),
    Status = masque_errors:handshake_status(Reason),
    Phrase = masque_errors:status_reason(Reason),
    Body = <<Phrase/binary, "\n">>,
    %% RFC 9931 (updates RFC 9298): a proxy that rejects an HTTP/1.1
    %% CONNECT/Upgrade MUST close the underlying connection, otherwise
    %% the client may treat subsequent bytes on the wire as belonging
    %% to the rejected resource.
    Base = [
        {<<"content-type">>, <<"text/plain; charset=utf-8">>},
        {<<"content-length">>, integer_to_binary(byte_size(Body))},
        {<<"connection">>, <<"close">>},
        {<<"proxy-status">>, proxy_status_field(Reason)}
    ],
    Headers = merge_extra_headers(Base, ExtraHeaders),
    _ = catch h1:send_response(Conn, StreamId, Status, Headers),
    _ = catch h1:send_data(Conn, StreamId, Body, true),
    _ = catch h1:close(Conn),
    ok.

merge_extra_headers(Base, []) ->
    Base;
merge_extra_headers(Base, Extra) ->
    Keys = [K || {K, _} <- Extra],
    Kept = [Pair || {K, _} = Pair <- Base, not lists:member(K, Keys)],
    Extra ++ Kept.

proxy_status_field(Reason) ->
    Error = proxy_status_error(Reason),
    <<"masque; error=", Error/binary>>.

proxy_status_error(bad_method)        -> <<"http_protocol_error">>;
proxy_status_error(bad_protocol)      -> <<"http_protocol_error">>;
proxy_status_error(bad_path)          -> <<"http_protocol_error">>;
proxy_status_error(bad_port)          -> <<"http_protocol_error">>;
proxy_status_error(bad_host)          -> <<"http_protocol_error">>;
proxy_status_error(resolution_failed) -> <<"dns_error">>;
proxy_status_error(forbidden)         -> <<"destination_ip_prohibited">>;
proxy_status_error(overload)          -> <<"proxy_internal_error">>;
proxy_status_error(_)                 -> <<"proxy_internal_error">>.
