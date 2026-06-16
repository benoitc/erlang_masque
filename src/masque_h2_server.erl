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
-include("masque_ip.hrl").

-ifdef(TEST).
%% Test-only: exercise the Extended CONNECT validator (pseudo-header
%% reading, template matching) without standing up a listener.
-export([validate/7]).
-endif.

-type listener_name() :: atom().
-type listener_opts() :: map().

-export_type([listener_name/0, listener_opts/0]).

%%====================================================================
%% API
%%====================================================================

-spec start_listener(listener_name(), listener_opts()) ->
    {ok, h2:server_ref()} | {error, term()}.
start_listener(Name, Opts0) when is_atom(Name), is_map(Opts0) ->
    persistent_term:erase({masque_drain, Name}),
    Opts = defaults(Opts0),
    Port = maps:get(port, Opts),
    #{handler := Handler} = h2_handlers(Opts#{drain_key => Name}),
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
    case h2:start_server(Name, Port, ServerOpts1) of
        {ok, Ref} ->
            persistent_term:put({masque_h2_ref, Name}, Ref),
            persistent_term:put({masque_h2_name, Ref}, Name),
            {ok, Ref};
        Error -> Error
    end.

-spec stop_listener(h2:server_ref() | listener_name()) -> ok | {error, term()}.
stop_listener({_, _, _} = Ref) ->
    case persistent_term:get({masque_h2_name, Ref}, undefined) of
        undefined -> ok;
        Name ->
            persistent_term:erase({masque_drain, Name}),
            persistent_term:erase({masque_h2_ref, Name}),
            persistent_term:erase({masque_h2_name, Ref})
    end,
    h2:stop_server(Ref);
stop_listener(Name) when is_atom(Name) ->
    case persistent_term:get({masque_h2_ref, Name}, undefined) of
        undefined ->
            {error, {no_ref_for_name, Name}};
        Ref ->
            stop_listener(Ref)
    end.

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
        ip_uri_template  => ?MASQUE_DEFAULT_IP_URI_PATH_PATTERN,
        handler          => masque_udp_proxy_handler,
        tcp_handler      => masque_tcp_proxy_handler,
        ip_handler       => masque_ip_proxy_handler,
        bind_handler     => masque_udp_bind_proxy_handler,
        accept_bind      => false
    },
    maps:merge(D, Opts).

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
      ip_template  => maps:get(ip_uri_template, Opts),
      udp_handler  => maps:get(handler, Opts),
      tcp_handler  => maps:get(tcp_handler, Opts),
      ip_handler   => maps:get(ip_handler, Opts),
      bind_handler => maps:get(bind_handler, Opts),
      accept_bind  => maps:get(accept_bind, Opts),
      resolver     => maps:get(resolver, Opts, fun default_resolver/1),
      handler_opts => maps:merge(
                        maps:merge(
                          maps:with([address_pool, routes, mtu], Opts),
                          maps:with(
                            [bind_address, bind_port, bind_socket_opts,
                             public_addresses, public_address_fun,
                             peer_filter_fun, scrub_fun, allow_private,
                             allow_loopback,
                             max_compression_contexts,
                             max_compression_contexts_in,
                             max_compression_contexts_out,
                             max_pending_compression_responses], Opts)),
                        maps:get(handler_opts, Opts, #{})),
      fallback     => maps:get(fallback, Opts, undefined),
      max_tunnels  => maps:get(max_tunnels_per_connection, Opts, 0),
      name         => maps:get(drain_key, Opts, undefined)}.

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
    #{udp_template := UdpTpl, tcp_template := TcpTpl,
      ip_template  := IpTpl,
      udp_handler := UdpHandler, tcp_handler := TcpHandler,
      ip_handler  := IpHandler,
      bind_handler := BindHandler,
      accept_bind  := AcceptBind,
      resolver    := Resolver,
      handler_opts := HandlerOpts, fallback := Fallback} = Dispatch,
    case validate(Method, Path, Headers, UdpTpl, TcpTpl, IpTpl,
                  AcceptBind) of
        {ok, Req0} ->
            Protocol = maps:get(protocol, Req0),
            HandlerMod = case Protocol of
                udp      -> UdpHandler;
                tcp      -> TcpHandler;
                ip       -> IpHandler;
                udp_bind -> BindHandler
            end,
            Req1 = Req0#{handler_opts => HandlerOpts},
            case resolve_target(Protocol, Req1, Resolver) of
                {ok, Req} ->
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

%% RFC 9484 §4.7.1 — hostname targets resolved before accept/1
resolve_target(ip, #{ip_target := Target} = Req, Resolver)
  when is_binary(Target) ->
    case Resolver(Target) of
        {ok, Addrs} -> {ok, Req#{resolved_addresses => Addrs}};
        {error, _}  -> {error, resolution_failed}
    end;
resolve_target(ip, #{ip_target := {_,_,_,_} = A} = Req, _Resolver) ->
    {ok, Req#{resolved_addresses => [A]}};
resolve_target(ip, #{ip_target := {_,_,_,_,_,_,_,_} = A} = Req, _Resolver) ->
    {ok, Req#{resolved_addresses => [A]}};
resolve_target(ip, Req, _Resolver) ->
    {ok, Req#{resolved_addresses => []}};
resolve_target(_, Req, _Resolver) ->
    {ok, Req}.

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

validate(Method, Path, Headers, UdpTemplate, TcpTemplate, IpTemplate,
         AcceptBind) ->
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

match_udp_or_bind(Path, Headers, Template) ->
    case masque_uri_udp_bind:parse_bind_header(Headers) of
        bind ->
            case masque_uri_udp_bind:match(Template, Path) of
                {ok, #{target_host := Host, target_port := Port,
                       bind        := Scope}} ->
                    case {header(<<":scheme">>, Headers),
                          header(<<":authority">>, Headers)} of
                        {Scheme, Authority}
                          when Scheme =/= undefined,
                               Authority =/= undefined ->
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
                {error, bad_port} -> {error, bad_port};
                {error, bad_host} -> {error, bad_host};
                {error, _}        -> {error, bad_path}
            end;
        _ ->
            match_path(Path, Headers, Template, udp)
    end.

%% `:scheme' and `:authority' presence is enforced by `h2' for
%% Extended CONNECT; we surface whatever it delivers without silently
%% substituting defaults.
match_path(Path, Headers, Template, Protocol) ->
    case masque_uri:match(Template, Path) of
        {ok, #{target_host := Host, target_port := Port}} ->
            case {header(<<":scheme">>, Headers),
                  header(<<":authority">>, Headers)} of
                {Scheme, Authority} when Scheme =/= undefined,
                                         Authority =/= undefined ->
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
        {error, bad_port} -> {error, bad_port};
        {error, bad_host} -> {error, bad_host};
        {error, _}        -> {error, bad_path}
    end.

match_ip_path(Path, Headers, Template) ->
    case masque_uri_ip:parse_server_template(Template) of
        {ok, T} ->
            case masque_uri_ip:match(T, Path) of
                {ok, #{target := Target, ipproto := IPProto}} ->
                    case {header(<<":scheme">>, Headers),
                          header(<<":authority">>, Headers)} of
                        {Scheme, Authority}
                          when Scheme =/= undefined,
                               Authority =/= undefined ->
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
                {error, bad_target}   -> {error, bad_host};
                {error, bad_ipproto}  -> {error, bad_port};
                {error, _}            -> {error, bad_path}
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
        {<<"proxy-status">>, proxy_status_field(Reason)}
    ],
    Headers = merge_extra_headers(Base, ExtraHeaders),
    ok = h2:send_response(Conn, StreamId, Status, Headers),
    ok = h2:send_data(Conn, StreamId, Body, true).

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
