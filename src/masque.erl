-module(masque).
-moduledoc """
Public API for the `masque` library.

`masque` tunnels UDP (RFC 9298), IP (RFC 9484) and TCP
(draft-ietf-httpbis-connect-tcp) traffic, plus Connect-UDP-Bind, over
HTTP/3, HTTP/2 and HTTP/1.1. Use this module to open client tunnels
(`connect/3`, `bind_connect/3`), send and receive on them, and start,
drain and stop proxy listeners.

This module, the `masque_handler` behaviour, the built-in handlers,
the codecs and the URI helpers are the documented surface. Modules
that do not appear in these docs are internal and may change between
versions.
""".

-export([version/0]).
-export([connect/3, connect/2, close/1, info/1]).
-export([send/2, send/3, recv/2, set_mode/2]).
-export([send_capsule/3, shutdown_write/1]).
-export([migrate/1]).
-export([reverse_listen/3, reverse_accept/2, reverse_accept/3, reverse_decline/2]).
-export([advertise_services/2, request_connection/2, request_connection/3, consumed/2]).
-export([start_listener/2, stop_listener/1]).
-export([start_listener_h2/2, stop_listener_h2/1]).
-export([start_listener_h1/2, stop_listener_h1/1]).
-export([drain_listener/1, undrain_listener/1, is_draining/1]).
-export([
    start_chain_listener/2,
    start_chain_listener_h2/2,
    start_chain_listener_h1/2
]).
-export([h3_handlers/1, h2_handlers/1]).

%% CONNECT-IP (RFC 9484) client API.
-export([
    send_ip_packet/2,
    request_addresses/2,
    assign_addresses/2,
    advertise_routes/2,
    ip_info/1
]).

%% Connect-UDP-Bind (draft-ietf-masque-connect-udp-listen-16) client API.
-export([
    bind_connect/3,
    send_to/3,
    assign_compression/2,
    open_uncompressed_context/1,
    close_compression/2,
    proxy_public_address/1
]).

-include("masque.hrl").
-include("masque_ip.hrl").
-include("masque_reverse.hrl").

%% Reverse connect (draft-rosomakho-masque-reverse-connect-01): a service
%% a connection request names or a client advertises, and the scope of a
%% control channel.
-type reverse_service() :: #{
    destination := local | binary() | inet:ip_address(),
    protocol := tcp | udp,
    port := inet:port_number()
}.
-type reverse_target() ::
    '*' | local | {wildcard, binary()} | masque_uri_ip:ip_target().
-type reverse_ipproto() :: '*' | tcp | udp.

-export_type([
    session/0,
    proxy_uri/0,
    target/0,
    transport/0,
    connect_opts/0,
    listener_opts/0,
    %% CONNECT-IP types.
    ip_version/0,
    ip_prefix/0,
    ip_prefix_request/0,
    ip_assignment/0,
    ip_route/0,
    ip_ipproto/0,
    ip_target/0,
    request_id/0,
    nz_request_id/0,
    %% Reverse connect.
    reverse_service/0,
    reverse_target/0,
    reverse_ipproto/0,
    %% Embedding in a user-owned quic_h3 server.
    h3_handler_fun/0,
    connection_handler_fun/0
]).

%%====================================================================
%% Types
%%====================================================================

-type session() :: pid().

-doc "Request handler for `quic_h3:start_server/3`, from `h3_handlers/1`.".
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

-doc "Connection handler for `quic_h3:start_server/3`, from `h3_handlers/1`.".
-type connection_handler_fun() :: fun((pid()) -> map()).

-type proxy_uri() :: binary() | string().

%% A UDP/TCP target — a resolved IP or a host name to resolve, and a
%% port. CONNECT-IP targets are `{ip_target(), ip_ipproto()}'.
-type udp_target() :: {binary() | inet:hostname() | inet:ip_address(), inet:port_number()}.
-type target() :: udp_target() | {ip_target(), ip_ipproto()}.

-type transport() :: h3 | h2 | h1.

%%--------------------------------------------------------------------
%% CONNECT-IP types (RFC 9484)
%%--------------------------------------------------------------------

-type ip_version() :: 4 | 6.

-type ip_prefix() ::
    {4, inet:ip4_address(), 0..32}
    | {6, inet:ip6_address(), 0..128}.

%% RFC 9484 §4.7.2 — ADDRESS_REQUEST Request IDs MUST be nonzero.
-type nz_request_id() :: pos_integer().

%% RFC 9484 §4.7.1 — ADDRESS_ASSIGN uses Request ID 0 for
%% unprompted (server-initiated) assignments.
-type request_id() :: non_neg_integer().

%% ADDRESS_REQUEST / ADDRESS_ASSIGN / ROUTE_ADVERTISEMENT entries are
%% exposed as tagged records (defined in `include/masque_ip.hrl').
%% Clients that want to build them without the include can use the
%% `masque_ip' helper module.
-type ip_prefix_request() :: #ip_prefix_request{}.
-type ip_assignment() :: #ip_assignment{}.
-type ip_route() :: #ip_route{}.

-type ip_ipproto() :: '*' | 0..255.

-type ip_target() ::
    '*'
    | inet:ip4_address()
    | inet:ip6_address()
    | ip_prefix()
    %% hostname
    | binary().

-type connect_opts() ::
    #{
        %% Tunnel protocol: `udp' (default), `tcp', or `ip'.
        protocol => udp | tcp | ip,
        %% Transport preference. `[h3, h2]' (default) races the two.
        %% `h1' may appear as a tertiary fallback for `udp' and `ip';
        %% `tcp' support on h1 lands with the CONNECT-TCP step.
        transports => [transport()],
        prefer_timeout_ms => non_neg_integer(),
        %% Head-start (ms) before the h1 attempt is spawned, measured
        %% from when the h2 attempt starts. Default 500.
        h1_prefer_timeout_ms => non_neg_integer(),
        %% CONNECT-TCP over h1: value for the `Proxy-Authorization'
        %% header (e.g. `<<"Basic dXNlcjpwYXNz">>'). Ignored on all
        %% other transport/protocol combinations.
        proxy_authorization => binary(),
        uri_template => binary(),
        verify => verify_peer | verify_none,
        cacerts => [public_key:der_encoded()],
        timeout => pos_integer(),
        capsule_protocol => boolean(),
        owner => pid(),
        ssl_opts => [ssl:tls_client_option()],
        %% h3 only: QUIC connection options, merged over masque's defaults
        %% (for example `session_ticket', `idle_timeout',
        %% `keep_alive_interval').
        quic_opts => map(),
        %% CONNECT-TCP framing: `raw' (earlier drafts, the default) or
        %% `capsule' (draft-ietf-httpbis-connect-tcp-18).
        tcp_framing => raw | capsule,
        %% CONNECT-TCP in capsule framing: the protocol token, which also
        %% picks the capsule codes. `<<"connect-tcp">>' (the default, the
        %% registered name), `<<"connect-tcp-12">>' (the draft's interop
        %% token), or `<<"connect-tcp-08">>' / `<<"connect-tcp-07">>' for
        %% peers of drafts -09 and -10.
        tcp_protocol => binary(),
        %% CONNECT-IP: local send-side MTU (1280..65535, default 1500).
        mtu => 1280..65535,
        %% Opt-in connection pooling. When `true', h2 / h3 attempts
        %% share a pooled upstream transport connection keyed by
        %% host/port/transport + a hash of connect-affecting opts
        %% (verify, cacerts, ssl_opts, alpn). h1 always bypasses the
        %% pool. Default `false'.
        upstream_pool => boolean(),
        %% Tuning forwarded to the pooled owner on cold dials
        %% (`idle_timeout_ms', `max_streams').
        upstream_pool_opts => map(),
        %% Extra request headers prepended to the CONNECT (or GET +
        %% Upgrade on h1). Useful for auth schemes that ride on the
        %% handshake request (`Authorization: PrivateToken token=...',
        %% proxy-specific metadata). Library-controlled pseudo-headers
        %% (`:method', `:scheme', `:authority', `:path', `:protocol',
        %% `capsule-protocol') are not overridable; a duplicate here
        %% is silently dropped.
        request_headers => [{binary(), binary()}],
        %% Bound on the `queue'-mode receive queue, in items (default
        %% 1000). See {@link recv/2}.
        rx_queue_limit => pos_integer(),
        %% Internal - set by racer, not by callers.
        transport => transport(),
        defer_owner => boolean(),
        proxy => {binary(), inet:port_number()},
        alpn => [binary()],
        mode => message | queue
    }.

-type listener_opts() ::
    #{
        port := inet:port_number(),
        %% DER binaries for H3, PEM paths for H2 — both listeners
        %% read these same keys.
        cert => term(),
        key => term(),
        %% h3: QUIC listener options merged over masque's defaults, for
        %% example `sni_callback', `max_streams_bidi', `require_client_cert'.
        %% With an `sni_callback', `cert' and `key' may be left out.
        quic_opts => map(),
        %% h3 and h2: CONNECT-TCP framing, `auto' (by the request's
        %% `capsule-protocol' header), `raw' or `capsule' (draft -18).
        tcp_framing => auto | raw | capsule,
        %% h2 and h1: TLS options for the listening socket, such as
        %% `sni_fun'.
        ssl_opts => [ssl:tls_server_option()],
        %% CONNECT-UDP
        uri_template => binary(),
        %% CONNECT-TCP
        tcp_uri_template => binary(),
        %% CONNECT-IP (RFC 9484)
        ip_uri_template => binary(),
        %% CONNECT-UDP handler
        handler => module(),
        %% CONNECT-TCP handler
        tcp_handler => module(),
        %% CONNECT-IP handler
        ip_handler => module(),
        handler_opts => term(),
        address_pool => ip_prefix() | [ip_prefix()],
        routes => [ip_route()],
        mtu => 1280..65535,
        resolver => fun((binary()) -> {ok, [inet:ip_address()]} | {error, term()}),
        allow => fun((target()) -> boolean()),
        %% CONNECT-TCP policy - forwarded to the tcp_handler through
        %% handler_opts. `family' picks the outbound DNS-resolved
        %% address class; `allow_private' gates non-global targets;
        %% `connect_timeout' bounds the outbound dial; `socket_opts'
        %% extend the gen_tcp options of the target socket.
        family => auto | inet | inet6,
        allow_private => boolean(),
        connect_timeout => pos_integer(),
        socket_opts => [gen_tcp:option()]
    }.

%%====================================================================
%% API
%%====================================================================

-doc """
Returns the library version as declared in the application resource file.
""".
-spec version() -> binary().
version() ->
    {ok, Vsn} = application:get_key(masque, vsn),
    list_to_binary(Vsn).

-doc """
Dial a MASQUE proxy and open a CONNECT-UDP tunnel to `Target`.

`ProxyURI` is an `https://host:port` URL identifying the proxy;
`Target` is a `{Host, Port}` pair naming the UDP endpoint to reach.
Returns `{ok, Session}` on 2xx, `{error, Reason}` otherwise.
""".
-spec connect(proxy_uri(), target(), connect_opts()) ->
    {ok, session()} | {error, term()}.
connect(ProxyURI, Target0, Opts) when is_map(Opts) ->
    case validate_connect_opts(Target0, Opts) of
        {ok, Opts0, Target} ->
            case parse_proxy_uri(ProxyURI) of
                {ok, Host, Port} ->
                    Owner = maps:get(owner, Opts0, self()),
                    Opts1 = Opts0#{proxy => {Host, Port}},
                    case normalize_transports(maps:get(transports, Opts1, [h3, h2])) of
                        {ok, Transports} ->
                            connect_via(Transports, Target, Opts1, Owner);
                        {error, _} = Err ->
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% Validate and normalize `connect_opts()`. Enforces RFC 9484
%% invariants for CONNECT-IP (capsule protocol required, target
%% shape matches protocol) and widens/normalizes shared keys.
validate_connect_opts(Target0, Opts) ->
    Protocol = maps:get(protocol, Opts, udp),
    maybe
        {ok, Target} ?= check_target_shape(Protocol, Target0),
        ok ?= check_timeout(Opts),
        {ok, Opts1} ?= check_capsule_protocol(Protocol, Opts),
        {ok, Opts2} ?= check_proxy_authorization(Opts1),
        {ok, Opts2, Target}
    end.

check_timeout(#{timeout := T}) when is_integer(T), T > 0 -> ok;
check_timeout(#{timeout := T}) -> {error, {invalid_opts, {timeout, T}}};
check_timeout(_) -> ok.

%% `proxy_authorization' is embedded verbatim on the CONNECT-TCP h1
%% wire; an embedded CR or LF would inject arbitrary headers. Reject
%% the opt before any socket is opened.
check_proxy_authorization(Opts) ->
    case maps:find(proxy_authorization, Opts) of
        error ->
            {ok, Opts};
        {ok, V} when is_binary(V) ->
            case has_crlf(V) of
                true ->
                    {error, {invalid_opts, proxy_authorization_contains_crlf}};
                false ->
                    {ok, Opts}
            end;
        {ok, _} ->
            {error, {invalid_opts, proxy_authorization_must_be_binary}}
    end.

has_crlf(B) when is_binary(B) ->
    binary:match(B, [<<"\r">>, <<"\n">>]) =/= nomatch.

check_target_shape(ip, {Target, IPProto} = T) ->
    case
        masque_uri_ip:validate_target(Target) andalso
            masque_uri_ip:validate_ipproto(IPProto)
    of
        true -> {ok, T};
        false -> {error, {bad_target_for_protocol, ip}}
    end;
check_target_shape(ip, _) ->
    {error, {bad_target_for_protocol, ip}};
check_target_shape(Proto, {Host, P}) when is_integer(P), P >= 1, P =< 65535 ->
    %% The host ends up in a path, an authority or a raw CONNECT line:
    %% only an IP address or a valid host name is accepted.
    case target_host(Host) of
        {ok, HostBin} -> {ok, {HostBin, P}};
        error -> {error, {bad_target_for_protocol, Proto}}
    end;
check_target_shape(Proto, _) ->
    {error, {bad_target_for_protocol, Proto}}.

target_host(IP) when is_tuple(IP) ->
    case inet:ntoa(IP) of
        {error, _} -> error;
        Text -> {ok, list_to_binary(Text)}
    end;
target_host(Host) when is_list(Host) ->
    try list_to_binary(Host) of
        Bin -> target_host(Bin)
    catch
        error:badarg -> error
    end;
target_host(Host) when is_binary(Host) ->
    case masque_uri:valid_host(Host) of
        true -> {ok, Host};
        false -> error
    end;
target_host(_) ->
    error.

check_capsule_protocol(ip, Opts) ->
    case maps:get(capsule_protocol, Opts, true) of
        false ->
            {error, {invalid_opts, capsule_protocol_required_for_ip}};
        _ ->
            {ok, Opts#{capsule_protocol => true}}
    end;
check_capsule_protocol(_, Opts) ->
    {ok, Opts}.

connect_via([h3], Target, Opts, Owner) ->
    dial_single_or_pool(session_mod(Opts, h3), h3, Target, Opts, Owner);
connect_via([h2], Target, Opts, Owner) ->
    dial_single_or_pool(session_mod(Opts, h2), h2, Target, Opts, Owner);
connect_via([h1], Target, Opts, Owner) ->
    dial_single(session_mod(Opts, h1), Target, Opts#{transport => h1}, Owner);
connect_via(Transports, Target, Opts, Owner) when
    length(Transports) >= 2
->
    masque_racer:race(Transports, Target, Opts, Owner).

%% Single-transport dial that honours `upstream_pool => true' the
%% same way the racer does; h1 is pool-bypassed so it keeps the
%% plain dial_single path.
%% udp-bind is never pooled: each bind needs its own connection.
dial_single_or_pool(Mod, Transport, Target, #{protocol := udp_bind} = Opts, Owner) ->
    dial_single(Mod, Target, Opts#{transport => Transport}, Owner);
dial_single_or_pool(
    Mod,
    Transport,
    Target,
    #{upstream_pool := true} = Opts,
    Owner
) when
    Transport =:= h2; Transport =:= h3
->
    case masque_racer:checkout_pool(Transport, Opts) of
        {ok, Opts1} ->
            case dial_single(Mod, Target, Opts1#{transport => Transport}, Owner) of
                {error, R} when
                    (R =:= owner_gone orelse R =:= stream_limit orelse R =:= goaway),
                    not is_map_key(pool_retried, Opts)
                ->
                    %% The pooled connection closed under us (idle
                    %% timer), hit the proxy's stream limit, or is
                    %% draining (GOAWAY): check out again, once. The
                    %% owner no longer offers itself, so the pool dials
                    %% another connection.
                    dial_single_or_pool(Mod, Transport, Target, Opts#{pool_retried => true}, Owner);
                Result ->
                    Result
            end;
        {error, _} = Err ->
            Err
    end;
dial_single_or_pool(Mod, Transport, Target, Opts, Owner) ->
    dial_single(Mod, Target, Opts#{transport => Transport}, Owner).

session_mod(Opts, h3) ->
    case maps:get(protocol, Opts, udp) of
        tcp -> masque_tcp_client_session;
        ip -> masque_ip_client_session;
        udp_bind -> masque_udp_bind_client_session;
        _ -> masque_client_session
    end;
session_mod(Opts, h2) ->
    case maps:get(protocol, Opts, udp) of
        tcp -> masque_tcp_client_session;
        ip -> masque_ip_client_session;
        udp_bind -> masque_udp_bind_client_session;
        _ -> masque_h2_client_session
    end;
session_mod(Opts, h1) ->
    case maps:get(protocol, Opts, udp) of
        udp -> masque_h1_client_session;
        ip -> masque_ip_h1_client_session;
        tcp -> masque_tcp_h1_client_session;
        udp_bind -> masque_udp_bind_h1_client_session
    end.

%% Direct (non-racing) dial via a single transport module.
%% Uses start (not start_link) + monitor so a fast session failure
%% returns {error, _} instead of crashing the caller with an EXIT.
dial_single(Mod, Target, Opts, Owner) ->
    case Mod:start(Target, Opts, Owner) of
        {ok, Pid} ->
            MRef = erlang:monitor(process, Pid),
            Timeout = maps:get(timeout, Opts, 5000),
            Result =
                try
                    gen_statem:call(
                        Pid,
                        handshake_await,
                        Timeout + 1000
                    )
                catch
                    exit:{noproc, _} -> {error, session_died};
                    exit:{normal, _} -> {error, session_died};
                    exit:{{shutdown, {masque_quiet, Why}}, _} -> {error, Why};
                    exit:{{shutdown, _}, _} -> {error, session_died};
                    exit:{timeout, _} -> {error, handshake_timeout};
                    exit:{Why, {gen_statem, call, _}} -> {error, Why};
                    exit:Other -> {error, Other}
                end,
            erlang:demonitor(MRef, [flush]),
            case Result of
                ok ->
                    {ok, Pid};
                {error, Reason} ->
                    try
                        exit(Pid, kill)
                    catch
                        _:_ -> ok
                    end,
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% An empty list means the default race. Unknown entries are refused
%% rather than dropped, and duplicates are removed (first one wins).
normalize_transports([]) ->
    {ok, [h3, h2]};
normalize_transports(L) when is_list(L) ->
    case lists:all(fun(T) -> lists:member(T, [h3, h2, h1]) end, L) of
        true -> {ok, dedup(L)};
        false -> {error, {invalid_opts, {transports, L}}}
    end;
normalize_transports(Other) ->
    {error, {invalid_opts, {transports, Other}}}.

dedup(L) ->
    lists:reverse(
        lists:foldl(
            fun(X, Acc) ->
                case lists:member(X, Acc) of
                    true -> Acc;
                    false -> [X | Acc]
                end
            end,
            [],
            L
        )
    ).

-doc "Equivalent to `connect(ProxyURI, Target, #{})`.".
-spec connect(proxy_uri(), target()) -> {ok, session()} | {error, term()}.
connect(ProxyURI, Target) ->
    connect(ProxyURI, Target, #{}).

-doc """
Close a MASQUE session.
""".
-spec close(session()) -> ok.
close(Sess) when is_pid(Sess) ->
    %% All session modules export stop/1.
    _ =
        (try
            gen_statem:call(Sess, stop, 5000)
        catch
            _:_ -> ok
        end),
    ok.

-doc """
Return a map describing the session's current state and peers.
""".
-spec info(session()) -> map().
info(Sess) when is_pid(Sess) ->
    gen_statem:call(Sess, info, 1000).

-doc """
Send data through the tunnel.

For UDP tunnels: sends a UDP packet (context-id 0). For TCP tunnels:
sends raw bytes on the stream.
""".
-spec send(session(), iodata()) -> ok | {error, term()}.
send(Sess, Data) ->
    gen_statem:call(Sess, {send, Data}).

-doc """
Send data under an explicit context-id (UDP extension use).
""".
-spec send(session(), non_neg_integer(), iodata()) ->
    ok | {error, term()}.
send(Sess, ContextId, Data) when is_integer(ContextId), ContextId >= 0 ->
    gen_statem:call(Sess, {send, ContextId, Data});
send(_Sess, _ContextId, _Data) ->
    {error, badarg}.

-doc """
Block until data is received or `Timeout` ms elapses.

Requires the session to be in `queue` delivery mode (see
`set_mode/2`). The queue holds at most `rx_queue_limit`
items (default 1000): datagram tunnels drop past it (counted as
`rx_dropped` in `info/1`), a CONNECT-TCP tunnel ends with
`rx_overflow`. After the peer ends the tunnel, data still queued
is returned first, then `{error, closed}` (or `{error,
rx_overflow}`).
""".
-spec recv(session(), pos_integer()) ->
    {ok, binary()} | {error, timeout | term()}.
recv(Sess, Timeout) ->
    try
        gen_statem:call(Sess, {recv, Timeout}, Timeout + 500)
    catch
        exit:{noproc, _} -> {error, closed};
        exit:{normal, _} -> {error, closed};
        exit:{shutdown, _} -> {error, closed};
        exit:{{shutdown, _}, _} -> {error, closed}
    end.

-doc """
Send a capsule on the tunnel's request stream (RFC 9297 §3.2).
""".
-spec send_capsule(session(), non_neg_integer(), iodata()) ->
    ok | {error, term()}.
send_capsule(Sess, Type, Value) when is_integer(Type), Type >= 0 ->
    gen_statem:call(Sess, {send_capsule, Type, Value});
send_capsule(_Sess, _Type, _Value) ->
    {error, badarg}.

-doc """
Switch the session between `message` and `queue` delivery modes.

`message` (default) delivers every incoming packet to the owner as
`{masque_data, Sess, Data}`. `queue` buffers packets and requires
the caller to pull them via `recv/2`.
""".
-spec set_mode(session(), message | queue) -> ok | {error, badarg}.
set_mode(Sess, Mode) when Mode =:= message; Mode =:= queue ->
    gen_statem:call(Sess, {set_mode, Mode});
set_mode(_Sess, _Mode) ->
    {error, badarg}.

-doc """
Half-close the write side of a TCP tunnel.

Sends END_STREAM and prevents further writes. The session stays
open for receiving data. Returns `{error, not_supported}` on UDP
sessions. Returns `{error, not_ready}` if still connecting.
""".
-spec shutdown_write(session()) -> ok | {error, term()}.
shutdown_write(Sess) when is_pid(Sess) ->
    gen_statem:call(Sess, shutdown_write).

-doc """
Move the tunnel's QUIC connection to a new local UDP port under a new
connection id. Call it when the network changes, so the proxy sees the
client on its new address and open tunnels carry on.

HTTP/3 only: other transports return `{error, not_supported}`, and a
tunnel on a shared pool connection returns `{error, pooled}`.
`{error, no_available_connection_id}` means the proxy has not issued a
spare connection id yet; the first arrives just after the handshake, so
try again shortly. `{error, handshake_not_confirmed}` means the handshake
is not confirmed yet; try again shortly too. `ok` means the move has started, not that the new
path is validated.
""".
-spec migrate(session()) -> ok | {error, term()}.
migrate(Sess) when is_pid(Sess) ->
    gen_statem:call(Sess, migrate).

%%====================================================================
%% Reverse connect (draft-rosomakho-masque-reverse-connect-01)
%%====================================================================

-doc """
Open a reverse connect control channel to a proxy, so it can ask you to
accept inbound connections.

`Scope` says which connections you take: `Target` is `local` (your own
services, `.` on the wire), `'*'`, a host name, `{wildcard, Domain}`, an
address or a `{4 | 6, Address, PrefixLen}` prefix; `IpProto` is `tcp`,
`udp` or `'*'`.

The owner (`owner`, default the caller) gets
`{masque_connection_request, Listen, Id, Service}` for each request and
answers with `reverse_accept/2,3` or `reverse_decline/2`. It gets
`{masque_closed, Listen, Reason}` if the channel ends from the proxy
side. Close it with `masque:close/1`.

Options are those of `connect/3` with one transport in `transports`
(default `[h3]`), plus `listen_uri_template` and `accept_uri_template`
(the draft's defaults otherwise). Pass your credentials in
`request_headers`. On HTTP/3 and HTTP/2 the channel gets a connection
of its own, which its accept streams share.
""".
-spec reverse_listen(
    binary() | string(), {reverse_target(), reverse_ipproto()}, map()
) ->
    {ok, pid()} | {error, term()}.
reverse_listen(ProxyURI, {Target, IpProto}, Opts) when is_map(Opts) ->
    maybe
        {ok, Host, Port} ?= parse_proxy_uri(ProxyURI),
        {ok, Transport} ?= listen_transport(maps:get(transports, Opts, [h3])),
        {ok, Template} ?=
            masque_uri_reverse:parse_listen_template(
                maps:get(listen_uri_template, Opts, ?MASQUE_DEFAULT_LISTEN_URI_TEMPLATE)
            ),
        Path = masque_uri_reverse:expand_listen(Template, #{target => Target, ipproto => IpProto}),
        Owner = maps:get(owner, Opts, self()),
        SessOpts = Opts#{proxy => {Host, Port}, transport => Transport, listen_path => Path},
        case Transport of
            h1 -> masque_listen_h1_client_session:start(SessOpts, Owner);
            _ -> masque_listen_client_session:start(SessOpts, Owner)
        end
    end.

listen_transport([T]) when T =:= h3; T =:= h2; T =:= h1 -> {ok, T};
listen_transport(Other) -> {error, {invalid_opts, {transports, Other}}}.

-doc "Equivalent to `reverse_accept(Listen, Id, #{})`.".
-spec reverse_accept(pid(), non_neg_integer()) -> {ok, session()} | {error, term()}.
reverse_accept(Listen, Id) ->
    reverse_accept(Listen, Id, #{}).

-doc """
Accept a connection request: open the accept stream for request `Id`.

The result is a tunnel to the service the request named: for a TCP
service it behaves like a CONNECT-TCP one (`{masque_data, Stream,
Bytes}`, `send/2`, `shutdown_write/1`, `close/1`), for a UDP service like
a CONNECT-UDP one (one datagram per message and per `send/2`). Connect it
to the service; if that fails, close the stream, as the draft asks.
`Opts` are merged over the channel's options (`owner`, `mode`,
`timeout`...).
""".
-spec reverse_accept(pid(), non_neg_integer(), map()) -> {ok, session()} | {error, term()}.
reverse_accept(Listen, Id, Opts) when is_map(Opts) ->
    case call_listen(Listen, {accept_spec, Id}) of
        {ok, #{service := Service, transport := T, opts := ListenOpts} = Spec} ->
            AcceptOpts0 = maps:merge(maps:without([owner, listen_path], ListenOpts), Opts),
            AcceptOpts1 = maps:merge(
                AcceptOpts0#{
                    transport => T,
                    uri_template => maps:get(accept_uri_template, Spec),
                    uri_vars => #{request_id => integer_to_binary(Id)}
                },
                accept_protocol(Service)
            ),
            AcceptOpts =
                case Spec of
                    #{pool_owner := Up} -> AcceptOpts1#{pool_owner => Up};
                    _ -> AcceptOpts1
                end,
            Owner = maps:get(owner, Opts, self()),
            dial_single(session_mod(AcceptOpts, T), service_target(Service), AcceptOpts, Owner);
        {error, _} = Err ->
            Err
    end.

%% Section 5.3: TCP in connect-tcp capsules, UDP like CONNECT-UDP, both
%% under the `connect-accept' token.
accept_protocol(#{protocol := tcp}) ->
    #{
        protocol => tcp,
        tcp_framing => capsule,
        tcp_protocol => ?MASQUE_CONNECT_ACCEPT_PROTOCOL
    };
accept_protocol(#{protocol := udp}) ->
    #{
        protocol => udp,
        protocol_token => ?MASQUE_CONNECT_ACCEPT_PROTOCOL,
        capsule_protocol => true
    }.

%% A target for `info/1'; the stream itself is addressed by its id.
service_target(#{destination := local, port := Port}) -> {<<"localhost">>, Port};
service_target(#{destination := Host, port := Port}) when is_binary(Host) -> {Host, Port};
service_target(#{destination := IP, port := Port}) -> {list_to_binary(inet:ntoa(IP)), Port}.

-doc "Decline a connection request (CONNECTION_REQUEST_DECLINED).".
-spec reverse_decline(pid(), non_neg_integer()) -> ok | {error, term()}.
reverse_decline(Listen, Id) ->
    call_listen(Listen, {decline, Id}).

-doc """
Tell the proxy which services you offer (AVAILABLE_SERVICES). Each call
replaces the previous list; it is a hint, not a restriction.
""".
-spec advertise_services(pid(), [reverse_service()]) -> ok | {error, term()}.
advertise_services(Listen, Services) when is_list(Services) ->
    call_listen(Listen, {advertise, Services}).

call_listen(Listen, Request) ->
    try
        gen_server:call(Listen, Request, 35000)
    catch
        exit:{noproc, _} -> {error, closed};
        exit:{normal, _} -> {error, closed};
        exit:{{shutdown, _}, _} -> {error, closed};
        exit:{_, {gen_server, call, _}} -> {error, closed}
    end.

-doc "Equivalent to `request_connection(Control, Service, #{})`.".
-spec request_connection(pid(), reverse_service()) ->
    {ok, pid()} | {error, declined | timeout | closed}.
request_connection(Control, Service) ->
    request_connection(Control, Service, #{}).

-doc """
Proxy side: ask the client of a control channel to accept a connection
to `Service` (CONNECTION_REQUEST), and wait for its accept stream.

`Control` is the control session: `self()` inside the `listen_handler`
callbacks. Returns `{ok, Stream}` once the client opened the stream,
`{error, declined}`, `{error, timeout}` after `timeout` ms (default
10000), or `{error, closed}` if the channel ended. The caller owns the
stream: it gets `{masque_data, Stream, Bytes}` and
`{masque_closed, Stream, Reason}`, writes with `send/2`, half-closes with
`shutdown_write/1`, closes with `close/1`, and returns receive credit
with `consumed/2`.
""".
-spec request_connection(pid(), reverse_service(), map()) ->
    {ok, pid()} | {error, declined | timeout | closed}.
request_connection(Control, Service, Opts) when is_map(Opts) ->
    Timeout = maps:get(timeout, Opts, 10000),
    try
        gen_server:call(Control, {request_connection, Service, Timeout}, Timeout + 5000)
    catch
        exit:{_, {gen_server, call, _}} -> {error, closed}
    end.

-doc """
Proxy side: give back receive credit for `N` bytes of an accept stream,
once you have passed them on. A stream whose bytes are not consumed
stops the client from sending. On a stream that already ended it does
nothing.
""".
-spec consumed(pid(), non_neg_integer()) -> ok | {error, term()}.
consumed(Stream, N) when is_integer(N), N >= 0 ->
    try
        gen_server:call(Stream, {consumed, N})
    catch
        %% The stream ended: there is no credit left to return.
        exit:{_, {gen_server, call, _}} -> ok
    end.

%%====================================================================
%% CONNECT-IP client API (RFC 9484)
%%====================================================================

-doc """
Send a full IP packet (starting at the IP header) through a
CONNECT-IP tunnel. Rejects packets larger than the session's MTU.
""".
-spec send_ip_packet(session(), binary()) -> ok | {error, term()}.
send_ip_packet(Sess, Packet) when is_pid(Sess), is_binary(Packet) ->
    masque_ip_client_session:send_ip_packet(Sess, Packet).

-doc """
Send an ADDRESS_REQUEST capsule asking the peer to assign
one or more addresses. Returns the allocated Request IDs.
""".
-spec request_addresses(
    session(),
    [{ip_version(), inet:ip_address(), non_neg_integer()}]
) ->
    {ok, [nz_request_id()]} | {error, term()}.
request_addresses(Sess, Prefixes) when is_pid(Sess) ->
    masque_ip_client_session:request_addresses(Sess, Prefixes).

-doc """
Send an ADDRESS_ASSIGN capsule. Non-zero Request IDs must
match an outstanding peer ADDRESS_REQUEST; ID 0 is always
accepted (unprompted, RFC 9484 §4.7.1).
""".
-spec assign_addresses(session(), [ip_assignment()]) ->
    ok | {error, term()}.
assign_addresses(Sess, Entries) when is_pid(Sess) ->
    masque_ip_client_session:assign_addresses(Sess, Entries).

-doc """
Send a ROUTE_ADVERTISEMENT capsule.
""".
-spec advertise_routes(session(), [ip_route()]) -> ok | {error, term()}.
advertise_routes(Sess, Routes) when is_pid(Sess) ->
    masque_ip_client_session:advertise_routes(Sess, Routes).

-doc """
Inspect the CONNECT-IP session state.
""".
-spec ip_info(session()) ->
    #{
        assigned := [ip_assignment()],
        routes := [ip_route()],
        mtu := 1280..65535,
        transport := transport()
    }.
ip_info(Sess) when is_pid(Sess) ->
    masque_ip_client_session:ip_info(Sess).

%%====================================================================
%% Connect-UDP-Bind client API
%% (draft-ietf-masque-connect-udp-listen-16)
%%====================================================================

-doc """
Open a Connect-UDP-Bind tunnel to `ProxyURI`. `Target` is
either `unscoped` (the bind socket on the proxy can talk to any
peer the proxy's policy allows) or `{Host, Port}` for a scoped
bind. The session emits `{masque_bind_packet, _, Peer, Bytes}`
messages to the owner; use `send_to/3` to send.
""".
-spec bind_connect(
    proxy_uri(),
    unscoped | {binary() | inet:hostname(), 1..65535},
    connect_opts()
) -> {ok, session()} | {error, term()}.
bind_connect(ProxyURI, Target0, Opts) when is_map(Opts) ->
    Opts1 = Opts#{protocol => udp_bind},
    maybe
        {ok, Target} ?= bind_target(Target0),
        ok ?= check_timeout(Opts1),
        {ok, Host, Port} ?= parse_proxy_uri(ProxyURI),
        Owner = maps:get(owner, Opts1, self()),
        Opts2 = Opts1#{proxy => {Host, Port}},
        {ok, Transports} ?= normalize_transports(maps:get(transports, Opts2, [h3, h2])),
        connect_via(Transports, Target, Opts2, Owner)
    end.

bind_target(unscoped) -> {ok, unscoped};
bind_target(Target) -> check_target_shape(udp_bind, Target).

-doc """
Send a UDP payload to `Peer` via the bind tunnel. The session
picks a context-id from the compression table; if none exists it
falls back to the uncompressed-context channel if open, otherwise
returns `{error, no_compression_context}`.
""".
-spec send_to(
    session(),
    {inet:ip_address(), inet:port_number()},
    binary()
) -> ok | {error, term()}.
send_to(Sess, {IP, Port} = Peer, Bytes) when
    is_pid(Sess),
    is_binary(Bytes),
    (tuple_size(IP) =:= 4 orelse tuple_size(IP) =:= 8),
    is_integer(Port),
    Port >= 1,
    Port =< 65535
->
    Mod = bind_session_module(Sess),
    Mod:send_to(Sess, Peer, Bytes);
send_to(_Sess, _Peer, _Bytes) ->
    {error, badarg}.

-doc """
Open an outbound compressed context for `Peer`. Returns the
allocated Context ID; the mapping is safe to use on send once the
matching `{masque_compression_acked, _, ContextId}` message
arrives.
""".
-spec assign_compression(
    session(),
    {inet:ip_address(), inet:port_number()}
) ->
    {ok, pos_integer()} | {error, term()}.
assign_compression(Sess, Peer) when is_pid(Sess) ->
    Mod = bind_session_module(Sess),
    Mod:assign_compression(Sess, Peer).

-doc """
Open the singleton uncompressed (IP Version 0) context.
Client-only per draft-16.
""".
-spec open_uncompressed_context(session()) ->
    {ok, pos_integer()} | {error, term()}.
open_uncompressed_context(Sess) when is_pid(Sess) ->
    Mod = bind_session_module(Sess),
    Mod:open_uncompressed_context(Sess).

-doc """
Retire a compression context.
""".
-spec close_compression(session(), pos_integer()) ->
    ok | {error, term()}.
close_compression(Sess, Id) when
    is_pid(Sess), is_integer(Id), Id > 0
->
    Mod = bind_session_module(Sess),
    Mod:close_compression(Sess, Id).

-doc """
Read the parsed `Proxy-Public-Address` list the proxy
advertised on the bind 2xx response.
""".
-spec proxy_public_address(session()) ->
    {ok, [{inet:ip_address(), inet:port_number()}]} | {error, term()}.
proxy_public_address(Sess) when is_pid(Sess) ->
    Mod = bind_session_module(Sess),
    Mod:proxy_public_address(Sess).

%% Pick the right bind client module based on the session's
%% transport. We can't do this from the pid alone without asking it,
%% so we fall through to the h2/h3 module which handles both. The h1
%% module accepts the same calls so dispatch via either is fine, but
%% we route by querying `info/1' to be precise.
bind_session_module(Sess) ->
    try gen_statem:call(Sess, info, 1000) of
        #{transport := h1} -> masque_udp_bind_h1_client_session;
        _ -> masque_udp_bind_client_session
    catch
        _:_ -> masque_udp_bind_client_session
    end.

%%====================================================================
%% Server facade
%%====================================================================

-spec start_listener(atom(), listener_opts()) -> {ok, pid()} | {error, term()}.
start_listener(Name, Opts) ->
    masque_server:start_listener(Name, Opts).

-spec stop_listener(atom()) -> ok | {error, term()}.
stop_listener(Name) ->
    masque_server:stop_listener(Name).

-spec start_listener_h2(atom(), map()) ->
    {ok, h2:server_ref()} | {error, term()}.
start_listener_h2(Name, Opts) ->
    masque_h2_server:start_listener(Name, Opts).

-spec stop_listener_h2(h2:server_ref() | atom()) -> ok | {error, term()}.
stop_listener_h2(Ref) ->
    masque_h2_server:stop_listener(Ref).

-spec start_listener_h1(atom(), map()) ->
    {ok, h1:server_ref()} | {error, term()}.
start_listener_h1(Name, Opts) ->
    masque_h1_server:start_listener(Name, Opts).

-spec stop_listener_h1(h1:server_ref() | atom()) -> ok | {error, term()}.
stop_listener_h1(Ref) ->
    masque_h1_server:stop_listener(Ref).

-doc """
Stop accepting new tunnels but let existing ones finish.
""".
-spec drain_listener(atom()) -> ok.
drain_listener(Name) ->
    persistent_term:put({masque_drain, Name}, true),
    ok.

-doc """
Re-enable new tunnels after draining.
""".
-spec undrain_listener(atom()) -> ok.
undrain_listener(Name) ->
    persistent_term:erase({masque_drain, Name}),
    ok.

-doc """
Check if a listener is draining.
""".
-spec is_draining(atom() | undefined) -> boolean().
is_draining(undefined) -> false;
is_draining(Name) -> persistent_term:get({masque_drain, Name}, false).

-doc """
Start a chaining (two-hop) listener on HTTP/3.

Convenience wrapper: starts an h3 listener with
`masque_chain_handler` wired up for all three tunnel protocols
(UDP, TCP, IP). Every accepted tunnel is relayed to the upstream
proxy specified in `handler_opts.upstream_proxy`.

Callers that want only a subset of protocols to chain can still
call `start_listener/2` directly and set `handler`,
`tcp_handler`, `ip_handler` individually.

See `start_chain_listener_h2/2` and
`start_chain_listener_h1/2` for the HTTP/2 and HTTP/1.1
siblings. A full Apple-Private-Relay-shaped ingress runs all three
so the client can race them.
""".
-spec start_chain_listener(atom(), map()) -> {ok, pid()} | {error, term()}.
start_chain_listener(Name, Opts) ->
    start_listener(Name, chain_all(Opts)).

-doc """
Start a chaining (two-hop) listener on HTTP/2.

Same shape as `start_chain_listener/2`; only the outer
transport differs. All three tunnel protocols chain; upstream
proxy URI goes in `handler_opts.upstream_proxy`.
""".
-spec start_chain_listener_h2(atom(), map()) ->
    {ok, h2:server_ref()} | {error, term()}.
start_chain_listener_h2(Name, Opts) ->
    start_listener_h2(Name, chain_all(Opts)).

-doc """
Start a chaining (two-hop) listener on HTTP/1.1.

Same shape as `start_chain_listener/2`; only the outer
transport differs. All three tunnel protocols chain; upstream
proxy URI goes in `handler_opts.upstream_proxy`.
""".
-spec start_chain_listener_h1(atom(), map()) ->
    {ok, h1:server_ref()} | {error, term()}.
start_chain_listener_h1(Name, Opts) ->
    start_listener_h1(Name, chain_all(Opts)).

chain_all(Opts) ->
    HOpts =
        case maps:get(handler_opts, Opts, #{}) of
            #{via_token := _} = H -> H;
            H when is_map(H) -> H#{via_token => masque_chain_handler:new_token()};
            H -> H
        end,
    Opts#{
        handler_opts => HOpts,
        handler => masque_chain_handler,
        tcp_handler => masque_chain_handler,
        ip_handler => masque_chain_handler
    }.

-spec h2_handlers(map()) ->
    #{
        handler := fun(
            (
                pid(),
                non_neg_integer(),
                binary(),
                binary(),
                list()
            ) -> any()
        )
    }.
h2_handlers(Opts) ->
    masque_h2_server:h2_handlers(Opts).

-doc """
Return the `handler` and `connection_handler` funs needed to
run MASQUE inside a user-owned `quic_h3:start_server/3` call.

`Opts` takes the listener options of `start_listener/2` that shape
request handling (templates, handlers, `handler_opts`, `accept_bind`,
`resolver`), plus `fallback`:
`fun(Conn, StreamId, Method, Path, Headers) -> any()`, called for
requests that are not MASQUE. Without it those requests are rejected.

MASQUE must be the h3 connection's owner (HTTP Datagrams are delivered
to that pid), so the returned `connection_handler` takes the owner
slot. Another extension that also needs it cannot share the connection;
run it on a separate listener.
""".
-spec h3_handlers(map()) ->
    #{
        handler := h3_handler_fun(),
        connection_handler := connection_handler_fun()
    }.
h3_handlers(Opts) ->
    masque_server:h3_handlers(Opts).

%%====================================================================
%% Internal
%%====================================================================

parse_proxy_uri(URI) when is_binary(URI) ->
    parse_proxy_uri(binary_to_list(URI));
parse_proxy_uri(URI) when is_list(URI) ->
    case uri_string:parse(URI) of
        #{scheme := "https", host := Host, port := Port} when
            is_integer(Port)
        ->
            {ok, list_to_binary(Host), Port};
        #{scheme := "https", host := Host} ->
            {ok, list_to_binary(Host), 443};
        _ ->
            {error, {invalid_proxy_uri, URI}}
    end.
