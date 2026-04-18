%%% @doc Public API for the `masque' library.
%%%
%%% `masque' implements RFC 9298 (Proxying UDP in HTTP) on top of
%%% `erlang_quic's HTTP/3 stack. The functions in this module are the
%%% stable surface used by applications; all other modules are internal
%%% and may change between versions.
%%%
%%% The surface is filled in incrementally across the implementation
%%% plan. Step 1 only exposes the module so the application compiles
%%% and is loadable; the behavioural functions are added in later steps.
-module(masque).

-export([version/0]).
-export([connect/3, connect/2, close/1, info/1]).
-export([send/2, send/3, recv/2, set_mode/2]).
-export([send_capsule/3, shutdown_write/1]).
-export([start_listener/2, stop_listener/1]).
-export([start_listener_h2/2, stop_listener_h2/1]).
-export([start_chain_listener/2]).
-export([h3_handlers/1, h2_handlers/1]).

-include("masque.hrl").

-export_type([
    session/0,
    proxy_uri/0,
    target/0,
    transport/0,
    connect_opts/0,
    listener_opts/0
]).

%%====================================================================
%% Types
%%====================================================================

-type session() :: pid().

-type proxy_uri() :: binary() | string().

%% A UDP target - either a resolved IP or a host name to resolve, and a port.
-type target() :: {binary() | inet:hostname() | inet:ip_address(), inet:port_number()}.

-type transport() :: h3 | h2.

-type connect_opts() ::
    #{
        %% Tunnel protocol: `udp' (default) or `tcp'.
        protocol => udp | tcp,
        %% Transport preference. `[h3, h2]' (default) races the two.
        transports => [transport()],
        prefer_timeout_ms => non_neg_integer(),
        uri_template => binary(),
        verify => verify_peer | verify_none,
        cacerts => [public_key:der_encoded()],
        timeout => pos_integer() | infinity,
        capsule_protocol => boolean(),
        owner => pid(),
        ssl_opts => [ssl:tls_client_option()],
        %% Internal - set by racer, not by callers.
        transport => transport(),
        proxy => {binary(), inet:port_number()},
        alpn => [binary()],
        mode => message | queue
    }.

-type listener_opts() ::
    #{
        port := inet:port_number(),
        certfile := file:filename(),
        keyfile := file:filename(),
        uri_template => binary(),
        handler => module(),
        handler_opts => term(),
        allow => fun((target()) -> boolean()),
        resolver => fun((inet:hostname()) ->
                            {ok, inet:ip_address()} | {error, term()})
    }.

%%====================================================================
%% API
%%====================================================================

%% @doc Returns the library version as declared in the application resource file.
-spec version() -> binary().
version() ->
    {ok, Vsn} = application:get_key(masque, vsn),
    list_to_binary(Vsn).

%% @doc Dial a MASQUE proxy and open a CONNECT-UDP tunnel to `Target'.
%%
%% `ProxyURI' is an `https://host:port' URL identifying the proxy;
%% `Target' is a `{Host, Port}' pair naming the UDP endpoint to reach.
%% Returns `{ok, Session}' on 2xx, `{error, Reason}' otherwise.
-spec connect(proxy_uri(), target(), connect_opts()) ->
    {ok, session()} | {error, term()}.
connect(ProxyURI, Target, Opts) when is_map(Opts) ->
    case parse_proxy_uri(ProxyURI) of
        {ok, Host, Port} ->
            Owner = maps:get(owner, Opts, self()),
            Opts1 = Opts#{proxy => {Host, Port}},
            Transports = normalize_transports(
                           maps:get(transports, Opts, [h3, h2])),
            connect_via(Transports, Target, Opts1, Owner);
        {error, _} = Err ->
            Err
    end.

connect_via([h3], Target, Opts, Owner) ->
    dial_single(session_mod(Opts, h3), Target, Opts#{transport => h3}, Owner);
connect_via([h2], Target, Opts, Owner) ->
    dial_single(session_mod(Opts, h2), Target, Opts#{transport => h2}, Owner);
connect_via(Transports, Target, Opts, Owner)
  when length(Transports) >= 2 ->
    masque_racer:race(Transports, Target, Opts, Owner).

session_mod(Opts, h3) ->
    case maps:get(protocol, Opts, udp) of
        tcp -> masque_tcp_client_session;
        _   -> masque_client_session
    end;
session_mod(Opts, h2) ->
    case maps:get(protocol, Opts, udp) of
        tcp -> masque_tcp_client_session;
        _   -> masque_h2_client_session
    end.

%% Direct (non-racing) dial via a single transport module.
%% Uses start (not start_link) + monitor so a fast session failure
%% returns {error, _} instead of crashing the caller with an EXIT.
dial_single(Mod, Target, Opts, Owner) ->
    case Mod:start(Target, Opts, Owner) of
        {ok, Pid} ->
            MRef = erlang:monitor(process, Pid),
            Timeout = maps:get(timeout, Opts, 5000),
            Result = try gen_statem:call(Pid, handshake_await,
                                        Timeout + 1000)
                     catch
                         exit:{noproc, _}      -> {error, session_died};
                         exit:{normal, _}      -> {error, session_died};
                         exit:{{shutdown,_}, _} -> {error, session_died}
                     end,
            erlang:demonitor(MRef, [flush]),
            case Result of
                ok ->
                    {ok, Pid};
                {error, Reason} ->
                    catch exit(Pid, kill),
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

normalize_transports([]) -> [h3, h2];
normalize_transports(L) when is_list(L) ->
    [T || T <- L, T =:= h3 orelse T =:= h2].

%% @equiv connect(ProxyURI, Target, #{})
-spec connect(proxy_uri(), target()) -> {ok, session()} | {error, term()}.
connect(ProxyURI, Target) ->
    connect(ProxyURI, Target, #{}).

%% @doc Close a MASQUE session.
-spec close(session()) -> ok.
close(Sess) when is_pid(Sess) ->
    %% All session modules export stop/1.
    _ = (catch gen_statem:call(Sess, stop, 5000)),
    ok.

%% @doc Return a map describing the session's current state and peers.
-spec info(session()) -> map().
info(Sess) when is_pid(Sess) ->
    gen_statem:call(Sess, info, 1000).

%% @doc Send data through the tunnel.
%%
%% For UDP tunnels: sends a UDP packet (context-id 0). For TCP tunnels:
%% sends raw bytes on the stream.
-spec send(session(), iodata()) -> ok | {error, term()}.
send(Sess, Data) ->
    gen_statem:call(Sess, {send, Data}).

%% @doc Send data under an explicit context-id (UDP extension use).
-spec send(session(), non_neg_integer(), iodata()) ->
    ok | {error, term()}.
send(Sess, ContextId, Data) ->
    gen_statem:call(Sess, {send, ContextId, Data}).

%% @doc Block until data is received or `Timeout' ms elapses.
%%
%% Requires the session to be in `queue' delivery mode (see
%% {@link set_mode/2}).
-spec recv(session(), pos_integer()) ->
    {ok, binary()} | {error, timeout | term()}.
recv(Sess, Timeout) ->
    gen_statem:call(Sess, {recv, Timeout}, Timeout + 500).

%% @doc Send a capsule on the tunnel's request stream (RFC 9297 §3.2).
-spec send_capsule(session(), non_neg_integer(), iodata()) ->
    ok | {error, term()}.
send_capsule(Sess, Type, Value) ->
    gen_statem:call(Sess, {send_capsule, Type, Value}).

%% @doc Switch the session between `message' and `queue' delivery modes.
%%
%% `message' (default) delivers every incoming packet to the owner as
%% `{masque_data, Sess, Data}'. `queue' buffers packets and requires
%% the caller to pull them via {@link recv/2}.
-spec set_mode(session(), message | queue) -> ok.
set_mode(Sess, Mode) ->
    gen_statem:call(Sess, {set_mode, Mode}).

%% @doc Half-close the write side of a TCP tunnel.
%%
%% Sends END_STREAM and prevents further writes. The session stays
%% open for receiving data. Returns `{error, not_supported}' on UDP
%% sessions. Returns `{error, not_ready}' if still connecting.
-spec shutdown_write(session()) -> ok | {error, term()}.
shutdown_write(Sess) when is_pid(Sess) ->
    gen_statem:call(Sess, shutdown_write).

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

-spec stop_listener_h2(h2:server_ref()) -> ok | {error, term()}.
stop_listener_h2(Ref) ->
    masque_h2_server:stop_listener(Ref).

%% @doc Start a chaining (two-hop) listener.
%%
%% Convenience wrapper: starts an h3 listener with
%% `masque_chain_handler' as the handler module. Every accepted
%% tunnel is relayed to the upstream proxy specified in
%% `handler_opts.upstream_proxy'.
-spec start_chain_listener(atom(), map()) -> {ok, pid()} | {error, term()}.
start_chain_listener(Name, Opts) ->
    start_listener(Name, Opts#{handler => masque_chain_handler}).

-spec h2_handlers(map()) ->
    #{handler := fun((pid(), non_neg_integer(), binary(), binary(),
                      list()) -> any())}.
h2_handlers(Opts) ->
    masque_h2_server:h2_handlers(Opts).

%% @doc Return the `handler' and `connection_handler' funs needed to
%% run MASQUE inside a user-owned `quic_h3:start_server/3' call.
%%
%% See {@link masque_server:h3_handlers/1} for the accepted option
%% keys (including the `fallback' hook that routes non-MASQUE requests
%% to the caller's own handler).
-spec h3_handlers(map()) ->
    #{handler := masque_server:h3_handler_fun(),
      connection_handler := masque_server:connection_handler_fun()}.
h3_handlers(Opts) ->
    masque_server:h3_handlers(Opts).

%%====================================================================
%% Internal
%%====================================================================

parse_proxy_uri(URI) when is_binary(URI) ->
    parse_proxy_uri(binary_to_list(URI));
parse_proxy_uri(URI) when is_list(URI) ->
    case uri_string:parse(URI) of
        #{scheme := "https", host := Host, port := Port}
          when is_integer(Port) ->
            {ok, list_to_binary(Host), Port};
        #{scheme := "https", host := Host} ->
            {ok, list_to_binary(Host), 443};
        _ ->
            {error, {invalid_proxy_uri, URI}}
    end.
