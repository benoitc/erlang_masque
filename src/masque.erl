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
-export([send_packet/2, send_packet/3, recv_packet/2, set_active/2]).
-export([send_capsule/3]).
-export([start_listener/2, stop_listener/1]).
-export([start_listener_h2/2, stop_listener_h2/1]).
-export([h3_handlers/1, h2_handlers/1]).

-include("masque.hrl").

-export_type([
    session/0,
    proxy_uri/0,
    target/0,
    connect_opts/0,
    listener_opts/0
]).

%%====================================================================
%% Types
%%====================================================================

-type session() :: pid().

-type proxy_uri() :: binary() | string().

%% A UDP target - either a resolved IP or a host name to resolve, and a port.
-type target() :: {inet:hostname() | inet:ip_address(), inet:port_number()}.

-type transport() :: h3 | h2.

-type connect_opts() ::
    #{
        %% Transport preference. `[h3, h2]' (default) races the two,
        %% giving h3 a `prefer_timeout_ms' head start; `[h3]' or
        %% `[h2]' uses only that transport.
        transports => [transport()],
        prefer_timeout_ms => non_neg_integer(),
        uri_template => binary(),
        verify => verify_peer | verify_none,
        cacerts => [public_key:der_encoded()],
        timeout => pos_integer() | infinity,
        capsule_protocol => boolean(),
        active => true | false | once | pos_integer(),
        owner => pid(),
        ssl_opts => [ssl:tls_client_option()]
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
    dial_single(masque_client_session, Target, Opts, Owner);
connect_via([h2], Target, Opts, Owner) ->
    dial_single(masque_h2_client_session, Target, Opts, Owner);
connect_via(Transports, Target, Opts, Owner)
  when length(Transports) >= 2 ->
    masque_racer:race(Transports, Target, Opts, Owner).

%% Direct (non-racing) dial via a single transport module.
dial_single(Mod, Target, Opts, Owner) ->
    case Mod:start_link(Target, Opts, Owner) of
        {ok, Pid} ->
            Timeout = maps:get(timeout, Opts, 5000),
            case gen_statem:call(Pid, handshake_await, Timeout + 1000) of
                ok ->
                    {ok, Pid};
                {error, Reason} ->
                    catch unlink(Pid),
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

%% @doc Close a MASQUE session and its underlying HTTP/3 connection.
-spec close(session()) -> ok.
close(Sess) when is_pid(Sess) ->
    _ = catch masque_client_session:stop(Sess),
    ok.

%% @doc Return a map describing the session's current state and peers.
-spec info(session()) -> map().
info(Sess) when is_pid(Sess) ->
    masque_client_session:info(Sess).

%% @doc Send a UDP packet through the tunnel (context-id 0).
-spec send_packet(session(), iodata()) -> ok | {error, term()}.
send_packet(Sess, Data) ->
    masque_client_session:send_packet(Sess, Data).

%% @doc Send a packet under an explicit context-id (extension use).
-spec send_packet(session(), non_neg_integer(), iodata()) ->
    ok | {error, term()}.
send_packet(Sess, ContextId, Data) ->
    masque_client_session:send_packet(Sess, ContextId, Data).

%% @doc Block until a UDP packet is received or `Timeout' ms elapses.
%%
%% Requires the session to be in `queue' delivery mode (see
%% {@link set_active/2}).
-spec recv_packet(session(), pos_integer()) ->
    {ok, binary()} | {error, timeout | term()}.
recv_packet(Sess, Timeout) ->
    masque_client_session:recv_packet(Sess, Timeout).

%% @doc Send a capsule on the tunnel's request stream (RFC 9297 §3.2).
%%
%% Capsules are reliably framed; unknown types travel through unchanged.
%% Incoming capsules are delivered to the owner as
%% `{masque_capsule, Sess, Type, Value}' messages.
-spec send_capsule(session(), non_neg_integer(), iodata()) ->
    ok | {error, term()}.
send_capsule(Sess, Type, Value) ->
    masque_client_session:send_capsule(Sess, Type, Value).

%% @doc Switch the session between `message' and `queue' delivery modes.
%%
%% `message' (default) delivers every incoming packet to the owner as
%% `{masque_packet, Sess, Data}'. `queue' buffers packets and requires
%% the caller to pull them via {@link recv_packet/2}.
-spec set_active(session(), message | queue) -> ok.
set_active(Sess, Mode) ->
    masque_client_session:set_active(Sess, Mode).

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
