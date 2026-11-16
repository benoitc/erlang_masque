-module(masque_listener_auth).
-moduledoc false.

%%% Who may use a listener.
%%%
%%% The built-in handlers relay to any public host a client names; only
%%% private, loopback and the proxy's own addresses are refused. A
%%% listener reachable from the Internet with them and no authentication
%%% is an open relay. So a listener that uses a built-in relaying handler
%%% starts only when one of these holds:
%%%
%%% - it has an `authenticate' fun, called for every tunnel request
%%%   (CONNECT-UDP, CONNECT-TCP, CONNECT-IP, Connect-UDP-Bind) before the
%%%   handler's `accept/1';
%%% - it is bound to a loopback address (`ip');
%%% - it sets `public_relay => true', saying so on purpose (or the
%%%   application env `public_relay' is `true', for a node that relays
%%%   on purpose; the listener option wins).
%%%
%%% Listeners whose handlers are the application's own are not checked:
%%% those handlers carry the policy. Reverse connect requests have their
%%% own `listen_handler:authenticate/1'.

-export([check_start/1, resolve/4]).

-define(RELAYING_HANDLERS, [
    masque_udp_proxy_handler,
    masque_tcp_proxy_handler,
    masque_ip_proxy_handler,
    masque_udp_bind_proxy_handler,
    masque_chain_handler
]).

%% `Opts' are the listener options after defaults.
-spec check_start(map()) -> ok | {error, term()}.
check_start(Opts) ->
    case maps:get(authenticate, Opts, undefined) of
        undefined ->
            Open =
                public_relay(Opts) orelse loopback(maps:get(ip, Opts, undefined)),
            case {Open, relaying(Opts)} of
                {true, _} -> ok;
                {false, []} -> ok;
                {false, Protocols} -> {error, {unauthenticated_relay, Protocols}}
            end;
        Fun when is_function(Fun, 1) ->
            ok;
        _ ->
            {error, {bad_option, authenticate}}
    end.

%% Authenticate a tunnel request, then resolve its target as before
%% (`masque_ip:resolve_target/3'). A refusal comes back as
%% `{error, Reason}', answered like any other.
-spec resolve(map(), atom(), map(), fun()) -> {ok, map()} | {error, term()}.
resolve(Dispatch, Protocol, Req, Resolver) ->
    case authenticate(maps:get(authenticate, Dispatch, undefined), Req) of
        {ok, Req1} -> masque_ip:resolve_target(Protocol, Req1, Resolver);
        {error, _} = Err -> Err
    end.

authenticate(undefined, Req) ->
    {ok, Req};
authenticate(Fun, Req) ->
    try Fun(Req) of
        ok -> {ok, Req};
        {ok, Identity} -> {ok, Req#{identity => Identity}};
        {reject, Reason} -> {error, Reason};
        _ -> {error, forbidden}
    catch
        Class:Reason ->
            %% The request (headers, tokens) is not logged.
            logger:error("masque authenticate fun failed: ~p:~0P", [Class, Reason, 6]),
            {error, forbidden}
    end.

relaying(Opts) ->
    Builtin = fun(Key, Default) ->
        lists:member(maps:get(Key, Opts, Default), ?RELAYING_HANDLERS)
    end,
    [udp || Builtin(handler, masque_udp_proxy_handler)] ++
        [tcp || Builtin(tcp_handler, masque_tcp_proxy_handler)] ++
        [ip || Builtin(ip_handler, masque_ip_proxy_handler)] ++
        [
            udp_bind
         || maps:get(accept_bind, Opts, false) =:= true,
            Builtin(bind_handler, masque_udp_bind_proxy_handler)
        ].

public_relay(Opts) ->
    maps:get(public_relay, Opts, application:get_env(masque, public_relay, false)) =:= true.

loopback({127, _, _, _}) -> true;
loopback({0, 0, 0, 0, 0, 0, 0, 1}) -> true;
loopback(_) -> false.
