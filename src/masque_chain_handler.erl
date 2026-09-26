-module(masque_chain_handler).
-moduledoc """
MASQUE handler that chains to an upstream proxy.

Instead of opening a `gen_udp` / `gen_tcp` socket to the resolved
target (what the built-in UDP / TCP / IP proxy handlers do), this
handler opens a MASQUE client session to an upstream proxy and
relays traffic both ways. The result is a two-hop tunnel:

```text
Client -> Ingress (this handler) -> Egress (upstream) -> Target
```

This is the server-side chaining pattern used by Apple Private
Relay: the client connects to the Ingress; the Ingress chains to
the Egress transparently.

Covers all three tunnel protocols:

- CONNECT-UDP (`protocol = udp`): packets forwarded via
  `masque:send/2` both ways.
- CONNECT-TCP (`protocol = tcp`): bytes forwarded via
  `masque:send/2` both ways.
- CONNECT-IP (`protocol = ip`): IP packets forwarded via
  `masque:send_ip_packet/2`; ROUTE_ADVERTISEMENT and
  unprompted ADDRESS_ASSIGN (request_id 0) from the upstream
  are forwarded to the client. A client ADDRESS_REQUEST is
  forwarded upstream with fresh request ids and the upstream
  ADDRESS_ASSIGN answer is relayed back under the client's
  ids.

Configure via `handler_opts`:
- `upstream_proxy := binary()` - URI of the upstream proxy
  (e.g. `<<"https://egress:4434">>`). Required.
- `upstream_opts => map()` - options forwarded to
  `masque:connect/3` for the upstream leg (verify, transports,
  timeout, etc.). Default `#{}`, which verifies the upstream
  certificate against the system CA store.
- `allow => fun(target()) -> boolean()` - optional policy
  gate, same as `masque_udp_proxy_handler`.

Loop detection: every upstream request carries a `via` header
(RFC 9110 section 7.6.3) listing the hops seen so far plus this
listener's pseudonym, a random token created when the chain
listener starts (`via_token` in `handler_opts`; the per-node
`node_token/0` when unset). A request whose `via` already
names this listener is rejected with `loop_detected` (508,
Proxy-Status `proxy_loop_detected`), so a chain that points back
at itself fails instead of recursing, while two chain listeners
on the same node can still be chained together.
""".
-behaviour(masque_handler).

-export([
    accept/1,
    init/2,
    handle_packet/2,
    handle_data/2,
    handle_capsule/3,
    handle_eof/1,
    handle_info/2,
    terminate/2
]).
-export([handle_ip_packet/2, handle_address_request/2]).
-export([node_token/0, init_node_token/0, new_token/0]).

-ifdef(TEST).
%% Test-only: construct a state record without running init/2 / opening
%% a real MASQUE session. The unit tests drive callbacks against this.
-export([test_state/2]).
-endif.

-include("masque.hrl").
-include("masque_ip.hrl").

-define(TOKEN_KEY, {?MODULE, node_token}).

-record(state, {
    upstream :: pid(),
    protocol :: udp | tcp | ip,
    %% Upstream request id -> client request id for forwarded
    %% ADDRESS_REQUESTs still waiting for their ADDRESS_ASSIGN.
    id_map = #{} :: #{pos_integer() => pos_integer()},
    %% CONNECT-TCP half-close: which legs already sent FIN.
    upstream_fin = false :: boolean(),
    downstream_fin = false :: boolean()
}).

-ifdef(TEST).
test_state(Upstream, Protocol) when
    is_pid(Upstream),
    Protocol =:= udp orelse Protocol =:= tcp orelse Protocol =:= ip
->
    #state{upstream = Upstream, protocol = Protocol}.
-endif.

%%====================================================================
%% Behaviour callbacks
%%====================================================================

-spec accept(masque_handler:req()) -> masque_handler:accept_result().
accept(Req) ->
    case is_loop(token(maps:get(handler_opts, Req, #{})), maps:get(headers, Req, [])) of
        true -> {reject, loop_detected};
        false -> accept_target(Req)
    end.

accept_target(#{protocol := ip, ip_target := Target, ip_ipproto := IPProto} = Req) ->
    Opts = maps:get(handler_opts, Req, #{}),
    AllowFun = maps:get(allow, Opts, fun(_) -> true end),
    case AllowFun({Target, IPProto}) of
        true -> accept;
        false -> {reject, forbidden}
    end;
accept_target(#{target_host := Host, target_port := Port} = Req) ->
    Opts = maps:get(handler_opts, Req, #{}),
    AllowFun = maps:get(allow, Opts, fun(_) -> true end),
    case AllowFun({Host, Port}) of
        true -> accept;
        false -> {reject, forbidden}
    end.

-spec init(masque_handler:req(), map()) -> {ok, #state{}} | {stop, term()}.
init(
    #{
        protocol := ip,
        ip_target := Target,
        ip_ipproto := IPProto
    } = Req,
    Opts
) ->
    UpstreamURI = maps:get(upstream_proxy, Opts),
    ConnOpts = upstream_connect_opts(Req, Opts, ip),
    case masque:connect(UpstreamURI, {Target, IPProto}, ConnOpts) of
        {ok, Sess} ->
            {ok, #state{upstream = Sess, protocol = ip}};
        {error, Reason} ->
            {stop, upstream_error(Reason)}
    end;
init(
    #{
        target_host := Host,
        target_port := Port,
        protocol := Proto
    } = Req,
    Opts
) ->
    UpstreamURI = maps:get(upstream_proxy, Opts),
    ConnOpts = upstream_connect_opts(Req, Opts, Proto),
    case masque:connect(UpstreamURI, {Host, Port}, ConnOpts) of
        {ok, Sess} ->
            {ok, #state{upstream = Sess, protocol = Proto}};
        {error, Reason} ->
            {stop, upstream_error(Reason)}
    end.

-doc """
This node's `via` pseudonym. Created by `masque_app` at start;
created on first use when the application is not running.
""".
-spec node_token() -> binary().
node_token() ->
    case persistent_term:get(?TOKEN_KEY, undefined) of
        undefined -> init_node_token();
        Token -> Token
    end.

-doc """
Create this node's `via` pseudonym unless it already exists.
""".
-spec init_node_token() -> binary().
init_node_token() ->
    case persistent_term:get(?TOKEN_KEY, undefined) of
        undefined ->
            Token = new_token(),
            persistent_term:put(?TOKEN_KEY, Token),
            Token;
        Token ->
            Token
    end.

-doc """
A fresh random `via` pseudonym. The chain listeners create one
per listener and pass it as `via_token` in `handler_opts`.
""".
-spec new_token() -> binary().
new_token() ->
    Hex = binary:encode_hex(crypto:strong_rand_bytes(8), lowercase),
    <<"masque-", Hex/binary>>.

token(#{via_token := Token}) when is_binary(Token) -> Token;
token(_) -> node_token().

upstream_connect_opts(Req, Opts, Proto) ->
    UpstreamOpts = maps:get(upstream_opts, Opts, #{}),
    Extra = [
        {K, V}
     || {K, V} <- maps:get(request_headers, UpstreamOpts, []),
        string:lowercase(K) =/= <<"via">>
    ],
    Via = {<<"via">>, via_value(token(Opts), maps:get(headers, Req, []))},
    UpstreamOpts#{
        timeout => maps:get(upstream_timeout, Opts, 5000),
        owner => self(),
        protocol => Proto,
        request_headers => Extra ++ [Via]
    }.

%% The upstream leg keeps the hops already listed and appends this
%% listener, so a loop through several proxies is caught too.
via_value(Token, Headers) ->
    Own = <<"1.1 ", Token/binary>>,
    case via_values(Headers) of
        [] -> Own;
        Prev -> iolist_to_binary(lists:join(<<", ">>, Prev ++ [Own]))
    end.

via_values(Headers) ->
    [V || {K, V} <- Headers, is_binary(K), string:lowercase(K) =:= <<"via">>].

is_loop(Token, Headers) ->
    Hops = lists:append([binary:split(V, <<",">>, [global]) || V <- via_values(Headers)]),
    lists:any(fun(Hop) -> received_by(Hop) =:= Token end, Hops).

%% `Via' entry: received-protocol RWS received-by [RWS comment].
received_by(Hop) ->
    case string:lexemes(Hop, " \t") of
        [_Proto, By | _] -> By;
        _ -> undefined
    end.

upstream_error({handshake_rejected, ?MASQUE_STATUS_LOOP_DETECTED}) ->
    {reject, loop_detected};
upstream_error({handshake_rejected, ?MASQUE_STATUS_LOOP_DETECTED, _}) ->
    {reject, loop_detected};
upstream_error(Reason) ->
    {resolution_failed, {upstream, Reason}}.

-spec handle_packet(binary(), #state{}) -> {ok, #state{}}.
handle_packet(Data, #state{upstream = Sess} = State) ->
    _ = masque:send(Sess, Data),
    {ok, State}.

-spec handle_data(binary(), #state{}) -> {ok, #state{}}.
handle_data(Data, #state{upstream = Sess} = State) ->
    _ = masque:send(Sess, Data),
    {ok, State}.

-spec handle_ip_packet(binary(), #state{}) -> {ok, #state{}}.
handle_ip_packet(Packet, #state{upstream = Sess} = State) ->
    _ = masque:send_ip_packet(Sess, Packet),
    {ok, State}.

%% Forward the client's ADDRESS_REQUEST upstream. The upstream
%% session allocates its own request ids; remember the mapping so the
%% answer can be relayed under the client's ids. If the upstream leg
%% cannot take the request, answer with the RFC 9484 "no address"
%% entry right away.
-spec handle_address_request([#ip_prefix_request{}], #state{}) ->
    {ok, #state{}} | {ok, #state{}, [term()]}.
handle_address_request(Requests, #state{upstream = Sess, id_map = Map} = State) ->
    Prefixes = [
        {V, Addr, Pfx}
     || #ip_prefix_request{version = V, address = Addr, prefix_len = Pfx} <- Requests
    ],
    DownIds = [Id || #ip_prefix_request{request_id = Id} <- Requests],
    try masque:request_addresses(Sess, Prefixes) of
        {ok, UpIds} when length(UpIds) =:= length(DownIds) ->
            Map1 = maps:merge(Map, maps:from_list(lists:zip(UpIds, DownIds))),
            {ok, State#state{id_map = Map1}};
        _ ->
            {ok, State, [{assign, masque_ip:reject_requests(Requests)}]}
    catch
        exit:_ ->
            {ok, State, [{assign, masque_ip:reject_requests(Requests)}]}
    end.

-spec handle_capsule(non_neg_integer(), binary(), #state{}) -> {ok, #state{}}.
handle_capsule(Type, Value, #state{upstream = Sess} = State) ->
    _ = masque:send_capsule(Sess, Type, Value),
    {ok, State}.

-spec handle_eof(#state{}) -> {ok, #state{}} | {stop, term(), #state{}}.
handle_eof(#state{upstream = Sess} = State) ->
    _ =
        (try
            masque:shutdown_write(Sess)
        catch
            _:_ -> ok
        end),
    case State of
        #state{protocol = tcp, upstream_fin = true} -> {stop, normal, State};
        _ -> {ok, State#state{downstream_fin = true}}
    end.

-spec handle_info(term(), #state{}) ->
    {ok, #state{}} | {ok, #state{}, [term()]} | {stop, term(), #state{}}.
handle_info(
    {masque_data, Sess, Data},
    #state{
        upstream = Sess,
        protocol = udp
    } = State
) ->
    {ok, State, [{send, Data}]};
handle_info(
    {masque_data, Sess, Data},
    #state{
        upstream = Sess,
        protocol = tcp
    } = State
) ->
    {ok, State, [{send_data, Data}]};
handle_info(
    {masque_ip_packet, Sess, Packet},
    #state{upstream = Sess, protocol = ip} = State
) ->
    {ok, State, [{send_ip_packet, Packet}]};
handle_info(
    {masque_address_assign, Sess, Entries},
    #state{upstream = Sess, protocol = ip, id_map = Map} = State
) ->
    %% Unprompted entries (request_id 0) pass through. Prompted ones
    %% answer a request we forwarded: relay them under the client's
    %% request id. Entries for ids we never forwarded are dropped, the
    %% ingress session would reject them on the client leg.
    {Relay, Map1} = lists:foldr(fun map_assign/2, {[], Map}, Entries),
    State1 = State#state{id_map = Map1},
    case Relay of
        [] -> {ok, State1};
        _ -> {ok, State1, [{assign, Relay}]}
    end;
handle_info(
    {masque_route_advertisement, Sess, Routes},
    #state{upstream = Sess, protocol = ip} = State
) ->
    {ok, State, [{advertise, Routes}]};
handle_info({masque_capsule, Sess, Type, Value}, #state{upstream = Sess} = State) ->
    {ok, State, [{send_capsule, Type, Value}]};
handle_info(
    {masque_closed, Sess, peer_fin},
    #state{upstream = Sess, protocol = tcp, downstream_fin = true} = State
) ->
    {stop, normal, State};
handle_info({masque_closed, Sess, peer_fin}, #state{upstream = Sess, protocol = tcp} = State) ->
    %% Upstream half-close: pass the FIN on, keep relaying client bytes.
    {ok, State#state{upstream_fin = true}, [{send_data, <<>>, true}]};
handle_info({masque_closed, Sess, _Reason}, #state{upstream = Sess} = State) ->
    {stop, upstream_closed, State};
handle_info(_Other, State) ->
    {ok, State}.

map_assign(#ip_assignment{request_id = 0} = E, {Acc, Map}) ->
    {[E | Acc], Map};
map_assign(#ip_assignment{request_id = UpId} = E, {Acc, Map}) ->
    case maps:take(UpId, Map) of
        {DownId, Map1} -> {[E#ip_assignment{request_id = DownId} | Acc], Map1};
        error -> {Acc, Map}
    end.

-spec terminate(term(), #state{}) -> ok.
terminate(_Reason, #state{upstream = Sess}) ->
    _ = masque:close(Sess),
    ok.
