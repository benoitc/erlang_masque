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
  `masque:send/2` both ways. Bytes the upstream refuses wait here with
  their flow-control credit held, so nothing is lost and a slow
  upstream slows the client. They go out again when an h3 upstream
  reports room (`masque_send_ready`), or on a retry that backs off
  from 5 ms to 200 ms for h2. An upstream that takes nothing for
  `stream_send_timeout_ms` (application env, default 30 s) ends the
  tunnel with `{upstream_send_failed, send_timeout}`.
- CONNECT-IP (`protocol = ip`): IP packets forwarded via
  `masque:send_ip_packet/2`; every ROUTE_ADVERTISEMENT and
  ADDRESS_ASSIGN from the upstream is forwarded to the client
  (an empty one too, it withdraws everything). A client
  ADDRESS_REQUEST is forwarded upstream with fresh request ids
  and the upstream ADDRESS_ASSIGN answer is relayed back under
  the client's ids. The other way, the client's ADDRESS_ASSIGN
  and ROUTE_ADVERTISEMENT go upstream, and an upstream
  ADDRESS_REQUEST is relayed to the client, whose answer goes
  back upstream.

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
-export([
    handle_ip_packet/2,
    handle_address_request/2,
    handle_address_assign/2,
    handle_route_advertisement/2
]).
-export([node_token/0, init_node_token/0, new_token/0]).

-ifdef(TEST).
%% Test-only: construct a state record without running init/2 / opening
%% a real MASQUE session. The unit tests drive callbacks against this.
-export([test_state/2]).
-endif.

-include("masque.hrl").
-include("masque_ip.hrl").

-define(TOKEN_KEY, {?MODULE, node_token}).

%% Time before trying a refused h2 upstream write again, doubling up to
%% the maximum while the upstream takes nothing. Retries are tagged
%% `{masque_timer, _}' so the session does not count them as traffic.
-define(RETRY_MS, 5).
-define(RETRY_MAX_MS, 200).
-define(RETRY_MSG, {masque_timer, chain_retry}).
-define(DEADLINE_MSG, {masque_timer, chain_deadline}).

-record(state, {
    upstream :: pid(),
    protocol :: udp | tcp | ip,
    %% Upstream request id -> client request id for forwarded
    %% ADDRESS_REQUESTs still waiting for their ADDRESS_ASSIGN.
    id_map = #{} :: #{pos_integer() => pos_integer()},
    %% CONNECT-IP: the addresses the last relayed ADDRESS_ASSIGN left
    %% the client holding (request id 0), repeated when this hop answers
    %% on its own, and the upstream ADDRESS_REQUEST ids relayed to the
    %% client and not answered yet.
    held = [] :: [#ip_assignment{}],
    up_requests = #{} :: #{pos_integer() => true},
    %% CONNECT-TCP half-close: which legs already sent FIN.
    upstream_fin = false :: boolean(),
    downstream_fin = false :: boolean(),
    %% CONNECT-TCP bytes the upstream refused (full send queue), oldest
    %% first. Their credit is held, so the client's window bounds this.
    pending = queue:new() :: queue:queue(binary()),
    retry_timer :: reference() | undefined,
    %% Wait before the next h2 retry; doubles while nothing goes out.
    retry_ms = ?RETRY_MS :: pos_integer(),
    %% While bytes are pending: when the upstream last took some, and the
    %% timer that ends the tunnel once it took none for the send timeout.
    progress_at :: integer() | undefined,
    deadline_timer :: reference() | undefined,
    %% The client's FIN arrived while bytes were still pending.
    eof_pending = false :: boolean()
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

%% A refused write wrote nothing and a byte stream cannot lose any, so
%% it waits here with its credit held until the upstream has room.
-spec handle_data(binary(), #state{}) ->
    {ok, #state{}} | {ok, #state{}, [hold_credit]} | {stop, term(), #state{}}.
handle_data(Data, #state{pending = Pending} = State) ->
    case queue:is_empty(Pending) of
        false ->
            {ok, State#state{pending = queue:in(Data, Pending)}, [hold_credit]};
        true ->
            case upstream_send(Data, State) of
                ok ->
                    {ok, State};
                {full, Wait} ->
                    State1 = stalled(State#state{pending = queue:in(Data, Pending)}),
                    {ok, wait(Wait, State1), [hold_credit]};
                {error, Reason} ->
                    {stop, {upstream_send_failed, Reason}, State}
            end
    end.

%% An h3 upstream tells us when its send queue drained (`ready'); h2
%% has no such event, so the write is retried (`poll').
upstream_send(Data, #state{upstream = Sess}) ->
    try masque:send(Sess, Data) of
        ok -> ok;
        {error, send_queue_full} -> {full, ready};
        {error, send_buffer_full} -> {full, poll};
        {error, _} = Err -> Err
    catch
        exit:Reason -> {error, Reason}
    end.

wait(ready, State) ->
    cancel_retry(State);
wait(poll, #state{retry_ms = Ms} = State) ->
    State1 = cancel_retry(State),
    State1#state{retry_timer = erlang:send_after(Ms, self(), ?RETRY_MSG)}.

cancel_retry(#state{retry_timer = undefined} = State) ->
    State;
cancel_retry(#state{retry_timer = TRef} = State) ->
    _ = erlang:cancel_timer(TRef),
    State#state{retry_timer = undefined}.

%% Bytes started to wait: arm the no-progress deadline.
stalled(#state{progress_at = undefined} = State) ->
    Timeout = masque_stream_send:send_timeout(),
    State#state{
        progress_at = now_ms(),
        deadline_timer = erlang:send_after(Timeout, self(), ?DEADLINE_MSG)
    };
stalled(State) ->
    State.

%% Nothing waits any more.
unstalled(#state{deadline_timer = Deadline} = State) ->
    _ =
        case Deadline of
            undefined -> ok;
            _ -> erlang:cancel_timer(Deadline)
        end,
    (cancel_retry(State))#state{
        progress_at = undefined, deadline_timer = undefined, retry_ms = ?RETRY_MS
    }.

%% The deadline fired: end the tunnel if the upstream took nothing for
%% the whole send timeout, otherwise wait for the time left.
check_deadline(#state{progress_at = undefined} = State) ->
    {ok, State#state{deadline_timer = undefined}};
check_deadline(#state{progress_at = At} = State) ->
    Timeout = masque_stream_send:send_timeout(),
    case now_ms() - At of
        Idle when Idle >= Timeout ->
            {stop, {upstream_send_failed, send_timeout}, unstalled(State)};
        Idle ->
            TRef = erlang:send_after(Timeout - Idle, self(), ?DEADLINE_MSG),
            {ok, State#state{deadline_timer = TRef}}
    end.

now_ms() -> erlang:monotonic_time(millisecond).

%% Send what the upstream takes now and give that credit back.
drain_pending(#state{pending = Pending} = State, Released) ->
    case queue:out(Pending) of
        {empty, _} ->
            drained(unstalled(State), Released);
        {{value, Data}, Rest} ->
            case upstream_send(Data, State) of
                ok ->
                    drain_pending(State#state{pending = Rest}, Released + byte_size(Data));
                {full, Wait} ->
                    {ok, wait(Wait, still_full(State, Released)), release_actions(Released)};
                {error, Reason} ->
                    {stop, {upstream_send_failed, Reason}, State}
            end
    end.

%% Some bytes went out: that is progress, retry soon again. None did:
%% back off.
still_full(State, Released) when Released > 0 ->
    State#state{progress_at = now_ms(), retry_ms = ?RETRY_MS};
still_full(#state{retry_ms = Ms} = State, 0) ->
    State#state{retry_ms = min(2 * Ms, ?RETRY_MAX_MS)}.

drained(#state{eof_pending = true} = State, Released) ->
    case finish_eof(State#state{eof_pending = false}) of
        {ok, State1} -> {ok, State1, release_actions(Released)};
        {stop, _, _} = Stop -> Stop
    end;
drained(State, Released) ->
    {ok, State, release_actions(Released)}.

release_actions(0) -> [];
release_actions(N) -> [{release_credit, N}].

-spec handle_ip_packet(binary(), #state{}) -> {ok, #state{}}.
handle_ip_packet(Packet, #state{upstream = Sess} = State) ->
    _ = masque:send_ip_packet(Sess, Packet),
    {ok, State}.

%% Forward the client's ADDRESS_REQUEST upstream. The upstream
%% session allocates its own request ids; remember the mapping so the
%% answer can be relayed under the client's ids. If the upstream leg
%% cannot take the request, answer with the RFC 9484 "no address"
%% entry right away, along with the addresses the client holds: an
%% address left out of an ADDRESS_ASSIGN is withdrawn.
-spec handle_address_request([#ip_prefix_request{}], #state{}) ->
    {ok, #state{}} | {ok, #state{}, [term()]}.
handle_address_request(Requests, #state{upstream = Sess, id_map = Map, held = Held} = State) ->
    Prefixes = [
        {V, Addr, Pfx}
     || #ip_prefix_request{version = V, address = Addr, prefix_len = Pfx} <- Requests
    ],
    DownIds = [Id || #ip_prefix_request{request_id = Id} <- Requests],
    Reject = [{assign, Held ++ masque_ip:reject_requests(Requests)}],
    try masque:request_addresses(Sess, Prefixes) of
        {ok, UpIds} when length(UpIds) =:= length(DownIds) ->
            Map1 = maps:merge(Map, maps:from_list(lists:zip(UpIds, DownIds))),
            {ok, State#state{id_map = Map1}};
        _ ->
            {ok, State, Reject}
    catch
        exit:_ ->
            {ok, State, Reject}
    end.

%% The client assigned addresses to this hop: pass them upstream. An
%% entry answering an upstream ADDRESS_REQUEST this hop relayed keeps
%% its id; any other non-zero id becomes 0 (an unprompted entry), and a
%% rejection for an unknown id is dropped.
-spec handle_address_assign([#ip_assignment{}], #state{}) -> {ok, #state{}}.
handle_address_assign(Entries, #state{upstream = Sess, up_requests = Up} = State) ->
    {Relay, Up1} = lists:foldr(fun relay_id/2, {[], Up}, Entries),
    _ =
        (try
            masque:assign_addresses(Sess, Relay)
        catch
            exit:_ -> ok
        end),
    {ok, State#state{up_requests = Up1}}.

-spec handle_route_advertisement([#ip_route{}], #state{}) -> {ok, #state{}}.
handle_route_advertisement(Routes, #state{upstream = Sess} = State) ->
    _ =
        (try
            masque:advertise_routes(Sess, Routes)
        catch
            exit:_ -> ok
        end),
    {ok, State}.

-spec handle_capsule(non_neg_integer(), binary(), #state{}) -> {ok, #state{}}.
handle_capsule(Type, Value, #state{upstream = Sess} = State) ->
    _ = masque:send_capsule(Sess, Type, Value),
    {ok, State}.

-spec handle_eof(#state{}) -> {ok, #state{}} | {stop, term(), #state{}}.
handle_eof(#state{pending = Pending} = State) ->
    case queue:is_empty(Pending) of
        true -> finish_eof(State);
        false -> {ok, State#state{eof_pending = true}}
    end.

finish_eof(#state{upstream = Sess} = State) ->
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
handle_info(?RETRY_MSG, State) ->
    drain_pending(State#state{retry_timer = undefined}, 0);
handle_info(?DEADLINE_MSG, State) ->
    check_deadline(State);
%% The h3 upstream's send queue drained: send what waits.
handle_info({masque_send_ready, Sess}, #state{upstream = Sess, pending = Pending} = State) ->
    case queue:is_empty(Pending) of
        true -> {ok, State};
        false -> drain_pending(State, 0)
    end;
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
    %% Each ADDRESS_ASSIGN is the full set (RFC 9484 section 4.7.1), so
    %% it is relayed even when empty: that withdraws every address.
    %% Unprompted entries (request_id 0) pass through. Prompted ones
    %% answer a request we forwarded: relay them under the client's
    %% request id. An entry with an id we never forwarded is still an
    %% address the client holds and goes as unprompted (id 0); a
    %% rejection for such an id is dropped.
    {Relay, Map1} = lists:foldr(fun map_assign/2, {[], Map}, Entries),
    {ok, State#state{id_map = Map1, held = masque_ip:held_set(Relay)}, [{assign, Relay}]};
%% The upstream asks this hop for addresses: ask the client, keeping
%% the upstream's request ids so the client's answer goes back as is.
handle_info(
    {masque_address_request, Sess, Requests},
    #state{upstream = Sess, protocol = ip, up_requests = Up} = State
) ->
    Up1 = lists:foldl(
        fun(#ip_prefix_request{request_id = Id}, Acc) -> Acc#{Id => true} end, Up, Requests
    ),
    {ok, State#state{up_requests = Up1}, [{request_addresses, Requests}]};
%% An ICMP error for a packet that could not go into the client's
%% tunnel: its source is on the upstream side.
handle_info({masque_ip_icmp, Icmp}, #state{upstream = Sess, protocol = ip} = State) ->
    _ = masque:send_ip_packet(Sess, Icmp),
    {ok, State};
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
%% A clean end upstream (UDP, IP) ends the client tunnel cleanly too.
handle_info({masque_closed, Sess, peer_fin}, #state{upstream = Sess} = State) ->
    {stop, normal, State};
handle_info({masque_closed, Sess, _Reason}, #state{upstream = Sess} = State) ->
    {stop, upstream_closed, State};
handle_info(_Other, State) ->
    {ok, State}.

map_assign(#ip_assignment{request_id = 0} = E, {Acc, Map}) ->
    {[E | Acc], Map};
map_assign(#ip_assignment{request_id = UpId} = E, {Acc, Map}) ->
    case maps:take(UpId, Map) of
        {DownId, Map1} -> {[E#ip_assignment{request_id = DownId} | Acc], Map1};
        error -> {unprompted(E, Acc), Map}
    end.

relay_id(#ip_assignment{request_id = 0} = E, {Acc, Up}) ->
    {[E | Acc], Up};
relay_id(#ip_assignment{request_id = Id} = E, {Acc, Up}) ->
    case maps:take(Id, Up) of
        {true, Up1} -> {[E | Acc], Up1};
        error -> {unprompted(E, Acc), Up}
    end.

unprompted(E, Acc) ->
    case masque_ip:is_rejection(E) of
        true -> Acc;
        false -> [E#ip_assignment{request_id = 0} | Acc]
    end.

-spec terminate(term(), #state{}) -> ok.
terminate(_Reason, #state{upstream = Sess}) ->
    _ = masque:close(Sess),
    ok.
