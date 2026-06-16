%%% @doc Server-side handler behaviour for MASQUE tunnels.
%%%
%%% Callbacks:
%%%
%%% <ul>
%%%  <li>`accept/1' - synchronous accept/reject gate for the handshake.
%%%      Return `accept' or `{reject, masque_errors:handshake_error()}'.
%%%      Optional; default is `accept'.</li>
%%%  <li>`init/2' - session start. Return `{ok, State}' or
%%%      `{ok, State, [action()]}' or `{stop, Reason}'.</li>
%%%  <li>`handle_packet/2' - inbound UDP payload (CONNECT-UDP tunnels).</li>
%%%  <li>`handle_data/2' - inbound TCP bytes (CONNECT-TCP tunnels).</li>
%%%  <li>`handle_capsule/3' - inbound capsule on the stream body.</li>
%%%  <li>`handle_info/2' - any other Erlang message.</li>
%%%  <li>`terminate/2' - session shutdown.</li>
%%% </ul>
%%%
%%% All callbacks are optional. Omitting a callback for a given event
%%% makes the session silently ignore it.
-module(masque_handler).

-export([default_accept/1]).

-export_type([req/0, accept_result/0]).

-type req() :: #{
    method := binary(),
    protocol => udp | tcp | ip,
    path := binary(),
    authority := binary(),
    scheme := binary(),
    %% UDP/TCP target
    target_host => binary(),
    target_port => 1..65535,
    %% CONNECT-IP target (RFC 9484 §3)
    ip_target => masque_uri_ip:ip_target(),
    ip_ipproto => masque_uri_ip:ip_ipproto(),
    %% Listener-side DNS resolution result (decision #3: resolver
    %% runs before the handler's accept/1, so hostname-based SSRF
    %% policy can apply to resolved addresses).
    resolved_addresses => [inet:ip_address()],
    headers := [{binary(), binary()}],
    handler_opts => term(),
    %% Connection-level info (H3 only; absent on H2)
    peer => {inet:ip_address(), inet:port_number()},
    peer_cert => binary()
}.

-type accept_result() ::
    accept
    | {reject, masque_errors:handshake_error()}
    %% Rejection with extra HTTP response headers. Useful for schemes
    %% that require a challenge header on 401 (Privacy Pass via
    %% `WWW-Authenticate: PrivateToken ...', RFC 9112 `Basic' / `Bearer'
    %% challenges, rate-limit `Retry-After' hints). Duplicate keys with
    %% the library-set headers (`content-type', `content-length',
    %% `proxy-status') take the caller's value.
    | {reject, masque_errors:handshake_error(), [{binary(), binary()}]}.

%%====================================================================
%% Behaviour
%%====================================================================

-callback accept(req()) -> accept_result().
-callback init(req(), term()) -> {ok, term()} | {ok, term(), [term()]} | {stop, term()}.
-callback handle_packet(binary(), term()) ->
    {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-callback handle_data(binary(), term()) ->
    {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-callback handle_capsule(non_neg_integer(), binary(), term()) ->
    {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-callback handle_info(term(), term()) ->
    {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-callback handle_eof(term()) -> {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-callback terminate(term(), term()) -> term().

%% CONNECT-IP callbacks (RFC 9484). All optional; each uses the
%% standard `{ok, State} | {ok, State, [action()]} | {stop, Reason,
%% State}' return shape so the IP session's action interpreter is
%% the same as TCP / UDP.
-callback handle_ip_packet(binary(), term()) ->
    {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-callback handle_address_request([term()], term()) ->
    {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-callback handle_address_assign([term()], term()) ->
    {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-callback handle_route_advertisement([term()], term()) ->
    {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.

-optional_callbacks([
    accept/1,
    init/2,
    handle_packet/2,
    handle_data/2,
    handle_capsule/3,
    handle_info/2,
    handle_eof/1,
    terminate/2,
    handle_ip_packet/2,
    handle_address_request/2,
    handle_address_assign/2,
    handle_route_advertisement/2
]).

%%====================================================================
%% API
%%====================================================================

%% @doc Default `accept/1' behaviour - accept every well-formed request.
-spec default_accept(req()) -> accept_result().
default_accept(_Req) ->
    accept.
