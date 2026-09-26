-module(masque_handler).
-moduledoc """
Server-side handler behaviour for MASQUE tunnels.

A handler owns the far side of one tunnel. The server session calls
it for every event and carries out the actions it returns. All
callbacks are optional: an event whose callback is missing is
ignored. `accept/1` runs before the session starts, `init/2` before
the 2xx is sent; the other callbacks run once the tunnel is open.

Which callbacks a protocol calls, the actions each protocol accepts,
the request map and what a crash does are described in the handlers
guide (`docs/2-use/handlers.md`). Connect-UDP-Bind sessions also call
`handle_bind_packet/3` (see `masque_udp_bind_proxy_handler`).
""".

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

-doc "Accept or reject the request before a session starts. Defaults to `accept`.".
-callback accept(req()) -> accept_result().
-doc "Start the tunnel. Runs before the 2xx; `{stop, Reason}` refuses it (502).".
-callback init(req(), term()) -> {ok, term()} | {ok, term(), [term()]} | {stop, term()}.
-doc "A UDP payload from the client (CONNECT-UDP, or context 0 of a scoped bind).".
-callback handle_packet(binary(), term()) ->
    {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-doc "Bytes from the client (CONNECT-TCP).".
-callback handle_data(binary(), term()) ->
    {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-doc "A capsule the session does not handle itself.".
-callback handle_capsule(non_neg_integer(), binary(), term()) ->
    {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-doc "Any other message sent to the session process.".
-callback handle_info(term(), term()) ->
    {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-doc "The client finished sending (CONNECT-TCP half-close).".
-callback handle_eof(term()) -> {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-doc "The session is ending. Close what the handler opened here.".
-callback terminate(term(), term()) -> term().

%% CONNECT-IP callbacks (RFC 9484). All optional; each uses the
%% standard `{ok, State} | {ok, State, [action()]} | {stop, Reason,
%% State}' return shape so the IP session's action interpreter is
%% the same as TCP / UDP.
-doc "An IP packet from the client (CONNECT-IP).".
-callback handle_ip_packet(binary(), term()) ->
    {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-doc "ADDRESS_REQUEST entries from the client (CONNECT-IP).".
-callback handle_address_request([term()], term()) ->
    {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-doc "ADDRESS_ASSIGN entries from the client (CONNECT-IP).".
-callback handle_address_assign([term()], term()) ->
    {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-doc "ROUTE_ADVERTISEMENT ranges from the client (CONNECT-IP).".
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

-doc """
Default `accept/1` behaviour - accept every well-formed request.
""".
-spec default_accept(req()) -> accept_result().
default_accept(_Req) ->
    accept.
