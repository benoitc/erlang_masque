-module(masque_errors).
-moduledoc """
RFC 9298 error to HTTP status code mapping.

All MASQUE failures reported during the CONNECT-UDP handshake must
be returned to the client as an HTTP status response. This module
centralises the mapping so server code and tests agree on the exact
status code for each failure mode.
""".

-export([handshake_status/1, status_reason/1, proxy_status/1, start_error/1]).

-include("masque.hrl").

-type handshake_error() ::
    bad_method
    | bad_protocol
    | bad_path
    | bad_port
    | bad_host
    | resolution_failed
    | upstream_timeout
    | forbidden
    | loop_detected
    | overload
    %% Reverse connect: a malformed request, and an accept whose request
    %% id is not pending for this client.
    | bad_request
    | unknown_request
    %% RFC 9209 section 2.3: the most specific proxy error type.
    | connection_refused
    | destination_unavailable
    | destination_unroutable
    | ip_prohibited
    | internal_error
    | denied
    %% A chained upstream proxy refused the request with this status.
    | {upstream_status, 400..599}
    | {other, 400..599}.

-export_type([handshake_error/0]).

-doc """
Map a handshake error to the status code MASQUE should return.
Any other reason (for example an unknown `{reject, _}` from a
handler) maps to 502 so the client still gets a response.
""".
-spec handshake_status(handshake_error() | term()) -> 400..599.
handshake_status(bad_method) ->
    ?MASQUE_STATUS_METHOD_NOT_ALLOWED;
handshake_status(bad_protocol) ->
    ?MASQUE_STATUS_NOT_IMPLEMENTED;
handshake_status(bad_path) ->
    ?MASQUE_STATUS_NOT_FOUND;
handshake_status(bad_port) ->
    ?MASQUE_STATUS_BAD_REQUEST;
handshake_status(bad_host) ->
    ?MASQUE_STATUS_BAD_REQUEST;
handshake_status(resolution_failed) ->
    ?MASQUE_STATUS_BAD_GATEWAY;
handshake_status(upstream_timeout) ->
    ?MASQUE_STATUS_GATEWAY_TIMEOUT;
handshake_status(forbidden) ->
    403;
handshake_status(loop_detected) ->
    ?MASQUE_STATUS_LOOP_DETECTED;
handshake_status(overload) ->
    503;
handshake_status(bad_request) ->
    ?MASQUE_STATUS_BAD_REQUEST;
handshake_status(unknown_request) ->
    ?MASQUE_STATUS_NOT_FOUND;
handshake_status(connection_refused) ->
    ?MASQUE_STATUS_BAD_GATEWAY;
handshake_status(destination_unavailable) ->
    ?MASQUE_STATUS_BAD_GATEWAY;
handshake_status(destination_unroutable) ->
    ?MASQUE_STATUS_BAD_GATEWAY;
handshake_status(ip_prohibited) ->
    ?MASQUE_STATUS_BAD_GATEWAY;
handshake_status(internal_error) ->
    ?MASQUE_STATUS_BAD_GATEWAY;
handshake_status(denied) ->
    403;
handshake_status({upstream_status, Status}) when
    is_integer(Status), Status >= 400, Status =< 599
->
    Status;
handshake_status({other, Status}) when
    is_integer(Status), Status >= 400, Status =< 599
->
    Status;
handshake_status(_) ->
    ?MASQUE_STATUS_BAD_GATEWAY.

-doc """
Short human-readable reason-phrase for the given error.
""".
-spec status_reason(handshake_error() | term()) -> binary().
status_reason(bad_method) -> <<"method must be CONNECT">>;
status_reason(bad_protocol) -> <<":protocol must be connect-udp">>;
status_reason(bad_path) -> <<"path does not match template">>;
status_reason(bad_port) -> <<"target_port out of range">>;
status_reason(bad_host) -> <<"target_host empty or malformed">>;
status_reason(resolution_failed) -> <<"could not resolve target">>;
status_reason(upstream_timeout) -> <<"target did not respond in time">>;
status_reason(forbidden) -> <<"target denied by policy">>;
status_reason(loop_detected) -> <<"proxy loop detected">>;
status_reason(overload) -> <<"proxy overloaded">>;
status_reason(bad_request) -> <<"malformed request">>;
status_reason(unknown_request) -> <<"no such connection request">>;
status_reason(connection_refused) -> <<"target refused the connection">>;
status_reason(destination_unavailable) -> <<"target unavailable">>;
status_reason(destination_unroutable) -> <<"no route to target">>;
status_reason(ip_prohibited) -> <<"target denied by policy">>;
status_reason(internal_error) -> <<"proxy internal error">>;
status_reason(denied) -> <<"request denied">>;
status_reason({upstream_status, _}) -> <<"upstream proxy refused the request">>;
status_reason(_) -> <<"request rejected">>.

-doc """
The `Proxy-Status` field (RFC 9209) for a rejected request: `masque`
with an `error` parameter naming the most specific proxy error type,
or, for a status passed on from a chained upstream proxy, a
`received-status` parameter instead.
""".
-spec proxy_status(handshake_error() | term()) -> binary().
proxy_status({upstream_status, Status}) when is_integer(Status) ->
    <<"masque; received-status=", (integer_to_binary(Status))/binary>>;
proxy_status(Reason) ->
    <<"masque; error=", (proxy_error(Reason))/binary>>.

proxy_error(bad_method) -> <<"http_request_error">>;
proxy_error(bad_protocol) -> <<"http_protocol_error">>;
proxy_error(bad_path) -> <<"http_request_error">>;
proxy_error(bad_port) -> <<"http_request_error">>;
proxy_error(bad_host) -> <<"http_request_error">>;
proxy_error(bad_request) -> <<"http_request_error">>;
proxy_error(unknown_request) -> <<"http_request_error">>;
proxy_error(resolution_failed) -> <<"dns_error">>;
proxy_error(upstream_timeout) -> <<"connection_timeout">>;
proxy_error(forbidden) -> <<"destination_ip_prohibited">>;
proxy_error(ip_prohibited) -> <<"destination_ip_prohibited">>;
proxy_error(connection_refused) -> <<"connection_refused">>;
proxy_error(destination_unavailable) -> <<"destination_unavailable">>;
proxy_error(destination_unroutable) -> <<"destination_ip_unroutable">>;
proxy_error(denied) -> <<"http_request_denied">>;
proxy_error(loop_detected) -> <<"proxy_loop_detected">>;
proxy_error(overload) -> <<"proxy_internal_error">>;
proxy_error(_) -> <<"proxy_internal_error">>.

-doc """
Map the reason a session failed to start with (the handler's
`{stop, Reason}` from `init/2`, or the session's own failure) to the
handshake error the listener answers with. `{reject, R}` answers `R`;
`{resolution_failed, Why}` answers the most specific error for `Why`
(a name that did not resolve stays `resolution_failed`); anything else,
a handler crash included, is `internal_error`.
""".
-spec start_error(term()) -> handshake_error() | term().
start_error({reject, Err}) ->
    Err;
start_error({resolution_failed, Why}) ->
    resolution_error(Why);
start_error(_) ->
    internal_error.

resolution_error({resolve, _}) ->
    resolution_failed;
resolution_error(private_address) ->
    ip_prohibited;
resolution_error(self_address) ->
    ip_prohibited;
resolution_error({Step, Reason}) when
    Step =:= tcp_connect; Step =:= connect; Step =:= upstream
->
    connect_error(Reason);
resolution_error({udp_open, _}) ->
    internal_error;
resolution_error(_) ->
    resolution_failed.

connect_error(econnrefused) -> connection_refused;
connect_error(timeout) -> upstream_timeout;
connect_error(etimedout) -> upstream_timeout;
connect_error(handshake_timeout) -> upstream_timeout;
connect_error(ehostunreach) -> destination_unroutable;
connect_error(enetunreach) -> destination_unroutable;
connect_error({connect, Reason}) -> connect_error(Reason);
connect_error(_) -> destination_unavailable.
