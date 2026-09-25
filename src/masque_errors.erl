%%% @doc RFC 9298 error to HTTP status code mapping.
%%%
%%% All MASQUE failures reported during the CONNECT-UDP handshake must
%%% be returned to the client as an HTTP status response. This module
%%% centralises the mapping so server code and tests agree on the exact
%%% status code for each failure mode.
-module(masque_errors).

-export([handshake_status/1, status_reason/1]).

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
    | {other, 400..599}.

-export_type([handshake_error/0]).

%% @doc Map a handshake error to the status code MASQUE should return.
%% Any other reason (for example an unknown `{reject, _}' from a
%% handler) maps to 502 so the client still gets a response.
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
handshake_status({other, Status}) when
    is_integer(Status), Status >= 400, Status =< 599
->
    Status;
handshake_status(_) ->
    ?MASQUE_STATUS_BAD_GATEWAY.

%% @doc Short human-readable reason-phrase for the given error.
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
status_reason(_) -> <<"request rejected">>.
