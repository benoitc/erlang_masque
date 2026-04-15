%%% @doc Server-side handler behaviour for MASQUE CONNECT-UDP tunnels.
%%%
%%% This behaviour is stable across the implementation plan but its
%%% callbacks are added in layers:
%%%
%%% <ul>
%%%  <li>`accept/1' (Step 3) - synchronous accept/reject decision for
%%%      the handshake. Runs in the handler process spawned by the H3
%%%      connection; return `accept' or `{reject, Reason}' where
%%%      `Reason' is a `masque_errors:handshake_error()'.</li>
%%%  <li>`init/2', `handle_packet/2', `handle_capsule/3',
%%%      `handle_info/2', `terminate/2' - added in Step 5/6 when the
%%%      session process is wired up.</li>
%%% </ul>
%%%
%%% Modules wanting the default accept-everything behaviour can simply
%%% omit `accept/1'; the server falls back to `accept'.
-module(masque_handler).

-export([default_accept/1]).

-export_type([req/0, accept_result/0]).

-type req() :: #{
    method := binary(),
    path := binary(),
    authority := binary(),
    scheme := binary(),
    target_host := binary(),
    target_port := 1..65535,
    headers := [{binary(), binary()}],
    handler_opts => term()
}.

-type accept_result() ::
    accept
  | {reject, masque_errors:handshake_error()}.

%%====================================================================
%% Behaviour
%%====================================================================

-callback accept(req()) -> accept_result().

-optional_callbacks([accept/1]).

%%====================================================================
%% API
%%====================================================================

%% @doc Default `accept/1' behaviour - accept every well-formed request.
-spec default_accept(req()) -> accept_result().
default_accept(_Req) ->
    accept.
