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
    protocol => udp | tcp,
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
-callback init(req(), term()) -> {ok, term()} | {ok, term(), [term()]} | {stop, term()}.
-callback handle_packet(binary(), term()) -> {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-callback handle_data(binary(), term()) -> {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-callback handle_capsule(non_neg_integer(), binary(), term()) -> {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-callback handle_info(term(), term()) -> {ok, term()} | {ok, term(), [term()]} | {stop, term(), term()}.
-callback terminate(term(), term()) -> term().

-optional_callbacks([accept/1, init/2, handle_packet/2, handle_data/2,
                     handle_capsule/3, handle_info/2, terminate/2]).

%%====================================================================
%% API
%%====================================================================

%% @doc Default `accept/1' behaviour - accept every well-formed request.
-spec default_accept(req()) -> accept_result().
default_accept(_Req) ->
    accept.
