%%% Shared `failed` state for client sessions.
%%%
%%% Client sessions dial the proxy from an internal event queued by
%%% `init/1`, so a dial error is known before the caller's
%%% `handshake_await` call is processed. Instead of exiting (which
%%% would turn the caller's `gen_statem:call` into an exit), a session
%%% parks the error in a `failed` state: the next `handshake_await`
%%% gets `{error, Reason}` and the session stops. With no caller the
%%% state gives up after the handshake timeout.
-module(masque_client_failed).
-moduledoc false.

-export([enter/1, handle/4, guard/1]).

%% State-enter actions for `failed`: a state timeout bounded by
%% the session's handshake timeout.
-spec enter(map()) -> [gen_statem:action()].
enter(Opts) ->
    [{state_timeout, maps:get(timeout, Opts, 5000), give_up}].

%% Event handling for `failed`. `Reason` is the parked error and
%% `OwnerRef` the session's owner monitor.
-spec handle(gen_statem:event_type(), term(), term(), reference()) ->
    gen_statem:event_handler_result(atom()).
handle({call, From}, handshake_await, Reason, _OwnerRef) ->
    {stop_and_reply, normal, [{reply, From, {error, Reason}}]};
handle({call, From}, stop, _Reason, _OwnerRef) ->
    {stop_and_reply, normal, [{reply, From, ok}]};
handle({call, From}, _Other, Reason, _OwnerRef) ->
    {keep_state_and_data, [{reply, From, {error, Reason}}]};
handle(state_timeout, give_up, _Reason, _OwnerRef) ->
    {stop, normal};
handle(info, {'DOWN', Ref, process, _, _}, _Reason, Ref) ->
    {stop, normal};
handle(_Type, _Event, _Reason, _OwnerRef) ->
    keep_state_and_data.

%% Run a dial step, turning an exit (e.g. a transport process
%% that went away mid-call) into `{error, Reason}`.
-spec guard(fun(() -> Result)) -> Result | {error, term()}.
guard(Fun) ->
    try
        Fun()
    catch
        exit:{Reason, {gen_statem, call, _}} -> {error, Reason};
        exit:{Reason, {gen_server, call, _}} -> {error, Reason};
        exit:Reason -> {error, Reason}
    end.
