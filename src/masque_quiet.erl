-module(masque_quiet).
-moduledoc false.

%%% Quiet exits for sessions.
%%%
%%% A session that ends because the target closed, the peer reset, a
%%% timer ran out or the client sent bad data has not crashed, yet a
%%% gen_server or gen_statem that stops with such a reason is logged as
%%% one. On a busy proxy that is one error report per finished tunnel.
%%%
%%% Sessions pass their callback results through `stop/1', which turns
%%% an explicit stop reason into `{shutdown, {masque_quiet, Reason}}', an
%%% exit OTP does not report. `normal', `shutdown' and `{shutdown, _}'
%%% are quiet already. A handler crash (`{handler_crash, _}') is logged
%%% once, with its stack, where the session catches it (`safe_apply'),
%%% so its exit is quiet too: otherwise OTP and the supervisor report it
%%% twice more. A handler that returns a bad value from `init'
%%% (`{bad_init, _}') stays loud. Exceptions never pass through here, so
%%% a real crash is still reported. Everything that reads an exit reason
%%% (`terminate', the h3 router, callers of a session) calls `reason/1'
%%% to get the original back.

-export([stop/1, reason/1]).

%% A gen_server or gen_statem callback result.
-spec stop(T) -> T.
stop({stop, Reason}) ->
    {stop, wrap(Reason)};
stop({stop, Reason, State}) ->
    {stop, wrap(Reason), State};
stop({stop, Reason, Reply, State}) ->
    {stop, wrap(Reason), Reply, State};
stop({stop_and_reply, Reason, Replies}) ->
    {stop_and_reply, wrap(Reason), Replies};
stop({stop_and_reply, Reason, Replies, Data}) ->
    {stop_and_reply, wrap(Reason), Replies, Data};
stop(Other) ->
    Other.

-spec reason(term()) -> term().
reason({shutdown, {masque_quiet, Reason}}) -> Reason;
reason(Reason) -> Reason.

wrap(normal) -> normal;
wrap(shutdown) -> shutdown;
wrap({shutdown, _} = R) -> R;
wrap({bad_init, _} = R) -> R;
wrap(Reason) -> {shutdown, {masque_quiet, Reason}}.
