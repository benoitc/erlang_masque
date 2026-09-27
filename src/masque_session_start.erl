%%% Deferred start of h2 and h1 server sessions.
%%%
%%% A session supervisor starts its children with
%%% `supervisor:start_child/2`, which waits for the child's `init/1`.
%%% The handler's `init/2` can take seconds (a TCP connect, DNS, a
%%% relay's upstream connect), so running it there would serialise
%%% every session start of that protocol behind the slowest one, and a
%%% same-node relay would wait on its own supervisor.
%%%
%%% Instead, when the listener passes `starter => {Pid, Ref}`, the
%%% session's `init/1` returns at once with `{continue, start}` and
%%% does the real work in `handle_continue/2`, then reports the outcome
%%% to the listener with `{masque_session_started, Ref, Result}`:
%%%
%%% - `ok`: the tunnel is open;
%%% - `{error, Reason}`: nothing was sent, the listener rejects;
%%% - `{error, {responded, Reason}}`: the 2xx (or 101/200) already went
%%%   out, the listener stays silent.
%%%
%%% The h3 path does not use this: its router already starts sessions
%%% from a worker (`masque_server_connection`).
-module(masque_session_start).
-moduledoc false.

-export([deferred/1, report/2, abandon/1, await/2]).

-define(START_TIMEOUT, 30000).

-type result() :: ok | {error, term()}.

-export_type([result/0]).

%% True when the listener asked for a deferred start.
-spec deferred(map()) -> boolean().
deferred(#{starter := {Pid, Ref}}) when is_pid(Pid), is_reference(Ref) -> true;
deferred(_Args) -> false.

%% Tell the listener how the start went.
-spec report(map(), result()) -> ok.
report(#{starter := {Pid, Ref}}, Result) ->
    Pid ! {masque_session_started, Ref, Result},
    ok;
report(_Args, _Result) ->
    ok.

%% A session that never got past its start still holds the h2
%% per-connection tunnel slot the listener reserved.
-spec abandon(map()) -> ok.
abandon(#{transport := h2, conn := Conn}) ->
    masque_h2_server:release_tunnel(Conn);
abandon(_Args) ->
    ok.

%% Start a session through `StartFun(Args)` (a supervisor call) and
%% wait for its report. On a timeout the session is killed; it never
%% ran `terminate/2`, so the caller releases what it reserved.
-spec await(fun((map()) -> {ok, pid()} | {error, term()}), map()) ->
    ok | {error, term()}.
await(StartFun, Args) ->
    Ref = make_ref(),
    case StartFun(Args#{starter => {self(), Ref}}) of
        {ok, Pid} ->
            MRef = erlang:monitor(process, Pid),
            receive
                {masque_session_started, Ref, Result} ->
                    erlang:demonitor(MRef, [flush]),
                    Result;
                {'DOWN', MRef, process, Pid, Reason} ->
                    {error, {session_crash, Reason}}
            after ?START_TIMEOUT ->
                erlang:demonitor(MRef, [flush]),
                exit(Pid, kill),
                {error, {start_timeout, killed}}
            end;
        {error, _} = Err ->
            Err
    end.
