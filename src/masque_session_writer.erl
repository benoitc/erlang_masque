%%% Writes a server session makes on behalf of a handler call.
%%%
%%% A write to the tunnel blocks until the transport takes it
%%% (`masque_stream_send', or the TLS socket on h1). Made by the session
%%% itself, it would stop the session reading: a reverse connect edge
%%% stream that sends would no longer deliver what the agent sends back,
%%% nor take the `consumed' calls that give the agent credit, and an
%%% agent that echoes would deadlock against it. So the writes of a
%%% handler call (the stream API of a reverse connect accept stream) run
%%% here, in order, one call at a time. The caller still waits for its
%%% write; the writer replies to it and then tells the session
%%% (`{masque_writer_done, Ref, Result}'), which runs the call's
%%% remaining actions.
%%%
%%% On h3 the writer makes the refused write itself, so it is the process
%%% quic_h3 tells about `send_ready'.
-module(masque_session_writer).
-moduledoc false.

-export([start_link/1, write/5, stop/1]).
-export_type([write_fun/0]).

%% The writer is linked to its session; this is only a safety net.
-define(CHECK_MS, 30000).

-type write_fun() :: fun((binary(), boolean()) -> ok | {error, term()}).

%% Start a writer for the calling session. `Write(Bytes, Fin)' puts
%% one chunk on the tunnel.
-spec start_link(write_fun()) -> pid().
start_link(Write) ->
    Session = self(),
    spawn_link(fun() -> loop(Session, Write) end).

%% Queue `Items' (`{Bytes, Fin}') for the tunnel. The writer replies
%% `Reply' to `From' once all are written, `{error, closed}' if one
%% fails, then sends `{masque_writer_done, Ref, ok | {error, R}}' to
%% the session.
-spec write(pid(), reference(), gen_server:from(), term(), [{binary(), boolean()}]) -> ok.
write(Writer, Ref, From, Reply, Items) ->
    Writer ! {write, Ref, From, Reply, Items},
    ok.

-spec stop(pid() | undefined) -> ok.
stop(undefined) ->
    ok;
stop(Writer) ->
    unlink(Writer),
    exit(Writer, kill),
    ok.

loop(Session, Write) ->
    receive
        {write, Ref, From, Reply, Items} ->
            Result = run(Items, Write),
            gen_server:reply(
                From,
                case Result of
                    ok -> Reply;
                    {error, _} -> {error, closed}
                end
            ),
            Session ! {masque_writer_done, Ref, Result},
            loop(Session, Write)
    after ?CHECK_MS ->
        case is_process_alive(Session) of
            true -> loop(Session, Write);
            false -> ok
        end
    end.

run([], _Write) ->
    ok;
run([{Bytes, Fin} | Rest], Write) ->
    try Write(Bytes, Fin) of
        ok -> run(Rest, Write);
        {error, _} = Err -> Err
    catch
        Class:Reason -> {error, {Class, Reason}}
    end.
