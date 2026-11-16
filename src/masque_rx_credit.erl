%%% Receive credit for one CONNECT-TCP stream with manual flow control.
%%%
%%% A session gives the peer credit back (`quic_h3:consume/3',
%%% `h2:consume/3') only once it is done with the bytes, so a slow
%%% consumer stops the peer after one stream window.
%%%
%%% h2 sends a WINDOW_UPDATE for every `consume'. Capsules do not line up
%%% with h2 frames, so credit would come back in few-byte pieces and a
%%% blocked peer would answer each with a few-byte DATA frame (silly
%%% window). Credit is returned once a step has built up: a full frame
%%% (16 KB), or half the stream window when the window is smaller, so the
%%% peer always has room to go on meanwhile. h3 credit goes back at once.
%%%
%%% Each session process serves one stream, so the pending credit lives in
%%% the process dictionary under a key private to this module.
-module(masque_rx_credit).
-moduledoc false.

-export([init/2, consume/4, step/1]).

-define(PENDING_KEY, {?MODULE, pending}).
-define(STEP_KEY, {?MODULE, step}).
-define(FRAME, 16384).
-define(DEFAULT_WINDOW, 65535).

%% Set the h2 step from the stream window this end advertises.
-spec init(h3 | h2, pid() | undefined) -> ok.
init(h2, Conn) when is_pid(Conn) ->
    put(?STEP_KEY, step(local_window(Conn))),
    ok;
init(_Transport, _Conn) ->
    ok.

%% Return `N' bytes of credit to the peer (batched on h2). The stream
%% may already be gone: that is not an error.
-spec consume(h3 | h2, pid(), non_neg_integer(), non_neg_integer()) -> ok.
consume(_Transport, _Conn, _Sid, 0) ->
    ok;
consume(h3, Conn, Sid, N) ->
    try
        _ = quic_h3:consume(Conn, Sid, N),
        ok
    catch
        exit:_ -> ok
    end;
consume(h2, Conn, Sid, N) ->
    Pending = pending() + N,
    case Pending >= get_step() of
        true ->
            put(?PENDING_KEY, 0),
            try
                _ = h2:consume(Conn, Sid, Pending),
                ok
            catch
                exit:_ -> ok
            end;
        false ->
            put(?PENDING_KEY, Pending),
            ok
    end.

%% The h2 credit step for a stream window.
-spec step(non_neg_integer()) -> pos_integer().
step(Window) ->
    min(?FRAME, max(1, Window div 2)).

local_window(Conn) ->
    try h2:get_settings(Conn) of
        #{initial_window_size := W} when is_integer(W) -> W;
        _ -> ?DEFAULT_WINDOW
    catch
        exit:_ -> ?DEFAULT_WINDOW
    end.

pending() ->
    case get(?PENDING_KEY) of
        undefined -> 0;
        N -> N
    end.

get_step() ->
    case get(?STEP_KEY) of
        undefined -> step(?DEFAULT_WINDOW);
        S -> S
    end.
