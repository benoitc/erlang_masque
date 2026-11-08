-module(masque_out).
-moduledoc false.

%%% Writes on an HTTP/3 or HTTP/2 stream from a server session's traffic
%%% path.
%%% The connection can be gone (the peer dropped it) while packets from
%%% the target are still queued in the session, before the close reaches
%%% it. A plain `quic_h3' call would then exit the session with `noproc'
%%% and an error report per tunnel; here the write fails quietly and the
%%% session is asked to stop with `connection_closed', as when the router
%%% reports the close.

-export([send_datagram/3, send_data/4, max_datagram_size/2, h2_send_data/4]).

-spec send_datagram(pid(), non_neg_integer(), iodata()) -> ok | {error, term()}.
send_datagram(Conn, StreamId, Data) ->
    guard(fun() -> quic_h3:send_datagram(Conn, StreamId, Data) end, {error, closed}).

-spec send_data(pid(), non_neg_integer(), iodata(), boolean()) -> ok | {error, term()}.
send_data(Conn, StreamId, Data, Fin) ->
    guard(fun() -> quic_h3:send_data(Conn, StreamId, Data, Fin) end, {error, closed}).

%% 0 means "no limit known", as `quic_h3' reports when datagrams are off.
-spec max_datagram_size(pid(), non_neg_integer()) -> non_neg_integer().
max_datagram_size(Conn, StreamId) ->
    guard(fun() -> quic_h3:max_datagram_size(Conn, StreamId) end, 0).

-spec h2_send_data(pid(), non_neg_integer(), iodata(), boolean()) -> ok | {error, term()}.
h2_send_data(Conn, StreamId, Data, Fin) ->
    guard(fun() -> h2:send_data(Conn, StreamId, Data, Fin) end, {error, closed}).

guard(Fun, Gone) ->
    try
        Fun()
    catch
        exit:_ ->
            gen_server:cast(self(), connection_closed),
            Gone
    end.
