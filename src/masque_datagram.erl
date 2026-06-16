%%% @doc RFC 9298 section 5 - inner framing for HTTP Datagrams.
%%%
%%% On top of the HTTP/3 datagram delivery (RFC 9297, already handled
%%% by `quic_h3'), each MASQUE payload is preceded by a Context ID
%%% varint. Context 0 carries raw UDP payloads; non-zero contexts are
%%% reserved for future extensions (compression, ICMP, QUIC-aware
%%% proxying).
-module(masque_datagram).

-export([encode/2, decode/1]).

-export_type([context_id/0]).

-type context_id() :: non_neg_integer().

-include("masque.hrl").

%% @doc Build the HTTP Datagram payload for `Payload' carried under
%% context `ContextId'. Returns an iolist.
-spec encode(context_id(), iodata()) -> iodata().
encode(ContextId, Payload) when is_integer(ContextId), ContextId >= 0 ->
    [quic_varint:encode(ContextId), Payload].

%% @doc Decode an HTTP Datagram payload.
-spec decode(binary()) ->
    {ok, {context_id(), binary()}} | {error, malformed_varint}.
decode(Bin) when is_binary(Bin) ->
    try
        {ContextId, Rest} = quic_varint:decode(Bin),
        {ok, {ContextId, Rest}}
    catch
        error:{incomplete, _} -> {error, malformed_varint};
        error:badarg -> {error, malformed_varint}
    end.
