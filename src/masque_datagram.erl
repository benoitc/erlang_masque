-module(masque_datagram).
-moduledoc """
RFC 9298 section 5 - inner framing for HTTP Datagrams.

On top of the HTTP/3 datagram delivery (RFC 9297, already handled
by `quic_h3`), each MASQUE payload is preceded by a Context ID
varint. Context 0 carries raw UDP payloads; non-zero contexts are
reserved for future extensions (compression, ICMP, QUIC-aware
proxying).
""".

-export([encode/2, decode/1, udp_payload/1]).

-export_type([context_id/0]).

-type context_id() :: non_neg_integer().

-include("masque.hrl").

-doc """
Build the HTTP Datagram payload for `Payload` carried under
context `ContextId`. Returns an iolist.
""".
-spec encode(context_id(), iodata()) -> iodata().
encode(ContextId, Payload) when is_integer(ContextId), ContextId >= 0 ->
    [quic_varint:encode(ContextId), Payload].

-doc """
Decode an HTTP Datagram payload.
""".
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

-doc """
Classify an HTTP Datagram payload received on a CONNECT-UDP stream.

Returns `{ok, Udp}` for a context-zero UDP payload, `too_large` for a
context-zero payload over 65527 bytes, which RFC 9298 section 5
requires the receiver to answer by aborting the stream, and `drop`
for an unknown context or a malformed payload, which is silently
dropped.
""".
-spec udp_payload(binary()) -> {ok, binary()} | too_large | drop.
udp_payload(Bin) ->
    case decode(Bin) of
        {ok, {?MASQUE_CONTEXT_ID_UDP, Udp}} when byte_size(Udp) =< ?MASQUE_MAX_UDP_PAYLOAD ->
            {ok, Udp};
        {ok, {?MASQUE_CONTEXT_ID_UDP, _}} ->
            too_large;
        _ ->
            drop
    end.
