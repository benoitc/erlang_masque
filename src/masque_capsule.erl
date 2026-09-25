%%% @doc MASQUE capsule registry.
%%%
%%% Capsules are reliable framed units carried on the CONNECT-UDP
%%% request/response stream body. The wire codec is the one from
%%% `quic_h3_capsule' (RFC 9297 section 3.2); this module adds a
%%% small registry identifying which capsule types MASQUE handles
%%% natively.
%%%
%%% RFC 9297 section 3.3 requires unknown capsule types to be
%%% silently ignored by the receiver. The known set is the capsules
%%% this library implements: DATAGRAM (RFC 9297), the CONNECT-IP
%%% capsules (RFC 9484) and the Connect-UDP-Bind compression capsules.
-module(masque_capsule).

-export([encode/2, decode/1, known/1]).

-include("masque_ip.hrl").
-include("masque_udp_bind.hrl").

%% RFC 9297 section 3.5: DATAGRAM capsule.
-define(CAPSULE_DATAGRAM, 16#00).

-export_type([type/0, value/0]).

-type type() :: non_neg_integer().
-type value() :: binary().

%% @doc Encode a single capsule.
-spec encode(type(), iodata()) -> iodata().
encode(Type, Value) ->
    quic_h3_capsule:encode(Type, Value).

%% @doc Decode a single capsule from the head of `Bin'.
-spec decode(binary()) ->
    {ok, {type(), value(), binary()}}
    | {more, non_neg_integer()}
    | {error, term()}.
decode(Bin) ->
    quic_h3_capsule:decode(Bin).

%% @doc Returns `true' for capsule types MASQUE handles natively,
%% and `false' for extension / unknown types (which must be
%% silently ignored per RFC 9297 section 3.3).
-spec known(type()) -> boolean().
known(?CAPSULE_DATAGRAM) -> true;
known(?MASQUE_CAPSULE_ADDRESS_ASSIGN) -> true;
known(?MASQUE_CAPSULE_ADDRESS_REQUEST) -> true;
known(?MASQUE_CAPSULE_ROUTE_ADVERTISEMENT) -> true;
known(?MASQUE_CAPSULE_COMPRESSION_ASSIGN) -> true;
known(?MASQUE_CAPSULE_COMPRESSION_ACK) -> true;
known(?MASQUE_CAPSULE_COMPRESSION_CLOSE) -> true;
known(_Type) -> false.
