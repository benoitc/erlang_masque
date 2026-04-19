%%% @doc MASQUE capsule registry.
%%%
%%% Capsules are reliable framed units carried on the CONNECT-UDP
%%% request/response stream body. The wire codec is the one from
%%% `quic_h3_capsule' (RFC 9297 section 3.2); this module adds a
%%% small registry identifying which capsule types MASQUE handles
%%% natively.
%%%
%%% RFC 9297 section 3.3 requires unknown capsule types to be
%%% silently ignored by the receiver, so the default set below is
%%% intentionally empty - RFC 9298 does not define any mandatory
%%% capsules. Extension RFCs (compressed datagrams, QUIC-aware
%%% proxying) can be added here as the library grows.
-module(masque_capsule).

-export([encode/2, decode/1, known/1]).

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
known(_Type) ->
    %% RFC 9298 defines no mandatory capsule types. Override by editing
    %% this clause when adding extension support.
    false.
