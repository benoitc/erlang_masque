%%% @doc Encode/decode the inner Bound UDP Proxying Payload, the
%%% bytes that follow the HTTP Datagram Context ID. Per
%%% draft-ietf-masque-connect-udp-listen-11 sections 4 (uncompressed)
%%% and 5 (compressed):
%%%
%%% <ul>
%%%   <li><b>Compressed</b> form: the payload is the UDP payload bytes
%%%       only. The peer tuple is implicit in the receiver's
%%%       compression-table entry for the Context ID the datagram
%%%       arrived on.</li>
%%%   <li><b>Uncompressed</b> form:
%%%       `IP Version (8) || IP Address (32 or 128) || UDP Port (16) ||
%%%        UDP Payload (..)'.
%%%       Network byte order. IP Version is 4 or 6 (IP Version 0 is
%%%       used in `COMPRESSION_ASSIGN' to *register* the uncompressed
%%%       channel, but the on-wire payloads on it carry a real
%%%       4 or 6 here).</li>
%%% </ul>
%%%
%%% This module never sees the Context ID; that is consumed by
%%% `masque_datagram' one layer above. The session is responsible for
%%% looking the Context ID up in its compression table and dispatching
%%% to the right shape (compressed vs uncompressed) based on the
%%% registered IP Version of the entry.
%%%
%%% Pure module - no I/O, no state. Address-family gating is enforced
%%% on encode using the advertised public-address families.
-module(masque_udp_bind_payload).

-export([encode_compressed/1,
         encode_uncompressed/3,
         decode_compressed/1,
         decode_uncompressed/1,
         family_advertised/2]).

-type families() :: [4 | 6].
-type encode_error() :: unadvertised_family.
-type decode_error() ::
      truncated
    | bad_ip_version
    | bad_udp_port.

-export_type([families/0, encode_error/0, decode_error/0]).

%%====================================================================
%% Encode
%%====================================================================

%% @doc Encode a payload onto a compressed Context ID. The IP-port
%% tuple is implicit (the receiver looks it up in its table).
%% Caller is expected to have verified the family is advertised via
%% `family_advertised/2' before invoking this.
-spec encode_compressed(binary()) -> binary().
encode_compressed(UdpPayload) when is_binary(UdpPayload) ->
    UdpPayload.

%% @doc Encode a payload onto an uncompressed Context ID. The peer
%% tuple is carried inline. Address family must be in the advertised
%% list.
-spec encode_uncompressed(
        {4 | 6, inet:ip_address(), inet:port_number()},
        binary(),
        families()) ->
    {ok, binary()} | {error, encode_error()}.
encode_uncompressed({V, _, _}, _Payload, Fams)
  when V =/= 4, V =/= 6 ->
    %% defensive; spec only allows 4 / 6 in the wire IP Version
    case lists:member(V, Fams) of
        true  -> {error, bad_ip_version};
        false -> {error, unadvertised_family}
    end;
encode_uncompressed({V, IP, Port}, Payload, Fams)
  when (V =:= 4 orelse V =:= 6),
       is_integer(Port), Port >= 0, Port =< 65535,
       is_binary(Payload) ->
    case lists:member(V, Fams) of
        false -> {error, unadvertised_family};
        true  -> {ok, build_uncompressed(V, IP, Port, Payload)}
    end.

%%====================================================================
%% Decode
%%====================================================================

%% @doc Decode a compressed payload (just the UDP bytes). Trivial;
%% provided for symmetry with `decode_uncompressed/1'.
-spec decode_compressed(binary()) -> {ok, binary()}.
decode_compressed(Payload) when is_binary(Payload) ->
    {ok, Payload}.

%% @doc Decode an uncompressed payload into the carried peer tuple
%% and the inner UDP bytes.
-spec decode_uncompressed(binary()) ->
    {ok, {4 | 6, inet:ip_address(), inet:port_number()}, binary()}
  | {error, decode_error()}.
decode_uncompressed(<<4:8, A:8, B:8, C:8, D:8, Port:16, Payload/binary>>) ->
    case Port of
        P when P >= 0, P =< 65535 ->
            {ok, {4, {A,B,C,D}, P}, Payload};
        _ ->
            {error, bad_udp_port}
    end;
decode_uncompressed(<<4:8, _/binary>>) ->
    {error, truncated};
decode_uncompressed(<<6:8, V6:16/binary, Port:16, Payload/binary>>) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>> = V6,
    case Port of
        P when P >= 0, P =< 65535 ->
            {ok, {6, {A,B,C,D,E,F,G,H}, P}, Payload};
        _ ->
            {error, bad_udp_port}
    end;
decode_uncompressed(<<6:8, _/binary>>) ->
    {error, truncated};
decode_uncompressed(<<Ver:8, _/binary>>) when Ver =/= 4, Ver =/= 6 ->
    {error, bad_ip_version};
decode_uncompressed(_) ->
    {error, truncated}.

%%====================================================================
%% Family gating helper
%%====================================================================

%% @doc Returns true iff the given IP version is in the advertised
%% list. Both encode paths consult this, and the session uses it on
%% incoming uncompressed payloads to drop those whose family is not
%% advertised (e.g. a peer reaching us over an IPv4-only proxy with
%% an IPv6 source somehow set).
-spec family_advertised(4 | 6, families()) -> boolean().
family_advertised(V, Fams) when is_integer(V), is_list(Fams) ->
    lists:member(V, Fams).

%%====================================================================
%% Internal
%%====================================================================

build_uncompressed(4, {A,B,C,D}, Port, Payload) ->
    <<4:8, A:8, B:8, C:8, D:8, Port:16, Payload/binary>>;
build_uncompressed(6, {A,B,C,D,E,F,G,H}, Port, Payload) ->
    <<6:8, A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16,
      Port:16, Payload/binary>>.
