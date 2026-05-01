%%% @doc Encode/decode the three Compression Context capsules used by
%%% Connect-UDP-Bind (draft-ietf-masque-connect-udp-listen-11
%%% sections 3.1 - 3.3):
%%%
%%% <ul>
%%%   <li>`COMPRESSION_ASSIGN' (0x11) - Context ID + IP Version +
%%%       (IP Address + UDP Port if Version != 0).</li>
%%%   <li>`COMPRESSION_ACK' (0x12) - Context ID only.</li>
%%%   <li>`COMPRESSION_CLOSE' (0x13) - Context ID only; zero is
%%%       malformed.</li>
%%% </ul>
%%%
%%% Pure data: this module never touches state, transports or
%%% sessions. It only encodes / decodes wire bytes and validates the
%%% structural rules the draft pins on these capsule bodies.
%%% Lifecycle invariants (singleton uncompressed, parity, per-tuple
%%% uniqueness, post-close prohibition, ACK accounting) live in
%%% `masque_compression_table'.
-module(masque_compression_capsule).

-export([encode/1, encode/2,
         encode_assign/1, encode_ack/1, encode_close/1]).
-export([decode_body/2,
         decode_assign/1, decode_ack/1, decode_close/1]).

-include("masque_udp_bind.hrl").

-type capsule_record() ::
      #compression_assign{}
    | #compression_ack{}
    | #compression_close{}.

-type decode_error() ::
      truncated
    | malformed_varint
    | bad_ip_version
    | zero_context_id
    | trailing_bytes
    | bad_ip_address
    | bad_udp_port.

-export_type([capsule_record/0, decode_error/0]).

%%====================================================================
%% Capsule-level encode (record -> framed capsule iodata)
%%====================================================================

%% @doc Encode a typed capsule record onto the RFC 9297 capsule
%% frame.
-spec encode(capsule_record()) -> iodata().
encode(#compression_assign{} = R) ->
    masque_capsule:encode(?MASQUE_CAPSULE_COMPRESSION_ASSIGN,
                          encode_assign(R));
encode(#compression_ack{} = R) ->
    masque_capsule:encode(?MASQUE_CAPSULE_COMPRESSION_ACK,
                          encode_ack(R));
encode(#compression_close{} = R) ->
    masque_capsule:encode(?MASQUE_CAPSULE_COMPRESSION_CLOSE,
                          encode_close(R)).

%% @doc Convenience: encode the body for a given capsule type atom.
-spec encode(assign | ack | close, capsule_record()) -> binary().
encode(assign, R) -> encode_assign(R);
encode(ack,    R) -> encode_ack(R);
encode(close,  R) -> encode_close(R).

%%====================================================================
%% Body encode
%%====================================================================

-spec encode_assign(#compression_assign{}) -> binary().
encode_assign(#compression_assign{context_id = Id,
                                  ip_version = 0,
                                  address    = undefined,
                                  port       = undefined})
  when is_integer(Id), Id > 0 ->
    iolist_to_binary([quic_varint:encode(Id), <<0:8>>]);
encode_assign(#compression_assign{context_id = Id,
                                  ip_version = 4,
                                  address    = {A,B,C,D},
                                  port       = Port})
  when is_integer(Id), Id > 0,
       is_integer(Port), Port >= 0, Port =< 65535 ->
    iolist_to_binary(
      [quic_varint:encode(Id),
       <<4:8, A:8, B:8, C:8, D:8, Port:16>>]);
encode_assign(#compression_assign{context_id = Id,
                                  ip_version = 6,
                                  address    = Addr,
                                  port       = Port})
  when is_integer(Id), Id > 0,
       is_tuple(Addr), tuple_size(Addr) =:= 8,
       is_integer(Port), Port >= 0, Port =< 65535 ->
    iolist_to_binary(
      [quic_varint:encode(Id),
       <<6:8>>, v6_bin(Addr), <<Port:16>>]).

-spec encode_ack(#compression_ack{}) -> binary().
encode_ack(#compression_ack{context_id = Id})
  when is_integer(Id), Id > 0 ->
    iolist_to_binary(quic_varint:encode(Id)).

-spec encode_close(#compression_close{}) -> binary().
encode_close(#compression_close{context_id = Id})
  when is_integer(Id), Id > 0 ->
    iolist_to_binary(quic_varint:encode(Id)).

%%====================================================================
%% Body decode
%%====================================================================

%% @doc Decode the body bytes of a Compression Context capsule into
%% the matching record. The capsule type is determined by the caller
%% from the capsule frame.
-spec decode_body(non_neg_integer(), binary()) ->
    {ok, capsule_record()} | {error, decode_error()}.
decode_body(?MASQUE_CAPSULE_COMPRESSION_ASSIGN, Body) ->
    decode_assign(Body);
decode_body(?MASQUE_CAPSULE_COMPRESSION_ACK, Body) ->
    decode_ack(Body);
decode_body(?MASQUE_CAPSULE_COMPRESSION_CLOSE, Body) ->
    decode_close(Body);
decode_body(_Type, _Body) ->
    {error, bad_ip_version}.    %% caller should not have routed here

-spec decode_assign(binary()) ->
    {ok, #compression_assign{}} | {error, decode_error()}.
decode_assign(Body) ->
    try
        {Id, Rest1} = decode_varint(Body),
        check_nonzero_id(Id),
        case Rest1 of
            <<0:8>> ->
                {ok, #compression_assign{
                        context_id = Id,
                        ip_version = 0,
                        address    = undefined,
                        port       = undefined}};
            <<0:8, _/binary>> ->
                throw(trailing_bytes);
            <<4:8, A:8, B:8, C:8, D:8, Port:16>> ->
                check_port(Port),
                {ok, #compression_assign{
                        context_id = Id,
                        ip_version = 4,
                        address    = {A,B,C,D},
                        port       = Port}};
            <<4:8, _/binary>> ->
                throw(truncated);
            <<6:8, V6:16/binary, Port:16>> ->
                check_port(Port),
                Addr = v6_tuple(V6),
                {ok, #compression_assign{
                        context_id = Id,
                        ip_version = 6,
                        address    = Addr,
                        port       = Port}};
            <<6:8, _/binary>> ->
                throw(truncated);
            <<Ver:8, _/binary>> when Ver =/= 0, Ver =/= 4, Ver =/= 6 ->
                throw(bad_ip_version);
            _ ->
                throw(truncated)
        end
    catch
        throw:Reason -> {error, Reason}
    end.

-spec decode_ack(binary()) ->
    {ok, #compression_ack{}} | {error, decode_error()}.
decode_ack(Body) ->
    try
        {Id, Rest} = decode_varint(Body),
        check_nonzero_id(Id),
        case Rest of
            <<>> -> {ok, #compression_ack{context_id = Id}};
            _    -> throw(trailing_bytes)
        end
    catch
        throw:Reason -> {error, Reason}
    end.

-spec decode_close(binary()) ->
    {ok, #compression_close{}} | {error, decode_error()}.
decode_close(Body) ->
    try
        {Id, Rest} = decode_varint(Body),
        check_nonzero_id(Id),
        case Rest of
            <<>> -> {ok, #compression_close{context_id = Id}};
            _    -> throw(trailing_bytes)
        end
    catch
        throw:Reason -> {error, Reason}
    end.

%%====================================================================
%% Internal
%%====================================================================

decode_varint(Bin) ->
    try
        quic_varint:decode(Bin)
    catch
        error:_ -> throw(malformed_varint)
    end.

check_nonzero_id(0) -> throw(zero_context_id);
check_nonzero_id(N) when is_integer(N), N > 0 -> ok.

check_port(P) when is_integer(P), P >= 0, P =< 65535 -> ok;
check_port(_) -> throw(bad_udp_port).

v6_bin({A,B,C,D,E,F,G,H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

v6_tuple(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    {A,B,C,D,E,F,G,H}.
