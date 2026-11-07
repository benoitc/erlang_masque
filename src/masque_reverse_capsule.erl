-module(masque_reverse_capsule).
-moduledoc false.

%%% Reverse connect control capsules (draft-rosomakho-masque-reverse-connect-01
%%% sections 4.4 and 5.1): AVAILABLE_SERVICES, CONNECTION_REQUEST and
%%% CONNECTION_REQUEST_DECLINED, and the service record they carry.
%%%
%%% Encoders return the capsule value (the bytes after type and length);
%%% `encode/1' wraps it into a whole capsule. Decoders take the value and
%%% reject anything malformed or with trailing bytes, which the caller
%%% treats as a stream error (RFC 9297 section 3.3).

-include("masque_reverse.hrl").

-export([encode/1, decode/2, type/1]).
-export([encode_service/1, decode_services/1]).

-export_type([service/0, destination/0, capsule/0]).

-type destination() :: local | binary() | inet:ip4_address() | inet:ip6_address().
-type service() :: #{
    destination := destination(), protocol := tcp | udp, port := inet:port_number()
}.
-type capsule() ::
    {available_services, [service()]}
    | {connection_request, non_neg_integer(), service()}
    | {connection_request_declined, non_neg_integer()}.

%% The capsule type for a decoded capsule's tag, or `unknown'.
-spec type(non_neg_integer()) ->
    available_services | connection_request | connection_request_declined | unknown.
type(?MASQUE_CAPSULE_AVAILABLE_SERVICES) -> available_services;
type(?MASQUE_CAPSULE_CONNECTION_REQUEST) -> connection_request;
type(?MASQUE_CAPSULE_CONNECTION_REQUEST_DECLINED) -> connection_request_declined;
type(_) -> unknown.

%% A whole capsule (type, length, value), as a binary.
-spec encode(capsule()) -> binary().
encode({available_services, Services}) ->
    wrap(?MASQUE_CAPSULE_AVAILABLE_SERVICES, [encode_service(S) || S <- Services]);
encode({connection_request, Id, Service}) ->
    wrap(?MASQUE_CAPSULE_CONNECTION_REQUEST, [varint(Id), encode_service(Service)]);
encode({connection_request_declined, Id}) ->
    wrap(?MASQUE_CAPSULE_CONNECTION_REQUEST_DECLINED, varint(Id)).

wrap(Type, Value) ->
    iolist_to_binary(masque_capsule:encode(Type, Value)).

%% Decode the value of a capsule of a known type.
-spec decode(available_services | connection_request | connection_request_declined, binary()) ->
    {ok, capsule()} | {error, malformed}.
decode(available_services, Bin) ->
    case decode_services(Bin) of
        {ok, Services} -> {ok, {available_services, Services}};
        Error -> Error
    end;
decode(connection_request, Bin) ->
    case read_varint(Bin) of
        {ok, Id, Rest} ->
            case decode_service(Rest) of
                {ok, Service, <<>>} -> {ok, {connection_request, Id, Service}};
                _ -> {error, malformed}
            end;
        error ->
            {error, malformed}
    end;
decode(connection_request_declined, Bin) ->
    case read_varint(Bin) of
        {ok, Id, <<>>} -> {ok, {connection_request_declined, Id}};
        _ -> {error, malformed}
    end.

%% Section 4.4, figure 9: type, destination, protocol, port.
-spec encode_service(service()) -> iodata().
encode_service(#{destination := Dest, protocol := Proto, port := Port}) ->
    [destination(Dest), proto_byte(Proto), <<Port:16>>].

destination(local) ->
    <<?MASQUE_DEST_LOCAL>>;
destination({A, B, C, D}) ->
    <<?MASQUE_DEST_IPV4, A, B, C, D>>;
destination({_, _, _, _, _, _, _, _} = IP) ->
    <<?MASQUE_DEST_IPV6, (<<<<X:16>> || X <- tuple_to_list(IP)>>)/binary>>;
destination(Host) when is_binary(Host) ->
    [<<?MASQUE_DEST_HOSTNAME>>, varint(byte_size(Host)), Host].

proto_byte(tcp) -> 6;
proto_byte(udp) -> 17.

-spec decode_services(binary()) -> {ok, [service()]} | {error, malformed}.
decode_services(Bin) ->
    decode_services(Bin, []).

decode_services(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
decode_services(Bin, Acc) ->
    case decode_service(Bin) of
        {ok, Service, Rest} -> decode_services(Rest, [Service | Acc]);
        error -> {error, malformed}
    end.

decode_service(<<?MASQUE_DEST_LOCAL, Rest/binary>>) ->
    proto_port(local, Rest);
decode_service(<<?MASQUE_DEST_IPV4, A, B, C, D, Rest/binary>>) ->
    proto_port({A, B, C, D}, Rest);
decode_service(<<?MASQUE_DEST_IPV6, Addr:16/binary, Rest/binary>>) ->
    proto_port(list_to_tuple([X || <<X:16>> <= Addr]), Rest);
decode_service(<<?MASQUE_DEST_HOSTNAME, Rest0/binary>>) ->
    case read_varint(Rest0) of
        {ok, Len, Rest1} when Len > 0 ->
            case Rest1 of
                <<Host:Len/binary, Rest2/binary>> ->
                    case masque_uri:valid_host(Host) of
                        true -> proto_port(Host, Rest2);
                        false -> error
                    end;
                _ ->
                    error
            end;
        _ ->
            error
    end;
decode_service(_) ->
    error.

proto_port(Dest, <<6, Port:16, Rest/binary>>) ->
    {ok, #{destination => Dest, protocol => tcp, port => Port}, Rest};
proto_port(Dest, <<17, Port:16, Rest/binary>>) ->
    {ok, #{destination => Dest, protocol => udp, port => Port}, Rest};
proto_port(_Dest, _) ->
    error.

varint(N) -> quic_varint:encode(N).

read_varint(<<0:2, V:6, Rest/binary>>) -> {ok, V, Rest};
read_varint(<<1:2, V:14, Rest/binary>>) -> {ok, V, Rest};
read_varint(<<2:2, V:30, Rest/binary>>) -> {ok, V, Rest};
read_varint(<<3:2, V:62, Rest/binary>>) -> {ok, V, Rest};
read_varint(_) -> error.
