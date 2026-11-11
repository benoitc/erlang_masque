-module(masque_tcp_capsule).
-moduledoc false.

%%% Capsule framing for CONNECT-TCP (draft-ietf-httpbis-connect-tcp-18
%%% section 3.1): TCP bytes travel in DATA capsules, and FINAL_DATA
%%% carries the last bytes and the sender's FIN.
%%%
%%% Two sets of capsule codes exist. The permanent ones (DATA 0x08,
%%% FINAL_DATA 0x09) belong to the protocol token `connect-tcp' and its
%%% interop token `connect-tcp-12'. Drafts -09 and -10 used provisional
%%% codes with the tokens `connect-tcp-08' and `connect-tcp-07'; they are
%%% kept so masque can talk to implementations of those drafts.
%%%
%%% Decoding streams: payload bytes are returned as they arrive, without
%%% waiting for the end of the capsule (section 3.1 SHOULD), so a large
%%% capsule never has to fit in memory.

-include("masque.hrl").

-export([
    token_version/1,
    client_protocol/1,
    request_framing/2,
    expects_continue/1,
    encode/3,
    decoder/1,
    decode/2,
    end_of_stream/1
]).

-type version() :: final | provisional.
-type item() :: {data, binary()} | {final, binary()}.
-export_type([version/0, item/0, decoder/0]).

-record(dec, {
    data :: non_neg_integer(),
    final :: non_neg_integer(),
    %% `header': waiting for a capsule header, `buf' holds its first
    %% bytes. `{payload, Kind, Left}': `Left' payload bytes of a DATA
    %% (`data') or FINAL_DATA (`final') capsule to come. `{skip, Left}':
    %% an unknown capsule's bytes to drop (RFC 9297 section 3.3).
    phase = header ::
        header
        | {payload, data | final, non_neg_integer()}
        | {skip, non_neg_integer()},
    buf = <<>> :: binary(),
    final_seen = false :: boolean()
}).
-opaque decoder() :: #dec{}.

%% The framing and codes a protocol token asks for. `auto' means the
%% plain `connect-tcp' token, where the request headers and the
%% listener decide.
-spec token_version(binary() | undefined) -> {capsule, version()} | auto | unknown.
token_version(?MASQUE_CONNECT_TCP_PROTOCOL) -> auto;
token_version(?MASQUE_CONNECT_TCP_12_PROTOCOL) -> {capsule, final};
token_version(?MASQUE_CONNECT_TCP_08_PROTOCOL) -> {capsule, provisional};
token_version(?MASQUE_CONNECT_TCP_07_PROTOCOL) -> {capsule, provisional};
token_version(_) -> unknown.

%% What a client sends, from its `tcp_framing' and `tcp_protocol'
%% options: the framing, the protocol token and the capsule codes. The
%% default is capsule framing (draft -18, about to be published); `raw'
%% is for h3 and h2 proxies of older drafts. The h1 client starts with
%% a classic CONNECT unless told otherwise, and switches to the upgrade
%% when the proxy asks for it (426, 501). In
%% capsule framing the token defaults to `connect-tcp', the protocol's
%% registered name; `connect-tcp-12' is the draft's interop token.
-spec client_protocol(map()) -> {raw | capsule, binary(), version()}.
client_protocol(Opts) ->
    case maps:get(tcp_framing, Opts, capsule) of
        raw ->
            {raw, ?MASQUE_CONNECT_TCP_PROTOCOL, final};
        capsule ->
            Token = maps:get(tcp_protocol, Opts, ?MASQUE_CONNECT_TCP_PROTOCOL),
            case token_version(Token) of
                {capsule, Version} -> {capsule, Token, Version};
                _ -> {capsule, Token, final}
            end
    end.

%% The framing a listener uses for a plain `connect-tcp' request. `auto'
%% follows the request's `capsule-protocol' header, which the draft only
%% makes a SHOULD; `capsule' and `raw' fix it.
-spec request_framing(auto | raw | capsule, [{binary(), binary()}]) -> raw | capsule.
request_framing(auto, Headers) ->
    case lists:keyfind(<<"capsule-protocol">>, 1, Headers) of
        {_, <<"?1">>} -> capsule;
        _ -> raw
    end;
request_framing(raw, _Headers) ->
    raw;
request_framing(capsule, _Headers) ->
    capsule.

%% Whether a request carries `Expect: 100-continue'.
-spec expects_continue([{binary(), binary()}]) -> boolean().
expects_continue(Headers) ->
    lists:any(
        fun({K, V}) ->
            string:lowercase(K) =:= <<"expect">> andalso
                string:lowercase(string:trim(V)) =:= <<"100-continue">>
        end,
        Headers
    ).

%% Bytes to send, as one DATA capsule, or FINAL_DATA when they end the
%% sender's side. A binary, which the transport libraries require.
-spec encode(version(), iodata(), boolean()) -> binary().
encode(Version, Bytes, Fin) ->
    {Data, Final} = codes(Version),
    Type =
        case Fin of
            true -> Final;
            false -> Data
        end,
    iolist_to_binary(masque_capsule:encode(Type, Bytes)).

-spec decoder(version()) -> decoder().
decoder(Version) ->
    {Data, Final} = codes(Version),
    #dec{data = Data, final = Final}.

%% Decode what arrived. Payload comes back in order; `{final, P}' marks
%% the end of a FINAL_DATA capsule, the peer's FIN. DATA or FINAL_DATA
%% after FINAL_DATA is invalid (section 3.5.1).
-spec decode(decoder(), binary()) -> {ok, [item()], decoder()} | {error, data_after_final}.
decode(Dec, Bin) ->
    decode(Dec, Bin, []).

%% The stream ended: only valid on a capsule boundary (section 3.5.1,
%% a capsule truncated by the end of the stream).
-spec end_of_stream(decoder()) -> ok | {error, truncated_capsule}.
end_of_stream(#dec{phase = header, buf = <<>>}) -> ok;
end_of_stream(_) -> {error, truncated_capsule}.

codes(final) ->
    {?MASQUE_CAPSULE_DATA, ?MASQUE_CAPSULE_FINAL_DATA};
codes(provisional) ->
    {?MASQUE_CAPSULE_DATA_PROVISIONAL, ?MASQUE_CAPSULE_FINAL_DATA_PROVISIONAL}.

decode(Dec, <<>>, Acc) ->
    {ok, lists:reverse(Acc), Dec};
decode(#dec{phase = header, buf = Buf} = Dec, Bin, Acc) ->
    All = <<Buf/binary, Bin/binary>>,
    case header(All) of
        more ->
            {ok, lists:reverse(Acc), Dec#dec{buf = All}};
        {Type, Len, Rest} ->
            case kind(Type, Dec) of
                skip ->
                    decode(Dec#dec{phase = {skip, Len}, buf = <<>>}, Rest, Acc);
                _ when Dec#dec.final_seen ->
                    {error, data_after_final};
                Kind when Len =:= 0 ->
                    decode(payload_done(Kind, Dec#dec{buf = <<>>}), Rest, emit(Kind, <<>>, Acc));
                Kind ->
                    decode(Dec#dec{phase = {payload, Kind, Len}, buf = <<>>}, Rest, Acc)
            end
    end;
decode(#dec{phase = {skip, Left}} = Dec, Bin, Acc) ->
    case Bin of
        <<_:Left/binary, Rest/binary>> ->
            decode(Dec#dec{phase = header}, Rest, Acc);
        _ ->
            {ok, lists:reverse(Acc), Dec#dec{phase = {skip, Left - byte_size(Bin)}}}
    end;
decode(#dec{phase = {payload, Kind, Left}} = Dec, Bin, Acc) ->
    case Bin of
        <<Chunk:Left/binary, Rest/binary>> ->
            decode(payload_done(Kind, Dec), Rest, emit(Kind, Chunk, Acc));
        _ ->
            Dec1 = Dec#dec{phase = {payload, Kind, Left - byte_size(Bin)}},
            {ok, lists:reverse([{data, Bin} | Acc]), Dec1}
    end.

kind(Type, #dec{data = Type}) -> data;
kind(Type, #dec{final = Type}) -> final;
kind(_Type, _Dec) -> skip.

payload_done(final, Dec) -> Dec#dec{phase = header, final_seen = true};
payload_done(data, Dec) -> Dec#dec{phase = header}.

emit(data, <<>>, Acc) -> Acc;
emit(data, Chunk, Acc) -> [{data, Chunk} | Acc];
emit(final, Chunk, Acc) -> [{final, Chunk} | Acc].

%% A capsule header: type and length, both QUIC varints (RFC 9297
%% section 3.2).
header(Bin) ->
    case varint(Bin) of
        {Type, Rest} ->
            case varint(Rest) of
                {Len, Rest2} -> {Type, Len, Rest2};
                more -> more
            end;
        more ->
            more
    end.

varint(<<0:2, V:6, Rest/binary>>) -> {V, Rest};
varint(<<1:2, V:14, Rest/binary>>) -> {V, Rest};
varint(<<2:2, V:30, Rest/binary>>) -> {V, Rest};
varint(<<3:2, V:62, Rest/binary>>) -> {V, Rest};
varint(_) -> more.
