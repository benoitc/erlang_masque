-module(masque_tcp_capsule).
-moduledoc false.

%%% Capsule framing for CONNECT-TCP as in draft-ietf-httpbis-connect-tcp-10
%%% (section 3): TCP bytes travel in DATA capsules, and FINAL_DATA carries
%%% the last bytes and the sender's FIN.

-include("masque.hrl").

-export([request_framing/1, request_framing/2, encode/2, decode/3]).

-type item() :: {data, binary()} | {final, binary()}.
-export_type([item/0]).

%% The framing a listener uses for a request. `auto' follows the
%% request's `capsule-protocol' header; `capsule' and `raw' fix it, for a
%% listener that only serves -10 clients, which may leave the header out
%% (the draft only says SHOULD), or only older ones.
-spec request_framing(auto | raw | capsule, [{binary(), binary()}]) -> raw | capsule.
request_framing(auto, Headers) -> request_framing(Headers);
request_framing(raw, _Headers) -> raw;
request_framing(capsule, _Headers) -> capsule.

%% A request asks for capsule framing with `capsule-protocol: ?1'.
-spec request_framing([{binary(), binary()}]) -> raw | capsule.
request_framing(Headers) ->
    case lists:keyfind(<<"capsule-protocol">>, 1, Headers) of
        {_, <<"?1">>} -> capsule;
        _ -> raw
    end.

%% Bytes to send, as one DATA capsule, or FINAL_DATA when they end the
%% sender's side.
%% A binary, which the transport libraries require.
-spec encode(iodata(), boolean()) -> binary().
encode(Bytes, false) ->
    iolist_to_binary(masque_capsule:encode(?MASQUE_CAPSULE_DATA, Bytes));
encode(Bytes, true) ->
    iolist_to_binary(masque_capsule:encode(?MASQUE_CAPSULE_FINAL_DATA, Bytes)).

%% Decode the complete capsules at the head of `Buf'. Returns the DATA
%% and FINAL_DATA payloads in order and the bytes of a capsule still
%% being received. Other capsule types are skipped (RFC 9297 section 3.3).
-spec decode(binary(), binary(), pos_integer()) ->
    {ok, [item()], binary()} | {error, term()}.
decode(Buf, Bin, Max) ->
    decode_loop(<<Buf/binary, Bin/binary>>, Max, []).

decode_loop(Buf, Max, Acc) ->
    case masque_capsule:decode(Buf) of
        {ok, {?MASQUE_CAPSULE_DATA, Value, Rest}} ->
            decode_loop(Rest, Max, [{data, Value} | Acc]);
        {ok, {?MASQUE_CAPSULE_FINAL_DATA, Value, Rest}} ->
            decode_loop(Rest, Max, [{final, Value} | Acc]);
        {ok, {_Other, _Value, Rest}} ->
            decode_loop(Rest, Max, Acc);
        {more, _} ->
            case masque_capsule:pending_size(Buf) > Max of
                true -> {error, capsule_buffer_overflow};
                false -> {ok, lists:reverse(Acc), Buf}
            end;
        {error, Reason} ->
            {error, Reason}
    end.
