-module(prop_masque).

-include_lib("proper/include/proper.hrl").

-define(TPL, <<"/.well-known/masque/udp/{target_host}/{target_port}/">>).

%%====================================================================
%% Datagram context-id codec roundtrip
%%====================================================================

prop_datagram_roundtrip() ->
    ?FORALL(
        {Ctx, Payload},
        {non_neg_integer_upto(62), binary()},
        begin
            Enc = iolist_to_binary(masque_datagram:encode(Ctx, Payload)),
            {ok, {Ctx, Payload}} =:= masque_datagram:decode(Enc)
        end
    ).

%%====================================================================
%% URI template roundtrip (hostnames only - covers the most common path)
%%====================================================================

prop_uri_hostname_roundtrip() ->
    ?FORALL(
        {Host, Port},
        {hostname(), port_number()},
        begin
            Path = masque_uri:expand(
                ?TPL,
                #{
                    target_host => Host,
                    target_port => Port
                }
            ),
            case masque_uri:match(?TPL, Path) of
                {ok, #{target_host := Host, target_port := Port}} -> true;
                _ -> false
            end
        end
    ).

%%====================================================================
%% Capsule encode/decode roundtrip via masque_capsule
%%====================================================================

prop_capsule_roundtrip() ->
    ?FORALL(
        {Type, Value},
        {non_neg_integer_upto(62), binary()},
        begin
            Enc = iolist_to_binary(masque_capsule:encode(Type, Value)),
            case masque_capsule:decode(Enc) of
                {ok, {Type, Value, <<>>}} -> true;
                _ -> false
            end
        end
    ).

%%====================================================================
%% Generators
%%====================================================================

non_neg_integer_upto(Bits) ->
    ?LET(N, proper_types:integer(0, (1 bsl Bits) - 1), N).

%% A reg-name `masque_uri' accepts: dot-joined labels, each label a run
%% of letters / digits / hyphen with no leading or trailing hyphen.
hostname() ->
    ?LET(
        Labels,
        non_empty(list(label())),
        list_to_binary(lists:join(".", Labels))
    ).

label() ->
    oneof([
        ?LET(C, alnum_char(), [C]),
        ?LET(
            {First, Middle, Last},
            {alnum_char(), list(ldh_char()), alnum_char()},
            [First | Middle] ++ [Last]
        )
    ]).

alnum_char() ->
    oneof([integer($a, $z), integer($A, $Z), integer($0, $9)]).

ldh_char() ->
    oneof([integer($a, $z), integer($A, $Z), integer($0, $9), $-]).

port_number() ->
    integer(1, 65535).
