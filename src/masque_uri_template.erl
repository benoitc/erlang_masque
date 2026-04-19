%%% @doc Generic URI-template engine used by MASQUE protocol facades
%%% (UDP, TCP, IP). Implements the subset of RFC 6570 that RFC 9298
%%% and RFC 9484 require: literal segments, Level-1 `{name}` path
%%% placeholders, and the Level-3 `{?name1,name2}` form operator for
%%% query strings.
%%%
%%% Two entry shapes:
%%%
%%% <ul>
%%%  <li>`parse_absolute/1' — accepts only absolute URI templates
%%%      (scheme + authority + path). Used by the CONNECT-IP
%%%      **client**, where RFC 9484 §3 requires an absolute template.</li>
%%%  <li>`parse_pattern/1' — accepts either a path+query pattern or
%%%      an absolute URI (in which case only the path+query portion
%%%      is used). Used by **servers** that match against the
%%%      `:path' pseudo-header and by legacy UDP/TCP callers that
%%%      have always accepted path-only templates.</li>
%%% </ul>
%%%
%%% The parsed result is a `template()' record that can be fed to
%%% `expand/2' and `match/2'. Variable names are atoms; variable
%%% values are always returned as binaries (percent-decoded).
-module(masque_uri_template).

-export([parse_absolute/1, parse_pattern/1]).
-export([expand/2, match/2]).
-export([authority/1, is_absolute/1]).

-export_type([template/0, segment/0, vars/0, parse_error/0]).

-record(tpl, {
    absolute  :: boolean(),
    scheme    :: binary() | undefined,
    authority :: binary() | undefined,
    segments  :: [segment()]
}).

-opaque template() :: #tpl{}.

-type segment() ::
      {literal, binary()}
    | {var, atom()}            %% Level-1 path placeholder
    | {query, [atom()]}.       %% Level-3 `{?v1,v2,...}` tail

-type vars() :: #{atom() => binary() | iodata() | integer() | atom()}.

-type parse_error() ::
      not_absolute
    | bad_template
    | bad_segment.

%%====================================================================
%% Parsing
%%====================================================================

%% @doc Parse an absolute URI template (`scheme://authority/path`).
%% Returns `{error, not_absolute}` if the template has no scheme or
%% authority.
-spec parse_absolute(binary()) -> {ok, template()} | {error, parse_error()}.
parse_absolute(Bin) when is_binary(Bin) ->
    case split_absolute(Bin) of
        {ok, Scheme, Authority, PathQuery} ->
            case parse_path_query(PathQuery) of
                {ok, Segments} ->
                    {ok, #tpl{absolute = true,
                              scheme = Scheme,
                              authority = Authority,
                              segments = Segments}};
                Err -> Err
            end;
        Err -> Err
    end.

%% @doc Parse a path+query pattern, or the path+query portion of an
%% absolute URI. Non-absolute inputs are accepted as-is.
-spec parse_pattern(binary()) -> {ok, template()} | {error, parse_error()}.
parse_pattern(Bin) when is_binary(Bin) ->
    {Scheme, Authority, PathQuery, Absolute} =
        case split_absolute(Bin) of
            {ok, S, A, P} -> {S, A, P, true};
            {error, not_absolute} -> {undefined, undefined, Bin, false}
        end,
    case parse_path_query(PathQuery) of
        {ok, Segments} ->
            {ok, #tpl{absolute = Absolute,
                      scheme = Scheme,
                      authority = Authority,
                      segments = Segments}};
        Err -> Err
    end.

-spec is_absolute(template()) -> boolean().
is_absolute(#tpl{absolute = A}) -> A.

-spec authority(template()) -> binary() | undefined.
authority(#tpl{authority = A}) -> A.

%%====================================================================
%% Expansion and matching
%%====================================================================

%% @doc Expand a template with `Vars`. Returns a binary — the full
%% URI for absolute templates, just the path+query for patterns.
-spec expand(template(), vars()) -> binary().
expand(#tpl{absolute = Absolute, scheme = Scheme,
            authority = Authority, segments = Segments}, Vars)
  when is_map(Vars) ->
    PathQuery = iolist_to_binary(expand_segments(Segments, Vars)),
    case Absolute of
        true  -> <<Scheme/binary, "://", Authority/binary, PathQuery/binary>>;
        false -> PathQuery
    end.

%% @doc Match a request `:path` against a template. Returns the
%% captured variables on success.
-spec match(template(), binary()) ->
    {ok, vars()} | {error, no_match | bad_pct}.
match(#tpl{segments = Segments}, Path) when is_binary(Path) ->
    try match_segments(Segments, Path, #{}) of
        {ok, Vars} -> {ok, Vars};
        nomatch    -> {error, no_match}
    catch
        throw:bad_pct -> {error, bad_pct}
    end.

%%====================================================================
%% Internal — URI splitting
%%====================================================================

%% Split `scheme://authority/path?query` into {Scheme, Authority,
%% PathQuery}. Returns {error, not_absolute} when the input doesn't
%% start with an unambiguous `scheme://` prefix.
split_absolute(<<"https://", Rest/binary>>) ->
    split_authority(<<"https">>, Rest);
split_absolute(<<"http://",  Rest/binary>>) ->
    split_authority(<<"http">>, Rest);
split_absolute(_) ->
    {error, not_absolute}.

split_authority(Scheme, Rest) ->
    case binary:match(Rest, <<"/">>) of
        {Pos, 1} ->
            <<Authority:Pos/binary, PathQuery/binary>> = Rest,
            case Authority of
                <<>> -> {error, not_absolute};
                _    -> {ok, Scheme, Authority, PathQuery}
            end;
        nomatch when Rest =/= <<>> ->
            %% Authority with no path → treat path as "/".
            {ok, Scheme, Rest, <<"/">>};
        nomatch ->
            {error, not_absolute}
    end.

%%====================================================================
%% Internal — segment parser
%%====================================================================

parse_path_query(Bin) ->
    try
        {ok, parse_segments(Bin, <<>>, [])}
    catch
        throw:bad_template -> {error, bad_template};
        throw:bad_segment  -> {error, bad_segment}
    end.

parse_segments(<<>>, Acc, Out) ->
    lists:reverse(emit_literal(Acc, Out));
parse_segments(<<"{?", Rest/binary>>, Acc, Out) ->
    case binary:split(Rest, <<"}">>) of
        [NamesBin, Tail] when NamesBin =/= <<>> ->
            Names = [binary_to_atom(N, utf8)
                     || N <- binary:split(NamesBin, <<",">>, [global]),
                        N =/= <<>>],
            case Names of
                [] -> throw(bad_segment);
                _  ->
                    Out1 = [{query, Names} | emit_literal(Acc, Out)],
                    parse_segments(Tail, <<>>, Out1)
            end;
        _ -> throw(bad_template)
    end;
parse_segments(<<"{", Rest/binary>>, Acc, Out) ->
    case binary:split(Rest, <<"}">>) of
        [Name, Tail] when Name =/= <<>> ->
            parse_segments(Tail, <<>>,
                           [{var, binary_to_atom(Name, utf8)}
                            | emit_literal(Acc, Out)]);
        _ -> throw(bad_template)
    end;
parse_segments(<<C, Rest/binary>>, Acc, Out) ->
    parse_segments(Rest, <<Acc/binary, C>>, Out).

emit_literal(<<>>, Out) -> Out;
emit_literal(Bin, Out)  -> [{literal, Bin} | Out].

%%====================================================================
%% Internal — expansion
%%====================================================================

expand_segments([], _Vars) -> [];
expand_segments([{literal, Bin} | Rest], Vars) ->
    [Bin | expand_segments(Rest, Vars)];
expand_segments([{var, Name} | Rest], Vars) ->
    [pct_encode_segment(to_binary(fetch_var(Name, Vars)))
     | expand_segments(Rest, Vars)];
expand_segments([{query, Names} | Rest], Vars) ->
    Pairs = [expand_query_pair(N, Vars) || N <- Names, maps:is_key(N, Vars)],
    Body = case Pairs of
               [] -> <<>>;
               _  -> iolist_to_binary(lists:join(<<"&">>, Pairs))
           end,
    case Body of
        <<>> -> expand_segments(Rest, Vars);
        _    -> [<<"?">>, Body | expand_segments(Rest, Vars)]
    end.

expand_query_pair(Name, Vars) ->
    NameBin = atom_to_binary(Name, utf8),
    ValBin = pct_encode_form(to_binary(fetch_var(Name, Vars))),
    <<NameBin/binary, "=", ValBin/binary>>.

fetch_var(Name, Vars) ->
    case maps:find(Name, Vars) of
        {ok, V} -> V;
        error   -> error({missing_var, Name})
    end.

to_binary(B) when is_binary(B) -> B;
to_binary(L) when is_list(L)   -> iolist_to_binary(L);
to_binary(I) when is_integer(I), I >= 0 -> integer_to_binary(I);
to_binary(A) when is_atom(A)   -> atom_to_binary(A, utf8).

%%====================================================================
%% Internal — matching
%%====================================================================

%% Match a path against segments. Supports up to one {query, _}
%% terminal segment; Level-1 {var, _} segments match within path
%% boundaries delimited by surrounding literals.
match_segments([], <<>>, Acc) ->
    {ok, Acc};
match_segments([], _Rem, _Acc) ->
    nomatch;
match_segments([{literal, Lit} | Rest], Path, Acc) ->
    LitSz = byte_size(Lit),
    case Path of
        <<Lit:LitSz/binary, Tail/binary>> ->
            match_segments(Rest, Tail, Acc);
        _ -> nomatch
    end;
match_segments([{var, Name}], Path, Acc) ->
    %% Trailing path variable — whole remainder (after optional query
    %% strip) is the value.
    {Value, _Query} = split_path_query(Path),
    case pct_decode(Value) of
        {ok, Decoded} when byte_size(Decoded) > 0 ->
            {ok, Acc#{Name => Decoded}};
        _ -> nomatch
    end;
match_segments([{var, Name}, {literal, NextLit} | Rest], Path, Acc) ->
    case binary:match(Path, NextLit) of
        {Pos, _} when Pos > 0 ->
            <<Raw:Pos/binary, _/binary>> = Path,
            case pct_decode(Raw) of
                {ok, Decoded} when byte_size(Decoded) > 0 ->
                    <<_:Pos/binary, Tail/binary>> = Path,
                    match_segments([{literal, NextLit} | Rest], Tail,
                                   Acc#{Name => Decoded});
                _ -> nomatch
            end;
        _ -> nomatch
    end;
match_segments([{var, _} | _], _, _) ->
    %% Two adjacent vars — ambiguous.
    throw(bad_template);
match_segments([{query, Names}], Path, Acc) ->
    %% Query-form segment consumes the rest of the path and the
    %% query string. Path portion must be empty (or have already
    %% been matched by earlier literals).
    {_, Query} = split_path_query(Path),
    case parse_query(Query, Names) of
        {ok, Vars} -> {ok, maps:merge(Acc, Vars)};
        nomatch    -> nomatch
    end;
match_segments([{query, _} | _], _, _) ->
    %% {query, _} must be terminal.
    throw(bad_template).

split_path_query(Bin) ->
    case binary:match(Bin, <<"?">>) of
        {Pos, 1} ->
            <<Path:Pos/binary, _:1/binary, Query/binary>> = Bin,
            {Path, Query};
        nomatch ->
            {Bin, <<>>}
    end.

%% Parse query string `k1=v1&k2=v2` into `#{k1 => Decoded, ...}`
%% restricted to the names listed in `Keep'. Missing keys → nomatch.
parse_query(<<>>, [])    -> {ok, #{}};
parse_query(<<>>, _Keep) -> nomatch;
parse_query(Bin, Keep) ->
    Pairs = binary:split(Bin, <<"&">>, [global]),
    try
        Vars = lists:foldl(fun(Pair, Acc) ->
            case binary:split(Pair, <<"=">>) of
                [K, V] ->
                    KA = binary_to_atom(K, utf8),
                    case lists:member(KA, Keep) of
                        true ->
                            {ok, Dec} = pct_decode_form(V),
                            Acc#{KA => Dec};
                        false -> Acc
                    end;
                _ -> throw(nomatch)
            end
        end, #{}, Pairs),
        case lists:all(fun(K) -> maps:is_key(K, Vars) end, Keep) of
            true  -> {ok, Vars};
            false -> nomatch
        end
    catch
        throw:nomatch -> nomatch;
        throw:bad_pct -> throw(bad_pct)
    end.

%%====================================================================
%% Percent encoding / decoding (RFC 3986 §2, application/x-www-form)
%%====================================================================

pct_encode_segment(Bin) ->
    << <<(pct_encode_byte(B, segment))/binary>> || <<B>> <= Bin >>.

pct_encode_form(Bin) ->
    << <<(pct_encode_byte(B, form))/binary>> || <<B>> <= Bin >>.

pct_encode_byte(B, _Ctx) when
    (B >= $A andalso B =< $Z);
    (B >= $a andalso B =< $z);
    (B >= $0 andalso B =< $9);
    B =:= $-; B =:= $.; B =:= $_; B =:= $~ ->
    <<B>>;
%% RFC 9484 uses `*` as the literal wildcard value for both
%% `target' and `ipproto'; keep it unencoded in both path and
%% query contexts. Every other reserved character follows RFC 6570
%% Level-1 "simple string expansion" and is percent-encoded.
pct_encode_byte($*, _Ctx) -> <<"*">>;
pct_encode_byte(B, _Ctx) ->
    Hi = hex_digit(B bsr 4),
    Lo = hex_digit(B band 16#0F),
    <<"%", Hi, Lo>>.

hex_digit(N) when N >= 0, N =< 9  -> N + $0;
hex_digit(N) when N >= 10, N =< 15 -> N - 10 + $A.

pct_decode(Bin) ->
    try
        {ok, iolist_to_binary(pct_decode_list(Bin))}
    catch
        throw:bad_pct -> throw(bad_pct)
    end.

%% form-urlencoded decoding: `+` → space, then percent-decode.
pct_decode_form(Bin) ->
    Bin1 = binary:replace(Bin, <<"+">>, <<" ">>, [global]),
    pct_decode(Bin1).

pct_decode_list(<<>>) -> [];
pct_decode_list(<<"%", H, L, Rest/binary>>) ->
    [<<(from_hex(H) * 16 + from_hex(L))>> | pct_decode_list(Rest)];
pct_decode_list(<<"%", _/binary>>) ->
    throw(bad_pct);
pct_decode_list(<<C, Rest/binary>>) ->
    [<<C>> | pct_decode_list(Rest)].

from_hex(C) when C >= $0, C =< $9 -> C - $0;
from_hex(C) when C >= $a, C =< $f -> C - $a + 10;
from_hex(C) when C >= $A, C =< $F -> C - $A + 10;
from_hex(_) -> throw(bad_pct).
