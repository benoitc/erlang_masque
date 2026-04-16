%%% @doc URI template handling for RFC 9298 CONNECT-UDP.
%%%
%%% RFC 9298 §3 defines the request path as the expansion of a URI
%%% template with two variables - `target_host` and `target_port`.
%%% `target_host` may be an IPv4 literal, an IPv6 literal, or a
%%% registered name; colons and any non-unreserved characters are
%%% percent-encoded on the wire.
%%%
%%% This module implements the subset of RFC 6570 Level 2 we need:
%%% templates made of literal segments interleaved with `{Name}`
%%% placeholders. Level 2 reserved-expansion (`{+var}`) and higher
%%% operators are not supported.
-module(masque_uri).

-export([expand/2, match/2, to_path/1, valid_host/1]).

-export_type([template/0, vars/0]).

-type template() :: binary().
-type vars() :: #{target_host := binary() | string(),
                  target_port := 1..65535}.

%%====================================================================
%% API
%%====================================================================

%% @doc Expand a URI template using `Vars`. Returns the absolute path
%% to place in the `:path` pseudo-header. Absolute `http(s)://…`
%% templates are accepted - only the path-and-onwards portion is
%% expanded, mirroring what servers actually match at runtime.
-spec expand(template(), vars()) -> binary().
expand(Template, Vars) when is_binary(Template), is_map(Vars) ->
    iolist_to_binary(expand_parts(parse(to_path(Template)), Vars)).

%% @doc Match a request path against a template.
%%
%% Returns `{ok, #{target_host := Host, target_port := Port}}` on
%% success with `Host` as a binary (percent-decoded) and `Port` as an
%% integer in `1..65535`. Returns `{error, Reason}` otherwise.
-spec match(template(), binary()) ->
    {ok, #{target_host := binary(), target_port := 1..65535}}
  | {error, no_match | bad_port | bad_host | bad_template}.
match(Template, Path) when is_binary(Template), is_binary(Path) ->
    try
        Parts = parse(to_path(Template)),
        case match_parts(Parts, Path, #{}) of
            {ok, #{target_host := H, target_port := P} = Out}
              when byte_size(H) > 0 ->
                case {valid_host(H), parse_port(P)} of
                    {true, {ok, PortInt}} ->
                        {ok, Out#{target_port := PortInt}};
                    {false, _} ->
                        {error, bad_host};
                    {_, error} ->
                        {error, bad_port}
                end;
            {ok, _} ->
                {error, bad_host};
            nomatch ->
                {error, no_match}
        end
    catch
        throw:bad_template -> {error, bad_template}
    end.

%% @doc Strip an absolute `http(s)://…' template to its path portion.
%% Path-shaped templates pass through unchanged.
-spec to_path(binary()) -> binary().
to_path(<<"http://",  Rest/binary>>) -> drop_authority(Rest);
to_path(<<"https://", Rest/binary>>) -> drop_authority(Rest);
to_path(Path) -> Path.

drop_authority(Rest) ->
    case binary:match(Rest, <<"/">>) of
        {Pos, 1} ->
            <<_:Pos/binary, Tail/binary>> = Rest,
            Tail;
        nomatch ->
            <<"/">>
    end.

%% @doc Validate `Host' as an IPv4 literal, IPv6 literal, or LDH
%% registered name. Rejects IPv6 zone identifiers (RFC 3986 excludes
%% the `%zone' suffix from URI host syntax).
-spec valid_host(binary()) -> boolean().
valid_host(<<>>) ->
    false;
valid_host(Host) when is_binary(Host) ->
    S = binary_to_list(Host),
    case inet:parse_address(S) of
        {ok, _} ->
            not has_zone_id(Host);
        {error, _} ->
            valid_reg_name(Host)
    end.

has_zone_id(Host) ->
    binary:match(Host, <<"%">>) =/= nomatch.

%% reg-name per RFC 3986: one or more labels joined by dots, each label
%% a non-empty run of alphanumerics / `-' with no leading or trailing
%% hyphen.
valid_reg_name(Host) ->
    Labels = binary:split(Host, <<".">>, [global]),
    Labels =/= [] andalso lists:all(fun valid_label/1, Labels).

valid_label(<<>>) -> false;
valid_label(L) ->
    Bytes = binary_to_list(L),
    lists:all(fun is_ldh/1, Bytes)
    andalso hd(Bytes) =/= $-
    andalso lists:last(Bytes) =/= $-.

is_ldh(C) when C >= $a, C =< $z -> true;
is_ldh(C) when C >= $A, C =< $Z -> true;
is_ldh(C) when C >= $0, C =< $9 -> true;
is_ldh($-)                      -> true;
is_ldh(_)                       -> false.

%%====================================================================
%% Template parsing
%%====================================================================

%% A parsed template is a list of `{literal, Bin}` and `{var, Name}`
%% alternating segments.
parse(Template) ->
    parse(Template, <<>>, []).

parse(<<>>, Acc, Out) ->
    lists:reverse(emit_literal(Acc, Out));
parse(<<"{", Rest/binary>>, Acc, Out) ->
    case binary:split(Rest, <<"}">>) of
        [Name, Tail] when Name =/= <<>> ->
            parse(Tail, <<>>,
                  [{var, binary_to_atom(Name, utf8)} | emit_literal(Acc, Out)]);
        _ ->
            throw(bad_template)
    end;
parse(<<C, Rest/binary>>, Acc, Out) ->
    parse(Rest, <<Acc/binary, C>>, Out).

emit_literal(<<>>, Out) -> Out;
emit_literal(Bin, Out)  -> [{literal, Bin} | Out].

%%====================================================================
%% Expansion
%%====================================================================

expand_parts([], _Vars) ->
    [];
expand_parts([{literal, Bin} | Rest], Vars) ->
    [Bin | expand_parts(Rest, Vars)];
expand_parts([{var, Name} | Rest], Vars) ->
    Val = maps:get(Name, Vars),
    [pct_encode(to_binary(Val)) | expand_parts(Rest, Vars)].

to_binary(B) when is_binary(B) -> B;
to_binary(L) when is_list(L)   -> list_to_binary(L);
to_binary(I) when is_integer(I), I >= 0 -> integer_to_binary(I);
to_binary(A) when is_atom(A)   -> atom_to_binary(A, utf8).

%%====================================================================
%% Matching
%%====================================================================

%% We consume `Path` left-to-right, peeling off each literal prefix and
%% capturing each variable up to the next literal (or end-of-string).
match_parts([], <<>>, Acc) ->
    {ok, Acc};
match_parts([], _Rem, _Acc) ->
    nomatch;
match_parts([{literal, Lit} | Rest], Path, Acc) ->
    case binary:match(Path, Lit) of
        {0, N} when N =:= byte_size(Lit) ->
            <<_:N/binary, Tail/binary>> = Path,
            match_parts(Rest, Tail, Acc);
        _ ->
            nomatch
    end;
match_parts([{var, Name}], Path, Acc) ->
    %% Trailing variable - the entire remainder is the value.
    case pct_decode(Path) of
        {ok, Decoded} when byte_size(Decoded) > 0 ->
            {ok, Acc#{Name => Decoded}};
        _ ->
            nomatch
    end;
match_parts([{var, Name}, {literal, NextLit} | Rest], Path, Acc) ->
    case binary:match(Path, NextLit) of
        {Pos, _} when Pos > 0 ->
            <<VarRaw:Pos/binary, _/binary>> = Path,
            case pct_decode(VarRaw) of
                {ok, Decoded} when byte_size(Decoded) > 0 ->
                    <<_:Pos/binary, Tail/binary>> = Path,
                    match_parts([{literal, NextLit} | Rest], Tail,
                                Acc#{Name => Decoded});
                _ ->
                    nomatch
            end;
        _ ->
            nomatch
    end;
match_parts([{var, _} | _], _Path, _Acc) ->
    %% Two adjacent `{var}` placeholders - ambiguous, reject.
    throw(bad_template).

parse_port(Bin) when is_binary(Bin) ->
    case catch binary_to_integer(Bin) of
        P when is_integer(P), P >= 1, P =< 65535 -> {ok, P};
        _ -> error
    end.

%%====================================================================
%% Percent encoding/decoding (RFC 3986 §2)
%%====================================================================

pct_encode(Bin) when is_binary(Bin) ->
    << <<(pct_encode_byte(B))/binary>> || <<B>> <= Bin >>.

pct_encode_byte(B) when
    (B >= $A andalso B =< $Z);
    (B >= $a andalso B =< $z);
    (B >= $0 andalso B =< $9);
    B =:= $-; B =:= $.; B =:= $_; B =:= $~ ->
    <<B>>;
pct_encode_byte(B) ->
    Hi = hex_digit(B bsr 4),
    Lo = hex_digit(B band 16#0F),
    <<"%", Hi, Lo>>.

hex_digit(N) when N >= 0, N =< 9  -> N + $0;
hex_digit(N) when N >= 10, N =< 15 -> N - 10 + $A.

pct_decode(Bin) ->
    try
        {ok, iolist_to_binary(pct_decode_list(Bin))}
    catch
        throw:bad_pct -> {error, bad_pct}
    end.

pct_decode_list(<<>>) ->
    [];
pct_decode_list(<<"%", H, L, Rest/binary>>) ->
    [ <<(from_hex(H) * 16 + from_hex(L))>> | pct_decode_list(Rest) ];
pct_decode_list(<<"%", _/binary>>) ->
    throw(bad_pct);
pct_decode_list(<<C, Rest/binary>>) ->
    [<<C>> | pct_decode_list(Rest)].

from_hex(C) when C >= $0, C =< $9 -> C - $0;
from_hex(C) when C >= $a, C =< $f -> C - $a + 10;
from_hex(C) when C >= $A, C =< $F -> C - $A + 10;
from_hex(_) -> throw(bad_pct).
