-module(masque_uri).
-moduledoc """
URI template handling for RFC 9298 CONNECT-UDP and the
CONNECT-TCP draft.

RFC 9298 §3 defines the request path as the expansion of a URI
template with two variables - `target_host` and `target_port`.
`target_host` may be an IPv4 literal, an IPv6 literal, or a
registered name; colons and any non-unreserved characters are
percent-encoded on the wire.

The template engine is `masque_uri_template`; this module is the
UDP/TCP layer on top of it and does the target validation
(`target_host` reg-name / IP literal rules, `target_port` integer
range). It also formats and parses `host:port` authorities.
""".

-export([expand/2, match/2, to_path/1, valid_host/1]).
-export([build_authority/2, parse_authority_form/1]).
-export([parse_ip_literal/1, parse_uint/2]).

-export_type([template/0, vars/0]).

-type template() :: binary().
-type vars() :: #{
    target_host := binary() | string(),
    target_port := 1..65535
}.

%%====================================================================
%% API
%%====================================================================

-doc """
Expand a URI template using `Vars`. Returns the absolute path
to place in the `:path` pseudo-header. Absolute `http(s)://...`
templates are accepted - only the path-and-onwards portion is
expanded, mirroring what servers actually match at runtime.
""".
-spec expand(template(), vars()) -> binary().
expand(Template, Vars) when is_binary(Template), is_map(Vars) ->
    PathTpl = to_path(Template),
    case masque_uri_template:parse_pattern(PathTpl) of
        {ok, T} ->
            masque_uri_template:expand(T, Vars);
        {error, _} = Err ->
            error({bad_template, Err})
    end.

-doc """
Match a request path against a template.

Returns `{ok, #{target_host := Host, target_port := Port}}` on
success with `Host` as a binary (percent-decoded) and `Port` as an
integer in `1..65535`. Returns `{error, Reason}` otherwise.
""".
-spec match(template(), binary()) ->
    {ok, #{target_host := binary(), target_port := 1..65535}}
    | {error, no_match | bad_port | bad_host | bad_template}.
match(Template, Path) when is_binary(Template), is_binary(Path) ->
    case masque_uri_template:parse_pattern(to_path(Template)) of
        {ok, T} ->
            match_with(T, Path);
        {error, _} ->
            {error, bad_template}
    end.

match_with(T, Path) ->
    case masque_uri_template:match(T, Path) of
        {ok, #{target_host := Host, target_port := Port}} when
            byte_size(Host) > 0
        ->
            case {valid_host(Host), parse_port(Port)} of
                {true, {ok, PortInt}} ->
                    {ok, #{target_host => Host, target_port => PortInt}};
                {false, _} ->
                    {error, bad_host};
                {_, error} ->
                    {error, bad_port}
            end;
        {ok, _} ->
            {error, bad_host};
        {error, no_match} ->
            {error, no_match};
        {error, bad_pct} ->
            {error, bad_host}
    end.

-doc """
Strip an absolute `http(s)://…` template to its path portion.
Path-shaped templates pass through unchanged.
""".
-spec to_path(binary()) -> binary().
to_path(<<"http://", Rest/binary>>) -> drop_authority(Rest);
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

-doc """
Validate `Host` as an IPv4 literal, IPv6 literal, or LDH
registered name. IP literals follow `parse_ip_literal/1`;
a name whose last label looks numeric (`127.1`, `0x7f.0.0.1`) is
rejected rather than left to a resolver that would read it as an
address.
""".
-spec valid_host(binary()) -> boolean().
valid_host(<<>>) ->
    false;
valid_host(Host) when is_binary(Host) ->
    case parse_ip_literal(Host) of
        {ok, _} -> true;
        error -> valid_reg_name(Host)
    end.

-doc """
Parse a strict IP literal: an IPv4 dotted quad of four decimal
octets without leading zeros, or an IPv6 address. Shorthand, hex and
octal IPv4 forms and IPv6 zone identifiers (`fe80::1%eth0`, which
RFC 3986 excludes from URI host syntax) are rejected.
""".
-spec parse_ip_literal(binary()) -> {ok, inet:ip_address()} | error.
parse_ip_literal(Bin) when is_binary(Bin) ->
    S = binary_to_list(Bin),
    Parsed =
        case {binary:match(Bin, <<"%">>), binary:match(Bin, <<":">>)} of
            {nomatch, nomatch} -> inet:parse_ipv4strict_address(S);
            {nomatch, _} -> inet:parse_ipv6strict_address(S);
            _ -> {error, einval}
        end,
    case Parsed of
        {ok, IP} -> {ok, IP};
        {error, _} -> error
    end.

-doc """
Parse a decimal integer in `0..Max`: ASCII digits only, no
sign, no leading zeros.
""".
-spec parse_uint(binary(), non_neg_integer()) -> {ok, non_neg_integer()} | error.
parse_uint(<<"0">>, _Max) ->
    {ok, 0};
parse_uint(<<C, _/binary>> = Bin, Max) when C >= $1, C =< $9 ->
    case lists:all(fun(D) -> D >= $0 andalso D =< $9 end, binary_to_list(Bin)) of
        true ->
            case binary_to_integer(Bin) of
                N when N =< Max -> {ok, N};
                _ -> error
            end;
        false ->
            error
    end;
parse_uint(_, _Max) ->
    error.

%% reg-name per RFC 3986: one or more labels joined by dots, each label
%% a non-empty run of alphanumerics / `-' with no leading or trailing
%% hyphen. A numeric-looking last label (no top-level domain is) marks
%% a non-canonical IPv4 form.
valid_reg_name(Host) ->
    Labels = binary:split(Host, <<".">>, [global]),
    lists:all(fun valid_label/1, Labels) andalso
        not numeric_label(lists:last(Labels)).

numeric_label(<<"0x", _/binary>>) -> true;
numeric_label(<<"0X", _/binary>>) -> true;
numeric_label(L) -> lists:all(fun(C) -> C >= $0 andalso C =< $9 end, binary_to_list(L)).

valid_label(<<>>) ->
    false;
valid_label(L) ->
    Bytes = binary_to_list(L),
    lists:all(fun is_ldh/1, Bytes) andalso
        hd(Bytes) =/= $- andalso
        lists:last(Bytes) =/= $-.

is_ldh(C) when C >= $a, C =< $z -> true;
is_ldh(C) when C >= $A, C =< $Z -> true;
is_ldh(C) when C >= $0, C =< $9 -> true;
is_ldh($-) -> true;
is_ldh(_) -> false.

%%====================================================================
%% Internal
%%====================================================================

parse_port(Bin) when is_binary(Bin) ->
    case parse_uint(Bin, 65535) of
        {ok, P} when P >= 1 -> {ok, P};
        _ -> error
    end;
parse_port(Int) when is_integer(Int), Int >= 1, Int =< 65535 ->
    {ok, Int};
parse_port(_) ->
    error.

%%====================================================================
%% Authority helpers (for CONNECT-TCP request-target + Host header)
%%====================================================================

-doc """
Format a `host:port` authority. IPv6 literals are wrapped in
square brackets per RFC 3986 §3.2.2. Used on the client side to
build the CONNECT request-target and `Host` header.
""".
-spec build_authority(binary(), inet:port_number()) -> binary().
build_authority(Host, Port) when is_binary(Host), is_integer(Port) ->
    HostPart =
        case is_ipv6_literal(Host) of
            true -> <<"[", Host/binary, "]">>;
            false -> Host
        end,
    iolist_to_binary([HostPart, ":", integer_to_binary(Port)]).

-doc """
Parse the authority-form of a request-target used by classic
CONNECT (RFC 9112 §3.2.3): `host:port` or `[ipv6]:port`. Strips the
brackets from the IPv6 literal on the way out. Rejects malformed
inputs (missing port, non-numeric port, empty host).
""".
-spec parse_authority_form(binary()) ->
    {ok, binary(), inet:port_number()} | {error, term()}.
parse_authority_form(<<"[", Rest/binary>>) ->
    case binary:split(Rest, <<"]:">>) of
        [Host, PortBin] when Host =/= <<>> ->
            case parse_port(PortBin) of
                {ok, Port} -> {ok, Host, Port};
                error -> {error, bad_port}
            end;
        _ ->
            {error, bad_authority}
    end;
parse_authority_form(Bin) when is_binary(Bin) ->
    case binary:matches(Bin, <<":">>) of
        [{Pos, 1}] ->
            <<Host:Pos/binary, ":", PortBin/binary>> = Bin,
            case Host of
                <<>> ->
                    {error, bad_host};
                _ ->
                    case parse_port(PortBin) of
                        {ok, Port} -> {ok, Host, Port};
                        error -> {error, bad_port}
                    end
            end;
        _ ->
            {error, bad_authority}
    end;
parse_authority_form(_) ->
    {error, bad_authority}.

is_ipv6_literal(Host) when is_binary(Host) ->
    case inet:parse_address(binary_to_list(Host)) of
        {ok, {_, _, _, _, _, _, _, _}} -> true;
        _ -> false
    end.
