%%% @doc Connect-UDP-Bind URI and header helpers.
%%%
%%% Sibling of `masque_uri' that adds bind-specific bits the existing
%%% UDP matcher must not learn about:
%%%
%%% <ul>
%%%   <li>The percent-encoded `*' wildcard for `target_host' /
%%%       `target_port', meaning "unscoped" - the bind socket can
%%%       talk to any peer the proxy's policy allows. The standard
%%%       `masque_uri:match/2' rejects `*' as a host/port, so the
%%%       dispatch path uses this matcher instead when the
%%%       `Connect-UDP-Bind' request header is present.</li>
%%%   <li>Parse and format the two HTTP fields the draft adds:
%%%       <ul>
%%%         <li>`Connect-UDP-Bind' - RFC 9651 Boolean. Both endpoints
%%%             send `?1' to indicate support; bind is only enabled
%%%             once each side has both sent and received it.</li>
%%%         <li>`Proxy-Public-Address' - RFC 9651 List of String
%%%             items, each a `"ip:port"' tuple (IPv6 literals
%%%             bracketed). Required on a successful bind response;
%%%             absent / malformed / empty must fail the
%%%             handshake.</li>
%%%       </ul></li>
%%% </ul>
%%%
%%% This module is pure - no I/O, no state. It is deliberately
%%% additive: nothing here changes the behaviour of `masque_uri' for
%%% legacy CONNECT-UDP requests.
-module(masque_uri_udp_bind).

-export([
    match/2,
    expand/2,
    classify/1
]).

-export([
    parse_bind_header/1,
    format_bind_header/0,
    parse_proxy_public_address/1,
    format_proxy_public_address/1
]).

-include("masque_udp_bind.hrl").

-type bind_target() ::
    unscoped
    | {Host :: binary(), Port :: 1..65535}.

-type bind_match() ::
    #{
        target_host := binary() | '*',
        target_port := 1..65535 | '*',
        bind := unscoped | scoped
    }.

-type bind_header_value() :: bind | absent | invalid.

-type proxy_public_address_error() :: absent | malformed | empty.

-export_type([
    bind_target/0,
    bind_match/0,
    bind_header_value/0,
    proxy_public_address_error/0
]).

%% Used in tests and by the bind matcher when comparing the encoded
%% wildcard literal that arrives on the wire.
-define(WILDCARD, <<"*">>).
-define(WILDCARD_PCT, <<"%2A">>).

%%====================================================================
%% URI matching / expansion
%%====================================================================

%% @doc Match a request path against a CONNECT-UDP URI template,
%% accepting `*' (or its percent-encoded form `%2A') for both
%% `target_host' and `target_port' to mean "unscoped bind". Returns a
%% map carrying the literal target plus a `bind' classification so
%% the caller can dispatch accordingly. Falls back to the legacy
%% `masque_uri:match/2' when neither variable is the wildcard.
-spec match(binary(), binary()) ->
    {ok, bind_match()} | {error, no_match | bad_port | bad_host | bad_template}.
match(Template, Path) when is_binary(Template), is_binary(Path) ->
    case masque_uri_template:parse_pattern(to_path(Template)) of
        {ok, T} ->
            match_with(T, Path);
        {error, _} ->
            {error, bad_template}
    end.

match_with(T, Path) ->
    case masque_uri_template:match(T, Path) of
        {ok, #{target_host := Host, target_port := Port}} ->
            classify_match(Host, Port);
        {error, no_match} ->
            {error, no_match};
        {error, bad_pct} ->
            {error, bad_host}
    end.

classify_match(Host, Port) ->
    case {decode_host(Host), decode_port(Port)} of
        {wildcard, wildcard} ->
            {ok, #{
                target_host => '*',
                target_port => '*',
                bind => unscoped
            }};
        {wildcard, _} ->
            {error, bad_host};
        {_, wildcard} ->
            {error, bad_host};
        {{ok, H}, {ok, P}} ->
            {ok, #{
                target_host => H,
                target_port => P,
                bind => scoped
            }};
        {{error, _}, _} ->
            {error, bad_host};
        {_, {error, _}} ->
            {error, bad_port}
    end.

decode_host(<<>>) ->
    {error, empty};
decode_host(?WILDCARD) ->
    wildcard;
decode_host(?WILDCARD_PCT) ->
    wildcard;
decode_host(Bin) when is_binary(Bin) ->
    case masque_uri:valid_host(Bin) of
        true -> {ok, Bin};
        false -> {error, bad_host}
    end.

decode_port(<<>>) ->
    {error, empty};
decode_port(?WILDCARD) ->
    wildcard;
decode_port(?WILDCARD_PCT) ->
    wildcard;
decode_port(Bin) when is_binary(Bin) ->
    case parse_port_value(Bin) of
        {ok, P} -> {ok, P};
        not_port -> {error, bad_port}
    end.

parse_port_value(Bin) ->
    try binary_to_integer(Bin) of
        N when is_integer(N), N >= 1, N =< 65535 -> {ok, N};
        _ -> not_port
    catch
        _:_ -> not_port
    end.

%% @doc Expand a CONNECT-UDP URI template for a bind handshake.
%% Accepts the typed `bind_target()' (`unscoped' or `{Host, Port}')
%% and a raw `vars()' map; the unscoped form encodes both target
%% variables as the wildcard `*'.
%%
%% The unscoped path goes directly through
%% `masque_uri_template:expand/2' rather than `masque_uri:expand/2'
%% because the latter's `vars()' typespec narrows `target_port' to
%% an integer port number, while we need a wildcard string for an
%% unscoped bind.
-spec expand(binary(), bind_target() | masque_uri_template:vars()) -> binary().
expand(Template, unscoped) ->
    expand_with_template(
        Template,
        #{
            target_host => ?WILDCARD,
            target_port => ?WILDCARD
        }
    );
expand(Template, {Host, Port}) when
    is_binary(Host) orelse is_list(Host),
    is_integer(Port),
    Port >= 1,
    Port =< 65535
->
    masque_uri:expand(
        Template,
        #{
            target_host => Host,
            target_port => Port
        }
    );
expand(Template, Vars) when is_map(Vars) ->
    masque_uri:expand(Template, Vars).

expand_with_template(Template, Vars) ->
    PathTpl = to_path(Template),
    case masque_uri_template:parse_pattern(PathTpl) of
        {ok, T} -> masque_uri_template:expand(T, Vars);
        {error, _} = Err -> error({bad_template, Err})
    end.

%% @doc Classify a bind target without doing any URI work. Useful for
%% callers that already hold the parsed values.
-spec classify(bind_match() | bind_target()) -> unscoped | scoped.
classify(#{bind := B}) -> B;
classify(unscoped) -> unscoped;
classify({_, _}) -> scoped.

%%====================================================================
%% Connect-UDP-Bind header (RFC 9651 Boolean)
%%====================================================================

%% @doc Read the `Connect-UDP-Bind' field from a Headers list.
%% Per draft-11, invalid value types are treated as absent (the
%% library returns `invalid' so the caller can choose to log or
%% reject; the dispatch path treats `invalid' the same as `absent').
-spec parse_bind_header([{binary(), binary()}]) -> bind_header_value().
parse_bind_header(Headers) when is_list(Headers) ->
    case header_value(?MASQUE_HF_CONNECT_UDP_BIND, Headers) of
        undefined -> absent;
        Bin -> classify_bind_value(strip(Bin))
    end.

classify_bind_value(<<"?1">>) -> bind;
classify_bind_value(<<"?0">>) -> absent;
classify_bind_value(_) -> invalid.

%% @doc The header pair to emit for `Connect-UDP-Bind: ?1' on a
%% request or response.
-spec format_bind_header() -> {binary(), binary()}.
format_bind_header() ->
    {?MASQUE_HF_CONNECT_UDP_BIND, <<"?1">>}.

%%====================================================================
%% Proxy-Public-Address header (RFC 9651 List of Strings)
%%====================================================================

%% @doc Parse the `Proxy-Public-Address' field. Distinguishes
%% `absent', `malformed' (the field is present but does not parse as
%% a list of `"ip:port"' strings), and `empty' (the list parses but
%% has zero usable entries) so the bind client can fail the
%% handshake on any of those.
-spec parse_proxy_public_address([{binary(), binary()}]) ->
    {ok, [{inet:ip_address(), inet:port_number()}]}
    | {error, proxy_public_address_error()}.
parse_proxy_public_address(Headers) when is_list(Headers) ->
    case header_value(?MASQUE_HF_PROXY_PUBLIC_ADDRESS, Headers) of
        undefined ->
            {error, absent};
        Raw ->
            case parse_string_list(strip(Raw)) of
                {ok, []} -> {error, empty};
                {ok, Strings} -> parse_addr_strings(Strings);
                {error, _} -> {error, malformed}
            end
    end.

%% @doc Render a list of `{ip, port}' tuples for emission on a
%% response. Bracket IPv6 literals; quote each entry as a Structured
%% Field String. Crashes on an empty list - draft-11 requires at
%% least one valid entry on a successful bind 2xx.
-spec format_proxy_public_address(
    [{inet:ip_address(), inet:port_number()}]
) -> binary().
format_proxy_public_address([]) ->
    erlang:error(empty_proxy_public_address);
format_proxy_public_address(Addrs) when is_list(Addrs) ->
    Items = [format_one(A) || A <- Addrs],
    iolist_to_binary(lists:join(<<", ">>, Items)).

format_one({{_, _, _, _} = V4, Port}) ->
    iolist_to_binary([$", inet:ntoa(V4), $:, integer_to_list(Port), $"]);
format_one({{_, _, _, _, _, _, _, _} = V6, Port}) ->
    iolist_to_binary([
        $",
        $[,
        inet:ntoa(V6),
        $],
        $:,
        integer_to_list(Port),
        $"
    ]).

%%====================================================================
%% Internal
%%====================================================================

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

header_value(Name, Headers) ->
    LName = lowercase_bin(Name),
    lookup_ci(LName, Headers).

lookup_ci(_, []) ->
    undefined;
lookup_ci(LName, [{K, V} | Rest]) ->
    case lowercase_bin(K) =:= LName of
        true -> V;
        false -> lookup_ci(LName, Rest)
    end.

lowercase_bin(B) when is_binary(B) ->
    iolist_to_binary(string:lowercase(B)).

strip(B) when is_binary(B) ->
    iolist_to_binary(string:trim(B, both, " \t")).

%% Parse an RFC 9651 list of bare-string items. We do not implement
%% the full sf grammar (no parameters, no inner lists) - that's all
%% draft-11 needs from us. Returns the unquoted strings in order.
parse_string_list(<<>>) ->
    {ok, []};
parse_string_list(Bin) ->
    Items = [strip(I) || I <- binary:split(Bin, <<",">>, [global])],
    case lists:foldr(fun unquote/2, {ok, []}, Items) of
        {ok, _} = Ok -> Ok;
        {error, _} = E -> E
    end.

unquote(_, {error, _} = E) ->
    E;
unquote(<<>>, {ok, Acc}) ->
    {ok, Acc};
unquote(Item, {ok, Acc}) ->
    case Item of
        <<$", Body/binary>> ->
            BSize = byte_size(Body),
            case BSize > 0 andalso binary:at(Body, BSize - 1) =:= $" of
                true ->
                    Inner = binary:part(Body, 0, BSize - 1),
                    {ok, [Inner | Acc]};
                false ->
                    {error, malformed}
            end;
        _ ->
            {error, malformed}
    end.

parse_addr_strings(Strings) ->
    parse_addr_strings(Strings, []).

parse_addr_strings([], Acc) ->
    case lists:reverse(Acc) of
        [] -> {error, empty};
        List -> {ok, List}
    end;
parse_addr_strings([Bin | Rest], Acc) ->
    case parse_ip_port(Bin) of
        {ok, Pair} -> parse_addr_strings(Rest, [Pair | Acc]);
        {error, _} = E -> E
    end.

parse_ip_port(<<$[, Rest/binary>>) ->
    %% IPv6 literal: "[address]:port".
    case binary:split(Rest, <<"]:">>) of
        [V6, PortBin] ->
            case {inet:parse_ipv6_address(binary_to_list(V6)), parse_port_value(PortBin)} of
                {{ok, Addr}, {ok, Port}} -> {ok, {Addr, Port}};
                _ -> {error, malformed}
            end;
        _ ->
            {error, malformed}
    end;
parse_ip_port(Bin) ->
    %% IPv4: "address:port".
    case binary:split(Bin, <<":">>) of
        [V4, PortBin] ->
            case {inet:parse_ipv4_address(binary_to_list(V4)), parse_port_value(PortBin)} of
                {{ok, Addr}, {ok, Port}} -> {ok, {Addr, Port}};
                _ -> {error, malformed}
            end;
        _ ->
            {error, malformed}
    end.
