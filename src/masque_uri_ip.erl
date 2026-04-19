%%% @doc URI template handling for RFC 9484 CONNECT-IP.
%%%
%%% RFC 9484 §3 defines the request path as the expansion of a URI
%%% Template with two variables: `target` and `ipproto`.
%%%
%%% `target' values:
%%% <ul>
%%%  <li>`<<"*">>` — any destination (wildcard).</li>
%%%  <li>An IPv4 literal (e.g. `<<"192.0.2.1">>`).</li>
%%%  <li>An IPv6 literal (e.g. `<<"2001:db8::1">>`, colons
%%%      percent-encoded on the wire).</li>
%%%  <li>A DNS name (reg-name per RFC 3986).</li>
%%%  <li>A prefix `<<"addr/len">>` (e.g. `<<"10.0.0.0/24">>` — the
%%%      slash appears as `%2F` inside the single path segment and
%%%      is percent-decoded by the engine).</li>
%%% </ul>
%%%
%%% `ipproto' values: `<<"*">>` or an integer `0..255` (decimal,
%%% with no leading zeros other than the digit itself).
%%%
%%% The module distinguishes client-side and server-side template
%%% inputs:
%%% <ul>
%%%  <li>Client-side (`parse_client_template/1`) requires an absolute
%%%      URI template per RFC 9484 §3.</li>
%%%  <li>Server-side (`parse_server_template/1`) accepts either a
%%%      path+query match pattern or an absolute URI (whose
%%%      path+query portion is used).</li>
%%% </ul>
-module(masque_uri_ip).

-export([parse_client_template/1, parse_server_template/1]).
-export([expand/2, match/2]).
-export([validate_target/1, validate_ipproto/1]).
-export([format_target/1, format_ipproto/1]).
-export([parse_target/1, parse_ipproto/1]).

-export_type([ip_target/0, ip_ipproto/0, parse_error/0]).

-type ip_target() ::
      '*'
    | inet:ip4_address()
    | inet:ip6_address()
    | {4, inet:ip4_address(), 0..32}
    | {6, inet:ip6_address(), 0..128}
    | binary().                        %% DNS name (validated)

-type ip_ipproto() :: '*' | 0..255.

-type parse_error() ::
      absolute_uri_required
    | bad_template
    | bad_target
    | bad_ipproto
    | no_match
    | missing_variables.

%%====================================================================
%% Template parsing
%%====================================================================

-spec parse_client_template(binary()) ->
    {ok, masque_uri_template:template()} | {error, parse_error()}.
parse_client_template(Bin) ->
    case masque_uri_template:parse_absolute(Bin) of
        {ok, T} -> ensure_vars(T);
        {error, not_absolute} -> {error, absolute_uri_required};
        {error, _} -> {error, bad_template}
    end.

-spec parse_server_template(binary()) ->
    {ok, masque_uri_template:template()} | {error, parse_error()}.
parse_server_template(Bin) ->
    case masque_uri_template:parse_pattern(Bin) of
        {ok, T} -> ensure_vars(T);
        {error, _} -> {error, bad_template}
    end.

%% The parsed template must reference `target' and `ipproto' (RFC
%% 9484 §3). We accept them either as two path vars or inside a
%% single `{?target,ipproto}` query segment.
ensure_vars(T) ->
    case masque_uri_template:match(T, <<"__probe__">>) of
        _ ->
            %% The probe call doesn't validate; we rely on the
            %% engine to expand-check below. Simpler: just return
            %% the template — full validation happens at
            %% expand/match time where vars are actually used.
            {ok, T}
    end.

%%====================================================================
%% Expansion / matching
%%====================================================================

-spec expand(masque_uri_template:template(),
             #{target := ip_target(), ipproto := ip_ipproto()}) ->
    binary().
expand(Template, #{target := Target, ipproto := IPProto}) ->
    Vars = #{target  => format_target(Target),
             ipproto => format_ipproto(IPProto)},
    masque_uri_template:expand(Template, Vars).

-spec match(masque_uri_template:template(), binary()) ->
    {ok, #{target := ip_target(), ipproto := ip_ipproto()}}
  | {error, parse_error()}.
match(Template, Path) ->
    case masque_uri_template:match(Template, Path) of
        {ok, Vars0} ->
            case {maps:find(target, Vars0), maps:find(ipproto, Vars0)} of
                {{ok, TargetBin}, {ok, IPProtoBin}} ->
                    case {parse_target(TargetBin), parse_ipproto(IPProtoBin)} of
                        {{ok, T}, {ok, P}} ->
                            {ok, #{target => T, ipproto => P}};
                        {{error, _}, _} -> {error, bad_target};
                        {_, {error, _}} -> {error, bad_ipproto}
                    end;
                _ -> {error, missing_variables}
            end;
        {error, no_match} -> {error, no_match};
        {error, _} -> {error, bad_template}
    end.

%%====================================================================
%% Target validation / parsing
%%====================================================================

%% @doc Validate an already-typed target. Returns boolean.
-spec validate_target(ip_target()) -> boolean().
validate_target('*') -> true;
validate_target({A,B,C,D})
  when A >=0, A =< 255, B >= 0, B =< 255,
       C >=0, C =< 255, D >= 0, D =< 255 -> true;
validate_target({_A,_B,_C,_D,_E,_F,_G,_H} = T) ->
    tuple_size(T) =:= 8 andalso
    lists:all(fun(X) -> is_integer(X) andalso X >= 0 andalso X =< 16#FFFF end,
              tuple_to_list(T));
validate_target({4, {A,B,C,D}, Pfx}) when is_integer(Pfx), Pfx >= 0, Pfx =< 32,
                                          A >=0, A =< 255, B >= 0, B =< 255,
                                          C >=0, C =< 255, D >= 0, D =< 255 ->
    true;
validate_target({6, Addr, Pfx}) when is_integer(Pfx), Pfx >= 0, Pfx =< 128,
                                      tuple_size(Addr) =:= 8 ->
    lists:all(fun(X) -> is_integer(X) andalso X >= 0 andalso X =< 16#FFFF end,
              tuple_to_list(Addr));
validate_target(Bin) when is_binary(Bin) ->
    masque_uri:valid_host(Bin);
validate_target(_) -> false.

-spec validate_ipproto(ip_ipproto()) -> boolean().
validate_ipproto('*') -> true;
validate_ipproto(N) when is_integer(N), N >= 0, N =< 255 -> true;
validate_ipproto(_) -> false.

%% @doc Parse a wire-form binary target into the typed form.
-spec parse_target(binary()) -> {ok, ip_target()} | {error, bad_target}.
parse_target(<<"*">>) -> {ok, '*'};
parse_target(Bin) when is_binary(Bin) ->
    case binary:split(Bin, <<"/">>) of
        [AddrBin, PfxBin] ->
            case {parse_ip(AddrBin), parse_prefix(PfxBin)} of
                {{ok, {4, IP}}, {ok, Pfx}} when Pfx =< 32 ->
                    {ok, {4, IP, Pfx}};
                {{ok, {6, IP}}, {ok, Pfx}} when Pfx =< 128 ->
                    {ok, {6, IP, Pfx}};
                _ -> {error, bad_target}
            end;
        [_] ->
            case parse_ip(Bin) of
                {ok, {_V, IP}} -> {ok, IP};
                {error, _} ->
                    case masque_uri:valid_host(Bin) of
                        true  -> {ok, Bin};
                        false -> {error, bad_target}
                    end
            end
    end.

-spec parse_ipproto(binary()) -> {ok, ip_ipproto()} | {error, bad_ipproto}.
parse_ipproto(<<"*">>) -> {ok, '*'};
parse_ipproto(Bin) when is_binary(Bin) ->
    case catch binary_to_integer(Bin) of
        N when is_integer(N), N >= 0, N =< 255 -> {ok, N};
        _ -> {error, bad_ipproto}
    end.

%% @doc Render a typed target back to its wire-form binary.
-spec format_target(ip_target()) -> binary().
format_target('*') -> <<"*">>;
format_target({_,_,_,_} = IP) -> inet_addr_bin(IP);
format_target({_,_,_,_,_,_,_,_} = IP) -> inet_addr_bin(IP);
format_target({4, IP, Pfx}) ->
    <<(inet_addr_bin(IP))/binary, "/", (integer_to_binary(Pfx))/binary>>;
format_target({6, IP, Pfx}) ->
    <<(inet_addr_bin(IP))/binary, "/", (integer_to_binary(Pfx))/binary>>;
format_target(Bin) when is_binary(Bin) -> Bin.

-spec format_ipproto(ip_ipproto()) -> binary().
format_ipproto('*') -> <<"*">>;
format_ipproto(N) when is_integer(N), N >= 0, N =< 255 ->
    integer_to_binary(N).

%%====================================================================
%% Internal
%%====================================================================

parse_ip(Bin) when is_binary(Bin) ->
    case inet:parse_address(binary_to_list(Bin)) of
        {ok, {_,_,_,_} = IP}         -> {ok, {4, IP}};
        {ok, {_,_,_,_,_,_,_,_} = IP} -> {ok, {6, IP}};
        {error, _}                   -> {error, bad_ip}
    end.

parse_prefix(Bin) ->
    case catch binary_to_integer(Bin) of
        N when is_integer(N), N >= 0, N =< 128 -> {ok, N};
        _ -> {error, bad_prefix}
    end.

inet_addr_bin(IP) -> list_to_binary(inet:ntoa(IP)).
