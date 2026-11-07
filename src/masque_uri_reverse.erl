-module(masque_uri_reverse).
-moduledoc false.

%%% URI templates for reverse connect (draft-rosomakho-masque-reverse-connect-01).
%%%
%%% Listener Control Channel (section 4.1): optional `target' and
%%% `ipproto'. `target' is a host name, an IP address or prefix (as in
%%% CONNECT-IP), `*', a wildcard domain `*.example.com', or `.' for local
%%% services only. `ipproto' is 6, 17 or `*'. A missing variable means `*'.
%%%
%%% Accepting Connection (section 5.2): a `request_id' variable, decimal.

-export([parse_listen_template/1, parse_accept_template/1]).
-export([expand_listen/2, match_listen/2]).
-export([expand_accept/2, match_accept/2]).
-export([parse_target/1, format_target/1, parse_ipproto/1, format_ipproto/1]).

-export_type([target/0, ipproto/0]).

-type target() :: '*' | local | {wildcard, binary()} | masque_uri_ip:ip_target().
-type ipproto() :: '*' | tcp | udp.

-spec parse_listen_template(binary()) ->
    {ok, masque_uri_template:template()} | {error, bad_template}.
parse_listen_template(Bin) ->
    parse(Bin, [target, ipproto], []).

%% Section 5.2: the template MUST contain `request_id'.
-spec parse_accept_template(binary()) ->
    {ok, masque_uri_template:template()} | {error, bad_template}.
parse_accept_template(Bin) ->
    parse(Bin, [request_id], [request_id]).

parse(Bin, Allowed, Required) ->
    case masque_uri_template:parse_pattern(Bin) of
        {ok, T} ->
            Names = masque_uri_template:var_names(T),
            case {Names -- Allowed, Required -- Names} of
                {[], []} -> {ok, T};
                _ -> {error, bad_template}
            end;
        {error, _} ->
            {error, bad_template}
    end.

-spec expand_listen(masque_uri_template:template(), #{target := target(), ipproto := ipproto()}) ->
    binary().
expand_listen(T, #{target := Target, ipproto := Proto}) ->
    masque_uri_template:expand(T, #{
        target => format_target(Target), ipproto => format_ipproto(Proto)
    }).

-spec match_listen(masque_uri_template:template(), binary()) ->
    {ok, #{target := target(), ipproto := ipproto()}}
    | {error, no_match | bad_target | bad_ipproto}.
match_listen(T, Path) ->
    case masque_uri_template:match(T, Path) of
        {ok, Vars} ->
            case {var(target, Vars, fun parse_target/1), var(ipproto, Vars, fun parse_ipproto/1)} of
                {{ok, Target}, {ok, Proto}} -> {ok, #{target => Target, ipproto => Proto}};
                {{error, _}, _} -> {error, bad_target};
                {_, {error, _}} -> {error, bad_ipproto}
            end;
        {error, _} ->
            {error, no_match}
    end.

-spec expand_accept(masque_uri_template:template(), non_neg_integer()) -> binary().
expand_accept(T, Id) ->
    masque_uri_template:expand(T, #{request_id => integer_to_binary(Id)}).

-spec match_accept(masque_uri_template:template(), binary()) ->
    {ok, non_neg_integer()} | {error, no_match | bad_request_id}.
match_accept(T, Path) ->
    case masque_uri_template:match(T, Path) of
        {ok, #{request_id := Bin}} ->
            case masque_uri:parse_uint(Bin, 16#3FFFFFFFFFFFFFFF) of
                {ok, Id} -> {ok, Id};
                error -> {error, bad_request_id}
            end;
        _ ->
            {error, no_match}
    end.

var(Key, Vars, Parse) ->
    case maps:find(Key, Vars) of
        error -> {ok, '*'};
        {ok, Bin} -> Parse(Bin)
    end.

-spec parse_target(binary()) -> {ok, target()} | {error, bad_target}.
parse_target(<<".">>) ->
    {ok, local};
parse_target(<<"*.", Domain/binary>>) ->
    case masque_uri:valid_host(Domain) of
        true -> {ok, {wildcard, Domain}};
        false -> {error, bad_target}
    end;
parse_target(Bin) ->
    masque_uri_ip:parse_target(Bin).

-spec format_target(target()) -> binary().
format_target(local) -> <<".">>;
format_target({wildcard, Domain}) -> <<"*.", Domain/binary>>;
format_target(T) -> masque_uri_ip:format_target(T).

-spec parse_ipproto(binary()) -> {ok, ipproto()} | {error, bad_ipproto}.
parse_ipproto(<<"*">>) -> {ok, '*'};
parse_ipproto(<<"6">>) -> {ok, tcp};
parse_ipproto(<<"17">>) -> {ok, udp};
parse_ipproto(_) -> {error, bad_ipproto}.

-spec format_ipproto(ipproto()) -> binary().
format_ipproto('*') -> <<"*">>;
format_ipproto(tcp) -> <<"6">>;
format_ipproto(udp) -> <<"17">>.
