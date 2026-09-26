%%% Safe TLS client options for MASQUE's TCP-based rungs.
%%%
%%% Centralises the TLS options every h1 and h2 client session sends
%%% to `ssl:connect/4` (directly or through `h2:connect/3`). Defaults
%%% match the posture `erlang_h1` uses on
%%% its own TLS client: verify the peer, trust the system CA store,
%%% check the hostname against the certificate, and advertise
%%% `http/1.1` in ALPN (`h2` for the HTTP/2 rung via `client_opts/3`). IPv6 literals are not valid SNI values
%%% (RFC 6066 section 3), so SNI is omitted when the proxy host is
%%% an IP literal.
%%%
%%% Caller overrides win: anything on `ssl_opts` in the session opts
%%% is merged on top of the defaults, and the top-level `verify` opt
%%% shorthand is honoured for parity with the h2/h3 sessions.
-module(masque_tls).
-moduledoc false.

-export([client_opts/2, client_opts/3]).

-export_type([proxy_host/0]).

-type proxy_host() :: binary() | string().

%% Build a merged list of `ssl:tls_client_option()` suitable for
%% `ssl:connect/4` when dialing a MASQUE proxy on HTTP/1.1. Accepts
%% the proxy host (as used on the wire) and the session-level opts
%% map. The following opts keys are consumed:
%%
%%   `verify`   : `verify_peer | verify_none` (default `verify_peer`)
%%   `cacerts`  : DER trust anchors (default: the system CA store)
%%   `ssl_opts` : list of extra `ssl:tls_client_option()` merged last
%%
%% Everything else in the opts map is ignored. Returns a plain list
%% ready to pass through to `ssl:connect/4`.
-spec client_opts(proxy_host(), map()) -> [ssl:tls_client_option()].
client_opts(Host, Opts) ->
    client_opts(Host, Opts, [<<"http/1.1">>]).

%% Same as `client_opts/2` with an explicit ALPN list, e.g.
%% `[<<"h2">>]` for the HTTP/2 rung.
-spec client_opts(proxy_host(), map(), [binary()]) ->
    [ssl:tls_client_option()].
client_opts(Host, Opts, Alpn) ->
    HostBin = to_bin(Host),
    IsIpLiteral = is_ip_literal(HostBin),
    Base =
        [
            {mode, binary},
            {active, false},
            {alpn_advertised_protocols, Alpn},
            {verify, maps:get(verify, Opts, verify_peer)},
            {cacerts, maps:get(cacerts, Opts, cacerts())},
            {customize_hostname_check, [
                {match_fun, public_key:pkix_verify_hostname_match_fun(https)}
            ]}
        ] ++ sni_opt(HostBin, IsIpLiteral),
    User = maps:get(ssl_opts, Opts, []),
    merge(Base, User).

%%====================================================================
%% Internal
%%====================================================================

cacerts() ->
    try
        public_key:cacerts_get()
    catch
        _:_ -> []
    end.

sni_opt(_HostBin, true) ->
    [];
sni_opt(HostBin, false) ->
    [{server_name_indication, binary_to_list(HostBin)}].

is_ip_literal(HostBin) when is_binary(HostBin) ->
    case inet:parse_address(binary_to_list(HostBin)) of
        {ok, _} -> true;
        _ -> false
    end.

%% Caller-supplied options win on a per-key basis. Non-tuple atoms
%% (e.g. `binary') and tuples with any arity are both supported.
merge(Default, Override) ->
    Over = sort_unique(Override),
    Kept = [D || D <- Default, not has_key(key_of(D), Over)],
    Kept ++ Over.

sort_unique(Opts) ->
    %% Drop earlier duplicates on the same key; keep the last value.
    lists:foldl(
        fun(O, Acc) ->
            K = key_of(O),
            [O | [X || X <- Acc, key_of(X) =/= K]]
        end,
        [],
        Opts
    ).

has_key(K, L) ->
    lists:any(fun(X) -> key_of(X) =:= K end, L).

key_of(T) when is_tuple(T), tuple_size(T) >= 1 -> element(1, T);
key_of(A) when is_atom(A) -> A.

to_bin(X) when is_binary(X) -> X;
to_bin(X) when is_list(X) -> list_to_binary(X);
to_bin(X) when is_atom(X) -> atom_to_binary(X, utf8).
