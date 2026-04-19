%%% @doc Safe TLS client options for MASQUE's HTTP/1.1 rung.
%%%
%%% Centralises the TLS options every h1 client session sends to
%%% `ssl:connect/4'. Defaults match the posture of `erlang_h1''s own
%%% `h1_client:connect_ssl/4': verify the peer, trust the system CA
%%% store, check the hostname against the certificate, and advertise
%%% `http/1.1' in ALPN. IPv6 literals are not valid SNI values
%%% (RFC 6066 §3), so SNI is omitted when the proxy host is an IP
%%% literal.
%%%
%%% Caller overrides win: anything on `ssl_opts' in the session opts
%%% is merged on top of the defaults, and the top-level `verify' opt
%%% shorthand is honoured for parity with the h2/h3 sessions.
-module(masque_tls).

-export([client_opts/2]).

-export_type([proxy_host/0]).

-type proxy_host() :: binary() | string().

%% @doc Build a merged list of `ssl:tls_client_option()' suitable for
%% `ssl:connect/4' when dialing a MASQUE proxy on HTTP/1.1. Accepts
%% the proxy host (as used on the wire) and the session-level opts
%% map. The following opts keys are consumed:
%%
%%   `verify'   : `verify_peer | verify_none' (default `verify_peer')
%%   `ssl_opts' : list of extra `ssl:tls_client_option()' merged last
%%
%% Everything else in the opts map is ignored. Returns a plain list
%% ready to pass through to `ssl:connect/4'.
-spec client_opts(proxy_host(), map()) -> [ssl:tls_client_option()].
client_opts(Host, Opts) ->
    HostBin = to_bin(Host),
    IsIpLiteral = is_ip_literal(HostBin),
    Base = [
        {mode, binary},
        {active, false},
        {alpn_advertised_protocols, [<<"http/1.1">>]},
        {verify, maps:get(verify, Opts, verify_peer)},
        {cacerts, cacerts()},
        {customize_hostname_check,
            [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]}
    ] ++ sni_opt(HostBin, IsIpLiteral),
    User = maps:get(ssl_opts, Opts, []),
    merge(Base, User).

%%====================================================================
%% Internal
%%====================================================================

cacerts() ->
    try public_key:cacerts_get()
    catch _:_ -> []
    end.

sni_opt(_HostBin, true) ->
    [];
sni_opt(HostBin, false) ->
    [{server_name_indication, binary_to_list(HostBin)}].

is_ip_literal(HostBin) when is_binary(HostBin) ->
    case inet:parse_address(binary_to_list(HostBin)) of
        {ok, _} -> true;
        _       -> false
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
      end, [], Opts).

has_key(K, L) ->
    lists:any(fun(X) -> key_of(X) =:= K end, L).

key_of(T) when is_tuple(T), tuple_size(T) >= 1 -> element(1, T);
key_of(A) when is_atom(A)                      -> A.

to_bin(X) when is_binary(X) -> X;
to_bin(X) when is_list(X)   -> list_to_binary(X);
to_bin(X) when is_atom(X)   -> atom_to_binary(X, utf8).
