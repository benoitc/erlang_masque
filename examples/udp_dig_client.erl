%%% @doc Example - resolve a DNS name through a MASQUE proxy.
%%%
%%% Opens a CONNECT-UDP tunnel to a UDP DNS resolver (default:
%%% 1.1.1.1:53) through the given proxy, sends a minimal DNS query,
%%% and prints the bytes of the response. A real DNS client would
%%% parse the reply; this example only demonstrates that UDP packets
%%% make a clean round trip through the tunnel.
%%%
%%% Usage:
%%%
%%%   rebar3 shell
%%%   1> c("examples/udp_dig_client").
%%%   2> udp_dig_client:resolve(<<"https://localhost:4433">>, <<"example.com">>).
-module(udp_dig_client).

-export([resolve/2, resolve/3, resolve/4]).

-define(DEFAULT_RESOLVER_IP, <<"1.1.1.1">>).
-define(DEFAULT_RESOLVER_PORT, 53).

resolve(ProxyURI, Name) ->
    resolve(ProxyURI, Name, ?DEFAULT_RESOLVER_IP, ?DEFAULT_RESOLVER_PORT).

resolve(ProxyURI, Name, ResolverIP) ->
    resolve(ProxyURI, Name, ResolverIP, ?DEFAULT_RESOLVER_PORT).

resolve(ProxyURI, Name, ResolverIP, ResolverPort) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Sess} = masque:connect(
        ProxyURI,
        {ResolverIP, ResolverPort},
        #{verify => verify_none}
    ),
    Query = build_dns_query(Name),
    ok = masque:send(Sess, Query),
    Result =
        receive
            {masque_data, Sess, Reply} -> {ok, Reply}
        after 3000 ->
            {error, timeout}
        end,
    masque:close(Sess),
    Result.

%% Build a minimal DNS query for A-record of `Name'. No EDNS, no AD, no
%% recursion flag shortcuts - just enough to go over the wire.
build_dns_query(Name) when is_binary(Name) ->
    TxnId = rand:uniform(65535),
    Header =
        <<TxnId:16, 1:1, 0:4, 0:1, 0:1, 1:1, 0:1, 0:3, 0:4, 1:16, 0:16, 0:16, 0:16>>,
    Labels = encode_labels(binary:split(Name, <<".">>, [global])),
    Question = <<Labels/binary, 0, 1:16, 1:16>>,
    <<Header/binary, Question/binary>>.

encode_labels(Labels) ->
    <<<<(byte_size(L)):8, L/binary>> || L <- Labels>>.
