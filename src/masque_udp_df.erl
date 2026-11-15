%%% Don't-fragment on the proxy's UDP sockets.
%%%
%%% RFC 9298 section 3.1: a UDP proxy must not introduce fragmentation
%%% and sets the IPv4 Don't Fragment bit where it can. The kernel then
%%% refuses a datagram larger than the path MTU (`emsgsize'), which the
%%% handlers drop like any other transient send error. The options are
%%% raw ones, so they are picked per OS; an OS this module does not
%%% know, or a setopt the kernel refuses, leaves the socket as it was.
-module(masque_udp_df).
-moduledoc false.

-export([set/2, options/2]).

%% <netinet/in.h> levels and option names.
-define(IPPROTO_IP, 0).
-define(IPPROTO_IPV6, 41).
-define(LINUX_IP_MTU_DISCOVER, 10).
-define(LINUX_IP_PMTUDISC_DO, 2).
-define(DARWIN_IP_DONTFRAG, 28).
-define(FREEBSD_IP_DONTFRAG, 67).
-define(IPV6_DONTFRAG, 62).

%% Set don't-fragment on `Socket' unless the handler opts say
%% `dont_fragment => false'.
-spec set(gen_udp:socket(), map()) -> ok.
set(Socket, Opts) ->
    case maps:get(dont_fragment, Opts, true) of
        false ->
            ok;
        _ ->
            lists:foreach(
                fun(Opt) -> _ = inet:setopts(Socket, [Opt]) end,
                options(os:type(), family(Socket))
            )
    end.

%% The raw socket options that forbid fragmentation for `Family' on `OS'.
-spec options({atom(), atom()}, inet | inet6) -> [{raw, integer(), integer(), binary()}].
options({unix, linux}, inet) ->
    [{raw, ?IPPROTO_IP, ?LINUX_IP_MTU_DISCOVER, int(?LINUX_IP_PMTUDISC_DO)}];
options({unix, darwin}, inet) ->
    [{raw, ?IPPROTO_IP, ?DARWIN_IP_DONTFRAG, int(1)}];
options({unix, freebsd}, inet) ->
    [{raw, ?IPPROTO_IP, ?FREEBSD_IP_DONTFRAG, int(1)}];
options({unix, OS}, inet6) when OS =:= linux; OS =:= darwin; OS =:= freebsd ->
    [{raw, ?IPPROTO_IPV6, ?IPV6_DONTFRAG, int(1)}];
options(_OS, _Family) ->
    [].

family(Socket) ->
    case inet:sockname(Socket) of
        {ok, {IP, _}} when tuple_size(IP) =:= 8 -> inet6;
        _ -> inet
    end.

int(N) -> <<N:32/native>>.
