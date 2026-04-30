%%% @doc Lightweight read-only IP packet parsing for CONNECT-IP scope
%%% checks (RFC 9484 section 5).
%%%
%%% The proxy negotiates a `target' (destination IP / prefix scope) and
%%% an `ipproto' (upper-layer protocol scope) when the URI template
%%% binds them. Inbound packets that fall outside the negotiated scope
%%% must be dropped before forwarding.
%%%
%%% IPv6 carries the upper-layer protocol behind a chain of extension
%%% headers; this module walks that chain to find the first
%%% non-extension `Next Header' value, which is what RFC 9484 says
%%% `ipproto' is matched against.
-module(masque_ip_packet).

-export([destination/1, upper_protocol/1,
         scope_passes/3, scope_check/3]).

-type version() :: 4 | 6.
-type address() :: inet:ip4_address() | inet:ip6_address().
-type proto() :: 0..255.

-export_type([version/0, address/0, proto/0]).

%% @doc Extract the IP version and destination address from `Packet'.
-spec destination(binary()) ->
    {ok, version(), address()} | {error, term()}.
destination(<<4:4, _:4, _:8, _:16, _:16, _:16, _:8, _:8, _:16,
              _:32, A:8, B:8, C:8, D:8, _/binary>>) ->
    {ok, 4, {A,B,C,D}};
destination(<<6:4, _:4, _:8, _:16, _:16, _:8, _:8,
              _Src:128, A:16, B:16, C:16, D:16,
              E:16, F:16, G:16, H:16, _/binary>>) ->
    {ok, 6, {A,B,C,D,E,F,G,H}};
destination(_) ->
    {error, malformed}.

%% @doc Return the upper-layer protocol number, walking IPv6 extension
%% headers (Hop-by-Hop 0, Routing 43, Fragment 44, Destination 60,
%% AH 51) to find the first non-extension Next Header.
-spec upper_protocol(binary()) -> {ok, proto()} | {error, term()}.
upper_protocol(<<4:4, IHL:4, _Rest:64, Proto:8, _/binary>> = Pkt)
  when IHL >= 5, byte_size(Pkt) >= IHL * 4 ->
    {ok, Proto};
upper_protocol(<<6:4, _:4, _:8, _:16, _:16, NextHdr:8, _:8,
                 _Src:128, _Dst:128, Rest/binary>>) ->
    walk_v6_ext(NextHdr, Rest);
upper_protocol(_) ->
    {error, malformed}.

%% @doc Combined `target' / `ipproto' scope check used by the
%% data plane. `*' means "any" on either axis.
-spec scope_passes(binary(),
                   masque_uri_ip:ip_target(),
                   masque_uri_ip:ip_ipproto()) -> boolean().
scope_passes(Packet, Target, IPProto) ->
    case scope_check(Packet, Target, IPProto) of
        ok         -> true;
        {error, _} -> false
    end.

%% @doc Reasonful variant of `scope_passes/3' for telemetry. Returns
%% the first failing axis instead of a boolean.
-spec scope_check(binary(),
                  masque_uri_ip:ip_target(),
                  masque_uri_ip:ip_ipproto()) ->
    ok | {error, malformed | scope_target | scope_ipproto}.
scope_check(Packet, Target, IPProto) ->
    case destination(Packet) of
        {ok, V, Dst} ->
            case target_matches(V, Dst, Target) of
                true ->
                    case ipproto_matches(Packet, IPProto) of
                        true  -> ok;
                        false -> {error, scope_ipproto}
                    end;
                false ->
                    {error, scope_target}
            end;
        {error, _} ->
            {error, malformed}
    end.

%%====================================================================
%% Internal
%%====================================================================

target_matches(_V, _Dst, '*') -> true;
target_matches(4, Dst, {_,_,_,_} = Want) -> Dst =:= Want;
target_matches(6, Dst, {_,_,_,_,_,_,_,_} = Want) -> Dst =:= Want;
target_matches(4, Dst, {4, Net, Pfx}) ->
    in_v4_prefix(Dst, Net, Pfx);
target_matches(6, Dst, {6, Net, Pfx}) ->
    in_v6_prefix(Dst, Net, Pfx);
target_matches(_V, _Dst, Bin) when is_binary(Bin) ->
    %% Hostname target: resolution happens at handshake time and the
    %% resolved addresses become routes, so packets are scoped via
    %% the route table rather than here.
    true;
target_matches(_, _, _) -> false.

in_v4_prefix({A,B,C,D}, {NA,NB,NC,ND}, Pfx) when Pfx =< 32 ->
    Mask = bnot ((1 bsl (32 - Pfx)) - 1) band 16#FFFFFFFF,
    Net  = (NA bsl 24) bor (NB bsl 16) bor (NC bsl 8) bor ND,
    Addr = (A  bsl 24) bor (B  bsl 16) bor (C  bsl 8) bor D,
    (Addr band Mask) =:= (Net band Mask).

in_v6_prefix(Addr, Net, Pfx) when Pfx =< 128 ->
    {A,B,C,D,E,F,G,H} = Addr,
    {NA,NB,NC,ND,NE,NF,NG,NH} = Net,
    AInt = (A bsl 112) bor (B bsl 96) bor (C bsl 80) bor (D bsl 64)
            bor (E bsl 48) bor (F bsl 32) bor (G bsl 16) bor H,
    NInt = (NA bsl 112) bor (NB bsl 96) bor (NC bsl 80) bor (ND bsl 64)
            bor (NE bsl 48) bor (NF bsl 32) bor (NG bsl 16) bor NH,
    HostBits = 128 - Pfx,
    Mask = bnot ((1 bsl HostBits) - 1) band ((1 bsl 128) - 1),
    (AInt band Mask) =:= (NInt band Mask).

ipproto_matches(_Packet, '*') -> true;
ipproto_matches(Packet, P) when is_integer(P) ->
    case upper_protocol(Packet) of
        {ok, P}      -> true;
        {ok, _}      -> false;
        {error, _}   -> false
    end.

%% IPv6 extension-header chain. Each header is 8 + Hdr_Ext_Len*8 bytes
%% with Next Header in byte 0; Fragment is fixed 8 bytes; AH uses
%% (Hdr_Ext_Len + 2) * 4 byte units.
walk_v6_ext(0, <<NH:8, ExtLen:8, _:6/binary, Rest/binary>>) ->
    consume_ext(NH, ExtLen, Rest, fun walk_v6_ext/2);
walk_v6_ext(43, <<NH:8, ExtLen:8, _:6/binary, Rest/binary>>) ->
    consume_ext(NH, ExtLen, Rest, fun walk_v6_ext/2);
walk_v6_ext(60, <<NH:8, ExtLen:8, _:6/binary, Rest/binary>>) ->
    consume_ext(NH, ExtLen, Rest, fun walk_v6_ext/2);
walk_v6_ext(44, <<NH:8, _:7/binary, Rest/binary>>) ->
    walk_v6_ext(NH, Rest);
walk_v6_ext(51, <<NH:8, ExtLen:8, _:6/binary, Rest/binary>>) ->
    %% AH: total length = (Hdr_Ext_Len + 2) * 4 bytes; we already ate 8.
    Total = (ExtLen + 2) * 4,
    case Total >= 8 andalso byte_size(Rest) >= (Total - 8) of
        true ->
            <<_:(Total - 8)/binary, More/binary>> = Rest,
            walk_v6_ext(NH, More);
        false ->
            {error, malformed}
    end;
walk_v6_ext(NH, _Rest) ->
    {ok, NH}.

consume_ext(NH, ExtLen, Rest, Cont) ->
    Skip = ExtLen * 8,
    case byte_size(Rest) >= Skip of
        true ->
            <<_:Skip/binary, More/binary>> = Rest,
            Cont(NH, More);
        false ->
            {error, malformed}
    end.
