-module(masque_icmp).
-moduledoc """
ICMPv4 (RFC 792) and ICMPv6 (RFC 4443) error-message
builders used by CONNECT-IP proxies to synthesise errors for
packets they cannot deliver.

Each builder returns a complete IP packet (IP header + ICMP
message) ready to hand back to the client via
`masque:send_ip_packet/2` or a handler's
`{send_ip_packet, _}` / `{icmp_error, _}` action.

Invoking-packet truncation (RFC 4443 §3.1 and RFC 1812 §4.3.2.3):
- ICMPv6: "as much of invoking packet as possible without the
  ICMPv6 packet exceeding the minimum IPv6 MTU" (1280 B).
  Budget: 1280 − 40 (IPv6 hdr) − 8 (ICMPv6 hdr) = 1232 B.
- ICMPv4: at least the IPv4 header plus 8 B of the original
  datagram's data; we cap at the IPv4 minimum MTU 576, i.e.
  576 − 20 − 8 = 548 B of the invoking packet.
""".

-export([
    dest_unreachable/3,
    packet_too_big/2,
    frag_needed/2,
    time_exceeded/2
]).

-export([apply_action/3]).
-export([is_error/1]).

%% Limits.
-define(V4_INVOKING_CAP, 548).
-define(V6_INVOKING_CAP, 1232).

%% Default source address for proxy-synthesised ICMP errors.
-define(DEFAULT_V4_SRC, {0, 0, 0, 0}).
-define(DEFAULT_V6_SRC, {0, 0, 0, 0, 0, 0, 0, 0}).

%%====================================================================
%% API
%%====================================================================

-doc """
True when `Packet` is an ICMP error message: ICMPv4 types 3,
4, 5, 11 and 12, or an ICMPv6 type below 128. RFC 1122 §3.2.2 and
RFC 4443 §2.4 (e) forbid answering those with another ICMP error.
""".
-spec is_error(binary()) -> boolean().
is_error(Packet) ->
    case masque_ip_packet:upper_layer(Packet) of
        {ok, 1, <<Type:8, _/binary>>} ->
            %% A non-initial fragment does not start with the ICMP
            %% header; its type byte is not meaningful.
            first_fragment(Packet) andalso lists:member(Type, [3, 4, 5, 11, 12]);
        {ok, 58, <<Type:8, _/binary>>} ->
            <<6:4, _/bitstring>> = Packet,
            Type < 128;
        _ ->
            false
    end.

first_fragment(<<4:4, _:4, _:8, _:16, _:16, _:3, Offset:13, _/binary>>) -> Offset =:= 0;
first_fragment(_) -> true.

-doc """
Build a Destination Unreachable ICMP packet.
Code maps to the RFC type/code tables.
For IPv4 (type 3): 0 = net unreachable, 1 = host unreachable,
3 = port unreachable, 4 = frag needed (RFC 792 / RFC 1812).
For IPv6 (type 1): 0 = no route, 1 = admin prohibited, 3 = addr
unreachable, 4 = port unreachable, 5 = src addr failed
ingress/egress policy (RFC 4443 section 3.1).
""".
-spec dest_unreachable(v4 | v6, non_neg_integer(), binary()) -> binary().
dest_unreachable(v4, Code, Invoking) ->
    build_v4(3, Code, <<0:32>>, Invoking);
dest_unreachable(v6, Code, Invoking) ->
    build_v6(1, Code, <<0:32>>, Invoking).

-doc """
Build an IPv6 Packet Too Big (type 2, RFC 4443 §3.2). `Mtu`
is the next-hop MTU that caused the drop.
""".
-spec packet_too_big(non_neg_integer(), binary()) -> binary().
packet_too_big(Mtu, Invoking) ->
    build_v6(2, 0, <<Mtu:32>>, Invoking).

-doc """
Build an IPv4 Destination Unreachable, Fragmentation Needed
and DF Set (type 3 code 4) carrying the next-hop `Mtu` (RFC 1191
sec 4). The IPv4 counterpart of `packet_too_big/2`.
""".
-spec frag_needed(0..16#FFFF, binary()) -> binary().
frag_needed(Mtu, Invoking) ->
    build_v4(3, 4, <<0:16, Mtu:16>>, Invoking).

-doc """
Build a Time Exceeded ICMP packet. `Code` is 0 (TTL/HL
exceeded in transit) or 1 (fragment reassembly timeout).
""".
-spec time_exceeded(v4 | v6, non_neg_integer(), binary()) -> binary().
time_exceeded(v4, Code, Invoking) ->
    build_v4(11, Code, <<0:32>>, Invoking);
time_exceeded(v6, Code, Invoking) ->
    build_v6(3, Code, <<0:32>>, Invoking).

time_exceeded(v4, Invoking) -> time_exceeded(v4, 0, Invoking);
time_exceeded(v6, Invoking) -> time_exceeded(v6, 0, Invoking).

-doc """
Translate a session-level `{icmp_error, Spec}` action into
the IP packet it represents. Used by the IP server session's
action interpreter. `Spec` accepts:
- `{dest_unreachable, v4|v6, Code}`
- `{packet_too_big, Mtu}`  (IPv6 only)
- `{frag_needed, Mtu}`  (IPv4 only)
- `{time_exceeded,   v4|v6}`
""".
-spec apply_action(atom(), term(), binary()) -> binary().
apply_action(dest_unreachable, {V, Code}, Invoking) ->
    dest_unreachable(V, Code, Invoking);
apply_action(packet_too_big, Mtu, Invoking) ->
    packet_too_big(Mtu, Invoking);
apply_action(frag_needed, Mtu, Invoking) ->
    frag_needed(Mtu, Invoking);
apply_action(time_exceeded, {V, Code}, Invoking) ->
    time_exceeded(V, Code, Invoking);
apply_action(time_exceeded, V, Invoking) when V =:= v4; V =:= v6 ->
    time_exceeded(V, Invoking).

%%====================================================================
%% Internal — IPv4 builder (type | code | csum | rest-of-header | body)
%%====================================================================

build_v4(Type, Code, RestHeader4, Invoking) ->
    Body = clamp(Invoking, ?V4_INVOKING_CAP),
    %% Preserve the invoking packet's destination as our source so
    %% the client sees the packet "from" the original target.
    {Src, Dst} = v4_endpoints(Invoking),
    Msg0 = <<Type:8, Code:8, 0:16, RestHeader4/binary, Body/binary>>,
    Csum = inet_checksum(Msg0),
    Msg = <<Type:8, Code:8, Csum:16, RestHeader4/binary, Body/binary>>,
    TotalLen = 20 + byte_size(Msg),
    Header0 =
        <<16#45:8, 0:8, TotalLen:16, 0:16, 2#010:3, 0:13, 64:8, 1:8, 0:16, (ip4_bin(Src))/binary,
            (ip4_bin(Dst))/binary>>,
    HdrCsum = inet_checksum(Header0),
    Header =
        <<16#45:8, 0:8, TotalLen:16, 0:16, 2#010:3, 0:13, 64:8, 1:8, HdrCsum:16,
            (ip4_bin(Src))/binary, (ip4_bin(Dst))/binary>>,
    <<Header/binary, Msg/binary>>.

v4_endpoints(
    <<4:4, _IHL:4, _TOS:8, _:16, _:16, _:16, _:8, _:8, _:16, SA:8, SB:8, SC:8, SD:8, DA:8, DB:8,
        DC:8, DD:8, _/binary>>
) ->
    {{DA, DB, DC, DD}, {SA, SB, SC, SD}};
v4_endpoints(_) ->
    {?DEFAULT_V4_SRC, ?DEFAULT_V4_SRC}.

ip4_bin({A, B, C, D}) -> <<A:8, B:8, C:8, D:8>>.

%%====================================================================
%% Internal — IPv6 builder (pseudo-header checksum, RFC 2460 §8.1)
%%====================================================================

build_v6(Type, Code, RestHeader4, Invoking) ->
    Body = clamp(Invoking, ?V6_INVOKING_CAP),
    {Src, Dst} = v6_endpoints(Invoking),
    Msg0 = <<Type:8, Code:8, 0:16, RestHeader4/binary, Body/binary>>,
    PayloadLen = byte_size(Msg0),
    %% ICMPv6 checksum includes the IPv6 pseudo-header.
    Pseudo = <<(ip6_bin(Src))/binary, (ip6_bin(Dst))/binary, PayloadLen:32, 0:24, 58:8>>,
    Csum = inet_checksum(<<Pseudo/binary, Msg0/binary>>),
    Msg = <<Type:8, Code:8, Csum:16, RestHeader4/binary, Body/binary>>,
    Header =
        <<6:4, 0:8, 0:20, PayloadLen:16, 58:8, 64:8, (ip6_bin(Src))/binary, (ip6_bin(Dst))/binary>>,
    <<Header/binary, Msg/binary>>.

v6_endpoints(
    <<6:4, _:28, _:16, _:8, _:8, SA:16, SB:16, SC:16, SD:16, SE:16, SF:16, SG:16, SH:16, DA:16,
        DB:16, DC:16, DD:16, DE:16, DF:16, DG:16, DH:16, _/binary>>
) ->
    {{DA, DB, DC, DD, DE, DF, DG, DH}, {SA, SB, SC, SD, SE, SF, SG, SH}};
v6_endpoints(_) ->
    {?DEFAULT_V6_SRC, ?DEFAULT_V6_SRC}.

ip6_bin({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

%%====================================================================
%% Internal — shared helpers
%%====================================================================

clamp(Bin, Max) when byte_size(Bin) =< Max -> Bin;
clamp(Bin, Max) -> binary:part(Bin, 0, Max).

inet_checksum(Bin) ->
    masque_ip_packet:checksum(Bin).
