-module(masque_ip_tests).
-include_lib("eunit/include/eunit.hrl").

%% IPv4 public
public_ipv4_test() ->
    ?assert(masque_ip:is_public({8,8,8,8})),
    ?assert(masque_ip:is_public({1,1,1,1})),
    ?assert(masque_ip:is_public({93,184,216,34})),
    ?assert(masque_ip:is_public({203,0,114,1})).

%% IPv4 loopback
loopback_v4_test() ->
    ?assertNot(masque_ip:is_public({127,0,0,1})),
    ?assertNot(masque_ip:is_public({127,255,255,255})).

%% IPv4 RFC 1918
rfc1918_10_test() ->
    ?assertNot(masque_ip:is_public({10,0,0,1})),
    ?assertNot(masque_ip:is_public({10,255,255,255})).

rfc1918_172_test() ->
    ?assertNot(masque_ip:is_public({172,16,0,1})),
    ?assertNot(masque_ip:is_public({172,31,255,255})),
    ?assert(masque_ip:is_public({172,15,255,255})),
    ?assert(masque_ip:is_public({172,32,0,0})).

rfc1918_192_test() ->
    ?assertNot(masque_ip:is_public({192,168,0,1})),
    ?assertNot(masque_ip:is_public({192,168,255,255})).

%% IPv4 link-local
link_local_v4_test() ->
    ?assertNot(masque_ip:is_public({169,254,0,1})),
    ?assertNot(masque_ip:is_public({169,254,255,255})).

%% IPv4 CGN (RFC 6598)
cgn_test() ->
    ?assertNot(masque_ip:is_public({100,64,0,1})),
    ?assertNot(masque_ip:is_public({100,127,255,255})),
    ?assert(masque_ip:is_public({100,63,255,255})),
    ?assert(masque_ip:is_public({100,128,0,0})).

%% IPv4 documentation / test ranges
doc_v4_test() ->
    ?assertNot(masque_ip:is_public({192,0,2,1})),
    ?assertNot(masque_ip:is_public({198,51,100,1})),
    ?assertNot(masque_ip:is_public({203,0,113,1})).

%% IPv4 benchmarking
benchmark_test() ->
    ?assertNot(masque_ip:is_public({198,18,0,1})),
    ?assertNot(masque_ip:is_public({198,19,255,255})).

%% IPv4 multicast + reserved
multicast_v4_test() ->
    ?assertNot(masque_ip:is_public({224,0,0,1})),
    ?assertNot(masque_ip:is_public({239,255,255,255})),
    ?assertNot(masque_ip:is_public({255,255,255,255})).

%% IPv4 zero network
zero_v4_test() ->
    ?assertNot(masque_ip:is_public({0,0,0,0})),
    ?assertNot(masque_ip:is_public({0,255,255,255})).

%% IPv6 public
public_ipv6_test() ->
    ?assert(masque_ip:is_public({16#2607,16#F8B0,16#4004,0,0,0,0,16#200E})),
    ?assert(masque_ip:is_public({16#2001,16#4860,16#4860,0,0,0,0,16#8888})).

%% IPv6 loopback and unspecified
loopback_v6_test() ->
    ?assertNot(masque_ip:is_public({0,0,0,0,0,0,0,1})),
    ?assertNot(masque_ip:is_public({0,0,0,0,0,0,0,0})).

%% IPv6 mapped v4
mapped_v4_test() ->
    ?assertNot(masque_ip:is_public({0,0,0,0,0,16#FFFF,16#7F00,1})).

%% IPv6 ULA
ula_test() ->
    ?assertNot(masque_ip:is_public({16#FC00,0,0,0,0,0,0,1})),
    ?assertNot(masque_ip:is_public({16#FD00,0,0,0,0,0,0,1})),
    ?assertNot(masque_ip:is_public({16#FDFF,16#FFFF,16#FFFF,16#FFFF,
                                    16#FFFF,16#FFFF,16#FFFF,16#FFFF})).

%% IPv6 link-local
link_local_v6_test() ->
    ?assertNot(masque_ip:is_public({16#FE80,0,0,0,0,0,0,1})),
    ?assertNot(masque_ip:is_public({16#FEBF,16#FFFF,0,0,0,0,0,1})).

%% IPv6 multicast
multicast_v6_test() ->
    ?assertNot(masque_ip:is_public({16#FF00,0,0,0,0,0,0,1})),
    ?assertNot(masque_ip:is_public({16#FF02,0,0,0,0,0,0,1})).

%% IPv6 documentation
doc_v6_test() ->
    ?assertNot(masque_ip:is_public({16#2001,16#DB8,0,0,0,0,0,1})).

%% IPv6 NAT64
nat64_test() ->
    ?assertNot(masque_ip:is_public({16#64,16#FF9B,0,0,0,0,0,1})).

%% IPv6 teredo
teredo_test() ->
    ?assertNot(masque_ip:is_public({16#2001,0,0,0,0,0,0,1})).

%% IPv6 discard
discard_test() ->
    ?assertNot(masque_ip:is_public({16#100,0,0,0,0,0,0,1})).
