%%% @doc IP address classification for SSRF protection.
%%%
%%% `is_public/1' returns `false' for loopback, RFC 1918 private,
%%% link-local, multicast, and reserved address ranges in both
%%% IPv4 and IPv6. The built-in proxy handlers call this after DNS
%%% resolution to reject tunnels targeting internal networks.
-module(masque_ip).

-export([is_public/1]).

-spec is_public(inet:ip_address()) -> boolean().

%% IPv4
is_public({0,_,_,_})                                      -> false; %% 0.0.0.0/8
is_public({10,_,_,_})                                     -> false; %% RFC 1918
is_public({100,B,_,_}) when B >= 64, B =< 127             -> false; %% RFC 6598 CGN
is_public({127,_,_,_})                                    -> false; %% loopback
is_public({169,254,_,_})                                  -> false; %% link-local
is_public({172,B,_,_}) when B >= 16, B =< 31              -> false; %% RFC 1918
is_public({192,0,0,_})                                    -> false; %% RFC 6890
is_public({192,0,2,_})                                    -> false; %% TEST-NET-1
is_public({192,88,99,_})                                  -> false; %% 6to4 relay
is_public({192,168,_,_})                                  -> false; %% RFC 1918
is_public({198,18,_,_})                                   -> false; %% benchmarking
is_public({198,19,_,_})                                   -> false; %% benchmarking
is_public({198,51,100,_})                                 -> false; %% TEST-NET-2
is_public({203,0,113,_})                                  -> false; %% TEST-NET-3
is_public({A,_,_,_}) when A >= 224                        -> false; %% multicast + reserved
%% IPv6
is_public({0,0,0,0,0,0,0,0})                             -> false; %% ::  unspecified
is_public({0,0,0,0,0,0,0,1})                             -> false; %% ::1 loopback
is_public({0,0,0,0,0,16#FFFF,_,_})                       -> false; %% ::ffff:0:0/96 mapped v4
is_public({16#64,16#FF9B,_,_,_,_,_,_})                   -> false; %% 64:ff9b::/96 NAT64
is_public({16#100,_,_,_,_,_,_,_})                        -> false; %% discard 100::/64
is_public({16#2001,0,_,_,_,_,_,_})                       -> false; %% teredo
is_public({16#2001,16#DB8,_,_,_,_,_,_})                  -> false; %% documentation
is_public({A,_,_,_,_,_,_,_}) when A >= 16#FC00,
                                   A =< 16#FDFF          -> false; %% ULA fc00::/7
is_public({A,_,_,_,_,_,_,_}) when A >= 16#FE80,
                                   A =< 16#FEBF          -> false; %% link-local fe80::/10
is_public({A,_,_,_,_,_,_,_}) when A >= 16#FF00           -> false; %% multicast ff00::/8
is_public(_)                                              -> true.
