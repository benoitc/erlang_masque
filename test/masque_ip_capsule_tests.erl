-module(masque_ip_capsule_tests).

-include_lib("eunit/include/eunit.hrl").
-include("masque_ip.hrl").

%%====================================================================
%% ADDRESS_ASSIGN round-trip
%%====================================================================

address_assign_v4_roundtrip_test() ->
    E = #ip_assignment{request_id = 7, version = 4,
                       address = {192,0,2,5}, prefix_len = 32},
    Body = masque_ip_capsule:encode_address_assign([E]),
    ?assertEqual({ok, [E]},
                 masque_ip_capsule:decode_address_assign(Body)).

address_assign_v6_roundtrip_test() ->
    E = #ip_assignment{request_id = 1, version = 6,
                       address = {16#2001,16#DB8,0,0,0,0,0,1},
                       prefix_len = 64},
    Body = masque_ip_capsule:encode_address_assign([E]),
    ?assertEqual({ok, [E]},
                 masque_ip_capsule:decode_address_assign(Body)).

address_assign_unprompted_zero_id_test() ->
    E = #ip_assignment{request_id = 0, version = 4,
                       address = {10,0,0,5}, prefix_len = 32},
    Body = masque_ip_capsule:encode_address_assign([E]),
    ?assertEqual({ok, [E]},
                 masque_ip_capsule:decode_address_assign(Body)).

address_assign_empty_allowed_test() ->
    %% ADDRESS_ASSIGN may be empty (withdraws everything).
    Body = masque_ip_capsule:encode_address_assign([]),
    ?assertEqual({ok, []},
                 masque_ip_capsule:decode_address_assign(Body)).

address_assign_bad_prefix_test() ->
    %% Directly crafted body with an out-of-range prefix for v4.
    BadBody = <<1, 4:8, 10:8, 0:8, 0:8, 0:8, 33:8>>,
    ?assertEqual({error, bad_prefix_length},
                 masque_ip_capsule:decode_address_assign(BadBody)).

%%====================================================================
%% ADDRESS_REQUEST validation
%%====================================================================

address_request_roundtrip_test() ->
    Es = [#ip_prefix_request{request_id = 1, version = 4,
                             address = {10,0,0,0}, prefix_len = 24},
          #ip_prefix_request{request_id = 2, version = 6,
                             address = {16#2001,16#DB8,0,0,0,0,0,0},
                             prefix_len = 32}],
    Body = masque_ip_capsule:encode_address_request(Es),
    ?assertEqual({ok, Es},
                 masque_ip_capsule:decode_address_request(Body)).

address_request_empty_rejected_encode_test() ->
    ?assertError(empty_address_request,
                 masque_ip_capsule:encode_address_request([])).

address_request_empty_rejected_decode_test() ->
    %% Empty body decodes as an empty list, which is malformed for
    %% ADDRESS_REQUEST specifically (§4.7.2 requires >=1 entry).
    ?assertEqual({error, empty_address_request},
                 masque_ip_capsule:decode_address_request(<<>>)).

address_request_zero_id_rejected_test() ->
    Body = <<0, 4:8, 10:8, 0:8, 0:8, 0:8, 32:8>>,
    ?assertEqual({error, zero_request_id_in_request},
                 masque_ip_capsule:decode_address_request(Body)).

address_request_duplicate_id_rejected_test() ->
    Es = [#ip_prefix_request{request_id = 1, version = 4,
                             address = {10,0,0,0}, prefix_len = 24},
          #ip_prefix_request{request_id = 1, version = 4,
                             address = {10,0,1,0}, prefix_len = 24}],
    ?assertError(duplicate_request_id,
                 masque_ip_capsule:encode_address_request(Es)).

%%====================================================================
%% ROUTE_ADVERTISEMENT validation
%%====================================================================

route_advertisement_roundtrip_test() ->
    Es = [#ip_route{version = 4,
                    start_addr = {10,0,0,0}, end_addr = {10,0,0,255},
                    ip_protocol = 0},
          #ip_route{version = 4,
                    start_addr = {192,0,2,0}, end_addr = {192,0,2,255},
                    ip_protocol = 6},
          #ip_route{version = 6,
                    start_addr = {16#2001,16#DB8,0,0,0,0,0,0},
                    end_addr   = {16#2001,16#DB8,0,0,0,0,0,16#FFFF},
                    ip_protocol = 17}],
    Body = masque_ip_capsule:encode_route_advertisement(Es),
    ?assertEqual({ok, Es},
                 masque_ip_capsule:decode_route_advertisement(Body)).

route_advertisement_empty_ok_test() ->
    Body = masque_ip_capsule:encode_route_advertisement([]),
    ?assertEqual({ok, []},
                 masque_ip_capsule:decode_route_advertisement(Body)).

route_advertisement_unordered_rejected_test() ->
    %% Two entries, same (V,P), Start address decreasing → unordered.
    Es = [#ip_route{version = 4, start_addr = {10,0,0,2},
                    end_addr = {10,0,0,3}, ip_protocol = 0},
          #ip_route{version = 4, start_addr = {10,0,0,0},
                    end_addr = {10,0,0,1}, ip_protocol = 0}],
    ?assertError(unordered_routes,
                 masque_ip_capsule:encode_route_advertisement(Es)).

route_advertisement_overlapping_rejected_test() ->
    %% Adjacent ranges with same (V,P) must be strictly disjoint.
    Es = [#ip_route{version = 4, start_addr = {10,0,0,0},
                    end_addr = {10,0,0,5}, ip_protocol = 0},
          #ip_route{version = 4, start_addr = {10,0,0,4},
                    end_addr = {10,0,0,10}, ip_protocol = 0}],
    ?assertError(unordered_routes,
                 masque_ip_capsule:encode_route_advertisement(Es)).

route_advertisement_proto_zero_overlap_rejected_test() ->
    %% Protocol-0 range covers 10.0.0.0-10.0.0.5 and there is a
    %% nonzero-protocol range 10.0.0.4-10.0.0.6 for the same version.
    Es = [#ip_route{version = 4, start_addr = {10,0,0,0},
                    end_addr = {10,0,0,5}, ip_protocol = 0},
          #ip_route{version = 4, start_addr = {10,0,0,4},
                    end_addr = {10,0,0,6}, ip_protocol = 6}],
    ?assertError(proto_zero_overlap,
                 masque_ip_capsule:encode_route_advertisement(Es)).

route_advertisement_proto_zero_disjoint_ok_test() ->
    %% Proto-0 range disjoint from nonzero ranges for same version.
    Es = [#ip_route{version = 4, start_addr = {10,0,0,0},
                    end_addr = {10,0,0,5}, ip_protocol = 0},
          #ip_route{version = 4, start_addr = {10,0,1,0},
                    end_addr = {10,0,1,5}, ip_protocol = 6}],
    Body = masque_ip_capsule:encode_route_advertisement(Es),
    ?assertEqual({ok, Es},
                 masque_ip_capsule:decode_route_advertisement(Body)).

%%====================================================================
%% Generic dispatch + reject_requests/1
%%====================================================================

generic_encode_dispatch_test() ->
    A = #ip_assignment{request_id = 1, version = 4,
                       address = {10,0,0,1}, prefix_len = 32},
    IoData = masque_ip_capsule:encode(address_assign, [A]),
    {ok, {Type, Body, <<>>}} = masque_capsule:decode(iolist_to_binary(IoData)),
    ?assertEqual(?MASQUE_CAPSULE_ADDRESS_ASSIGN, Type),
    ?assertEqual({ok, [A]}, masque_ip_capsule:decode_body(Type, Body)).

reject_requests_v4_test() ->
    R = #ip_prefix_request{request_id = 7, version = 4,
                           address = {10,0,0,1}, prefix_len = 32},
    ?assertEqual([#ip_assignment{request_id = 7, version = 4,
                                 address = {0,0,0,0}, prefix_len = 32}],
                 masque_ip:reject_requests([R])).

reject_requests_v6_test() ->
    R = #ip_prefix_request{request_id = 9, version = 6,
                           address = {16#2001,16#DB8,0,0,0,0,0,1},
                           prefix_len = 128},
    ?assertEqual([#ip_assignment{request_id = 9, version = 6,
                                 address = {0,0,0,0,0,0,0,0},
                                 prefix_len = 128}],
                 masque_ip:reject_requests([R])).
