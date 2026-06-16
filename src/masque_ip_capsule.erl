%%% @doc RFC 9484 §5 — CONNECT-IP capsule codec.
%%%
%%% Encodes and decodes the three CONNECT-IP capsule types on top of
%%% `masque_capsule' (RFC 9297 framing):
%%%
%%% <ul>
%%%  <li>`ADDRESS_ASSIGN' (0x01) — Request IDs may be 0 (unprompted).</li>
%%%  <li>`ADDRESS_REQUEST' (0x02) — at least one entry, Request IDs
%%%      MUST be nonzero and unique per sender.</li>
%%%  <li>`ROUTE_ADVERTISEMENT' (0x03) — lexicographic ordering by
%%%      (Version, IP Protocol, Start Address); ranges disjoint
%%%      within equal (Version, Protocol); protocol-0 ranges MUST NOT
%%%      overlap nonzero-protocol ranges for the same Version.</li>
%%% </ul>
%%%
%%% Every validation failure returns `{error, Reason}' — callers map
%%% this into an H3_MESSAGE_ERROR stream reset per RFC 9297 §3.3.

-module(masque_ip_capsule).

-export([
    encode_address_assign/1,
    encode_address_request/1,
    encode_route_advertisement/1
]).

-export([
    decode_address_assign/1,
    decode_address_request/1,
    decode_route_advertisement/1
]).

-export([encode/2, decode_body/2]).

-include("masque_ip.hrl").

-type address_entry() :: #ip_assignment{}.
-type request_entry() :: #ip_prefix_request{}.
-type route_entry() :: #ip_route{}.

-type decode_error() ::
    truncated
    | malformed_varint
    | bad_ip_version
    | bad_prefix_length
    | empty_address_request
    | duplicate_request_id
    | zero_request_id_in_request
    | unordered_routes
    | overlapping_routes
    | proto_zero_overlap.

-export_type([
    address_entry/0,
    request_entry/0,
    route_entry/0,
    decode_error/0
]).

%%====================================================================
%% Capsule-level encode (body -> framed capsule)
%%====================================================================

%% @doc Encode a typed capsule onto the RFC 9297 capsule frame.
%% Dispatches on the capsule type atom.
-spec encode(
    address_assign | address_request | route_advertisement,
    [address_entry() | request_entry() | route_entry()]
) ->
    iodata().
encode(address_assign, Entries) ->
    Body = encode_address_assign(Entries),
    masque_capsule:encode(?MASQUE_CAPSULE_ADDRESS_ASSIGN, Body);
encode(address_request, Entries) ->
    Body = encode_address_request(Entries),
    masque_capsule:encode(?MASQUE_CAPSULE_ADDRESS_REQUEST, Body);
encode(route_advertisement, Entries) ->
    Body = encode_route_advertisement(Entries),
    masque_capsule:encode(?MASQUE_CAPSULE_ROUTE_ADVERTISEMENT, Body).

%% @doc Decode the body bytes of a CONNECT-IP capsule into typed
%% entries. The capsule type is determined by the caller from the
%% capsule frame (e.g. via `masque_capsule:decode/1').
-spec decode_body(non_neg_integer(), binary()) ->
    {ok, [address_entry() | request_entry() | route_entry()]}
    | {error, decode_error()}.
decode_body(?MASQUE_CAPSULE_ADDRESS_ASSIGN, Body) ->
    decode_address_assign(Body);
decode_body(?MASQUE_CAPSULE_ADDRESS_REQUEST, Body) ->
    decode_address_request(Body);
decode_body(?MASQUE_CAPSULE_ROUTE_ADVERTISEMENT, Body) ->
    decode_route_advertisement(Body);
decode_body(_Type, _Body) ->
    %% Unknown capsule types are handled (dropped) by the caller.
    {error, {unknown_capsule_type, _Type}}.

%%====================================================================
%% ADDRESS_ASSIGN (0x01) — request_id >= 0 allowed
%%====================================================================

-spec encode_address_assign([address_entry()]) -> binary().
encode_address_assign(Entries) ->
    iolist_to_binary([encode_addr_entry(E) || E <- Entries]).

-spec decode_address_assign(binary()) ->
    {ok, [address_entry()]} | {error, decode_error()}.
decode_address_assign(Body) ->
    try
        Entries = decode_addr_entries(Body, fun make_assignment/4, []),
        {ok, Entries}
    catch
        throw:Err -> {error, Err}
    end.

make_assignment(ReqId, Ver, Addr, Pfx) ->
    #ip_assignment{
        request_id = ReqId,
        version = Ver,
        address = Addr,
        prefix_len = Pfx
    }.

%%====================================================================
%% ADDRESS_REQUEST (0x02) — >=1 entry, all request_id > 0 and unique
%%====================================================================

-spec encode_address_request([request_entry()]) -> binary().
encode_address_request([]) ->
    erlang:error(empty_address_request);
encode_address_request(Entries) ->
    %% The `#ip_prefix_request{}` record's `request_id` field is typed
    %% `pos_integer()`, so the "contains 0" case is unreachable via
    %% the public API. Uniqueness still needs a runtime check.
    Ids = [R#ip_prefix_request.request_id || R <- Entries],
    case length(Ids) =:= length(lists:usort(Ids)) of
        true -> ok;
        false -> erlang:error(duplicate_request_id)
    end,
    iolist_to_binary([encode_req_entry(E) || E <- Entries]).

-spec decode_address_request(binary()) ->
    {ok, [request_entry()]} | {error, decode_error()}.
decode_address_request(Body) ->
    try
        Entries = decode_addr_entries(Body, fun make_request/4, []),
        case Entries of
            [] ->
                {error, empty_address_request};
            _ ->
                Ids = [R#ip_prefix_request.request_id || R <- Entries],
                case length(Ids) =:= length(lists:usort(Ids)) of
                    true -> {ok, Entries};
                    false -> {error, duplicate_request_id}
                end
        end
    catch
        throw:Err -> {error, Err}
    end.

make_request(0, _Ver, _Addr, _Pfx) ->
    throw(zero_request_id_in_request);
make_request(ReqId, Ver, Addr, Pfx) ->
    #ip_prefix_request{
        request_id = ReqId,
        version = Ver,
        address = Addr,
        prefix_len = Pfx
    }.

%%====================================================================
%% ROUTE_ADVERTISEMENT (0x03)
%%====================================================================

-spec encode_route_advertisement([route_entry()]) -> binary().
encode_route_advertisement(Entries) ->
    ok = validate_routes(Entries),
    iolist_to_binary([encode_route_entry(E) || E <- Entries]).

-spec decode_route_advertisement(binary()) ->
    {ok, [route_entry()]} | {error, decode_error()}.
decode_route_advertisement(Body) ->
    try
        Entries = decode_route_entries(Body, []),
        case validate_routes_result(Entries) of
            ok -> {ok, Entries};
            {error, E} -> {error, E}
        end
    catch
        throw:Err -> {error, Err}
    end.

%%====================================================================
%% Internal — per-entry encode (ADDRESS_ASSIGN / ADDRESS_REQUEST)
%%====================================================================

encode_addr_entry(#ip_assignment{
    request_id = Id,
    version = V,
    address = A,
    prefix_len = P
}) ->
    encode_addr_tuple(Id, V, A, P);
encode_addr_entry(#ip_prefix_request{
    request_id = Id,
    version = V,
    address = A,
    prefix_len = P
}) ->
    encode_addr_tuple(Id, V, A, P).

encode_req_entry(#ip_prefix_request{
    request_id = Id,
    version = V,
    address = A,
    prefix_len = P
}) ->
    encode_addr_tuple(Id, V, A, P).

encode_addr_tuple(Id, 4, {A, B, C, D}, Pfx) when Pfx >= 0, Pfx =< 32 ->
    [quic_varint:encode(Id), <<4:8, A:8, B:8, C:8, D:8, Pfx:8>>];
encode_addr_tuple(Id, 6, Addr, Pfx) when
    Pfx >= 0,
    Pfx =< 128,
    tuple_size(Addr) =:= 8
->
    [quic_varint:encode(Id), <<6:8>>, v6_bin(Addr), <<Pfx:8>>];
encode_addr_tuple(_Id, _V, _A, _P) ->
    erlang:error(bad_ip_version).

v6_bin({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

%%====================================================================
%% Internal — per-entry decode (ADDRESS_ASSIGN / ADDRESS_REQUEST)
%%====================================================================

decode_addr_entries(<<>>, _Mk, Acc) ->
    lists:reverse(Acc);
decode_addr_entries(Bin, Mk, Acc) ->
    {ReqId, Rest1} = decode_varint(Bin),
    case Rest1 of
        <<4:8, A:8, B:8, C:8, D:8, Pfx:8, Rest2/binary>> when Pfx =< 32 ->
            case prefix_host_bits_zero(4, {A, B, C, D}, Pfx) of
                true ->
                    decode_addr_entries(
                        Rest2,
                        Mk,
                        [Mk(ReqId, 4, {A, B, C, D}, Pfx) | Acc]
                    );
                false ->
                    throw(non_canonical_prefix)
            end;
        <<4:8, _:8, _:8, _:8, _:8, Pfx:8, _/binary>> when Pfx > 32 ->
            throw(bad_prefix_length);
        <<4:8, _/binary>> ->
            throw(truncated);
        <<6:8, V6:128/binary-unit:1, Rest3/binary>> ->
            <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>> = V6,
            case Rest3 of
                <<Pfx:8, Rest4/binary>> when Pfx =< 128 ->
                    case
                        prefix_host_bits_zero(
                            6,
                            {A, B, C, D, E, F, G, H},
                            Pfx
                        )
                    of
                        true ->
                            decode_addr_entries(
                                Rest4,
                                Mk,
                                [
                                    Mk(
                                        ReqId,
                                        6,
                                        {A, B, C, D, E, F, G, H},
                                        Pfx
                                    )
                                    | Acc
                                ]
                            );
                        false ->
                            throw(non_canonical_prefix)
                    end;
                <<Pfx:8, _/binary>> when Pfx > 128 ->
                    throw(bad_prefix_length);
                _ ->
                    throw(truncated)
            end;
        <<Ver:8, _/binary>> when Ver =/= 4, Ver =/= 6 ->
            throw(bad_ip_version);
        _ ->
            throw(truncated)
    end.

%%====================================================================
%% Internal — per-entry encode/decode (ROUTE_ADVERTISEMENT)
%%====================================================================

encode_route_entry(#ip_route{
    version = 4,
    start_addr = {A, B, C, D},
    end_addr = {E, F, G, H},
    ip_protocol = P
}) when
    P >= 0, P =< 255
->
    <<4:8, A:8, B:8, C:8, D:8, E:8, F:8, G:8, H:8, P:8>>;
encode_route_entry(#ip_route{
    version = 6,
    start_addr = S,
    end_addr = E,
    ip_protocol = P
}) when
    P >= 0, P =< 255, tuple_size(S) =:= 8, tuple_size(E) =:= 8
->
    <<6:8, (v6_bin(S))/binary, (v6_bin(E))/binary, P:8>>;
encode_route_entry(_) ->
    erlang:error(bad_ip_version).

decode_route_entries(<<>>, Acc) ->
    lists:reverse(Acc);
decode_route_entries(<<4:8, A:8, B:8, C:8, D:8, E:8, F:8, G:8, H:8, P:8, Rest/binary>>, Acc) ->
    Route = #ip_route{
        version = 4,
        start_addr = {A, B, C, D},
        end_addr = {E, F, G, H},
        ip_protocol = P
    },
    decode_route_entries(Rest, [Route | Acc]);
decode_route_entries(
    <<6:8, S:16/binary, E:16/binary, P:8, Rest/binary>>,
    Acc
) ->
    <<SA:16, SB:16, SC:16, SD:16, SE:16, SF:16, SG:16, SH:16>> = S,
    <<EA:16, EB:16, EC:16, ED:16, EE:16, EF:16, EG:16, EH:16>> = E,
    Route = #ip_route{
        version = 6,
        start_addr = {SA, SB, SC, SD, SE, SF, SG, SH},
        end_addr = {EA, EB, EC, ED, EE, EF, EG, EH},
        ip_protocol = P
    },
    decode_route_entries(Rest, [Route | Acc]);
decode_route_entries(<<Ver:8, _/binary>>, _Acc) when Ver =/= 4, Ver =/= 6 ->
    throw(bad_ip_version);
decode_route_entries(_, _Acc) ->
    throw(truncated).

%%====================================================================
%% Internal — ROUTE_ADVERTISEMENT validation
%%====================================================================

validate_routes(Entries) ->
    case validate_routes_result(Entries) of
        ok -> ok;
        {error, E} -> erlang:error(E)
    end.

validate_routes_result([]) ->
    ok;
validate_routes_result(Entries) ->
    case check_each_range(Entries) of
        ok ->
            case check_sort_and_disjoint(Entries) of
                ok -> check_proto_zero_overlap(Entries);
                {error, _} = Err -> Err
            end;
        {error, _} = Err ->
            Err
    end.

%% RFC 9484 §4.7.2: every route advertises a non-empty range, i.e.
%% start_addr =< end_addr.
check_each_range([]) ->
    ok;
check_each_range([#ip_route{start_addr = S, end_addr = E} | Rest]) when
    S =< E
->
    check_each_range(Rest);
check_each_range(_) ->
    {error, route_range_reversed}.

%% Verify the list is sorted by (Version, Protocol, Start) with
%% strict disjointness within equal (Version, Protocol) buckets.
check_sort_and_disjoint([_] = _L) ->
    ok;
check_sort_and_disjoint([A, B | Rest]) ->
    case compare_route(A, B) of
        lt -> check_sort_and_disjoint([B | Rest]);
        _ -> {error, unordered_routes}
    end;
check_sort_and_disjoint([]) ->
    ok.

%% Strict "A < B" order across different (V, P) buckets is pure
%% lexicographic; within the same (V, P) bucket it additionally
%% requires E1 < S2 (disjoint ranges).
compare_route(#ip_route{version = V1}, #ip_route{version = V2}) when V1 < V2 ->
    lt;
compare_route(#ip_route{version = V1}, #ip_route{version = V2}) when V1 > V2 ->
    gt;
compare_route(#ip_route{ip_protocol = P1}, #ip_route{ip_protocol = P2}) when
    P1 < P2
->
    lt;
compare_route(#ip_route{ip_protocol = P1}, #ip_route{ip_protocol = P2}) when
    P1 > P2
->
    gt;
compare_route(#ip_route{end_addr = E1}, #ip_route{start_addr = S2}) ->
    %% Same (V, P) bucket — ranges must be strictly disjoint and
    %% ordered by start address, which is equivalent to E1 < S2.
    case E1 < S2 of
        true -> lt;
        false -> overlap
    end.

%% For each Version, protocol-0 ranges must not overlap any nonzero-
%% protocol range for the same Version (RFC 9484 §4.7.3).
check_proto_zero_overlap(Entries) ->
    ByVer = lists:foldl(
        fun(#ip_route{version = V} = R, Acc) ->
            maps:update_with(
                V,
                fun(L) -> [R | L] end,
                [R],
                Acc
            )
        end,
        #{},
        Entries
    ),
    maps:fold(
        fun
            (_V, Rs, ok) -> check_version_zero_overlap(Rs);
            (_V, _Rs, Err) -> Err
        end,
        ok,
        ByVer
    ).

check_version_zero_overlap(Rs) ->
    {Zeros, NonZeros} = lists:partition(
        fun(#ip_route{ip_protocol = P}) -> P =:= 0 end, Rs
    ),
    case Zeros of
        [] -> ok;
        _ -> check_zero_vs_nonzero(Zeros, NonZeros)
    end.

check_zero_vs_nonzero(_Zeros, []) ->
    ok;
check_zero_vs_nonzero(Zeros, [NZ | Rest]) ->
    case lists:any(fun(Z) -> ranges_overlap(Z, NZ) end, Zeros) of
        true -> {error, proto_zero_overlap};
        false -> check_zero_vs_nonzero(Zeros, Rest)
    end.

ranges_overlap(
    #ip_route{start_addr = S1, end_addr = E1},
    #ip_route{start_addr = S2, end_addr = E2}
) ->
    %% Inclusive ranges overlap iff max(S) =< min(E).
    max(S1, S2) =< min(E1, E2).

%% RFC 9484 §4.6: ADDRESS_ASSIGN/REQUEST prefixes must be canonical
%% (host bits zero).
prefix_host_bits_zero(_V, _IP, 0) ->
    true;
prefix_host_bits_zero(4, {A, B, C, D}, Pfx) when Pfx =< 32 ->
    N = (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D,
    HostBits = 32 - Pfx,
    (N band ((1 bsl HostBits) - 1)) =:= 0;
prefix_host_bits_zero(6, {A, B, C, D, E, F, G, H}, Pfx) when Pfx =< 128 ->
    N =
        (A bsl 112) bor (B bsl 96) bor (C bsl 80) bor (D bsl 64) bor
            (E bsl 48) bor (F bsl 32) bor (G bsl 16) bor H,
    HostBits = 128 - Pfx,
    (N band ((1 bsl HostBits) - 1)) =:= 0.

%%====================================================================
%% Internal — varint wrapper
%%====================================================================

decode_varint(Bin) ->
    try
        quic_varint:decode(Bin)
    catch
        error:_ -> throw(malformed_varint)
    end.
