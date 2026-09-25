-module(masque_compression_table_tests).

-include_lib("eunit/include/eunit.hrl").
-include("masque_udp_bind.hrl").

%%====================================================================
%% Constructors and parity
%%====================================================================

own_client_starts_at_2_test() ->
    T = masque_compression_table:new_own(client, #{}),
    {ok, E, _T2} =
        masque_compression_table:open_compressed(T, {4, {10, 0, 0, 1}, 1234}),
    ?assertEqual(2, E#compression_entry.context_id).

own_proxy_starts_at_1_test() ->
    T = masque_compression_table:new_own(proxy, #{}),
    {ok, E, _T2} =
        masque_compression_table:open_compressed(T, {4, {10, 0, 0, 1}, 1234}),
    ?assertEqual(1, E#compression_entry.context_id).

own_client_increments_by_2_test() ->
    T0 = masque_compression_table:new_own(client, #{}),
    {ok, _, T1} =
        masque_compression_table:open_compressed(T0, {4, {10, 0, 0, 1}, 1234}),
    {ok, E2, _T2} =
        masque_compression_table:open_compressed(T1, {4, {10, 0, 0, 2}, 1234}),
    ?assertEqual(4, E2#compression_entry.context_id).

own_proxy_increments_by_2_test() ->
    T0 = masque_compression_table:new_own(proxy, #{}),
    {ok, _, T1} =
        masque_compression_table:open_compressed(T0, {4, {10, 0, 0, 1}, 1234}),
    {ok, E2, _T2} =
        masque_compression_table:open_compressed(T1, {4, {10, 0, 0, 2}, 1234}),
    ?assertEqual(3, E2#compression_entry.context_id).

%%====================================================================
%% open_compressed: family gating, post-close prohibition
%%====================================================================

open_v4_only_rejects_v6_test() ->
    T = masque_compression_table:new_own(
        client,
        #{advertised_families => [4]}
    ),
    ?assertEqual(
        {error, unadvertised_family},
        masque_compression_table:open_compressed(
            T, {6, {16#2001, 0, 0, 0, 0, 0, 0, 1}, 4433}
        )
    ).

open_compressed_records_pending_ack_test() ->
    T = masque_compression_table:new_own(client, #{}),
    {ok, E, _T2} =
        masque_compression_table:open_compressed(T, {4, {10, 0, 0, 1}, 1234}),
    ?assertEqual(pending_ack, E#compression_entry.state),
    ?assertEqual(outbound, E#compression_entry.direction).

%% Same-side duplicate tuple (own table already has it) is malformed.
open_compressed_duplicate_tuple_rejected_test() ->
    T0 = masque_compression_table:new_own(client, #{}),
    {ok, _, T1} =
        masque_compression_table:open_compressed(T0, {4, {10, 0, 0, 1}, 1234}),
    ?assertEqual(
        {error, malformed_duplicate_tuple},
        masque_compression_table:open_compressed(
            T1, {4, {10, 0, 0, 1}, 1234}
        )
    ).

%%====================================================================
%% open_uncompressed: client-only, singleton, post-close prohibition
%%====================================================================

open_uncompressed_client_succeeds_test() ->
    T = masque_compression_table:new_own(client, #{}),
    {ok, E, _T2} = masque_compression_table:open_uncompressed(T),
    ?assertEqual(0, E#compression_entry.ip_version),
    ?assertEqual(undefined, E#compression_entry.address),
    ?assertEqual(undefined, E#compression_entry.port).

open_uncompressed_proxy_rejected_test() ->
    T = masque_compression_table:new_own(proxy, #{}),
    ?assertEqual(
        {error, uncompressed_only_from_client},
        masque_compression_table:open_uncompressed(T)
    ).

%% Singleton: a second open_uncompressed/1 returns
%% {error, uncompressed_context_already_open}.
open_uncompressed_singleton_test() ->
    T0 = masque_compression_table:new_own(client, #{}),
    {ok, _, T1} = masque_compression_table:open_uncompressed(T0),
    ?assertEqual(
        {error, uncompressed_context_already_open},
        masque_compression_table:open_uncompressed(T1)
    ).

%% Post-close prohibition (draft-11): after the client closed its
%% uncompressed context the proxy opens no new compressed contexts.
open_compressed_after_uncompressed_close_rejected_test() ->
    T0 = masque_compression_table:new_own(proxy, #{}),
    {ok, _, T1} =
        masque_compression_table:open_compressed(T0, {4, {10, 0, 0, 1}, 1234}),
    T2 = masque_compression_table:mark_uncompressed_closed(T1),
    ?assertEqual(
        {error, uncompressed_closed},
        masque_compression_table:open_compressed(T2, {4, {10, 0, 0, 2}, 1234})
    ).

%% Cross-side conflict on the proxy: the client assigns a tuple the
%% proxy already opened; the proxy's own context is the one to close.
install_conflict_on_proxy_closes_own_id_test() ->
    Own0 = masque_compression_table:new_own(proxy, #{}),
    {ok, #compression_entry{context_id = OwnId}, Own1} =
        masque_compression_table:open_compressed(Own0, {4, {10, 0, 0, 1}, 1234}),
    Peer = masque_compression_table:new_peer(proxy, #{}),
    A = #compression_assign{context_id = 2, ip_version = 4, address = {10, 0, 0, 1}, port = 1234},
    {ok, {conflict, close_proxy_id, OwnId}, Peer1} =
        masque_compression_table:install(Peer, A, Own1),
    ?assertMatch({ok, _}, masque_compression_table:lookup_by_id(Peer1, 2)).

%% Same conflict seen from the client: the proxy's incoming context is
%% the one to close.
install_conflict_on_client_names_proxy_id_test() ->
    Own0 = masque_compression_table:new_own(client, #{}),
    {ok, _, Own1} =
        masque_compression_table:open_compressed(Own0, {4, {10, 0, 0, 1}, 1234}),
    Peer = masque_compression_table:new_peer(client, #{}),
    A = #compression_assign{context_id = 3, ip_version = 4, address = {10, 0, 0, 1}, port = 1234},
    ?assertMatch(
        {ok, {conflict, close_proxy_id, 3}, _},
        masque_compression_table:install(Peer, A, Own1)
    ).

install_without_conflict_test() ->
    Own = masque_compression_table:new_own(proxy, #{}),
    Peer = masque_compression_table:new_peer(proxy, #{}),
    A = #compression_assign{context_id = 2, ip_version = 4, address = {10, 0, 0, 1}, port = 1234},
    ?assertMatch({ok, _}, masque_compression_table:install(Peer, A, Own)).

install_unknown_ip_version_rejected_test() ->
    Peer = masque_compression_table:new_peer(proxy, #{}),
    A = #compression_assign{context_id = 2, ip_version = 5, address = undefined, port = undefined},
    ?assertEqual({error, bad_ip_version}, masque_compression_table:install(Peer, A)).

%%====================================================================
%% install: parity, duplicates, conflict resolution
%%====================================================================

install_peer_with_correct_parity_succeeds_test() ->
    %% Client-side peer table receives a proxy ASSIGN with odd id.
    T = masque_compression_table:new_peer(client, #{}),
    A = #compression_assign{
        context_id = 3,
        ip_version = 4,
        address = {10, 0, 0, 1},
        port = 1234
    },
    {ok, T2} = masque_compression_table:install(T, A),
    ?assertMatch(
        {ok, _},
        masque_compression_table:lookup_by_id(T2, 3)
    ),
    ?assertMatch(
        {ok, _},
        masque_compression_table:lookup_by_tuple(
            T2, {4, {10, 0, 0, 1}, 1234}
        )
    ).

install_peer_with_wrong_parity_rejected_test() ->
    %% Client-side peer table; proxy must use odd; even id rejected.
    T = masque_compression_table:new_peer(client, #{}),
    A = #compression_assign{
        context_id = 4,
        ip_version = 4,
        address = {10, 0, 0, 1},
        port = 1234
    },
    ?assertEqual(
        {error, bad_parity},
        masque_compression_table:install(T, A)
    ).

install_proxy_with_wrong_parity_rejected_test() ->
    %% Proxy-side peer table; client must use even; odd id rejected.
    T = masque_compression_table:new_peer(proxy, #{}),
    A = #compression_assign{
        context_id = 3,
        ip_version = 4,
        address = {10, 0, 0, 1},
        port = 1234
    },
    ?assertEqual(
        {error, bad_parity},
        masque_compression_table:install(T, A)
    ).

install_duplicate_id_rejected_test() ->
    T0 = masque_compression_table:new_peer(client, #{}),
    A1 = #compression_assign{
        context_id = 3,
        ip_version = 4,
        address = {10, 0, 0, 1},
        port = 1234
    },
    {ok, T1} = masque_compression_table:install(T0, A1),
    A2 = #compression_assign{
        context_id = 3,
        ip_version = 4,
        address = {10, 0, 0, 2},
        port = 1234
    },
    ?assertEqual(
        {error, duplicate_context_id},
        masque_compression_table:install(T1, A2)
    ).

install_same_side_duplicate_tuple_malformed_test() ->
    T0 = masque_compression_table:new_peer(client, #{}),
    A1 = #compression_assign{
        context_id = 3,
        ip_version = 4,
        address = {10, 0, 0, 1},
        port = 1234
    },
    {ok, T1} = masque_compression_table:install(T0, A1),
    A2 = #compression_assign{
        context_id = 5,
        ip_version = 4,
        address = {10, 0, 0, 1},
        port = 1234
    },
    ?assertEqual(
        {error, malformed_duplicate_tuple},
        masque_compression_table:install(T1, A2)
    ).

install_unadvertised_family_rejected_test() ->
    T = masque_compression_table:new_peer(
        client,
        #{advertised_families => [4]}
    ),
    A = #compression_assign{
        context_id = 3,
        ip_version = 6,
        address = {16#2001, 0, 0, 0, 0, 0, 0, 1},
        port = 4433
    },
    ?assertEqual(
        {error, unadvertised_family},
        masque_compression_table:install(T, A)
    ).

%%====================================================================
%% install: uncompressed asymmetry
%%====================================================================

%% The proxy-side peer table accepts a client-originated v0 ASSIGN.
install_proxy_accepts_client_uncompressed_test() ->
    T = masque_compression_table:new_peer(proxy, #{}),
    A = #compression_assign{
        context_id = 2,
        ip_version = 0,
        address = undefined,
        port = undefined
    },
    {ok, T2} = masque_compression_table:install(T, A),
    ?assertMatch(
        {ok, _},
        masque_compression_table:lookup_by_id(T2, 2)
    ).

%% The client-side peer table rejects a proxy-originated v0 ASSIGN.
install_client_rejects_proxy_uncompressed_test() ->
    T = masque_compression_table:new_peer(client, #{}),
    A = #compression_assign{
        context_id = 3,
        ip_version = 0,
        address = undefined,
        port = undefined
    },
    ?assertEqual(
        {error, uncompressed_only_from_client},
        masque_compression_table:install(T, A)
    ).

%% A second incoming v0 ASSIGN on the proxy side is malformed
%% (singleton invariant).
install_proxy_second_uncompressed_rejected_test() ->
    T0 = masque_compression_table:new_peer(proxy, #{}),
    A1 = #compression_assign{
        context_id = 2,
        ip_version = 0,
        address = undefined,
        port = undefined
    },
    {ok, T1} = masque_compression_table:install(T0, A1),
    A2 = #compression_assign{
        context_id = 4,
        ip_version = 0,
        address = undefined,
        port = undefined
    },
    ?assertEqual(
        {error, uncompressed_context_already_open},
        masque_compression_table:install(T1, A2)
    ).

%%====================================================================
%% install_ack
%%====================================================================

install_ack_pending_succeeds_test() ->
    T0 = masque_compression_table:new_own(client, #{}),
    {ok, E, T1} =
        masque_compression_table:open_compressed(T0, {4, {10, 0, 0, 1}, 1234}),
    Id = E#compression_entry.context_id,
    {ok, T2} =
        masque_compression_table:install_ack(
            T1, #compression_ack{context_id = Id}
        ),
    {ok, E2} = masque_compression_table:lookup_by_id(T2, Id),
    ?assertEqual(installed, E2#compression_entry.state).

install_ack_unknown_id_malformed_test() ->
    T = masque_compression_table:new_own(client, #{}),
    ?assertEqual(
        {error, malformed_unknown_ack},
        masque_compression_table:install_ack(
            T, #compression_ack{context_id = 12}
        )
    ).

%% Repeated ACK is idempotent (no second state transition required).
install_ack_idempotent_test() ->
    T0 = masque_compression_table:new_own(client, #{}),
    {ok, E, T1} =
        masque_compression_table:open_compressed(T0, {4, {10, 0, 0, 1}, 1234}),
    Id = E#compression_entry.context_id,
    {ok, T2} =
        masque_compression_table:install_ack(
            T1, #compression_ack{context_id = Id}
        ),
    {ok, T3} =
        masque_compression_table:install_ack(
            T2, #compression_ack{context_id = Id}
        ),
    ?assertEqual(T2, T3).

%%====================================================================
%% install_close
%%====================================================================

install_close_removes_entry_test() ->
    T0 = masque_compression_table:new_peer(client, #{}),
    {ok, T1} =
        masque_compression_table:install(
            T0, #compression_assign{
                context_id = 3,
                ip_version = 4,
                address = {10, 0, 0, 1},
                port = 1234
            }
        ),
    {ok, T2} =
        masque_compression_table:install_close(
            T1, #compression_close{context_id = 3}
        ),
    ?assertEqual(
        not_found,
        masque_compression_table:lookup_by_id(T2, 3)
    ),
    ?assertEqual(
        not_found,
        masque_compression_table:lookup_by_tuple(
            T2, {4, {10, 0, 0, 1}, 1234}
        )
    ).

install_close_unknown_id_test() ->
    T = masque_compression_table:new_peer(client, #{}),
    ?assertEqual(
        {error, unknown_context},
        masque_compression_table:install_close(
            T, #compression_close{context_id = 99}
        )
    ).

%%====================================================================
%% Bounds
%%====================================================================

open_compressed_table_full_test() ->
    T0 = masque_compression_table:new_own(client, #{max_entries => 1}),
    {ok, _, T1} =
        masque_compression_table:open_compressed(T0, {4, {10, 0, 0, 1}, 1234}),
    ?assertEqual(
        {error, table_full},
        masque_compression_table:open_compressed(
            T1, {4, {10, 0, 0, 2}, 1234}
        )
    ).
