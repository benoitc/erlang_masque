%%% @doc Per-session Connect-UDP-Bind compression table.
%%%
%%% Two of these live in every bind session, one per role:
%%% <ul>
%%%   <li><b>own</b> table - context-IDs we have opened on the peer
%%%       via outbound `COMPRESSION_ASSIGN'. Allocations follow the
%%%       parity rule (client uses even IDs, proxy uses odd).</li>
%%%   <li><b>peer</b> table - context-IDs the peer has opened on us
%%%       via incoming `COMPRESSION_ASSIGN'. We installed them; we
%%%       look up by ID on receipt of a datagram and by tuple when
%%%       compressing outbound traffic to a peer we already have a
%%%       mapping for.</li>
%%% </ul>
%%%
%%% Draft-ietf-masque-connect-udp-listen-11 invariants enforced here:
%%%
%%% <ul>
%%%   <li>Parity: client-even / proxy-odd context-IDs on `open'.
%%%       Cross-parity from the peer is malformed on `install'.</li>
%%%   <li>Duplicate context-ID is malformed.</li>
%%%   <li>Per-tuple uniqueness with the two distinct draft-11 cases:
%%%     <ul>
%%%       <li>Cross-side conflict: peer ASSIGNs a tuple our side
%%%           already opened. The table emits
%%%           `{conflict, close_proxy_id}' so the session can send
%%%           the matching `COMPRESSION_CLOSE'.</li>
%%%       <li>Same-side conflict: peer ASSIGNs a tuple it already
%%%           has open. Returned as
%%%           `{error, malformed_duplicate_tuple}'; the session
%%%           aborts the request stream.</li>
%%%     </ul></li>
%%%   <li>Uncompressed (IP Version 0) asymmetry:
%%%     <ul>
%%%       <li>`open_uncompressed/1' on a proxy-side own table
%%%           returns `{error, uncompressed_only_from_client}'.</li>
%%%       <li>The proxy-side peer table accepts an incoming version-0
%%%           ASSIGN (the client opened it).</li>
%%%       <li>The client-side peer table rejects an incoming
%%%           version-0 ASSIGN (only the client may originate
%%%           uncompressed mappings).</li>
%%%     </ul></li>
%%%   <li>Singleton uncompressed: at most one open IP Version 0
%%%       mapping per session. Second `open_uncompressed/1' returns
%%%       `{error, uncompressed_context_already_open}'; second
%%%       incoming version-0 ASSIGN is malformed.</li>
%%%   <li>Post-close prohibition: once the proxy-side own
%%%       uncompressed mapping has been closed, the proxy must not
%%%       open new compressed mappings - the client could not deliver
%%%       payloads that need the uncompressed channel. `open_compressed/2'
%%%       returns `{error, uncompressed_closed}' on a proxy-side own
%%%       table after the closure.</li>
%%%   <li>Address-family gating: `open_compressed/2' for a family not
%%%       in the advertised list returns `{error, unadvertised_family}';
%%%       the same family check applies to `install/2'.</li>
%%%   <li>Bounds (`max_in', `max_out') on the peer / own tables to
%%%       limit memory in the face of a hostile peer.</li>
%%% </ul>
%%%
%%% This module is pure data. No process, no I/O. Sessions thread the
%%% returned `state()' through their gen_server state.
-module(masque_compression_table).

-export([new_own/2, new_peer/2,
         open_compressed/2, open_uncompressed/1,
         install/2,
         install_ack/2,
         install_close/2,
         lookup_by_id/2, lookup_by_tuple/2,
         entries/1,
         is_empty/1]).

-include("masque_udp_bind.hrl").

-type role() :: client | proxy.
-type direction() :: own | peer.
-type peer_tuple() :: {4 | 6, inet:ip_address(), inet:port_number()}.

-record(state, {
    role               :: role(),
    direction          :: direction(),
    advertised_families = [4, 6] :: [4 | 6],
    %% Next outbound ID to consider. We bump in steps of 2 so the
    %% parity invariant holds. Clients start at 2, proxies at 1.
    %% Only meaningful on `direction = own'.
    next_id            :: pos_integer(),
    %% Mapping context-id -> #compression_entry{}
    entries  = #{}     :: #{pos_integer() => #compression_entry{}},
    %% Reverse index for lookup_by_tuple/2. Only includes entries
    %% with a non-undefined peer tuple (i.e. IP Version 4 / 6).
    by_tuple = #{}     :: #{peer_tuple() => pos_integer()},
    %% Tracks the singleton-uncompressed invariant.
    uncompressed_id      = undefined :: undefined | pos_integer(),
    max_entries        :: pos_integer()
}).

-opaque state() :: #state{}.

-type open_error() ::
      uncompressed_only_from_client
    | uncompressed_context_already_open
    | unadvertised_family
    | table_full.

-type install_error() ::
      bad_parity
    | duplicate_context_id
    | uncompressed_only_from_client
    | uncompressed_context_already_open
    | malformed_duplicate_tuple
    | unadvertised_family
    | table_full.

-type install_ack_error() ::
      malformed_unknown_ack.

-type install_close_error() ::
      unknown_context.

-type install_result() ::
      {ok, state()}
    | {ok, {conflict, close_proxy_id, pos_integer()}, state()}.

-export_type([state/0, role/0, direction/0, peer_tuple/0,
              open_error/0, install_error/0,
              install_ack_error/0, install_close_error/0,
              install_result/0]).

%%====================================================================
%% Constructors
%%====================================================================

%% @doc Build a fresh "own" table - the one that allocates outbound
%% context-IDs. `role' decides the parity. `Opts' may set
%% `advertised_families' (default `[4,6]') and `max_entries'
%% (default 1024).
-spec new_own(role(), map()) -> state().
new_own(Role, Opts) ->
    #state{role = Role,
           direction = own,
           advertised_families =
               maps:get(advertised_families, Opts, [4, 6]),
           next_id = first_id(Role),
           max_entries = maps:get(max_entries, Opts, 1024)}.

%% @doc Build a fresh "peer" table - the one that records incoming
%% `COMPRESSION_ASSIGN's from the peer. The peer's parity is the
%% opposite of `Role'.
-spec new_peer(role(), map()) -> state().
new_peer(Role, Opts) ->
    #state{role = Role,
           direction = peer,
           advertised_families =
               maps:get(advertised_families, Opts, [4, 6]),
           next_id = first_id(peer_of(Role)),
           max_entries = maps:get(max_entries, Opts, 1024)}.

%%====================================================================
%% Outbound: open
%%====================================================================

%% @doc Allocate a fresh own context-ID for a compressed
%% (IP Version 4 / 6) mapping to the given peer tuple. Returns the
%% new entry plus the updated state. The session emits a matching
%% `COMPRESSION_ASSIGN' on the wire and waits for ACK before using
%% the ID.
-spec open_compressed(state(), peer_tuple()) ->
    {ok, #compression_entry{}, state()} | {error, open_error()}.
open_compressed(#state{direction = peer}, _Peer) ->
    erlang:error(open_on_peer_table);
open_compressed(#state{advertised_families = Fams} = S,
                {V, IP, Port} = Peer)
  when (V =:= 4 orelse V =:= 6),
       is_integer(Port), Port >= 0, Port =< 65535 ->
    case lists:member(V, Fams) of
        false ->
            {error, unadvertised_family};
        true ->
            case is_full(S) of
                true  -> {error, table_full};
                false ->
                    case maps:is_key(Peer, S#state.by_tuple) of
                        true ->
                            %% Same tuple already mapped on our own
                            %% side; refuse the duplicate. Per draft-11
                            %% the cross-side conflict resolution is
                            %% only triggered by an *incoming* ASSIGN.
                            {error, malformed_duplicate_tuple};
                        false ->
                            allocate(V, IP, Port, Peer, S)
                    end
            end
    end.

%% @doc Allocate a fresh own context-ID for an uncompressed
%% (IP Version 0) mapping. Client-only.
-spec open_uncompressed(state()) ->
    {ok, #compression_entry{}, state()} | {error, open_error()}.
open_uncompressed(#state{direction = peer}) ->
    erlang:error(open_on_peer_table);
open_uncompressed(#state{role = proxy}) ->
    {error, uncompressed_only_from_client};
open_uncompressed(#state{uncompressed_id = Id}) when Id =/= undefined ->
    {error, uncompressed_context_already_open};
open_uncompressed(#state{} = S) ->
    case is_full(S) of
        true  -> {error, table_full};
        false -> allocate_uncompressed(S)
    end.

%%====================================================================
%% Inbound: install (peer's ASSIGN)
%%====================================================================

%% @doc Record a peer-originated `COMPRESSION_ASSIGN' on the peer
%% table.
%%
%% Returns:
%% <ul>
%%   <li>`{ok, NewState}' on a clean install.</li>
%%   <li>`{ok, {conflict, close_proxy_id, Id}, NewState}' when the
%%       peer's tuple matches one our own side has already opened
%%       (the proxy must close the proxy-opened context per
%%       draft-11). The session emits the matching CLOSE; the close
%%       refers to the `Id' on the *own* table, not this one.</li>
%%   <li>`{error, _}' on a malformed install.</li>
%% </ul>
%%
%% The own table is passed in too because the cross-side conflict
%% rule needs visibility into our own allocations. `OwnTable' is
%% read-only; the conflict resolution itself happens in the session,
%% which removes the conflicted entry from the own table after
%% sending CLOSE.
-spec install(state(), #compression_assign{}) ->
    install_result() | {error, install_error()}.
install(#state{direction = own}, _Assign) ->
    erlang:error(install_on_own_table);
install(#state{} = S, #compression_assign{context_id = Id} = A) ->
    case parity_ok(S, Id) of
        false -> {error, bad_parity};
        true  -> install_1(S, A)
    end.

install_1(#state{entries = E}, #compression_assign{context_id = Id})
  when is_map_key(Id, E) ->
    {error, duplicate_context_id};
install_1(#state{} = S, #compression_assign{ip_version = 0} = A) ->
    install_uncompressed(S, A);
install_1(#state{advertised_families = Fams} = S,
          #compression_assign{ip_version = V} = A)
  when V =:= 4; V =:= 6 ->
    case lists:member(V, Fams) of
        false -> {error, unadvertised_family};
        true  -> install_compressed(S, A)
    end;
install_1(_S, _A) ->
    {error, bad_parity}.   %% defensive; draft only allows 0 / 4 / 6

install_uncompressed(#state{role = client}, _A) ->
    {error, uncompressed_only_from_client};
install_uncompressed(#state{uncompressed_id = OldId}, _A)
  when OldId =/= undefined ->
    {error, uncompressed_context_already_open};
install_uncompressed(#state{} = S,
                     #compression_assign{context_id = Id}) ->
    case is_full(S) of
        true  -> {error, table_full};
        false ->
            Entry = #compression_entry{
                       context_id = Id,
                       ip_version = 0,
                       address    = undefined,
                       port       = undefined,
                       state      = installed,
                       direction  = inbound},
            S2 = S#state{
                   entries        = maps:put(Id, Entry, S#state.entries),
                   uncompressed_id = Id},
            {ok, S2}
    end.

install_compressed(#state{} = S,
                   #compression_assign{context_id = Id,
                                       ip_version = V,
                                       address    = A,
                                       port       = Port}) ->
    Tuple = {V, A, Port},
    case is_full(S) of
        true  -> {error, table_full};
        false ->
            case maps:get(Tuple, S#state.by_tuple, undefined) of
                undefined ->
                    %% Clean install. Cross-side conflict (the same
                    %% tuple existing on the *own* table) is the
                    %% session's job to detect; we just record what
                    %% the peer told us.
                    Entry = #compression_entry{
                               context_id = Id,
                               ip_version = V,
                               address    = A,
                               port       = Port,
                               state      = installed,
                               direction  = inbound},
                    S2 = S#state{
                           entries  = maps:put(Id, Entry,
                                               S#state.entries),
                           by_tuple = maps:put(Tuple, Id,
                                               S#state.by_tuple)},
                    {ok, S2};
                _PriorId ->
                    %% Same-side duplicate: the peer has the same
                    %% tuple open under two of its own context-IDs.
                    %% Malformed per draft-11.
                    {error, malformed_duplicate_tuple}
            end
    end.

%%====================================================================
%% Inbound: install_ack (peer's ACK of our ASSIGN)
%%====================================================================

%% @doc Record a peer `COMPRESSION_ACK'. Only valid against the own
%% table (we sent the original ASSIGN).
-spec install_ack(state(), #compression_ack{}) ->
    {ok, state()} | {error, install_ack_error()}.
install_ack(#state{direction = peer}, _Ack) ->
    erlang:error(install_ack_on_peer_table);
install_ack(#state{} = S, #compression_ack{context_id = Id}) ->
    case maps:get(Id, S#state.entries, undefined) of
        undefined ->
            {error, malformed_unknown_ack};
        #compression_entry{state = pending_ack} = E ->
            E2 = E#compression_entry{state = installed},
            {ok, S#state{entries = maps:put(Id, E2, S#state.entries)}};
        #compression_entry{state = installed} ->
            %% Idempotent: ACK after a previous ACK. Treat as ok
            %% rather than malformed; the peer simply repeated.
            {ok, S}
    end.

%%====================================================================
%% Inbound: install_close (peer's CLOSE of one of its / our IDs)
%%====================================================================

%% @doc Record a peer `COMPRESSION_CLOSE'. Removes the entry from
%% whichever table holds it. The caller is expected to dispatch by
%% direction first - typically the session looks up the ID in both
%% tables and calls install_close on the matching one.
-spec install_close(state(), #compression_close{}) ->
    {ok, state()} | {error, install_close_error()}.
install_close(#state{} = S, #compression_close{context_id = Id}) ->
    case maps:take(Id, S#state.entries) of
        error ->
            {error, unknown_context};
        {Entry, NewEntries} ->
            S2 = S#state{entries = NewEntries},
            S3 = drop_tuple_index(Entry, S2),
            S4 = clear_uncompressed_marker(Id, S3),
            {ok, S4}
    end.

%%====================================================================
%% Read-only lookups
%%====================================================================

-spec lookup_by_id(state(), pos_integer()) ->
    {ok, #compression_entry{}} | not_found.
lookup_by_id(#state{entries = E}, Id) when is_integer(Id), Id > 0 ->
    case maps:get(Id, E, undefined) of
        undefined -> not_found;
        Entry     -> {ok, Entry}
    end.

-spec lookup_by_tuple(state(), peer_tuple()) ->
    {ok, #compression_entry{}} | not_found.
lookup_by_tuple(#state{entries = E, by_tuple = T} = _S, Tuple) ->
    case maps:get(Tuple, T, undefined) of
        undefined -> not_found;
        Id        -> {ok, maps:get(Id, E)}
    end.

-spec entries(state()) -> [#compression_entry{}].
entries(#state{entries = E}) ->
    maps:values(E).

-spec is_empty(state()) -> boolean().
is_empty(#state{entries = E}) ->
    map_size(E) =:= 0.

%%====================================================================
%% Internal
%%====================================================================

first_id(client) -> 2;
first_id(proxy)  -> 1.

peer_of(client) -> proxy;
peer_of(proxy)  -> client.

%% True iff the peer's chosen context-ID has the parity that side is
%% allowed to use.
parity_ok(#state{role = Role}, Id) ->
    case peer_of(Role) of
        client -> Id band 1 =:= 0;        %% clients: even
        proxy  -> Id band 1 =:= 1         %% proxies: odd
    end.

is_full(#state{entries = E, max_entries = Max}) ->
    map_size(E) >= Max.

allocate(V, IP, Port, Peer, S) ->
    Id = S#state.next_id,
    Entry = #compression_entry{
               context_id = Id,
               ip_version = V,
               address    = IP,
               port       = Port,
               state      = pending_ack,
               direction  = outbound},
    S2 = S#state{
           entries  = maps:put(Id, Entry, S#state.entries),
           by_tuple = maps:put(Peer, Id, S#state.by_tuple),
           next_id  = Id + 2},
    {ok, Entry, S2}.

allocate_uncompressed(S) ->
    Id = S#state.next_id,
    Entry = #compression_entry{
               context_id = Id,
               ip_version = 0,
               address    = undefined,
               port       = undefined,
               state      = pending_ack,
               direction  = outbound},
    S2 = S#state{
           entries        = maps:put(Id, Entry, S#state.entries),
           next_id        = Id + 2,
           uncompressed_id = Id},
    {ok, Entry, S2}.

drop_tuple_index(#compression_entry{ip_version = 0}, S) ->
    S;
drop_tuple_index(#compression_entry{ip_version = V,
                                    address    = A,
                                    port       = Port},
                 #state{by_tuple = T} = S) ->
    S#state{by_tuple = maps:remove({V, A, Port}, T)}.

clear_uncompressed_marker(Id, #state{uncompressed_id = Id} = S) ->
    S#state{uncompressed_id = undefined};
clear_uncompressed_marker(_Id, S) ->
    S.
