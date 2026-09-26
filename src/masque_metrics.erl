-module(masque_metrics).
-moduledoc """
Metrics instrumentation for masque tunnels.

Uses `instrument_meter` to track tunnel lifecycle, throughput,
and rejections. Call `setup/0` from application start. Instruments
are stored in `persistent_term` for zero-overhead lookups.
""".

-export([
    setup/0,
    tunnel_opened/1,
    tunnel_closed/2,
    tunnel_rejected/1,
    bytes_in/2,
    bytes_out/2
]).

%% Simple counters for CONNECT-IP plumbing. These intentionally do
%% NOT use `instrument_meter' - they are a lightweight surface for
%% downstream consumers (TUN/router, metrics scrapers) and tests to
%% read directly via `counters:get/2'. `setup_ip_counters/0' is split
%% out from `setup/0' so test environments without the meter system
%% running can still exercise the counter API.
-export([
    setup_ip_counters/0,
    ip_drop_inc/1,
    ip_drop_count/1,
    ip_drop_reasons/0,
    ip_assign_inc/0,
    ip_assigned_count/0,
    ip_release_inc/0,
    ip_released_count/0,
    ip_advertise_inc/0,
    ip_advertised_count/0
]).

%% Simple drop counters for Connect-UDP-Bind sessions, same shape as
%% the CONNECT-IP ones.
-export([
    setup_bind_counters/0,
    bind_drop_inc/1,
    bind_drop_count/1,
    bind_drop_reasons/0
]).

-spec setup() -> ok.
setup() ->
    setup_ip_counters(),
    setup_bind_counters(),
    Meter = instrument_meter:get_meter(<<"masque">>),
    persistent_term:put(
        masque_tunnels_total,
        instrument_meter:create_counter(
            Meter,
            <<"masque.tunnels.total">>,
            #{description => <<"Total tunnels opened">>}
        )
    ),
    persistent_term:put(
        masque_tunnels_active,
        instrument_meter:create_up_down_counter(
            Meter,
            <<"masque.tunnels.active">>,
            #{description => <<"Currently active tunnels">>}
        )
    ),
    persistent_term:put(
        masque_tunnels_rejected,
        instrument_meter:create_counter(
            Meter,
            <<"masque.tunnels.rejected">>,
            #{description => <<"Tunnels rejected by policy">>}
        )
    ),
    persistent_term:put(
        masque_bytes_in,
        instrument_meter:create_counter(
            Meter,
            <<"masque.bytes.in">>,
            #{description => <<"Bytes received from clients">>}
        )
    ),
    persistent_term:put(
        masque_bytes_out,
        instrument_meter:create_counter(
            Meter,
            <<"masque.bytes.out">>,
            #{description => <<"Bytes sent to clients">>}
        )
    ),
    persistent_term:put(
        masque_tunnel_duration,
        instrument_meter:create_histogram(
            Meter,
            <<"masque.tunnel.duration_ms">>,
            #{description => <<"Tunnel duration in milliseconds">>}
        )
    ),
    ok.

-doc """
Idempotent allocator for the IP-side simple counters. Safe to
call multiple times; only the first call wins (subsequent calls
keep the existing reference so counts accumulated from earlier
callers are preserved).
""".
-spec setup_ip_counters() -> ok.
setup_ip_counters() ->
    case persistent_term:get(masque_ip_drop_counters, undefined) of
        undefined ->
            Ref = counters:new(
                length(ip_drop_reasons()),
                [write_concurrency]
            ),
            persistent_term:put(masque_ip_drop_counters, Ref);
        _ ->
            ok
    end,
    case persistent_term:get(masque_ip_lifecycle_counters, undefined) of
        undefined ->
            %% [assigned, released, advertised]
            LRef = counters:new(3, [write_concurrency]),
            persistent_term:put(masque_ip_lifecycle_counters, LRef);
        _ ->
            ok
    end,
    ok.

-spec tunnel_opened(map()) -> ok.
tunnel_opened(Attrs) ->
    instrument_meter:add(
        persistent_term:get(masque_tunnels_total), 1, Attrs
    ),
    instrument_meter:add(
        persistent_term:get(masque_tunnels_active), 1, Attrs
    ).

-spec tunnel_closed(number(), map()) -> ok.
tunnel_closed(DurationMs, Attrs) ->
    instrument_meter:add(
        persistent_term:get(masque_tunnels_active), -1, Attrs
    ),
    instrument_meter:record(
        persistent_term:get(masque_tunnel_duration),
        DurationMs,
        Attrs
    ).

-spec tunnel_rejected(map()) -> ok.
tunnel_rejected(Attrs) ->
    instrument_meter:add(
        persistent_term:get(masque_tunnels_rejected),
        1,
        normalise_attrs(Attrs)
    ).

%% `instrument_meter' labels must be scalars (atom/binary/integer);
%% flatten any tuple-shaped reasons (`{other, 401}') into a binary.
normalise_attrs(Attrs) when is_map(Attrs) ->
    maps:map(fun(_K, V) -> normalise_value(V) end, Attrs).

normalise_value(V) when is_atom(V); is_binary(V); is_integer(V) -> V;
normalise_value(V) -> iolist_to_binary(io_lib:format("~p", [V])).

-spec bytes_in(non_neg_integer(), map()) -> ok.
bytes_in(Bytes, Attrs) ->
    instrument_meter:add(
        persistent_term:get(masque_bytes_in), Bytes, Attrs
    ).

-spec bytes_out(non_neg_integer(), map()) -> ok.
bytes_out(Bytes, Attrs) ->
    instrument_meter:add(
        persistent_term:get(masque_bytes_out), Bytes, Attrs
    ).

%%====================================================================
%% IP drop counters - simple, instrument_meter-free.
%%====================================================================

%% Ordered list of recognised drop reasons. The position in this list
%% is the `counters' index for that reason. `other' captures any
%% reason not in this list so a downstream consumer's custom drop
%% reasons still get counted.
-spec ip_drop_reasons() -> [atom()].
ip_drop_reasons() ->
    [
        bcp38,
        scope_target,
        scope_ipproto,
        malformed,
        forward_drop,
        ttl_zero,
        mtu_exceeded,
        other
    ].

-spec ip_drop_inc(atom()) -> ok.
ip_drop_inc(Reason) ->
    case persistent_term:get(masque_ip_drop_counters, undefined) of
        %% setup/0 not called yet (e.g. in tests)
        undefined -> ok;
        Ref -> counters:add(Ref, reason_index(Reason), 1)
    end.

-spec ip_drop_count(atom()) -> non_neg_integer().
ip_drop_count(Reason) ->
    case persistent_term:get(masque_ip_drop_counters, undefined) of
        undefined -> 0;
        Ref -> counters:get(Ref, reason_index(Reason))
    end.

reason_index(Reason) ->
    case index_of(Reason, ip_drop_reasons(), 1) of
        not_found -> index_of(other, ip_drop_reasons(), 1);
        I -> I
    end.

index_of(_X, [], _I) -> not_found;
index_of(X, [X | _], I) -> I;
index_of(X, [_ | T], I) -> index_of(X, T, I + 1).

%%====================================================================
%% IP lifecycle counters - assign / release / advertise.
%%====================================================================

-spec ip_assign_inc() -> ok.
ip_assign_inc() -> lifecycle_inc(1).
-spec ip_release_inc() -> ok.
ip_release_inc() -> lifecycle_inc(2).
-spec ip_advertise_inc() -> ok.
ip_advertise_inc() -> lifecycle_inc(3).

-spec ip_assigned_count() -> non_neg_integer().
ip_assigned_count() -> lifecycle_get(1).
-spec ip_released_count() -> non_neg_integer().
ip_released_count() -> lifecycle_get(2).
-spec ip_advertised_count() -> non_neg_integer().
ip_advertised_count() -> lifecycle_get(3).

lifecycle_inc(Idx) ->
    case persistent_term:get(masque_ip_lifecycle_counters, undefined) of
        undefined -> ok;
        Ref -> counters:add(Ref, Idx, 1)
    end.

lifecycle_get(Idx) ->
    case persistent_term:get(masque_ip_lifecycle_counters, undefined) of
        undefined -> 0;
        Ref -> counters:get(Ref, Idx)
    end.

%%====================================================================
%% Connect-UDP-Bind drop counters.
%%====================================================================

-doc """
Idempotent allocator for the udp-bind drop counters.
""".
-spec setup_bind_counters() -> ok.
setup_bind_counters() ->
    case persistent_term:get(masque_bind_drop_counters, undefined) of
        undefined ->
            Ref = counters:new(
                length(bind_drop_reasons()),
                [write_concurrency]
            ),
            persistent_term:put(masque_bind_drop_counters, Ref);
        _ ->
            ok
    end.

%% Ordered list of recognised udp-bind drop reasons; `other' catches
%% the rest (including handler-supplied reasons).
-spec bind_drop_reasons() -> [atom()].
bind_drop_reasons() ->
    [
        context_zero,
        unknown_context,
        malformed,
        peer_filter,
        pending_limit,
        uncompressed_closed,
        other
    ].

-spec bind_drop_inc(atom()) -> ok.
bind_drop_inc(Reason) ->
    case persistent_term:get(masque_bind_drop_counters, undefined) of
        undefined -> ok;
        Ref -> counters:add(Ref, bind_reason_index(Reason), 1)
    end.

-spec bind_drop_count(atom()) -> non_neg_integer().
bind_drop_count(Reason) ->
    case persistent_term:get(masque_bind_drop_counters, undefined) of
        undefined -> 0;
        Ref -> counters:get(Ref, bind_reason_index(Reason))
    end.

bind_reason_index(Reason) ->
    case index_of(Reason, bind_drop_reasons(), 1) of
        not_found -> index_of(other, bind_drop_reasons(), 1);
        I -> I
    end.
