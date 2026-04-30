%%% @doc Metrics instrumentation for masque tunnels.
%%%
%%% Uses `instrument_meter' to track tunnel lifecycle, throughput,
%%% and rejections. Call `setup/0' from application start. Instruments
%%% are stored in `persistent_term' for zero-overhead lookups.
-module(masque_metrics).

-export([setup/0,
         tunnel_opened/1, tunnel_closed/2,
         tunnel_rejected/1,
         bytes_in/2, bytes_out/2]).

%% Simple counters for CONNECT-IP plumbing. These intentionally do
%% NOT use `instrument_meter' - they are a lightweight surface for
%% downstream consumers (TUN/router, metrics scrapers) and tests to
%% read directly via `counters:get/2'. `setup_ip_counters/0' is split
%% out from `setup/0' so test environments without the meter system
%% running can still exercise the counter API.
-export([setup_ip_counters/0,
         ip_drop_inc/1, ip_drop_count/1, ip_drop_reasons/0]).

-spec setup() -> ok.
setup() ->
    setup_ip_counters(),
    Meter = instrument_meter:get_meter(<<"masque">>),
    persistent_term:put(masque_tunnels_total,
        instrument_meter:create_counter(
            Meter, <<"masque.tunnels.total">>,
            #{description => <<"Total tunnels opened">>})),
    persistent_term:put(masque_tunnels_active,
        instrument_meter:create_up_down_counter(
            Meter, <<"masque.tunnels.active">>,
            #{description => <<"Currently active tunnels">>})),
    persistent_term:put(masque_tunnels_rejected,
        instrument_meter:create_counter(
            Meter, <<"masque.tunnels.rejected">>,
            #{description => <<"Tunnels rejected by policy">>})),
    persistent_term:put(masque_bytes_in,
        instrument_meter:create_counter(
            Meter, <<"masque.bytes.in">>,
            #{description => <<"Bytes received from clients">>})),
    persistent_term:put(masque_bytes_out,
        instrument_meter:create_counter(
            Meter, <<"masque.bytes.out">>,
            #{description => <<"Bytes sent to clients">>})),
    persistent_term:put(masque_tunnel_duration,
        instrument_meter:create_histogram(
            Meter, <<"masque.tunnel.duration_ms">>,
            #{description => <<"Tunnel duration in milliseconds">>})),
    ok.

%% @doc Idempotent allocator for the IP drop counters. Safe to call
%% multiple times; only the first call wins (subsequent calls keep
%% the existing reference so counts accumulated from earlier callers
%% are preserved).
-spec setup_ip_counters() -> ok.
setup_ip_counters() ->
    case persistent_term:get(masque_ip_drop_counters, undefined) of
        undefined ->
            Ref = counters:new(length(ip_drop_reasons()),
                               [write_concurrency]),
            persistent_term:put(masque_ip_drop_counters, Ref),
            ok;
        _ ->
            ok
    end.

-spec tunnel_opened(map()) -> ok.
tunnel_opened(Attrs) ->
    instrument_meter:add(
        persistent_term:get(masque_tunnels_total), 1, Attrs),
    instrument_meter:add(
        persistent_term:get(masque_tunnels_active), 1, Attrs).

-spec tunnel_closed(number(), map()) -> ok.
tunnel_closed(DurationMs, Attrs) ->
    instrument_meter:add(
        persistent_term:get(masque_tunnels_active), -1, Attrs),
    instrument_meter:record(
        persistent_term:get(masque_tunnel_duration),
        DurationMs, Attrs).

-spec tunnel_rejected(map()) -> ok.
tunnel_rejected(Attrs) ->
    instrument_meter:add(
        persistent_term:get(masque_tunnels_rejected), 1,
        normalise_attrs(Attrs)).

%% `instrument_meter' labels must be scalars (atom/binary/integer);
%% flatten any tuple-shaped reasons (`{other, 401}') into a binary.
normalise_attrs(Attrs) when is_map(Attrs) ->
    maps:map(fun(_K, V) -> normalise_value(V) end, Attrs).

normalise_value(V) when is_atom(V); is_binary(V); is_integer(V) -> V;
normalise_value(V) ->
    iolist_to_binary(io_lib:format("~p", [V])).

-spec bytes_in(non_neg_integer(), map()) -> ok.
bytes_in(Bytes, Attrs) ->
    instrument_meter:add(
        persistent_term:get(masque_bytes_in), Bytes, Attrs).

-spec bytes_out(non_neg_integer(), map()) -> ok.
bytes_out(Bytes, Attrs) ->
    instrument_meter:add(
        persistent_term:get(masque_bytes_out), Bytes, Attrs).

%%====================================================================
%% IP drop counters - simple, instrument_meter-free.
%%====================================================================

%% Ordered list of recognised drop reasons. The position in this list
%% is the `counters' index for that reason. `other' captures any
%% reason not in this list so a downstream consumer's custom drop
%% reasons still get counted.
-spec ip_drop_reasons() -> [atom()].
ip_drop_reasons() ->
    [bcp38, scope_target, scope_ipproto, malformed,
     forward_drop, ttl_zero, mtu_exceeded, other].

-spec ip_drop_inc(atom()) -> ok.
ip_drop_inc(Reason) ->
    case persistent_term:get(masque_ip_drop_counters, undefined) of
        undefined -> ok;       %% setup/0 not called yet (e.g. in tests)
        Ref       -> counters:add(Ref, reason_index(Reason), 1)
    end.

-spec ip_drop_count(atom()) -> non_neg_integer().
ip_drop_count(Reason) ->
    case persistent_term:get(masque_ip_drop_counters, undefined) of
        undefined -> 0;
        Ref       -> counters:get(Ref, reason_index(Reason))
    end.

reason_index(Reason) ->
    case index_of(Reason, ip_drop_reasons(), 1) of
        not_found -> index_of(other, ip_drop_reasons(), 1);
        I         -> I
    end.

index_of(_X, [], _I) -> not_found;
index_of(X, [X | _], I) -> I;
index_of(X, [_ | T], I) -> index_of(X, T, I + 1).
