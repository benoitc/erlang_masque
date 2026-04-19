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

-spec setup() -> ok.
setup() ->
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
