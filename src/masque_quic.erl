-module(masque_quic).
-moduledoc false.

%%% QUIC options shared by every h3 client connection.

-export([client_opts/1]).

%% masque's defaults, overridden by the caller's `quic_opts'.
-spec client_opts(map()) -> map().
client_opts(Opts) ->
    Defaults = #{
        alpn => maps:get(alpn, Opts, [<<"h3">>]),
        max_datagram_frame_size => 65535,
        %% QUIC closes a silent connection after 30 s; tunnels outlive that.
        keep_alive_interval => auto
    },
    maps:merge(Defaults, maps:get(quic_opts, Opts, #{})).
