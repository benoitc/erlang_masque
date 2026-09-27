%%% @doc A pooled CONNECT-TCP stream gets its data straight from the
%%% transport, while the 2xx comes through the pool owner. Data that
%%% overtakes the 2xx must still reach the application.
-module(masque_pooled_early_data_tests).

-include_lib("eunit/include/eunit.hrl").

data_before_response_is_kept_test() ->
    {ok, Mock} = masque_mock_transport:start(#{}),
    {ok, Owner} = masque_upstream_owner:start_link(#{
        transport => quic_h3,
        transport_mod => masque_mock_transport,
        conn => Mock,
        idle_timeout_ms => 10000
    }),
    Opts = #{
        proxy => {<<"127.0.0.1">>, 443},
        protocol => tcp,
        transport => h3,
        pool_owner => Owner,
        timeout => 5000
    },
    {ok, Sess} = masque_tcp_client_session:start({<<"192.0.2.6">>, 80}, Opts, self()),
    Await = spawn_link(fun() -> gen_statem:call(Sess, handshake_await) end),
    #{refs := 1} = wait_refs(Owner, 50),
    [StreamId] = [Sid || {set_stream_handler, [Sid, _]} <- masque_mock_transport:calls(Mock)],
    %% Stream data first, straight from the transport...
    Sess ! {quic_h3, Mock, {data, StreamId, <<"banner">>, false}},
    %% ...then the 2xx, through the pool owner.
    Owner ! {quic_h3, Mock, {response, StreamId, 200, []}},
    receive
        {masque_data, Sess, <<"banner">>} -> ok
    after 2000 -> ?assert(false)
    end,
    unlink(Await),
    exit(Sess, kill),
    unlink(Owner),
    exit(Owner, kill),
    masque_mock_transport:stop(Mock).

wait_refs(Owner, 0) ->
    masque_upstream_owner:info(Owner);
wait_refs(Owner, N) ->
    case masque_upstream_owner:info(Owner) of
        #{refs := 1} = I ->
            I;
        _ ->
            timer:sleep(20),
            wait_refs(Owner, N - 1)
    end.
