%%% Client side of a reverse connect control channel over HTTP/3 or
%%% HTTP/2 (draft-rosomakho-masque-reverse-connect-01 sections 4 and 5).
%%%
%%% The channel runs on a connection of its own (a dedicated
%%% `masque_upstream_owner'), because the accept streams it answers with
%%% must use the same connection (section 5.2.2). The owner process gets
%%% `{masque_connection_request, Listen, Id, Service}' for each request
%%% and answers with `masque:reverse_accept/2,3' or
%%% `masque:reverse_decline/2'. When the channel ends it gets
%%% `{masque_closed, Listen, Reason}', and the connection closes with it.
-module(masque_listen_client_session).
-moduledoc false.
-behaviour(gen_server).

-export([start/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include("masque.hrl").
-include("masque_reverse.hrl").

-define(H3_MESSAGE_ERROR, 16#10e).

-record(state, {
    owner :: pid(),
    owner_mon :: reference(),
    upstream :: pid(),
    transport :: h3 | h2,
    conn :: pid(),
    stream_id :: non_neg_integer(),
    buf = <<>> :: binary(),
    %% Request ids seen on this channel (section 5.1: never reused), and
    %% the ones not answered yet.
    seen = masque_reverse_ids:new() :: masque_reverse_ids:ids(),
    open = #{} :: #{non_neg_integer() => masque_reverse_capsule:service()},
    accept_template :: binary(),
    opts :: map(),
    fin_sent = false :: boolean()
}).

%% `Opts' carries `proxy', `transport', `listen_path' and the client
%% options; the call returns once the proxy answered.
-spec start(map(), pid()) -> {ok, pid()} | {error, term()}.
start(Opts, Owner) ->
    gen_server:start(?MODULE, {Opts, Owner}, [{timeout, maps:get(timeout, Opts, 5000) + 10000}]).

init({#{proxy := {Host, Port}, transport := T, listen_path := Path} = Opts, Owner}) ->
    process_flag(trap_exit, true),
    OwnerMon = erlang:monitor(process, Owner),
    Upstream = #{
        transport => owner_transport(T),
        host => Host,
        port => Port,
        connect_opts => masque_racer:pool_connect_opts(T, Host, Opts)
    },
    case masque_upstream_owner:start_dedicated(self(), Upstream) of
        {ok, UpOwner} ->
            Headers = request_headers(T, Host, Port, Path, Opts),
            ReqOpts =
                case T of
                    h3 -> #{end_stream => false};
                    h2 -> #{protocol => ?MASQUE_CONNECT_LISTEN_PROTOCOL}
                end,
            case masque_upstream_owner:acquire_stream(UpOwner, Headers, self(), ReqOpts) of
                {ok, Sid, Conn} ->
                    S = #state{
                        owner = Owner,
                        owner_mon = OwnerMon,
                        upstream = UpOwner,
                        transport = T,
                        conn = Conn,
                        stream_id = Sid,
                        accept_template = maps:get(
                            accept_uri_template, Opts, ?MASQUE_DEFAULT_ACCEPT_URI_TEMPLATE
                        ),
                        opts = Opts
                    },
                    await_response(S, maps:get(timeout, Opts, 5000));
                {error, Reason} ->
                    _ = stop_upstream(UpOwner),
                    {stop, Reason}
            end;
        {error, Reason} ->
            {stop, Reason}
    end.

stop_upstream(Pid) ->
    try
        masque_upstream_owner:stop(Pid)
    catch
        _:_ -> ok
    end.

owner_transport(h3) -> quic_h3;
owner_transport(h2) -> h2.

request_headers(T, Host, Port, Path, Opts) ->
    Extra = [
        {K, V}
     || {K, V} <- maps:get(request_headers, Opts, []),
        is_binary(K),
        is_binary(V),
        binary:first(K) =/= $:
    ],
    Base = [
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, masque_uri:build_authority(Host, Port)},
        {<<":path">>, Path}
    ],
    Proto =
        case T of
            h3 -> [{<<":protocol">>, ?MASQUE_CONNECT_LISTEN_PROTOCOL}];
            h2 -> []
        end,
    Base ++ Proto ++ [{<<"capsule-protocol">>, <<"?1">>} | Extra].

%% Sections 4.3 and 3.2 of RFC 9297: a 2xx that starts the capsule
%% protocol. Interim responses are skipped.
await_response(#state{conn = C, stream_id = Sid} = S, Timeout) ->
    receive
        {Tag, C, {response, Sid, Status, _}} when
            (Tag =:= quic_h3 orelse Tag =:= h2), Status >= 100, Status < 200
        ->
            await_response(S, Timeout);
        {Tag, C, {informational, Sid, _, _}} when Tag =:= h2 ->
            await_response(S, Timeout);
        {Tag, C, {response, Sid, Status, Headers}} when
            (Tag =:= quic_h3 orelse Tag =:= h2), Status >= 200, Status < 300
        ->
            case proplists:get_value(<<"capsule-protocol">>, Headers) of
                <<"?1", _/binary>> ->
                    {ok, S};
                _ ->
                    _ = stop_upstream(S#state.upstream),
                    {stop, {bad_response, capsule_protocol}}
            end;
        {Tag, C, {response, Sid, Status, _}} when Tag =:= quic_h3; Tag =:= h2 ->
            _ = stop_upstream(S#state.upstream),
            {stop, {handshake_rejected, Status}};
        {Tag, C, {stream_reset, Sid, _}} when Tag =:= quic_h3; Tag =:= h2 ->
            _ = stop_upstream(S#state.upstream),
            {stop, peer_reset}
    after Timeout ->
        _ = stop_upstream(S#state.upstream),
        {stop, handshake_timeout}
    end.

%% Section 5.2: an id the proxy offered and that is not answered yet.
handle_call(Request, From, State) ->
    masque_quiet:stop(handle_call_inner(Request, From, State)).

handle_call_inner({accept_spec, Id}, _From, #state{open = Open} = S) ->
    case maps:take(Id, Open) of
        {Service, Open2} ->
            Spec = #{
                service => Service,
                transport => S#state.transport,
                pool_owner => S#state.upstream,
                accept_uri_template => S#state.accept_template,
                opts => S#state.opts
            },
            {reply, {ok, Spec}, S#state{open = Open2}};
        error ->
            {reply, {error, unknown_request}, S}
    end;
handle_call_inner({decline, Id}, _From, #state{open = Open} = S) ->
    case maps:take(Id, Open) of
        {_, Open2} ->
            reply_send(masque_reverse_capsule:encode({connection_request_declined, Id}), S#state{
                open = Open2
            });
        error ->
            {reply, {error, unknown_request}, S}
    end;
handle_call_inner({advertise, Services}, _From, S) ->
    reply_send(masque_reverse_capsule:encode({available_services, Services}), S);
handle_call_inner(migrate, _From, #state{transport = h3, upstream = Up} = S) ->
    {reply, masque_upstream_owner:migrate(Up), S};
handle_call_inner(migrate, _From, S) ->
    {reply, {error, not_supported}, S};
handle_call_inner(info, _From, #state{transport = T, open = Open} = S) ->
    {reply, #{protocol => listen, transport => T, pending => map_size(Open)}, S};
handle_call_inner(stop, _From, S) ->
    {stop, normal, ok, S};
handle_call_inner(_Request, _From, S) ->
    {reply, {error, unknown_call}, S}.

%% Capsule writes wait for the transport (`masque_stream_send'); a
%% failed one ends the channel.
reply_send(Capsule, #state{transport = T, conn = C, stream_id = Sid} = S) ->
    case masque_stream_send:send(T, C, Sid, Capsule, false) of
        ok -> {reply, ok, S};
        {error, Reason} -> {stop, {control_send_failed, Reason}, {error, closed}, S}
    end.

handle_cast(Msg, State) ->
    masque_quiet:stop(handle_cast_inner(Msg, State)).

handle_cast_inner(_Msg, S) ->
    {noreply, S}.

handle_info(Msg, State) ->
    masque_quiet:stop(handle_info_inner(Msg, State)).

handle_info_inner({Tag, C, {data, Sid, Bytes, Fin}}, #state{conn = C, stream_id = Sid} = S) when
    Tag =:= quic_h3; Tag =:= h2
->
    stream_in(Bytes, Fin, S);
handle_info_inner({Tag, C, {stream_reset, Sid, _}}, #state{conn = C, stream_id = Sid} = S) when
    Tag =:= quic_h3; Tag =:= h2
->
    {stop, peer_reset, S};
handle_info_inner({Tag, C, {closed, _}}, #state{conn = C} = S) when Tag =:= quic_h3; Tag =:= h2 ->
    {stop, peer_closed, S};
handle_info_inner({quic_h3, _C, {send_ready, _}}, S) ->
    {noreply, S};
handle_info_inner({'DOWN', Ref, process, _, _}, #state{owner_mon = Ref} = S) ->
    {stop, owner_gone, S};
handle_info_inner({'EXIT', _Pid, _Reason}, S) ->
    {noreply, S};
handle_info_inner(_Msg, S) ->
    {noreply, S}.

stream_in(Bytes, Fin, #state{buf = Buf} = S) ->
    case capsules(<<Buf/binary, Bytes/binary>>, S) of
        {ok, <<>>, S2} when Fin -> {stop, peer_fin, S2#state{buf = <<>>}};
        {ok, _, S2} when Fin -> {stop, truncated_capsule, S2};
        {ok, Rest, S2} -> {noreply, S2#state{buf = Rest}};
        Stop -> Stop
    end.

capsules(Buf, S) ->
    case masque_capsule:decode(Buf) of
        {ok, {Type, Value, Rest}} ->
            case capsule(masque_reverse_capsule:type(Type), Value, S) of
                {ok, S2} -> capsules(Rest, S2);
                Stop -> Stop
            end;
        {more, _} ->
            case masque_capsule:pending_size(Buf) > ?MASQUE_DEFAULT_MAX_CAPSULE_SIZE of
                true -> {stop, capsule_buffer_overflow, S};
                false -> {ok, Buf, S}
            end;
        {error, _} ->
            {stop, malformed_capsule, S}
    end.

%% Section 5.1: a malformed request, or an id used before, is a stream
%% error. Other capsule types are skipped (RFC 9297 section 3.3).
capsule(connection_request, Value, #state{seen = Seen, open = Open, owner = Owner} = S) ->
    case masque_reverse_capsule:decode(connection_request, Value) of
        {ok, {connection_request, Id, Service}} ->
            case masque_reverse_ids:seen(Id, Seen) of
                true ->
                    {stop, malformed_capsule, S};
                false ->
                    S2 = S#state{seen = masque_reverse_ids:add(Id, Seen)},
                    case map_size(Open) >= max_pending(S) of
                        true ->
                            %% The owner already has as many requests as it
                            %% may hold: decline, so a proxy cannot grow the
                            %% agent's memory or its owner's mailbox.
                            decline_now(Id, S2);
                        false ->
                            Owner ! {masque_connection_request, self(), Id, Service},
                            {ok, S2#state{open = Open#{Id => Service}}}
                    end
            end;
        {error, _} ->
            {stop, malformed_capsule, S}
    end;
capsule(_Other, _Value, S) ->
    {ok, S}.

max_pending(#state{opts = Opts}) ->
    maps:get(max_pending_requests, Opts, ?MASQUE_DEFAULT_MAX_PENDING_REQUESTS).

decline_now(Id, #state{transport = T, conn = C, stream_id = Sid} = S) ->
    Capsule = masque_reverse_capsule:encode({connection_request_declined, Id}),
    case masque_stream_send:send(T, C, Sid, Capsule, false) of
        ok -> {ok, S};
        {error, Reason} -> {stop, {control_send_failed, Reason}, S}
    end.

terminate(Reason, State) ->
    terminate_inner(masque_quiet:reason(Reason), State).

terminate_inner(Reason, #state{owner = Owner, upstream = Up} = S) ->
    _ =
        (try
            end_stream(Reason, S)
        catch
            _:_ -> ok
        end),
    _ =
        case Reason of
            normal -> ok;
            owner_gone -> ok;
            _ -> Owner ! {masque_closed, self(), Reason}
        end,
    _ =
        (try
            masque_upstream_owner:stop(Up)
        catch
            _:_ -> ok
        end),
    ok;
terminate_inner(_Reason, _S) ->
    ok.

end_stream(Reason, #state{transport = h3, conn = C, stream_id = Sid}) when
    Reason =:= malformed_capsule; Reason =:= truncated_capsule; Reason =:= capsule_buffer_overflow
->
    quic_h3:cancel(C, Sid, ?H3_MESSAGE_ERROR);
end_stream(Reason, #state{transport = h2, conn = C, stream_id = Sid}) when
    Reason =:= malformed_capsule; Reason =:= truncated_capsule; Reason =:= capsule_buffer_overflow
->
    h2:cancel(C, Sid, protocol_error);
end_stream(Reason, _S) when Reason =:= peer_reset; Reason =:= peer_closed ->
    ok;
end_stream(_Reason, #state{transport = h3, conn = C, stream_id = Sid}) ->
    quic_h3:send_data(C, Sid, <<>>, true);
end_stream(_Reason, #state{transport = h2, conn = C, stream_id = Sid}) ->
    h2:send_data(C, Sid, <<>>, true).

code_change(_OldVsn, S, _Extra) ->
    {ok, S}.
