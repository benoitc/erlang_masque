%%% Client side of a reverse connect control channel over HTTP/1.1
%%% (draft-rosomakho-masque-reverse-connect-01 section 4.2).
%%%
%%% `GET' with `Upgrade: connect-listen' on a TLS connection of its own;
%%% after the 101 the connection carries capsules only. Each accept is a
%%% new connection (section 5.2.1), so this session only hands out the
%%% request ids and the proxy's address. Messages to the owner are the
%%% same as over HTTP/3 and HTTP/2.
-module(masque_listen_h1_client_session).
-moduledoc false.
-behaviour(gen_server).

-export([start/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include("masque.hrl").
-include("masque_reverse.hrl").

-record(state, {
    owner :: pid(),
    owner_mon :: reference(),
    socket :: ssl:sslsocket(),
    buf = <<>> :: binary(),
    seen = masque_reverse_ids:new() :: masque_reverse_ids:ids(),
    open = #{} :: #{non_neg_integer() => masque_reverse_capsule:service()},
    accept_template :: binary(),
    opts :: map()
}).

-spec start(map(), pid()) -> {ok, pid()} | {error, term()}.
start(Opts, Owner) ->
    gen_server:start(?MODULE, {Opts, Owner}, [{timeout, maps:get(timeout, Opts, 5000) + 5000}]).

init({#{proxy := {Host, Port}, listen_path := Path} = Opts, Owner}) ->
    process_flag(trap_exit, true),
    OwnerMon = erlang:monitor(process, Owner),
    Timeout = maps:get(timeout, Opts, 5000),
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    SSLOpts = masque_tls:client_opts(Host, Opts),
    case ssl:connect(binary_to_list(Host), Port, SSLOpts, Timeout) of
        {ok, Socket} ->
            _ = masque_tls:bound_sends(ssl, Socket),
            case ssl:send(Socket, upgrade_request(Host, Port, Path, Opts)) of
                ok ->
                    case read_response(Socket, <<>>, Deadline) of
                        {ok, 101, Headers, Rest} ->
                            case proplists:get_value(<<"capsule-protocol">>, Headers) of
                                <<"?1", _/binary>> ->
                                    S = #state{
                                        owner = Owner,
                                        owner_mon = OwnerMon,
                                        socket = Socket,
                                        accept_template = maps:get(
                                            accept_uri_template,
                                            Opts,
                                            ?MASQUE_DEFAULT_ACCEPT_URI_TEMPLATE
                                        ),
                                        opts = Opts
                                    },
                                    case bytes_in(Rest, S) of
                                        {ok, S2} ->
                                            ok = ssl:setopts(Socket, [{active, once}]),
                                            {ok, S2};
                                        {stop, Reason, _} ->
                                            _ = ssl:close(Socket),
                                            {stop, Reason}
                                    end;
                                _ ->
                                    _ = ssl:close(Socket),
                                    {stop, {bad_response, capsule_protocol}}
                            end;
                        {ok, Status, _, _} ->
                            _ = ssl:close(Socket),
                            {stop, {handshake_rejected, Status}};
                        {error, Reason} ->
                            _ = ssl:close(Socket),
                            {stop, Reason}
                    end;
                {error, Reason} ->
                    _ = ssl:close(Socket),
                    {stop, {send, Reason}}
            end;
        {error, Reason} ->
            {stop, {connect, Reason}}
    end.

upgrade_request(Host, Port, Path, Opts) ->
    nomatch = binary:match(Path, [<<"\r">>, <<"\n">>, <<" ">>]),
    Extra = [
        [K, <<": ">>, V, <<"\r\n">>]
     || {K, V} <- maps:get(request_headers, Opts, []),
        is_binary(K),
        is_binary(V),
        binary:match(<<K/binary, V/binary>>, [<<"\r">>, <<"\n">>]) =:= nomatch
    ],
    [
        <<"GET ">>,
        Path,
        <<" HTTP/1.1\r\nHost: ">>,
        masque_uri:build_authority(Host, Port),
        <<"\r\nConnection: Upgrade\r\nUpgrade: ">>,
        ?MASQUE_CONNECT_LISTEN_PROTOCOL,
        <<"\r\nCapsule-Protocol: ?1\r\n">>,
        Extra,
        <<"\r\n">>
    ].

%% The status line and headers, skipping interim responses other than
%% 101.
read_response(Socket, Acc, Deadline) ->
    case binary:split(Acc, <<"\r\n\r\n">>) of
        [Head, Rest] ->
            [StatusLine | Lines] = binary:split(Head, <<"\r\n">>, [global]),
            case binary:split(StatusLine, <<" ">>, [global]) of
                [_, CodeBin | _] ->
                    case masque_uri:parse_uint(CodeBin, 599) of
                        {ok, Code} when Code >= 100, Code < 200, Code =/= 101 ->
                            read_response(Socket, Rest, Deadline);
                        {ok, Code} ->
                            {ok, Code, headers(Lines), Rest};
                        error ->
                            {error, bad_status}
                    end;
                _ ->
                    {error, bad_status}
            end;
        [_] when byte_size(Acc) > 65536 ->
            {error, headers_too_large};
        [_] ->
            Left = Deadline - erlang:monotonic_time(millisecond),
            case Left > 0 andalso ssl:recv(Socket, 0, Left) of
                {ok, More} -> read_response(Socket, <<Acc/binary, More/binary>>, Deadline);
                false -> {error, handshake_timeout};
                {error, timeout} -> {error, handshake_timeout};
                {error, Reason} -> {error, {recv, Reason}}
            end
    end.

headers(Lines) ->
    [
        {string:lowercase(string:trim(K)), string:trim(V)}
     || L <- Lines, [K, V] <- [binary:split(L, <<":">>)]
    ].

handle_call(Request, From, State) ->
    masque_quiet:stop(handle_call_inner(Request, From, State)).

handle_call_inner({accept_spec, Id}, _From, #state{open = Open} = S) ->
    case maps:take(Id, Open) of
        {Service, Open2} ->
            Spec = #{
                service => Service,
                transport => h1,
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
handle_call_inner(migrate, _From, S) ->
    {reply, {error, not_supported}, S};
handle_call_inner(info, _From, #state{open = Open} = S) ->
    {reply, #{protocol => listen, transport => h1, pending => map_size(Open)}, S};
handle_call_inner(stop, _From, S) ->
    {stop, normal, ok, S};
handle_call_inner(_Request, _From, S) ->
    {reply, {error, unknown_call}, S}.

%% The socket's send timeout bounds the write; a failed one ends the
%% channel.
reply_send(Capsule, #state{socket = Sock} = S) ->
    case ssl:send(Sock, Capsule) of
        ok -> {reply, ok, S};
        {error, Reason} -> {stop, {control_send_failed, Reason}, {error, closed}, S}
    end.

handle_cast(Msg, State) ->
    masque_quiet:stop(handle_cast_inner(Msg, State)).

handle_cast_inner(_Msg, S) ->
    {noreply, S}.

handle_info(Msg, State) ->
    masque_quiet:stop(handle_info_inner(Msg, State)).

handle_info_inner({ssl, Sock, Bytes}, #state{socket = Sock} = S) ->
    case bytes_in(Bytes, S) of
        {ok, S2} ->
            _ = ssl:setopts(Sock, [{active, once}]),
            {noreply, S2};
        Stop ->
            Stop
    end;
handle_info_inner({ssl_closed, Sock}, #state{socket = Sock, buf = <<>>} = S) ->
    {stop, peer_closed, S};
handle_info_inner({ssl_closed, Sock}, #state{socket = Sock} = S) ->
    {stop, truncated_capsule, S};
handle_info_inner({ssl_error, Sock, Reason}, #state{socket = Sock} = S) ->
    {stop, {ssl_error, Reason}, S};
handle_info_inner({'DOWN', Ref, process, _, _}, #state{owner_mon = Ref} = S) ->
    {stop, owner_gone, S};
handle_info_inner(_Msg, S) ->
    {noreply, S}.

bytes_in(<<>>, S) ->
    {ok, S};
bytes_in(Bytes, #state{buf = Buf} = S) ->
    capsules(<<Buf/binary, Bytes/binary>>, S).

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
                false -> {ok, S#state{buf = Buf}}
            end;
        {error, _} ->
            {stop, malformed_capsule, S}
    end.

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

decline_now(Id, #state{socket = Sock} = S) ->
    Capsule = masque_reverse_capsule:encode({connection_request_declined, Id}),
    case ssl:send(Sock, Capsule) of
        ok -> {ok, S};
        {error, Reason} -> {stop, {control_send_failed, Reason}, S}
    end.

terminate(Reason, State) ->
    terminate_inner(masque_quiet:reason(Reason), State).

terminate_inner(Reason, #state{owner = Owner, socket = Sock}) ->
    _ =
        (try
            ssl:close(Sock)
        catch
            _:_ -> ok
        end),
    _ =
        case Reason of
            normal -> ok;
            owner_gone -> ok;
            _ -> Owner ! {masque_closed, self(), Reason}
        end,
    ok;
terminate_inner(_Reason, _S) ->
    ok.

code_change(_OldVsn, S, _Extra) ->
    {ok, S}.
