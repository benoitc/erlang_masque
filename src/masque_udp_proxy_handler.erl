%%% @doc Built-in MASQUE handler that bridges a CONNECT-UDP tunnel to
%%% a real UDP flow on the server.
%%%
%%% For every accepted tunnel the handler opens a `gen_udp' socket
%%% bound to ephemeral port and a specific family, resolves the
%%% target hostname, and relays bytes in both directions:
%%%
%%% <ul>
%%%   <li>Client-to-target: `handle_packet/2' sends the payload to the
%%%       resolved target on the UDP socket.</li>
%%%   <li>Target-to-client: `{udp, Socket, _, _, Bytes}' messages arrive
%%%       on the session process and are emitted as `send' actions
%%%       back through the tunnel.</li>
%%% </ul>
%%%
%%% Configure policy via `handler_opts':
%%% <ul>
%%%   <li>`allow => fun(target()) -> boolean()' - gate on host+port.</li>
%%%   <li>`resolver => fun(binary()) -> {ok, inet:ip_address()}
%%%                                   | {error, term()}' - override the
%%%       default `inet:getaddr/2' resolver.</li>
%%%   <li>`family => inet | inet6 | auto' (default `auto').</li>
%%%   <li>`socket_opts => [gen_udp:option()]' - extra options merged on
%%%       top of `[binary, {active, true}]'.</li>
%%%   <li>`port => inet:port_number()' - bind the local UDP socket to
%%%       a fixed port. Default `0' (kernel-assigned ephemeral).
%%%       Useful for firewall rules; conflicts with concurrent tunnels
%%%       that share a listener.</li>
%%% </ul>
-module(masque_udp_proxy_handler).
-behaviour(masque_handler).

-export([accept/1, init/2, handle_packet/2, handle_info/2, terminate/2]).

-record(state, {
    socket :: gen_udp:socket(),
    target_ip :: inet:ip_address(),
    target_port :: 1..65535
}).

%%====================================================================
%% Behaviour callbacks
%%====================================================================

-spec accept(masque_handler:req()) -> masque_handler:accept_result().
accept(#{target_host := Host, target_port := Port} = Req) ->
    Opts = maps:get(handler_opts, Req, #{}),
    AllowFun = maps:get(allow, Opts, fun default_allow/1),
    case AllowFun({Host, Port}) of
        true -> accept;
        false -> {reject, forbidden}
    end.

-spec init(masque_handler:req(), term()) -> {ok, #state{}} | {stop, term()}.
init(#{target_host := Host, target_port := Port} = Req, Opts) ->
    ResolverFun = maps:get(resolver, Opts, fun default_resolver/1),
    Family = pick_family(maps:get(family, Opts, auto), Host),
    SocketOpts = [
        binary,
        {active, true}
        | maps:get(socket_opts, Opts, [])
    ],
    BindPort = maps:get(port, Opts, 0),
    AllowPrivate = maps:get(allow_private, Opts, false),
    case resolve(ResolverFun, Host, Family) of
        {ok, IP, BindFamily} ->
            case AllowPrivate orelse masque_ip:is_public(IP) of
                false ->
                    {stop, {resolution_failed, private_address}};
                true ->
                    open_udp(IP, Port, BindPort, BindFamily, SocketOpts)
            end;
        {error, Reason} ->
            _ = Req,
            {stop, {resolution_failed, {resolve, Reason}}}
    end.

-spec handle_packet(binary(), #state{}) -> {ok, #state{}} | {stop, term(), #state{}}.
handle_packet(Data, #state{socket = S} = State) ->
    case gen_udp:send(S, Data) of
        ok ->
            {ok, State};
        {error, Reason} when
            Reason =:= closed;
            Reason =:= einval;
            Reason =:= enotconn
        ->
            %% Socket is unusable - close the tunnel rather than
            %% silently black-holing every packet.
            {stop, {target_socket_lost, Reason}, State};
        {error, _Transient} ->
            %% Transient send errors (ENOBUFS, EAGAIN, etc.): drop and
            %% keep going - HTTP Datagrams are unreliable by design.
            {ok, State}
    end.

%% Defensive double-check: on connected UDP the kernel already drops
%% non-target sources, but we re-validate at application level in
%% case a platform ever weakens that guarantee.
-spec handle_info(term(), #state{}) ->
    {ok, #state{}} | {ok, #state{}, [term()]} | {stop, term(), #state{}}.
handle_info(
    {udp, Socket, FromIP, FromPort, Bytes},
    #state{socket = Socket, target_ip = IP, target_port = Port} = State
) when
    FromIP =:= IP, FromPort =:= Port
->
    {ok, State, [{send, Bytes}]};
handle_info(
    {udp, Socket, _FromIP, _FromPort, _Bytes},
    #state{socket = Socket} = State
) ->
    %% Source mismatch - drop silently.
    {ok, State};
handle_info({udp_passive, Socket}, #state{socket = Socket} = State) ->
    %% Only hit if the user passed `{active, N}` in socket_opts.
    _ = inet:setopts(Socket, [{active, true}]),
    {ok, State};
handle_info({udp_error, Socket, Reason}, #state{socket = Socket} = State) ->
    {stop, {target_socket_error, Reason}, State};
handle_info({udp_closed, Socket}, #state{socket = Socket} = State) ->
    {stop, target_socket_closed, State};
handle_info(_Other, State) ->
    {ok, State}.

-spec terminate(term(), #state{}) -> ok.
terminate(_Reason, #state{socket = S}) ->
    _ = gen_udp:close(S),
    ok.

%%====================================================================
%% Policy defaults
%%====================================================================

default_allow({_Host, _Port}) ->
    true.

default_resolver(Host) when is_binary(Host) ->
    default_resolver(binary_to_list(Host));
default_resolver(Host) when is_list(Host) ->
    case inet_parse:address(Host) of
        {ok, IP} ->
            {ok, IP};
        _ ->
            case inet:getaddr(Host, inet) of
                {ok, IP} -> {ok, IP};
                {error, _} -> inet:getaddr(Host, inet6)
            end
    end.

open_udp(IP, Port, BindPort, BindFamily, SocketOpts) ->
    case gen_udp:open(BindPort, [BindFamily | SocketOpts]) of
        {ok, Socket} ->
            case gen_udp:connect(Socket, IP, Port) of
                ok ->
                    {ok, #state{
                        socket = Socket,
                        target_ip = IP,
                        target_port = Port
                    }};
                {error, CReason} ->
                    _ = gen_udp:close(Socket),
                    {stop, {resolution_failed, {connect, CReason}}}
            end;
        {error, Reason} ->
            {stop, {resolution_failed, {udp_open, Reason}}}
    end.

%%====================================================================
%% Helpers
%%====================================================================

pick_family(inet, _Host) ->
    inet;
pick_family(inet6, _Host) ->
    inet6;
pick_family(auto, Host) ->
    %% Auto-pick based on whether the host string looks like an IPv6 literal.
    HostStr =
        if
            is_binary(Host) -> binary_to_list(Host);
            true -> Host
        end,
    case inet:parse_address(HostStr) of
        {ok, {_, _, _, _, _, _, _, _}} -> inet6;
        _ -> inet
    end.

resolve(ResolverFun, Host, Family) ->
    case ResolverFun(Host) of
        {ok, IP} ->
            ActualFamily =
                if
                    tuple_size(IP) =:= 8 -> inet6;
                    true -> Family
                end,
            {ok, IP, ActualFamily};
        Err ->
            Err
    end.
