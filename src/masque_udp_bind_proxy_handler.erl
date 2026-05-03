%%% @doc Default Connect-UDP-Bind handler. Owns the per-session
%%% upstream `gen_udp' socket, computes the `Proxy-Public-Address'
%%% list for the response, gates inbound packets via
%%% `peer_filter_fun', and emits actions for the bind session to
%%% put on the wire.
%%%
%%% This module ships a `masque_handler'-shaped callback set
%%% (`init/2', `handle_info/2', `terminate/2') plus the
%%% `handle_bind_packet/3' entry the bind session calls when a
%%% datagram arrives from the client. `handle_bind_packet/3' is not
%%% on the existing `masque_handler' behaviour because no other
%%% protocol uses it; the bind sessions invoke it directly.
%%%
%%% Configurable via `handler_opts':
%%%
%%% <ul>
%%%   <li>`bind_address :: inet:ip_address() | any' - which
%%%       interface to bind to. Default `any'.</li>
%%%   <li>`bind_port :: inet:port_number()' - default `0'
%%%       (kernel-assigned ephemeral).</li>
%%%   <li>`bind_socket_opts :: [gen_udp:option()]' - merged on top of
%%%       `[binary, {active, true}]'.</li>
%%%   <li>`public_addresses :: [{ip_address(), port()}]' -
%%%       list emitted on `Proxy-Public-Address'. Required if the
%%%       socket is bound to a wildcard address; otherwise sockname
%%%       is the fallback.</li>
%%%   <li>`public_address_fun :: fun((sockname()) -> [{ip, port}])'
%%%       - alternative to the static list. Takes precedence when
%%%       set.</li>
%%%   <li>`peer_filter_fun :: fun((ip(), port()) -> ok | {drop, atom()})'
%%%       - per-packet egress policy. Default rejects RFC 1918,
%%%       link-local, and multicast unless `allow_private => true';
%%%       loopback is allowed by default for testability.</li>
%%%   <li>`scrub_fun :: fun((Packet, State) -> {pass, Packet, State} |
%%%                                            {drop, Reason, State})'
%%%       - data-plane policy hook for DDoS scrubbing or other
%%%       per-packet filtering. Default identity.</li>
%%% </ul>
-module(masque_udp_bind_proxy_handler).

-export([init/2, handle_bind_packet/3, handle_info/2, terminate/2]).

-include("masque_udp_bind.hrl").

-record(state, {
    socket               :: gen_udp:socket(),
    public_addresses     :: [{inet:ip_address(), inet:port_number()}],
    advertised_families  :: [4 | 6],
    peer_filter_fun      :: fun((inet:ip_address(),
                                 inet:port_number()) ->
                                ok | {drop, atom()}),
    scrub_fun            :: fun((binary(), term()) ->
                                {pass, binary(), term()}
                              | {drop, atom(), term()}),
    user_state           :: term()
}).

-type opts() :: map().
-type ip_port() :: {inet:ip_address(), inet:port_number()}.

%%====================================================================
%% Lifecycle
%%====================================================================

-spec init(masque_handler:req(), opts()) ->
    {ok, #state{}, [term()]} | {stop, term()}.
init(_Req, Opts) ->
    BindAddr = maps:get(bind_address, Opts, any),
    BindPort = maps:get(bind_port, Opts, 0),
    SocketOpts = [binary, {active, true},
                  {ip, BindAddr}
                  | maps:get(bind_socket_opts, Opts, [])],
    case gen_udp:open(BindPort, SocketOpts) of
        {ok, Socket} ->
            case resolve_public_addresses(Socket, Opts) of
                {ok, Addresses} ->
                    Families = families(Addresses),
                    State = #state{
                        socket = Socket,
                        public_addresses = Addresses,
                        advertised_families = Families,
                        peer_filter_fun =
                            maps:get(peer_filter_fun, Opts,
                                     fun default_peer_filter/2),
                        scrub_fun =
                            maps:get(scrub_fun, Opts,
                                     fun default_scrub/2),
                        user_state = maps:get(user_state, Opts, undefined)
                    },
                    Headers = response_headers(Addresses),
                    {ok, State, [{response_headers, Headers}]};
                {error, Reason} ->
                    _ = gen_udp:close(Socket),
                    {stop, Reason}
            end;
        {error, Reason} ->
            {stop, {udp_open, Reason}}
    end.

-spec terminate(term(), #state{}) -> ok.
terminate(_Reason, #state{socket = S}) ->
    _ = gen_udp:close(S),
    ok.

%%====================================================================
%% Inbound from the client (already decoded by the session)
%%====================================================================

%% @doc The bind session calls this with the decoded peer tuple and
%% the inner UDP payload. Returns either an `ok' continuation or a
%% drop with a reason that the session can attribute via metrics.
-spec handle_bind_packet(ip_port(), binary(), #state{}) ->
    {ok, #state{}} | {drop, atom(), #state{}}.
handle_bind_packet({IP, Port}, Payload, #state{} = S0)
  when is_binary(Payload) ->
    case (S0#state.peer_filter_fun)(IP, Port) of
        ok ->
            scrub_then_send(IP, Port, Payload, S0);
        {drop, Reason} ->
            {drop, Reason, S0}
    end.

scrub_then_send(IP, Port, Payload, #state{} = S0) ->
    case (S0#state.scrub_fun)(Payload, S0#state.user_state) of
        {pass, ScrubbedPayload, US} ->
            S1 = S0#state{user_state = US},
            send_to_peer(IP, Port, ScrubbedPayload, S1);
        {drop, Reason, US} ->
            {drop, Reason, S0#state{user_state = US}}
    end.

send_to_peer(IP, Port, Payload, #state{socket = Sock} = S) ->
    case gen_udp:send(Sock, IP, Port, Payload) of
        ok                -> {ok, S};
        {error, _Reason}  -> {drop, socket_error, S}
    end.

%%====================================================================
%% {udp, ...} from kernel: outbound to the client
%%====================================================================

-spec handle_info(term(), #state{}) ->
    {ok, #state{}} | {ok, #state{}, [term()]} | {stop, term(), #state{}}.
handle_info({udp, Socket, FromIP, FromPort, Bytes},
            #state{socket = Socket} = S) ->
    %% Drop frames whose source family is not advertised. This
    %% defends against weird kernel behaviour and against the proxy's
    %% own bind socket receiving packets from a family the client
    %% isn't expecting.
    case lists:member(family_of(FromIP), S#state.advertised_families) of
        false ->
            {ok, S};
        true ->
            {ok, S, [{send_bind_packet,
                      {FromIP, FromPort}, Bytes}]}
    end;
handle_info({udp_passive, Socket}, #state{socket = Socket} = S) ->
    _ = inet:setopts(Socket, [{active, true}]),
    {ok, S};
handle_info({udp_error, Socket, Reason}, #state{socket = Socket} = S) ->
    {stop, {bind_socket_error, Reason}, S};
handle_info({udp_closed, Socket}, #state{socket = Socket} = S) ->
    {stop, bind_socket_closed, S};
handle_info(_Other, S) ->
    {ok, S}.

%%====================================================================
%% Public-address resolution
%%====================================================================

resolve_public_addresses(Socket, Opts) ->
    case {maps:find(public_address_fun, Opts),
          maps:find(public_addresses, Opts)} of
        {{ok, Fun}, _} when is_function(Fun, 1) ->
            case inet:sockname(Socket) of
                {ok, Sn} ->
                    case Fun(Sn) of
                        []      -> {error, no_public_addresses};
                        Addrs when is_list(Addrs) -> {ok, Addrs}
                    end;
                {error, Reason} ->
                    {error, {sockname, Reason}}
            end;
        {error, {ok, []}} ->
            {error, no_public_addresses};
        {error, {ok, Addrs}} when is_list(Addrs) ->
            {ok, Addrs};
        {error, error} ->
            sockname_fallback(Socket)
    end.

%% sockname is the fallback only when bound to a specific interface.
%% If the socket is bound to a wildcard (0.0.0.0 / ::), refuse - that
%% address is not usable as a public address.
sockname_fallback(Socket) ->
    case inet:sockname(Socket) of
        {ok, {{0,0,0,0}, _}} ->
            {error, no_public_addresses};
        {ok, {{0,0,0,0,0,0,0,0}, _}} ->
            {error, no_public_addresses};
        {ok, {Addr, Port}} ->
            {ok, [{Addr, Port}]};
        {error, Reason} ->
            {error, {sockname, Reason}}
    end.

response_headers(Addresses) ->
    [masque_uri_udp_bind:format_bind_header(),
     {?MASQUE_HF_PROXY_PUBLIC_ADDRESS,
      masque_uri_udp_bind:format_proxy_public_address(Addresses)}].

families(Addresses) ->
    lists:usort([family_of(IP) || {IP, _} <- Addresses]).

family_of({_, _, _, _})             -> 4;
family_of({_, _, _, _, _, _, _, _}) -> 6.

%%====================================================================
%% Default policies
%%====================================================================

%% Reject RFC 1918, link-local, multicast. Loopback is allowed
%% (CT scaffolding runs the upstream peer on 127.0.0.1).
default_peer_filter(IP, _Port) ->
    case is_private(IP) of
        true  -> {drop, peer_filter};
        false -> ok
    end.

is_private({127, _, _, _})              -> false;     %% loopback ok
is_private({10, _, _, _})               -> true;
is_private({172, B, _, _}) when B >= 16, B =< 31 -> true;
is_private({192, 168, _, _})            -> true;
is_private({169, 254, _, _})            -> true;       %% link-local
is_private({A, _, _, _}) when A >= 224, A =< 239 -> true;  %% multicast
is_private({0, 0, 0, 0, 0, 0, 0, 1})    -> false;      %% v6 loopback
is_private({16#FE80, _, _, _, _, _, _, _}) -> true;    %% v6 link-local
is_private({16#FF00, _, _, _, _, _, _, _}) -> true;    %% v6 multicast
is_private({A, _, _, _, _, _, _, _})
  when A >= 16#FC00, A =< 16#FDFF -> true;            %% v6 ULA
is_private(_) -> false.

default_scrub(Packet, State) ->
    {pass, Packet, State}.
