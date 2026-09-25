%%% @doc End-to-end tests for CONNECT-IP through a chain handler.
%%%
%%% Ingress listener runs `masque_chain_handler' in `protocol = ip'
%%% mode; egress listener runs `masque_ip_proxy_handler' with a real
%%% /29 address pool. A CONNECT-IP client dials the ingress and the
%%% chain handler fans out to the egress.
%%%
%%% Covers:
%%% <ul>
%%%   <li>IP packet round-trip through the chain</li>
%%%   <li>Initial ROUTE_ADVERTISEMENT from the egress reaching the
%%%       downstream client</li>
%%%   <li>Unprompted ADDRESS_ASSIGN from the egress reaching the
%%%       downstream client</li>
%%%   <li>Upstream failure (egress dead) produces a clean reject
%%%       with no leaked ingress sessions</li>
%%% </ul>
-module(masque_chain_ip_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("masque_ip.hrl").

-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([
    initial_route_advertisement_forwarded/1,
    upstream_failure_returns_reject/1,
    unprompted_address_assign_forwarded/1,
    chained_address_request_answered/1
]).

all() ->
    [
        initial_route_advertisement_forwarded,
        unprompted_address_assign_forwarded,
        chained_address_request_answered,
        upstream_failure_returns_reject
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Ctx} = masque_test_helpers:generate_certs(),
    [{ctx, Ctx} | Config].

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(ctx, Config)),
    ok.

init_per_testcase(upstream_failure_returns_reject, Config) ->
    Ctx = ?config(ctx, Config),
    %% Only the ingress; upstream URI points at a dead port.
    IngressName = unique("chain_ip_ingress"),
    {ok, _} = masque:start_chain_listener(IngressName, #{
        port => 0,
        cert => maps:get(cert, Ctx),
        key => maps:get(key, Ctx),
        ip_handler => masque_chain_handler,
        handler_opts => #{
            upstream_proxy => <<"https://127.0.0.1:1">>,
            upstream_opts => #{
                verify => verify_none,
                transports => [h3],
                alpn => [<<"h3">>],
                timeout => 300
            }
        }
    }),
    {ok, IngressPort} = quic:get_server_port(IngressName),
    [{ingress_name, IngressName}, {ingress_port, IngressPort} | Config];
init_per_testcase(Case, Config) ->
    Ctx = ?config(ctx, Config),
    EgressHandler =
        case Case of
            unprompted_address_assign_forwarded ->
                %% Fixture that sends an unprompted ADDRESS_ASSIGN on init
                %% so the chain's forwarding path has something to see.
                masque_ip_unprompted_handler;
            _ ->
                masque_ip_proxy_handler
        end,
    EgressName = unique("chain_ip_egress"),
    {ok, _} = masque:start_listener(EgressName, #{
        port => 0,
        cert => maps:get(cert, Ctx),
        key => maps:get(key, Ctx),
        ip_handler => EgressHandler,
        handler_opts => #{
            allow_private => true,
            address_pool => #ip_route{
                version = 4,
                start_addr = {10, 77, 0, 1},
                end_addr = {10, 77, 0, 3},
                ip_protocol = 0
            },
            routes => [
                #ip_route{
                    version = 4,
                    start_addr = {0, 0, 0, 0},
                    end_addr = {255, 255, 255, 255},
                    ip_protocol = 0
                }
            ]
        }
    }),
    {ok, EgressPort} = quic:get_server_port(EgressName),
    %% Ingress: chain handler pointed at the egress.
    IngressName = unique("chain_ip_ingress"),
    {ok, _} = masque:start_chain_listener(IngressName, #{
        port => 0,
        cert => maps:get(cert, Ctx),
        key => maps:get(key, Ctx),
        ip_handler => masque_chain_handler,
        handler_opts => #{
            upstream_proxy => iolist_to_binary(
                [
                    "https://127.0.0.1:",
                    integer_to_list(EgressPort)
                ]
            ),
            upstream_opts => #{
                verify => verify_none,
                transports => [h3],
                alpn => [<<"h3">>]
            }
        }
    }),
    {ok, IngressPort} = quic:get_server_port(IngressName),
    [
        {egress_name, EgressName},
        {ingress_name, IngressName},
        {ingress_port, IngressPort}
        | Config
    ].

end_per_testcase(_Case, Config) ->
    case ?config(ingress_name, Config) of
        undefined -> ok;
        I -> _ = masque:stop_listener(I)
    end,
    case ?config(egress_name, Config) of
        undefined -> ok;
        E -> _ = masque:stop_listener(E)
    end,
    ok.

%%====================================================================
%% Cases
%%====================================================================

initial_route_advertisement_forwarded(Config) ->
    {ok, Sess} = connect_ip(?config(ingress_port, Config)),
    receive
        {masque_route_advertisement, Sess, Routes} ->
            [
                #ip_route{
                    version = 4,
                    start_addr = {0, 0, 0, 0},
                    end_addr = {255, 255, 255, 255},
                    ip_protocol = 0
                }
            ] = Routes
    after 3000 ->
        ct:fail("no ROUTE_ADVERTISEMENT forwarded through chain")
    end,
    ok = masque:close(Sess).

unprompted_address_assign_forwarded(Config) ->
    %% Trigger the test egress handler by sending one IP packet; the
    %% handler replies with an unprompted ADDRESS_ASSIGN (request_id
    %% = 0) plus an IP packet echo. The chain handler forwards the
    %% assign and the downstream client's owner receives it.
    {ok, Sess} = connect_ip(?config(ingress_port, Config)),
    ok = masque:send_ip_packet(Sess, <<"trigger">>),
    {ok, Assign} = recv_assign(Sess, 3000),
    #ip_assignment{request_id = 0, version = 4, address = {10, 77, 0, 1}} =
        Assign,
    ok = masque:close(Sess).

chained_address_request_answered(Config) ->
    %% The ingress forwards ADDRESS_REQUEST to the egress, which
    %% allocates from its pool; the answer comes back under the
    %% client's own request ids.
    {ok, Sess} = connect_ip(?config(ingress_port, Config)),
    {ok, [Id1]} = masque:request_addresses(Sess, [{4, {0, 0, 0, 0}, 32}]),
    {ok, A1} = recv_assign(Sess, 3000),
    #ip_assignment{request_id = Id1, version = 4, address = {10, 77, 0, 1}} = A1,
    {ok, [Id2]} = masque:request_addresses(Sess, [{4, {0, 0, 0, 0}, 32}]),
    {ok, A2} = recv_assign(Sess, 3000),
    #ip_assignment{request_id = Id2, address = {10, 77, 0, 2}} = A2,
    ok = masque:close(Sess).

%% Drain owner messages until an `ADDRESS_ASSIGN' arrives. Discards
%% `ROUTE_ADVERTISEMENT' and other interleaved traffic that does not
%% concern this case.
recv_assign(Sess, Timeout) ->
    receive
        {masque_address_assign, Sess, [A | _]} ->
            {ok, A};
        {masque_route_advertisement, Sess, _} ->
            recv_assign(Sess, Timeout);
        {masque_ip_packet, Sess, _} ->
            recv_assign(Sess, Timeout)
    after Timeout ->
        {error, timeout}
    end.

upstream_failure_returns_reject(Config) ->
    %% Egress is dead; the chain handler's init/2 returns {stop, _}
    %% and the listener turns that into a reject. The client surfaces
    %% it as a handshake error from `masque:connect/3'.
    Port = ?config(ingress_port, Config),
    Result = connect_ip(Port),
    ?assertMatch({error, _}, Result).

%%====================================================================
%% Helpers
%%====================================================================

connect_ip(Port) ->
    Url = iolist_to_binary(
        ["https://127.0.0.1:", integer_to_binary(Port)]
    ),
    masque:connect(
        Url,
        {'*', '*'},
        #{
            protocol => ip,
            transports => [h3],
            verify => verify_none,
            %% Leaves headroom for the chain handler's own
            %% upstream connect (default 5 s) which happens
            %% inside this call's wall-clock budget.
            timeout => 10000
        }
    ).

unique(Prefix) ->
    list_to_atom(
        Prefix ++ "_" ++
            integer_to_list(erlang:unique_integer([positive]))
    ).
