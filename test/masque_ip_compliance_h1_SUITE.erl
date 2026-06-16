%%% @doc RFC 9484 normative compliance, HTTP/1.1 transport row.
%%%
%%% Mirrors the server-exercising cases of `masque_ip_compliance_SUITE'
%%% (which is h3-only) against a real h1 listener so the default
%%% `masque_ip_proxy_handler' is covered across all three transports.
-module(masque_ip_compliance_h1_SUITE).

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
    initial_route_advertisement/1,
    address_allocation_round_robin/1,
    pool_exhaustion_rejects/1,
    oversize_packet_rejected/1,
    inject_packet_via_registry/1
]).

all() ->
    [
        initial_route_advertisement,
        address_allocation_round_robin,
        pool_exhaustion_rejects,
        oversize_packet_rejected,
        inject_packet_via_registry
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Ctx} = masque_test_helpers:generate_certs(),
    [{ctx, Ctx} | Config].

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(ctx, Config)),
    ok.

init_per_testcase(Case, Config) ->
    Ctx = ?config(ctx, Config),
    Listener = list_to_atom(
        "ip_comp_h1_" ++ atom_to_list(Case) ++ "_" ++
            integer_to_list(erlang:unique_integer([positive]))
    ),
    Opts = case_opts(Case, Ctx),
    Parent = self(),
    Keeper = erlang:spawn(fun() -> keeper_loop(Parent, Listener, Opts) end),
    Port =
        receive
            {Keeper, started, P} -> P
        after 5000 ->
            ct:fail(keeper_start_timeout)
        end,
    [{listener, Listener}, {port, Port}, {keeper, Keeper} | Config].

end_per_testcase(_Case, Config) ->
    ?config(keeper, Config) ! stop,
    ok.

keeper_loop(Parent, Name, Opts) ->
    case masque:start_listener_h1(Name, Opts) of
        {ok, Ref} ->
            Parent ! {self(), started, h1:server_port(Ref)},
            keeper_wait(Name);
        {error, Reason} ->
            Parent ! {self(), start_failed, Reason}
    end.

keeper_wait(Name) ->
    receive
        stop ->
            _ = masque:stop_listener_h1(Name),
            ok;
        _ ->
            keeper_wait(Name)
    end.

case_opts(initial_route_advertisement, Ctx) ->
    Base = base_opts(Ctx),
    Base#{
        address_pool => {4, {10, 200, 0, 0}, 16},
        routes => [
            #ip_route{
                version = 4,
                start_addr = {0, 0, 0, 0},
                end_addr = {255, 255, 255, 255},
                ip_protocol = 0
            }
        ]
    };
case_opts(address_allocation_round_robin, Ctx) ->
    Base = base_opts(Ctx),
    Base#{
        address_pool => #ip_route{
            version = 4,
            start_addr = {10, 200, 0, 1},
            end_addr = {10, 200, 0, 3},
            ip_protocol = 0
        }
    };
case_opts(pool_exhaustion_rejects, Ctx) ->
    Base = base_opts(Ctx),
    Base#{
        address_pool => #ip_route{
            version = 4,
            start_addr = {10, 200, 0, 1},
            end_addr = {10, 200, 0, 1},
            ip_protocol = 0
        }
    };
case_opts(inject_packet_via_registry, Ctx) ->
    Base = base_opts(Ctx),
    Base#{
        address_pool => #ip_route{
            version = 4,
            start_addr = {10, 200, 0, 1},
            end_addr = {10, 200, 0, 3},
            ip_protocol = 0
        }
    };
case_opts(_, Ctx) ->
    base_opts(Ctx).

base_opts(Ctx) ->
    #{
        port => 0,
        cert => maps:get(cert_file, Ctx),
        key => maps:get(key_file, Ctx)
    }.

%%====================================================================
%% Cases
%%====================================================================

initial_route_advertisement(Config) ->
    {ok, Sess} = do_connect(?config(port, Config)),
    receive
        {masque_route_advertisement, Sess, [R | _]} ->
            ?assertMatch(
                #ip_route{
                    version = 4,
                    start_addr = {0, 0, 0, 0},
                    end_addr = {255, 255, 255, 255},
                    ip_protocol = 0
                },
                R
            )
    after 2000 -> ct:fail("no initial ROUTE_ADVERTISEMENT")
    end,
    ok = masque:close(Sess).

address_allocation_round_robin(Config) ->
    {ok, Sess} = do_connect(?config(port, Config)),
    _ = flush_advertise(Sess),
    {ok, [Id1]} =
        masque:request_addresses(Sess, [{4, {0, 0, 0, 0}, 0}]),
    receive
        {masque_address_assign, Sess, [
            #ip_assignment{
                request_id = Id1,
                version = 4,
                address = A1,
                prefix_len = 32
            }
        ]} ->
            ?assertEqual({10, 200, 0, 1}, A1)
    after 2000 -> ct:fail("no assign 1")
    end,
    {ok, [Id2]} =
        masque:request_addresses(Sess, [{4, {0, 0, 0, 0}, 0}]),
    receive
        {masque_address_assign, Sess, [#ip_assignment{request_id = Id2, address = A2}]} ->
            ?assertEqual({10, 200, 0, 2}, A2)
    after 2000 -> ct:fail("no assign 2")
    end,
    ok = masque:close(Sess).

pool_exhaustion_rejects(Config) ->
    {ok, Sess} = do_connect(?config(port, Config)),
    _ = flush_advertise(Sess),
    {ok, [Id1]} = masque:request_addresses(Sess, [{4, {0, 0, 0, 0}, 0}]),
    receive
        {masque_address_assign, Sess, [#ip_assignment{request_id = Id1, address = {10, 200, 0, 1}}]} ->
            ok
    after 2000 -> ct:fail("first assign missed")
    end,
    {ok, [Id2]} = masque:request_addresses(Sess, [{4, {0, 0, 0, 0}, 0}]),
    receive
        {masque_address_assign, Sess, [
            #ip_assignment{
                request_id = Id2,
                address = {0, 0, 0, 0},
                prefix_len = 32
            }
        ]} ->
            ok
    after 2000 -> ct:fail("no rejection for exhausted pool")
    end,
    ok = masque:close(Sess).

oversize_packet_rejected(Config) ->
    {ok, Sess} = do_connect(?config(port, Config)),
    _ = flush_advertise(Sess),
    Big = binary:copy(<<"x">>, 2000),
    ?assertMatch(
        {error, {packet_too_large, 2000, 1500}},
        masque:send_ip_packet(Sess, Big)
    ),
    ok = masque:close(Sess).

inject_packet_via_registry(Config) ->
    {ok, Sess} = do_connect(?config(port, Config)),
    _ = flush_advertise(Sess),
    {ok, [Id]} = masque:request_addresses(Sess, [{4, {0, 0, 0, 0}, 0}]),
    Assigned =
        receive
            {masque_address_assign, Sess, [
                #ip_assignment{request_id = Id, version = 4, address = A}
            ]} ->
                A
        after 2000 -> ct:fail("no assign")
        end,
    {ok, ServerPid, _Ctx} = masque_ip_session_registry:lookup(Assigned),
    Pkt = ipv4_packet({203, 0, 113, 1}, Assigned, 17),
    ok = masque_ip:inject_packet(ServerPid, Pkt),
    receive
        {masque_ip_packet, Sess, Got} when Got =:= Pkt -> ok
    after 2000 -> ct:fail("injected packet did not arrive at client")
    end,
    ok = masque:close(Sess).

ipv4_packet({SA, SB, SC, SD}, {DA, DB, DC, DD}, Proto) ->
    IHL = 5,
    Total = IHL * 4,
    <<4:4, IHL:4, 0:8, Total:16, 0:16, 0:16, 64:8, Proto:8, 0:16, SA:8, SB:8, SC:8, SD:8, DA:8,
        DB:8, DC:8, DD:8>>.

%%====================================================================
%% Internal
%%====================================================================

do_connect(Port) ->
    Url = iolist_to_binary(
        ["https://127.0.0.1:", integer_to_binary(Port)]
    ),
    masque:connect(
        Url,
        {'*', '*'},
        #{
            protocol => ip,
            transports => [h1],
            verify => verify_none,
            ssl_opts => [{verify, verify_none}]
        }
    ).

flush_advertise(Sess) ->
    receive
        {masque_route_advertisement, Sess, _} -> ok
    after 500 -> ok
    end.
