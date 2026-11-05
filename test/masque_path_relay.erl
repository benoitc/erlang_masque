%%% @doc Test fixture: a UDP relay that plays the network between a QUIC
%%% client and the proxy, so a test can change the client's network.
%%%
%%% The client dials the relay. Each client address gets its own upstream
%%% socket bound to the current source IP, so the proxy sees that IP.
%%% `change_network/2' makes the old path dead in both directions and
%%% moves new paths to a new source IP, as losing Wi-Fi for mobile data
%%% does. `nat_rebind/2' moves existing paths behind the client's back.
-module(masque_path_relay).

-export([start/1, stop/1, port/1]).
-export([change_network/2, network_down/1, network_up/1, nat_rebind/2, sources/1]).

-record(state, {
    front :: gen_udp:socket(),
    server_port :: inet:port_number(),
    source_ip = {127, 0, 0, 1} :: inet:ip_address(),
    %% Client address -> upstream socket, and the way back.
    up = #{} :: map(),
    down = #{} :: map(),
    %% Client addresses whose network is gone.
    dead = [] :: list(),
    up_state = true :: boolean(),
    sources = [] :: [inet:ip_address()]
}).

start(ServerPort) ->
    Parent = self(),
    {Pid, Ref} = spawn_monitor(fun() ->
        {ok, Front} = gen_udp:open(0, [binary, {active, true}, {ip, {127, 0, 0, 1}}]),
        Parent ! {self(), ready},
        loop(#state{front = Front, server_port = ServerPort})
    end),
    receive
        {Pid, ready} ->
            erlang:demonitor(Ref, [flush]),
            Pid;
        {'DOWN', Ref, process, Pid, Reason} ->
            error({relay_failed, Reason})
    end.

stop(Pid) -> exit(Pid, kill).

port(Pid) -> call(Pid, port).

%% The old path stops carrying anything; new paths use `IP'.
change_network(Pid, IP) -> call(Pid, {change_network, IP}).

%% Nothing passes in either direction.
network_down(Pid) -> call(Pid, down).
network_up(Pid) -> call(Pid, up).

%% Existing client paths get a new source, without the client knowing.
nat_rebind(Pid, IP) -> call(Pid, {nat_rebind, IP}).

%% Source IPs the proxy has been sent packets from, newest first.
sources(Pid) -> call(Pid, sources).

call(Pid, Req) ->
    Ref = make_ref(),
    Pid ! {call, self(), Ref, Req},
    receive
        {Ref, Reply} -> Reply
    after 5000 -> error(relay_timeout)
    end.

loop(S) ->
    receive
        {call, From, Ref, Req} ->
            {Reply, S2} = handle_call(Req, S),
            From ! {Ref, Reply},
            loop(S2);
        {udp, Front, IP, Port, Data} when Front =:= S#state.front ->
            loop(from_client({IP, Port}, Data, S));
        {udp, Up, _IP, _Port, Data} ->
            from_server(Up, Data, S),
            loop(S)
    after infinity ->
        ok
    end.

handle_call(port, #state{front = Front} = S) ->
    {ok, Port} = inet:port(Front),
    {Port, S};
handle_call({change_network, IP}, S) ->
    {ok, S#state{source_ip = IP, dead = maps:keys(S#state.up) ++ S#state.dead}};
handle_call(down, S) ->
    {ok, S#state{up_state = false}};
handle_call(up, S) ->
    {ok, S#state{up_state = true}};
handle_call({nat_rebind, IP}, S) ->
    S2 = S#state{source_ip = IP},
    {ok, maps:fold(fun(Client, Old, Acc) -> rebind(Client, Old, Acc) end, S2, S2#state.up)};
handle_call(sources, S) ->
    {S#state.sources, S}.

rebind(Client, Old, #state{up = Up, down = Down} = S) ->
    New = open_up(S#state.source_ip),
    S#state{
        up = Up#{Client => New},
        down = (maps:remove(Old, Down))#{New => Client}
    }.

from_client(_Client, _Data, #state{up_state = false} = S) ->
    S;
from_client(Client, Data, S) ->
    case lists:member(Client, S#state.dead) of
        true -> S;
        false -> forward(Client, Data, S)
    end.

forward(Client, Data, #state{up = Up} = S) ->
    {Sock, S2} =
        case Up of
            #{Client := Existing} ->
                {Existing, S};
            _ ->
                New = open_up(S#state.source_ip),
                {New, S#state{up = Up#{Client => New}, down = (S#state.down)#{New => Client}}}
        end,
    _ = gen_udp:send(Sock, {127, 0, 0, 1}, S2#state.server_port, Data),
    Sources = S2#state.sources,
    case Sources of
        [Ip | _] when Ip =:= S2#state.source_ip -> S2;
        _ -> S2#state{sources = [S2#state.source_ip | Sources]}
    end.

from_server(_Up, _Data, #state{up_state = false}) ->
    ok;
from_server(Up, Data, #state{down = Down, front = Front, dead = Dead}) ->
    case Down of
        #{Up := {IP, Port} = Client} ->
            case lists:member(Client, Dead) of
                true ->
                    ok;
                false ->
                    _ = gen_udp:send(Front, IP, Port, Data),
                    ok
            end;
        _ ->
            ok
    end.

open_up(IP) ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, true}, {ip, IP}]),
    Sock.
