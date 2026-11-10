%% Who may use a listener (`masque_listener_auth'): a listener with the
%% built-in relaying handlers refuses to start unauthenticated on every
%% interface; it starts with `authenticate', a loopback `ip' or
%% `public_relay => true'; and `authenticate' sees every tunnel request.
-module(masque_auth_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, groups/0, suite/0]).
-export([init_per_suite/1, end_per_suite/1, init_per_group/2, end_per_group/2]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    refuses_unauthenticated_relay/1,
    starts_with_public_relay/1,
    starts_bound_to_loopback/1,
    starts_with_custom_handlers/1,
    authenticate_rejects/1,
    authenticate_passes_identity/1,
    authenticate_crash_is_forbidden/1
]).
%% tcp_handler used to see the request
-export([accept/1, init/2, handle_data/2, terminate/2]).

suite() -> [{timetrap, {seconds, 60}}].

all() -> [{group, h3}, {group, h2}, {group, h1}].

groups() ->
    Cases = [
        refuses_unauthenticated_relay,
        starts_with_public_relay,
        starts_bound_to_loopback,
        starts_with_custom_handlers,
        authenticate_rejects,
        authenticate_passes_identity,
        authenticate_crash_is_forbidden
    ],
    [{h3, [], Cases}, {h2, [], Cases}, {h1, [], Cases}].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Certs} = masque_test_helpers:generate_certs(),
    {ok, L} = gen_tcp:listen(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, EchoPort} = inet:port(L),
    Echo = spawn(fun() -> echo_accept(L) end),
    ok = gen_tcp:controlling_process(L, Echo),
    [{certs, Certs}, {echo, Echo}, {echo_port, EchoPort} | Config].

end_per_suite(Config) ->
    exit(?config(echo, Config), kill),
    masque_test_helpers:cleanup_certs(?config(certs, Config)),
    ok.

init_per_group(T, Config) -> [{transport, T} | Config].
end_per_group(_T, _Config) -> ok.

%% The test node allows public relaying (test/test.config); these cases
%% check the default.
init_per_testcase(_Case, Config) ->
    application:set_env(masque, public_relay, false),
    Name = list_to_atom("auth_" ++ integer_to_list(erlang:unique_integer([positive]))),
    [{name, Name} | Config].

end_per_testcase(_Case, Config) ->
    application:set_env(masque, public_relay, true),
    _ = stop(?config(transport, Config), ?config(name, Config)),
    ok.

%%====================================================================
%% Cases
%%====================================================================

refuses_unauthenticated_relay(Config) ->
    ?assertMatch(
        {error, {unauthenticated_relay, [udp, tcp, ip]}},
        start(Config, #{})
    ).

starts_with_public_relay(Config) ->
    {ok, Port} = port(start(Config, #{public_relay => true}), Config),
    ok = echo(Config, Port, #{}).

starts_bound_to_loopback(Config) ->
    {ok, Port} = port(start(Config, #{ip => {127, 0, 0, 1}}), Config),
    ok = echo(Config, Port, #{}).

%% The application's own handlers carry the policy: no check.
starts_with_custom_handlers(Config) ->
    Custom = #{
        handler => ?MODULE,
        tcp_handler => ?MODULE,
        ip_handler => ?MODULE,
        handler_opts => #{report_to => self()}
    },
    ?assertMatch({ok, _}, port(start(Config, Custom), Config)).

authenticate_rejects(Config) ->
    Auth = fun(_Req) -> {reject, {other, 401}} end,
    {ok, Port} = port(start(Config, #{authenticate => Auth}), Config),
    ?assertMatch({error, {handshake_rejected, 401, _}}, norm(connect(Config, Port, #{}))).

%% The token the client sends reaches `authenticate'; its identity
%% reaches the handler.
authenticate_passes_identity(Config) ->
    Auth = fun(#{headers := H}) ->
        case lists:keyfind(<<"authorization">>, 1, H) of
            {_, <<"Bearer good">>} -> {ok, <<"alice">>};
            _ -> {reject, {other, 401}}
        end
    end,
    {ok, Port} = port(
        start(Config, #{
            authenticate => Auth,
            tcp_handler => ?MODULE,
            handler_opts => #{report_to => self()}
        }),
        Config
    ),
    Good = #{request_headers => [{<<"authorization">>, <<"Bearer good">>}]},
    {ok, Sess} = connect(Config, Port, Good),
    receive
        {identity, Id} -> ?assertEqual(<<"alice">>, Id)
    after 5000 -> ct:fail(no_identity)
    end,
    masque:close(Sess),
    Bad = #{request_headers => [{<<"authorization">>, <<"Bearer bad">>}]},
    ?assertMatch({error, {handshake_rejected, 401, _}}, norm(connect(Config, Port, Bad))).

%% A crashing `authenticate' refuses the request (403) and logs no
%% request headers.
authenticate_crash_is_forbidden(Config) ->
    Auth = fun(_Req) -> error(boom) end,
    {ok, Port} = port(start(Config, #{authenticate => Auth}), Config),
    ?assertMatch({error, {handshake_rejected, 403, _}}, norm(connect(Config, Port, #{}))).

%%====================================================================
%% tcp_handler reporting the identity
%%====================================================================

accept(#{handler_opts := #{report_to := Pid}} = Req) ->
    Pid ! {identity, maps:get(identity, Req, none)},
    accept;
accept(_Req) ->
    accept.

init(Req, Opts) -> masque_tcp_proxy_handler:init(Req, Opts#{allow_private => true}).
handle_data(Data, State) -> masque_tcp_proxy_handler:handle_data(Data, State).
terminate(Reason, State) -> masque_tcp_proxy_handler:terminate(Reason, State).

%%====================================================================
%% Helpers
%%====================================================================

start(Config, Extra) ->
    #{cert := Cert, key := Key, cert_file := CertFile, key_file := KeyFile} =
        ?config(certs, Config),
    Base = #{port => 0, handler_opts => #{allow_private => true, allow_self => true}},
    Opts0 = maps:merge(Base, Extra),
    Opts = Opts0#{
        handler_opts => maps:merge(maps:get(handler_opts, Base), maps:get(handler_opts, Extra, #{}))
    },
    Name = ?config(name, Config),
    case ?config(transport, Config) of
        h3 -> masque:start_listener(Name, Opts#{cert => Cert, key => Key});
        h2 -> masque:start_listener_h2(Name, Opts#{cert => CertFile, key => KeyFile});
        h1 -> masque:start_listener_h1(Name, Opts#{cert => CertFile, key => KeyFile})
    end.

port({ok, _} = Ok, Config) ->
    case {?config(transport, Config), Ok} of
        {h3, {ok, _}} -> quic:get_server_port(?config(name, Config));
        {_, {ok, {_, _, Port}}} -> {ok, Port}
    end;
port(Other, _Config) ->
    Other.

stop(h3, Name) -> masque:stop_listener(Name);
stop(h2, Name) -> masque:stop_listener_h2(Name);
stop(h1, Name) -> masque:stop_listener_h1(Name).

connect(Config, Port, Opts) ->
    masque:connect(
        iolist_to_binary(["https://127.0.0.1:", integer_to_list(Port)]),
        {<<"127.0.0.1">>, ?config(echo_port, Config)},
        maps:merge(
            #{
                protocol => tcp,
                transports => [?config(transport, Config)],
                verify => verify_none,
                timeout => 5000
            },
            Opts
        )
    ).

echo(Config, Port, Opts) ->
    {ok, Sess} = connect(Config, Port, Opts),
    ok = masque:send(Sess, <<"x">>),
    receive
        {masque_data, Sess, <<"x">>} -> ok
    after 5000 -> ct:fail(no_echo)
    end,
    masque:close(Sess),
    ok.

%% h3 rejections carry no headers in the error; keep the status only.
norm({error, {handshake_rejected, Status}}) -> {error, {handshake_rejected, Status, []}};
norm(Other) -> Other.

echo_accept(L) ->
    case gen_tcp:accept(L) of
        {ok, S} ->
            P = spawn(fun() -> echo_loop(S) end),
            _ = gen_tcp:controlling_process(S, P),
            echo_accept(L);
        _ ->
            ok
    end.

echo_loop(S) ->
    case gen_tcp:recv(S, 0) of
        {ok, B} ->
            _ = gen_tcp:send(S, B),
            echo_loop(S);
        _ ->
            ok
    end.
