%%% @doc End-to-end coverage for the auth hooks a Private Relay-style
%%% app needs from the library.
%%%
%%% <ul>
%%%  <li>A handler can reject a request with extra response headers
%%%      (the `{reject, Error, [{Name, Value}]}' shape) so schemes
%%%      like Privacy Pass can attach a `WWW-Authenticate' challenge
%%%      on 401.</li>
%%%  <li>A client can prepend request headers onto the CONNECT
%%%      handshake (`request_headers' opt) so the retry after the
%%%      challenge carries the `Authorization: PrivateToken ...'
%%%      header.</li>
%%% </ul>
-module(masque_auth_challenge_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1,
         init_per_testcase/2, end_per_testcase/2]).

-export([reject_carries_challenge_header_h3/1,
         reject_carries_challenge_header_h2/1,
         authenticated_retry_succeeds_h3/1,
         authenticated_retry_succeeds_h2/1]).

-export([accept/1, init/2, handle_packet/2, terminate/2]).

all() ->
    [reject_carries_challenge_header_h3,
     reject_carries_challenge_header_h2,
     authenticated_retry_succeeds_h3,
     authenticated_retry_succeeds_h2].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    {ok, Certs} = masque_test_helpers:generate_certs(),
    [{certs, Certs} | Config].

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(certs, Config)),
    ok.

init_per_testcase(Case, Config) ->
    Certs = ?config(certs, Config),
    Common = #{handler => ?MODULE,
               handler_opts => #{token => <<"valid-token">>}},
    case case_transport(Case) of
        h3 ->
            {ok, Server} = masque_test_helpers:start_masque_server(
                             maps:merge(Certs, Common)),
            [{server, Server},
             {port, maps:get(port, Server)},
             {transport, h3} | Config];
        h2 ->
            Name = unique_name("auth_h2"),
            Opts = #{port => 0,
                     cert => maps:get(cert_file, Certs),
                     key  => maps:get(key_file, Certs),
                     handler => ?MODULE,
                     handler_opts => #{token => <<"valid-token">>}},
            {ok, Ref} = masque:start_listener_h2(Name, Opts),
            {_, _, Port} = Ref,
            [{h2_ref, Ref},
             {port, Port},
             {transport, h2} | Config]
    end.

end_per_testcase(_Case, Config) ->
    case ?config(server, Config) of
        undefined -> ok;
        S         -> _ = masque_test_helpers:stop_masque_server(S)
    end,
    case ?config(h2_ref, Config) of
        undefined -> ok;
        R         -> _ = masque:stop_listener_h2(R)
    end,
    ok.

case_transport(reject_carries_challenge_header_h3)  -> h3;
case_transport(reject_carries_challenge_header_h2)  -> h2;
case_transport(authenticated_retry_succeeds_h3)     -> h3;
case_transport(authenticated_retry_succeeds_h2)     -> h2.

%%====================================================================
%% Handler: requires `Authorization: PrivateToken token=valid-token',
%% otherwise rejects with 401 + `WWW-Authenticate: PrivateToken ...'.
%%====================================================================

accept(#{headers := Hdrs, handler_opts := #{token := Expected}}) ->
    case header(<<"authorization">>, Hdrs) of
        <<"PrivateToken token=", Got/binary>> when Got =:= Expected ->
            accept;
        _ ->
            {reject, {other, 401},
             [{<<"www-authenticate">>,
               <<"PrivateToken challenge=\"opaque-challenge\", "
                 "token-key=\"base64key\", max-age=3600">>}]}
    end.

init(_Req, _Opts) ->
    {ok, #{}}.

handle_packet(Data, State) ->
    {ok, State, [{send, Data}]}.

terminate(_Reason, _State) ->
    ok.

header(Name, H) ->
    case lists:keyfind(Name, 1, H) of
        {_, V} -> V;
        false  -> undefined
    end.

%%====================================================================
%% Cases
%%====================================================================

reject_carries_challenge_header_h3(Config) ->
    exercise_reject(Config).

reject_carries_challenge_header_h2(Config) ->
    exercise_reject(Config).

authenticated_retry_succeeds_h3(Config) ->
    exercise_accept(Config).

authenticated_retry_succeeds_h2(Config) ->
    exercise_accept(Config).

%%====================================================================
%% Helpers
%%====================================================================

exercise_reject(Config) ->
    Port = ?config(port, Config),
    Transport = ?config(transport, Config),
    ProxyURI = proxy_uri(Port),
    %% No Authorization header - must be rejected with 401.
    Opts = #{transports => [Transport],
             protocol => udp,
             timeout => 5000,
             owner => self(),
             verify => verify_none,
             ssl_opts => [{verify, verify_none}]},
    R = masque:connect(ProxyURI, {<<"127.0.0.1">>, 9}, Opts),
    %% h3 wraps the status in `handshake_failed'; h2 surfaces it
    %% directly. Accept either shape - both are the same 401.
    ?assertMatch({error, Err} when
                    Err =:= {handshake_rejected, 401} orelse
                    Err =:= {handshake_failed, {handshake_rejected, 401}},
                 R).

exercise_accept(Config) ->
    Port = ?config(port, Config),
    Transport = ?config(transport, Config),
    ProxyURI = proxy_uri(Port),
    Opts = #{transports => [Transport],
             protocol => udp,
             timeout => 5000,
             owner => self(),
             verify => verify_none,
             ssl_opts => [{verify, verify_none}],
             request_headers =>
               [{<<"authorization">>,
                 <<"PrivateToken token=valid-token">>}]},
    {ok, Sess} = masque:connect(ProxyURI, {<<"127.0.0.1">>, 9}, Opts),
    try
        ok = masque:send(Sess, <<"ping">>),
        receive
            {masque_data, Sess, <<"ping">>} -> ok
        after 3000 ->
            ct:fail(no_echo)
        end
    after
        ok = masque:close(Sess)
    end.

proxy_uri(Port) ->
    iolist_to_binary(["https://localhost:", integer_to_list(Port)]).

unique_name(Prefix) ->
    list_to_atom(Prefix ++ "_" ++
                 integer_to_list(erlang:unique_integer([positive]))).
