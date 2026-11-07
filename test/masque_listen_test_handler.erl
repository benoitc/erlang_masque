-module(masque_listen_test_handler).

%% A listen handler for lifecycle tests: the `x-identity' header is the
%% identity, and the identity `refuse' makes `init/2' stop.

-behaviour(masque_listen_handler).

-export([authenticate/1, init/2]).

authenticate(#{headers := Headers}) ->
    case lists:keyfind(<<"x-identity">>, 1, Headers) of
        {_, Identity} -> {ok, Identity};
        false -> {reject, {other, 401}}
    end.

init(<<"refuse">>, _Req) -> {stop, refused};
init(Identity, _Req) -> {ok, Identity}.
