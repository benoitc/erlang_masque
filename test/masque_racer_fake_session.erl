%%% @doc Test fixture - a fake MASQUE client session that mirrors
%%% the contract the racer drives (`start/3', `handshake_await',
%%% `{set_owner, _}', `stop/1'), but never touches the network.
%%%
%%% Behaviour is parameterised via keys on the `Opts' map passed to
%%% `start/3'. Because the racer passes one shared Opts map to every
%%% attempt, per-transport tuning is keyed by the `transport' entry
%%% the racer injects for each attempt:
%%%
%%% ```
%%% #{
%%%     fake_by_transport => #{
%%%         h3 => #{fake_result => {error, no_quic}},
%%%         h2 => #{fake_result => ok, fake_delay_ms => 20},
%%%         h1 => #{fake_result => ok, fake_delay_ms => 100}
%%%     }
%%% }
%%% '''
%%%
%%% Top-level `fake_result' / `fake_delay_ms' keys act as the default
%%% for transports not listed in `fake_by_transport'.
-module(masque_racer_fake_session).
-behaviour(gen_statem).

-export([start/3, stop/1]).
-export([init/1, callback_mode/0, terminate/3, code_change/4]).
-export([connecting/3, open/3]).

-record(data, {
    result :: ok | {error, term()},
    delay_ms :: non_neg_integer(),
    handshake_from :: undefined | gen_statem:from(),
    owner :: pid()
}).

start(_Target, Opts, Owner) ->
    gen_statem:start(?MODULE, {Opts, Owner}, []).

stop(Pid) ->
    gen_statem:call(Pid, stop, 1000).

callback_mode() -> state_functions.

init({Opts, Owner}) ->
    {Result, Delay} = resolve_tuning(Opts),
    Data = #data{
        result = Result,
        delay_ms = Delay,
        owner = Owner
    },
    {ok, connecting, Data, [{state_timeout, Delay, resolve}]}.

resolve_tuning(Opts) ->
    ByT = maps:get(fake_by_transport, Opts, #{}),
    Transport = maps:get(transport, Opts, undefined),
    Spec = maps:get(
        Transport,
        ByT,
        maps:with([fake_result, fake_delay_ms], Opts)
    ),
    Result = maps:get(fake_result, Spec, ok),
    Delay = maps:get(fake_delay_ms, Spec, 0),
    {Result, Delay}.

connecting(state_timeout, resolve, #data{result = Result} = D) ->
    case Result of
        ok ->
            _ = reply_handshake(D, ok),
            {next_state, open, D#data{handshake_from = undefined}};
        {error, _} = Err ->
            _ = reply_handshake(D, Err),
            {stop, normal}
    end;
connecting({call, From}, handshake_await, D) ->
    {keep_state, D#data{handshake_from = From}};
connecting({call, From}, {set_owner, NewOwner}, D) ->
    {keep_state, D#data{owner = NewOwner}, [{reply, From, ok}]};
connecting({call, From}, stop, D) ->
    {stop_and_reply, normal, [{reply, From, ok}], D}.

open({call, From}, handshake_await, D) ->
    {keep_state, D, [{reply, From, ok}]};
open({call, From}, {set_owner, NewOwner}, D) ->
    {keep_state, D#data{owner = NewOwner}, [{reply, From, ok}]};
open({call, From}, stop, D) ->
    {stop_and_reply, normal, [{reply, From, ok}], D}.

terminate(_Reason, _State, _D) -> ok.

code_change(_OldVsn, State, D, _Extra) -> {ok, State, D}.

reply_handshake(#data{handshake_from = undefined}, _Reply) -> ok;
reply_handshake(#data{handshake_from = From}, Reply) -> gen_statem:reply(From, Reply).
