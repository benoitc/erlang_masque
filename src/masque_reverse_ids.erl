-module(masque_reverse_ids).
-moduledoc false.

%%% Request ids a reverse connect agent has seen on one control channel.
%%%
%%% Draft-rosomakho-masque-reverse-connect-01 section 5.1: a proxy must not
%%% reuse a request id, and a reuse is a stream error. Remembering every id
%%% would let a proxy grow the agent's memory without limit, so only the
%%% last `?KEEP' ids are kept: a reuse of an older id goes unnoticed. The
%%% ids are random, so there is no high-water mark to keep instead.

-export([new/0, seen/2, add/2]).
-export_type([ids/0]).

-define(KEEP, 4096).

-opaque ids() :: {#{non_neg_integer() => true}, queue:queue(non_neg_integer())}.

-spec new() -> ids().
new() ->
    {#{}, queue:new()}.

-spec seen(non_neg_integer(), ids()) -> boolean().
seen(Id, {Set, _}) ->
    is_map_key(Id, Set).

-spec add(non_neg_integer(), ids()) -> ids().
add(Id, {Set, Q}) ->
    Q2 = queue:in(Id, Q),
    case map_size(Set) >= ?KEEP of
        true ->
            {{value, Old}, Q3} = queue:out(Q2),
            {maps:put(Id, true, maps:remove(Old, Set)), Q3};
        false ->
            {maps:put(Id, true, Set), Q2}
    end.
