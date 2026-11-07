-module(masque_reverse_registry).
-moduledoc false.

%%% Pending reverse connect requests
%%% (draft-rosomakho-masque-reverse-connect-01 section 5).
%%%
%%% A control session registers each CONNECTION_REQUEST it sends under a
%%% random 62-bit id (section 6 asks for unpredictable ids on h1). An
%%% accept request is matched against the entry; the accept stream takes
%%% it atomically, so a request answered twice, or after it timed out,
%%% finds nothing. The table is owned by `masque_sup', so it outlives the
%%% sessions that write to it.

-include("masque_reverse.hrl").

-export([new_table/0, register/1, lookup/1, take/1, delete/1, delete_control/1]).

-export_type([entry/0]).

-define(TABLE, masque_reverse_pending).

%% `conn' is the h3 or h2 connection the control channel runs on, or
%% `undefined' on h1, where accepts come on new connections and are
%% matched by `identity' instead.
-type entry() :: #{
    control := pid(),
    conn := pid() | undefined,
    identity := term(),
    requester := pid(),
    service := masque_reverse_capsule:service()
}.

-spec new_table() -> ok.
new_table() ->
    _ = ets:new(?TABLE, [
        set, named_table, public, {read_concurrency, true}, {write_concurrency, true}
    ]),
    ok.

%% Store a request under a fresh random id.
-spec register(entry()) -> non_neg_integer().
register(Entry) ->
    Id = rand:uniform(?MASQUE_REQUEST_ID_MAX + 1) - 1,
    case ets:insert_new(?TABLE, {Id, Entry}) of
        true -> Id;
        false -> register(Entry)
    end.

-spec lookup(non_neg_integer()) -> {ok, entry()} | error.
lookup(Id) ->
    case ets:lookup(?TABLE, Id) of
        [{_, Entry}] -> {ok, Entry};
        [] -> error
    end.

%% Remove and return the entry: only one caller gets it.
-spec take(non_neg_integer()) -> {ok, entry()} | error.
take(Id) ->
    case ets:take(?TABLE, Id) of
        [{_, Entry}] -> {ok, Entry};
        [] -> error
    end.

-spec delete(non_neg_integer()) -> ok.
delete(Id) ->
    true = ets:delete(?TABLE, Id),
    ok.

%% Every request of a control channel that ended.
-spec delete_control(pid()) -> ok.
delete_control(Control) ->
    _ = ets:select_delete(?TABLE, [{{'_', #{control => Control}}, [], [true]}]),
    ok.
