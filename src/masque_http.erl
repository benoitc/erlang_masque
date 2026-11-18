%%% HTTP field checks shared by every protocol and transport.
%%%
%%% - `capsule_protocol/1' reads a received `Capsule-Protocol' field as
%%%   the Structured Field Boolean RFC 9297 section 3.4 defines: `?1'
%%%   with any parameters is true, `?0' and anything malformed is false
%%%   ("Receivers MUST ignore unknown parameters"). Sending stays a bare
%%%   `?1'.
%%% - `capsule_response/2' and `capsule_request/1' apply RFC 9297
%%%   section 3.2: a capsule-protocol message has no `Content-Length',
%%%   `Content-Type' or `Transfer-Encoding', and a 204, 205 or 206
%%%   response to one is malformed.
%%% - `upgrade_ack/2' checks an HTTP/1.1 101 the way RFC 9298 section
%%%   3.3, RFC 9484 section 4.3 and draft-ietf-httpbis-connect-tcp
%%%   section 3.2 ask: `Connection' lists `upgrade' and there is a
%%%   single `Upgrade' field whose value is the token requested.
%%%
%%% Field names compare case-insensitively, so the h1 header lists can
%%% be passed as they come.
-module(masque_http).
-moduledoc false.

-export([
    capsule_protocol/1,
    sf_boolean/1,
    capsule_response/2,
    capsule_request/1,
    upgrade_ack/2,
    count/2
]).

-type headers() :: [{iodata(), iodata()}].

-export_type([headers/0]).

%% Fields a capsule-protocol message must not carry.
-define(BODY_FIELDS, [<<"content-length">>, <<"content-type">>, <<"transfer-encoding">>]).

%% Whether the message's `Capsule-Protocol' field is true. Several
%% field lines combine into one value (RFC 9110 section 5.3), which is
%% then a list and not a Boolean, so malformed.
-spec capsule_protocol(headers()) -> boolean().
capsule_protocol(Headers) ->
    case values(<<"capsule-protocol">>, Headers) of
        [] -> false;
        Values -> sf_boolean(iolist_to_binary(lists:join(<<", ">>, Values)))
    end.

%% A Structured Field Item (RFC 9651 section 4.2) that is the Boolean
%% true, with any parameters.
-spec sf_boolean(binary() | undefined) -> boolean().
sf_boolean(undefined) ->
    false;
sf_boolean(Value) when is_binary(Value) ->
    case string:trim(Value, both, " \t") of
        <<"?1", Rest/binary>> -> params(Rest);
        _ -> false
    end.

%% RFC 9297 section 3.2 for a 2xx (or 101) response to a request that
%% uses the Capsule Protocol.
-spec capsule_response(100..599, headers()) -> ok | {error, malformed_response}.
capsule_response(Status, _Headers) when Status >= 204, Status =< 206 ->
    {error, malformed_response};
capsule_response(_Status, Headers) ->
    case has_body_fields(Headers) of
        true -> {error, malformed_response};
        false -> ok
    end.

%% RFC 9297 section 3.2 for a request: a capsule-protocol request with a
%% body field is malformed (400).
-spec capsule_request(headers()) -> ok | {error, bad_request}.
capsule_request(Headers) ->
    case capsule_protocol(Headers) andalso has_body_fields(Headers) of
        true -> {error, bad_request};
        false -> ok
    end.

%% Whether a 101 confirms the upgrade to `Token'.
-spec upgrade_ack(headers(), binary()) -> boolean().
upgrade_ack(Headers, Token) ->
    ConnTokens = [
        lower(string:trim(T, both, " \t"))
     || V <- values(<<"connection">>, Headers),
        T <- binary:split(V, <<",">>, [global])
    ],
    lists:member(<<"upgrade">>, ConnTokens) andalso
        case values(<<"upgrade">>, Headers) of
            [Upgrade] -> lower(string:trim(Upgrade, both, " \t")) =:= lower(Token);
            _ -> false
        end.

%% How many field lines named `Name' the message has.
-spec count(binary(), headers()) -> non_neg_integer().
count(Name, Headers) ->
    length(values(Name, Headers)).

%%====================================================================
%% Internal
%%====================================================================

has_body_fields(Headers) ->
    lists:any(fun(Name) -> values(Name, Headers) =/= [] end, ?BODY_FIELDS).

values(Name, Headers) ->
    [iolist_to_binary(V) || {N, V} <- Headers, lower(N) =:= Name].

lower(V) ->
    string:lowercase(iolist_to_binary(V)).

%% Parameters (RFC 9651 section 3.1.2): `;' key [ `=' bare-item ].
params(<<>>) ->
    true;
params(<<$;, Rest/binary>>) ->
    key_start(skip_sp(Rest));
params(_) ->
    false.

key_start(<<C, Rest/binary>>) when (C >= $a andalso C =< $z) orelse C =:= $* ->
    key_rest(Rest);
key_start(_) ->
    false.

key_rest(<<C, Rest/binary>>) when
    (C >= $a andalso C =< $z) orelse (C >= $0 andalso C =< $9) orelse
        C =:= $_ orelse C =:= $- orelse C =:= $. orelse C =:= $*
->
    key_rest(Rest);
key_rest(<<$=, Rest/binary>>) ->
    case bare_item(Rest) of
        {ok, After} -> params(After);
        error -> false
    end;
key_rest(Rest) ->
    params(Rest).

skip_sp(<<$\s, Rest/binary>>) -> skip_sp(Rest);
skip_sp(Bin) -> Bin.

%% Bare items (RFC 9651 section 3.3): the rest of the input, or `error'.
bare_item(<<$?, B, Rest/binary>>) when B =:= $0; B =:= $1 ->
    {ok, Rest};
bare_item(<<$", Rest/binary>>) ->
    sf_string(Rest);
bare_item(<<$%, $", Rest/binary>>) ->
    display_string(Rest);
bare_item(<<$:, Rest/binary>>) ->
    byte_sequence(Rest);
bare_item(<<$@, Rest/binary>>) ->
    number(Rest);
bare_item(<<C, _/binary>> = Bin) when C =:= $-; C >= $0, C =< $9 ->
    number(Bin);
bare_item(<<C, Rest/binary>>) when
    (C >= $a andalso C =< $z) orelse (C >= $A andalso C =< $Z) orelse C =:= $*
->
    token(Rest);
bare_item(_) ->
    error.

sf_string(<<$\\, C, Rest/binary>>) when C =:= $"; C =:= $\\ -> sf_string(Rest);
sf_string(<<$", Rest/binary>>) -> {ok, Rest};
sf_string(<<C, Rest/binary>>) when C >= 16#20, C =< 16#7E, C =/= $\\ -> sf_string(Rest);
sf_string(_) -> error.

display_string(<<$%, H1, H2, Rest/binary>>) ->
    case is_lhex(H1) andalso is_lhex(H2) of
        true -> display_string(Rest);
        false -> error
    end;
display_string(<<$", Rest/binary>>) ->
    {ok, Rest};
display_string(<<C, Rest/binary>>) when C >= 16#20, C =< 16#7E, C =/= $% ->
    display_string(Rest);
display_string(_) ->
    error.

is_lhex(C) -> (C >= $0 andalso C =< $9) orelse (C >= $a andalso C =< $f).

byte_sequence(<<$:, Rest/binary>>) ->
    {ok, Rest};
byte_sequence(<<C, Rest/binary>>) when
    (C >= $a andalso C =< $z) orelse (C >= $A andalso C =< $Z) orelse
        (C >= $0 andalso C =< $9) orelse C =:= $+ orelse C =:= $/ orelse C =:= $=
->
    byte_sequence(Rest);
byte_sequence(_) ->
    error.

%% Integer or decimal: up to 15 digits, or up to 12 before a `.' and 1
%% to 3 after it.
number(<<$-, Rest/binary>>) -> number_digits(Rest);
number(Bin) -> number_digits(Bin).

number_digits(Bin) ->
    {Int, Rest} = digits(Bin, 0),
    case Rest of
        <<$., Frac/binary>> when Int >= 1, Int =< 12 ->
            case digits(Frac, 0) of
                {F, After} when F >= 1, F =< 3 -> {ok, After};
                _ -> error
            end;
        _ when Int >= 1, Int =< 15 ->
            {ok, Rest};
        _ ->
            error
    end.

digits(<<C, Rest/binary>>, N) when C >= $0, C =< $9 -> digits(Rest, N + 1);
digits(Rest, N) -> {N, Rest}.

token(<<C, Rest/binary>>) when
    (C >= $a andalso C =< $z) orelse (C >= $A andalso C =< $Z) orelse
        (C >= $0 andalso C =< $9) orelse C =:= $: orelse C =:= $/
->
    token(Rest);
token(<<C, Rest/binary>>) ->
    case lists:member(C, "!#$%&'*+-.^_`|~") of
        true -> token(Rest);
        false -> {ok, <<C, Rest/binary>>}
    end;
token(<<>>) ->
    {ok, <<>>}.
