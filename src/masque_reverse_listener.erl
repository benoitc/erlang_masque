-module(masque_reverse_listener).
-moduledoc false.

%%% Listener side of reverse connect
%%% (draft-rosomakho-masque-reverse-connect-01), shared by the h3, h2 and
%%% h1 listeners. Off unless the listener sets `accept_listen => true'.
%%%
%%% `config/1' reads the listener options once. `match/3' tells whether a
%%% request is a `connect-listen' or `connect-accept' one; `route/5' then
%%% validates it and returns the session to start:
%%%
%%% - `connect-listen' (sections 4.2, 4.3): the `listen_handler''s
%%%   `authenticate/1' decides; the control session runs with the
%%%   identity it returned.
%%% - `connect-accept' (sections 5.2.1, 5.2.2): the request id must be
%%%   pending for this client: on h3 and h2 the accept must come on the
%%%   control channel's connection, on h1 `authenticate/1' must return the
%%%   control channel's identity. Anything else is 404. The stream then
%%%   runs as a CONNECT-TCP session in capsule framing, with the accept
%%%   handler.

-include("masque.hrl").
-include("masque_reverse.hrl").

-export([config/1, match/3, route/5]).

-export_type([config/0]).

-type config() ::
    disabled
    | #{
        handler := module() | undefined,
        listen_template := masque_uri_template:template(),
        accept_template := masque_uri_template:template(),
        idle_ms := non_neg_integer() | infinity
    }.

-spec config(map()) -> config().
config(#{accept_listen := true} = Opts) ->
    {ok, Listen} = masque_uri_reverse:parse_listen_template(
        maps:get(listen_uri_template, Opts, ?MASQUE_DEFAULT_LISTEN_URI_TEMPLATE)
    ),
    {ok, Accept} = masque_uri_reverse:parse_accept_template(
        maps:get(accept_uri_template, Opts, ?MASQUE_DEFAULT_ACCEPT_URI_TEMPLATE)
    ),
    #{
        handler => maps:get(listen_handler, Opts, undefined),
        listen_template => Listen,
        accept_template => Accept,
        idle_ms => maps:get(listen_idle_timeout_ms, Opts, infinity)
    };
config(_Opts) ->
    disabled.

%% `listen', `accept', or `false' for every other request.
-spec match(config(), binary(), [{binary(), binary()}]) -> listen | accept | false.
match(disabled, _Method, _Headers) ->
    false;
match(_Config, <<"CONNECT">>, Headers) ->
    token(header(<<":protocol">>, Headers));
match(_Config, <<"GET">>, Headers) ->
    case upgrade_requested(header(<<"connection">>, Headers)) of
        true -> token(lowercase(header(<<"upgrade">>, Headers)));
        false -> false
    end;
match(_Config, _Method, _Headers) ->
    false.

token(?MASQUE_CONNECT_LISTEN_PROTOCOL) -> listen;
token(?MASQUE_CONNECT_ACCEPT_PROTOCOL) -> accept;
token(_) -> false.

%% Validate a request `match/3' recognised. `Base' carries what the
%% listener knows of the client (`peer', `peer_cert') and its
%% `handler_opts'. `Conn' is the h3 or h2 connection, `undefined' on h1.
-spec route(config(), h3 | h2 | h1, pid() | undefined, binary(), map()) ->
    {ok, listen | tcp, module(), map(), masque_handler:req()}
    | {reject, masque_errors:handshake_error()}
    | {reject, masque_errors:handshake_error(), [{binary(), binary()}]}.
route(Config, Transport, Conn, Path, #{headers := Headers} = Base) ->
    case request(Transport, Path, Headers, Base) of
        {ok, Req} ->
            case token_of(Transport, Headers) of
                listen -> route_listen(Config, Req);
                accept -> route_accept(Config, Transport, Conn, Req)
            end;
        {error, Reason} ->
            {reject, Reason}
    end.

token_of(h1, Headers) -> token(lowercase(header(<<"upgrade">>, Headers)));
token_of(_, Headers) -> token(header(<<":protocol">>, Headers)).

%% The request fields every session expects. Extended CONNECT needs
%% `:scheme' and `:authority' (section 4.3, 5.2.2); h1 needs `Host'.
request(h1, Path, Headers, Base) ->
    case header(<<"host">>, Headers) of
        undefined ->
            {error, bad_request};
        Host ->
            {ok, Base#{method => <<"GET">>, path => Path, authority => Host, scheme => <<"https">>}}
    end;
request(_, Path, Headers, Base) ->
    case {header(<<":scheme">>, Headers), header(<<":authority">>, Headers)} of
        {Scheme, Authority} when Scheme =/= undefined, Authority =/= undefined ->
            {ok, Base#{
                method => <<"CONNECT">>, path => Path, authority => Authority, scheme => Scheme
            }};
        _ ->
            {error, bad_request}
    end.

route_listen(#{handler := undefined}, _Req) ->
    %% The draft requires authenticated users; no handler, no service.
    {reject, forbidden};
route_listen(#{handler := Handler, listen_template := T, idle_ms := IdleMs}, #{path := Path} = Req) ->
    case masque_uri_reverse:match_listen(T, Path) of
        {ok, #{target := Target, ipproto := Proto}} ->
            Req1 = Req#{protocol => listen, listen_target => Target, listen_ipproto => Proto},
            case authenticate(Handler, Req1) of
                {ok, Identity} ->
                    HOpts = maps:get(handler_opts, Req1, #{}),
                    {ok, listen, Handler, HOpts#{idle_timeout_ms => IdleMs}, Req1#{
                        reverse_identity => Identity
                    }};
                Reject ->
                    Reject
            end;
        {error, no_match} ->
            {reject, bad_path};
        {error, _} ->
            {reject, bad_request}
    end.

route_accept(#{accept_template := T} = Config, Transport, Conn, #{path := Path} = Req) ->
    case masque_uri_reverse:match_accept(T, Path) of
        {ok, Id} ->
            case masque_reverse_registry:lookup(Id) of
                {ok, Entry} -> check_accept(Config, Transport, Conn, Id, Entry, Req);
                error -> {reject, unknown_request}
            end;
        {error, no_match} ->
            {reject, bad_path};
        {error, _} ->
            {reject, bad_request}
    end.

%% h3 and h2: the accept runs on the control channel's connection
%% (section 5.2.2). h1: the same identity as the control channel
%% (section 6). A mismatch looks like an unknown id, so ids of other
%% clients do not leak.
check_accept(Config, h1, _Conn, Id, #{identity := Identity} = Entry, Req) ->
    case authenticate(handler_of(Config), Req) of
        {ok, Identity} -> accept_session(Id, Entry, Req);
        {ok, _Other} -> {reject, unknown_request};
        Reject -> Reject
    end;
check_accept(_Config, _Transport, Conn, Id, #{conn := Conn} = Entry, Req) when is_pid(Conn) ->
    accept_session(Id, Entry, Req);
check_accept(_Config, _Transport, _Conn, _Id, _Entry, _Req) ->
    {reject, unknown_request}.

handler_of(#{handler := Handler}) -> Handler.

%% TCP accept streams run as CONNECT-TCP in capsule framing with the
%% permanent codes (section 5.3), and get no `100 Continue'.
accept_session(Id, #{service := #{protocol := tcp}}, Req) ->
    Req1 = Req#{
        protocol => tcp,
        reverse_id => Id,
        tcp_framing => capsule,
        tcp_version => final,
        tcp_continue => false
    },
    {ok, tcp, masque_reverse_accept_handler, maps:get(handler_opts, Req, #{}), Req1};
accept_session(_Id, _Entry, _Req) ->
    {reject, unknown_request}.

authenticate(undefined, _Req) ->
    {reject, forbidden};
authenticate(Handler, Req) ->
    case Handler:authenticate(Req) of
        {ok, Identity} -> {ok, Identity};
        {reject, Reason} -> {reject, Reason};
        {reject, Reason, Extra} when is_list(Extra) -> {reject, Reason, Extra}
    end.

upgrade_requested(undefined) ->
    false;
upgrade_requested(Value) ->
    lists:member(
        <<"upgrade">>, [string:trim(T) || T <- binary:split(lowercase(Value), <<",">>, [global])]
    ).

header(Name, Headers) ->
    case lists:keyfind(Name, 1, Headers) of
        {_, V} -> V;
        false -> undefined
    end.

lowercase(undefined) -> undefined;
lowercase(B) -> string:lowercase(B).
