-module(masque_listen_handler).
-moduledoc """
Behaviour for the server side of reverse connect
(draft-rosomakho-masque-reverse-connect-01).

A listener started with `accept_listen => true` serves `connect-listen`
control channels and `connect-accept` streams. Its `listen_handler`
module decides who may open a control channel and follows each one.

`authenticate/1` runs in the listener before anything is answered, for
every `connect-listen` request and, on HTTP/1.1, for every
`connect-accept` request too: there each accept comes on a new
connection, and it is only matched to its control channel when
`authenticate/1` returns the same identity. On HTTP/3 and HTTP/2 an
accept must come on the control channel's own connection instead. The
draft requires authenticated users, so there is no default.

The control session's pid is the handle you pass to
`masque:request_connection/3`. See the reverse connect guide
(`docs/2-use/reverse-connect.md`).
""".

-export_type([identity/0]).

-type identity() :: term().

-doc """
Authenticate a request. Return the client's identity, or a rejection
(the same reasons and extra headers as a handler's `accept/1`).
""".
-callback authenticate(masque_handler:req()) ->
    {ok, identity()}
    | {reject, masque_errors:handshake_error()}
    | {reject, masque_errors:handshake_error(), [{binary(), binary()}]}.

-doc """
A control channel is about to open. The state defaults to the identity.
`{stop, Reason}` refuses it (502).
""".
-callback init(identity(), masque_handler:req()) -> {ok, term()} | {stop, term()}.

-doc "The client's AVAILABLE_SERVICES: the full list, replacing the previous one.".
-callback handle_services([masque:reverse_service()], term()) ->
    {ok, term()} | {stop, term(), term()}.

-doc "Any other message sent to the control session.".
-callback handle_info(term(), term()) -> {ok, term()} | {stop, term(), term()}.

-doc "The control channel is ending.".
-callback terminate(term(), term()) -> term().

-optional_callbacks([init/2, handle_services/2, handle_info/2, terminate/2]).
