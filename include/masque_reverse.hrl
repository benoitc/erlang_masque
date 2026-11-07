%%% -*- erlang -*-
%%%
%%% Reverse connect constants (draft-rosomakho-masque-reverse-connect-01).

-ifndef(MASQUE_REVERSE_HRL).
-define(MASQUE_REVERSE_HRL, true).

%% Upgrade tokens and `:protocol' values (section 7.1).
-define(MASQUE_CONNECT_LISTEN_PROTOCOL, <<"connect-listen">>).
-define(MASQUE_CONNECT_ACCEPT_PROTOCOL, <<"connect-accept">>).

%% Default templates (sections 4.1 and 5.2).
-define(MASQUE_DEFAULT_LISTEN_URI_TEMPLATE, <<"/.well-known/masque/listen/{target}/{ipproto}/">>).
-define(MASQUE_DEFAULT_ACCEPT_URI_TEMPLATE, <<"/.well-known/masque/accept/{request_id}/">>).

%% Capsule types (section 7.3). The draft leaves them TBD; these are
%% provisional private values, kept here only, until it assigns real
%% ones. None is a reserved GREASE value (RFC 9297 section 5.4).
-define(MASQUE_CAPSULE_AVAILABLE_SERVICES, 16#5243a0).
-define(MASQUE_CAPSULE_CONNECTION_REQUEST, 16#5243a1).
-define(MASQUE_CAPSULE_CONNECTION_REQUEST_DECLINED, 16#5243a2).

%% Service destination types (section 4.4).
-define(MASQUE_DEST_LOCAL, 0).
-define(MASQUE_DEST_HOSTNAME, 1).
-define(MASQUE_DEST_IPV4, 4).
-define(MASQUE_DEST_IPV6, 6).

%% Request ids are random 62-bit values (section 6), the largest a QUIC
%% varint holds.
-define(MASQUE_REQUEST_ID_MAX, (1 bsl 62) - 1).

-endif.
