%%% -*- erlang -*-
%%%
%%% Connect-UDP-Bind protocol constants -
%%% draft-ietf-masque-connect-udp-listen-11.
%%%
%%% Capsule type codes are IANA-provisional. The Connect-UDP-Bind /
%%% Proxy-Public-Address HTTP fields are also provisional registrations
%%% in the IANA HTTP Field Name registry.

-ifndef(MASQUE_UDP_BIND_HRL).
-define(MASQUE_UDP_BIND_HRL, true).

%%====================================================================
%% HTTP fields (draft-11 sections 6 and 7)
%%====================================================================

%% Boolean Structured Field per RFC 9651. Sent on both request and
%% response to negotiate bind support.
-define(MASQUE_HF_CONNECT_UDP_BIND, <<"connect-udp-bind">>).

%% Structured Field List per RFC 9651, members are Strings of the
%% form "ip:port" (IPv6 literals bracketed).
-define(MASQUE_HF_PROXY_PUBLIC_ADDRESS, <<"proxy-public-address">>).

%%====================================================================
%% Capsule types (draft-11 section 11.2)
%%====================================================================

-define(MASQUE_CAPSULE_COMPRESSION_ASSIGN, 16#11).
-define(MASQUE_CAPSULE_COMPRESSION_ACK,    16#12).
-define(MASQUE_CAPSULE_COMPRESSION_CLOSE,  16#13).

%%====================================================================
%% IP Version field (draft-11 sections 3.1 and 4)
%%====================================================================

%% IP Version 0 marks an "uncompressed" registration: the
%% COMPRESSION_ASSIGN omits IP Address and UDP Port, and datagrams
%% on the assigned Context ID carry the inner peer tuple in the
%% payload. Only the client may originate one of these.
-define(MASQUE_IP_VERSION_UNCOMPRESSED, 0).

%%====================================================================
%% Records
%%====================================================================

%% A COMPRESSION_ASSIGN capsule, decoded.
%% - context_id is non-zero (zero is malformed).
%% - For ip_version = 0, address and port are `undefined'.
%% - For ip_version = 4 / 6, address is a 4- or 8-tuple and port is
%%   a 1..65535 integer.
-record(compression_assign, {
    context_id :: pos_integer(),
    ip_version :: 0 | 4 | 6,
    address    :: undefined | inet:ip_address(),
    port       :: undefined | inet:port_number()
}).

%% A COMPRESSION_ACK capsule.
-record(compression_ack, {
    context_id :: pos_integer()
}).

%% A COMPRESSION_CLOSE capsule. Context ID 0 is malformed.
-record(compression_close, {
    context_id :: pos_integer()
}).

%% A live entry in a per-session compression table.
%% `state' tracks the ACK lifecycle of an outbound mapping; inbound
%% mappings (those the peer registered with us) jump straight to
%% `installed' on receipt.
-record(compression_entry, {
    context_id :: pos_integer(),
    ip_version :: 0 | 4 | 6,
    address    :: undefined | inet:ip_address(),
    port       :: undefined | inet:port_number(),
    state      :: pending_ack | installed | closing,
    direction  :: outbound | inbound
}).

%% A peer tuple as advertised in `Proxy-Public-Address'.
-record(public_address, {
    address :: inet:ip_address(),
    port    :: inet:port_number()
}).

-endif.
