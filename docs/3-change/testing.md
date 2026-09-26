# Testing

This page tells you how the test tree is organised, which fixture to reach for, how to run one suite or one case, and which traps have bitten the suites before. Read it before you add or change a test. After reading it you know which suite should hold your new case and how to write a lifecycle regression test. Read [debugging](debugging.md) next when a test fails and you need to see inside a tunnel.

## Suite map

All tests live in `test/`. EUnit modules end in `_tests`, Common Test suites end in `_SUITE`, and the one PropEr module is `prop_masque`. Everything else in `test/` is a fixture.

### Codec and parser unit tests (EUnit)

Pure functions, no network. Add a case here when you change wire encoding or URI parsing.

| Module | Covers |
| --- | --- |
| `masque_datagram_tests` | RFC 9298 context-id framing (`masque_datagram`) |
| `masque_ip_datagram_tests` | the same framing used for CONNECT-IP packets |
| `masque_capsule_tests` | `masque_capsule` encode/decode and `known/1` |
| `masque_ip_capsule_tests` | ADDRESS_ASSIGN / ADDRESS_REQUEST / ROUTE_ADVERTISEMENT validation |
| `masque_compression_capsule_tests` | udp-bind COMPRESSION_ASSIGN / ACK / CLOSE |
| `masque_compression_table_tests` | udp-bind compression table: parity, duplicates, uncompressed singleton, post-close rules |
| `masque_udp_bind_payload_tests` | udp-bind compressed and uncompressed payloads |
| `masque_icmp_tests` | ICMPv4 / ICMPv6 error builders and checksums |
| `masque_ip_packet_tests` | IP header helpers, IPv6 extension-header walking, scope checks |
| `masque_ip_tests` | `masque_ip:is_public/1` address classification |
| `masque_uri_tests`, `masque_uri_ip_tests`, `masque_uri_udp_bind_tests` | URI template expansion and matching per protocol |

### Component unit tests (EUnit)

One module driven in isolation, sometimes against a fake transport.

| Module | Covers |
| --- | --- |
| `masque_facade_tests` | `masque:connect/3` option validation (CRLF in `proxy_authorization`, target shape) |
| `masque_tls_tests` | `masque_tls:client_opts/2,3` defaults and overrides |
| `masque_h1_client_session_tests` | h1 request headers, response validation, authority formatting |
| `masque_h2_server_tests` | h2 Extended CONNECT validation (`validate/7` in `masque_h2_server`, test-only export) |
| `masque_racer_tests` | racer scheduling and winner selection, using `masque_racer_fake_session` |
| `masque_upstream_owner_tests` | pooled connection owner, using `masque_mock_transport` |
| `masque_upstream_pool_tests` | pool fingerprinting, checkout, single-flight dials |
| `masque_chain_handler_tests` | chain handler IP paths against a mock upstream session |
| `masque_ip_proxy_handler_tests` | default CONNECT-IP handler: drops, lifecycle events, allocation |
| `masque_ip_session_registry_tests` | CONNECT-IP address registry |
| `masque_udp_bind_proxy_handler_tests` | default udp-bind handler: public address, peer filter |

### Compliance suites (CT)

End-to-end behaviour pinned to a spec. Add a case here when you implement or fix a normative requirement, and update [conformance](../reference/conformance.md).

| Suite | Covers |
| --- | --- |
| `masque_compliance_SUITE` | RFC 9298 handshake and datagrams over h3, plus h2 echo, chain and CONNECT-TCP round trips. Some cases drive `quic_h3` directly to send malformed requests. |
| `masque_ip_compliance_SUITE` | RFC 9484 over h3 with the default IP handler |
| `masque_ip_compliance_h1_SUITE` | the server-side RFC 9484 cases against an h1 listener |
| `masque_udp_bind_compliance_SUITE` | udp-listen draft over h3 (and the h3/h2 race) |

### Per-transport suites (CT)

| Suite | Covers |
| --- | --- |
| `masque_h1_SUITE` | CONNECT-UDP over HTTP/1.1 |
| `masque_h1_race_SUITE` | three-way race where only h1 is reachable |
| `masque_tcp_h1_SUITE` | classic `CONNECT host:port` over HTTP/1.1 |
| `masque_ip_h3_SUITE`, `masque_ip_h2_SUITE`, `masque_ip_h1_SUITE` | CONNECT-IP per transport |

### Lifecycle and robustness suites (CT)

| Suite | Covers |
| --- | --- |
| `masque_lifecycle_SUITE` | sessions end on connection close, GOAWAY, stream reset and FIN; output held until finalize; TCP half-close; udp-bind teardown |
| `masque_backpressure_SUITE` | `active_n` on proxy sockets: bytes arrive in order, server session mailbox stays small |
| `masque_client_errors_SUITE` | TLS verification defaults, failed dials return `{error, _}`, no session left behind |
| `masque_client_rx_SUITE` | queue-mode `rx_queue_limit`, `recv/2` after the peer closes |

### Feature suites (CT)

| Suite | Covers |
| --- | --- |
| `masque_auth_challenge_SUITE` | `{reject, Error, Headers}` challenges and `request_headers` on retry |
| `masque_chain_listener_SUITE` | `masque:start_chain_listener*/2` on h3, h2, h1 |
| `masque_chain_ip_SUITE` | CONNECT-IP through a chain |
| `masque_upstream_pool_SUITE` | pooled upstream shared by several chain tunnels |
| `masque_two_hop_example_SUITE` | smoke test of `examples/two_hop_relay.erl` (the test profile compiles `examples/`) |
| `masque_interop_SUITE` | an external MASQUE binary; skipped unless `MASQUE_GO_BIN` is set |

### Property tests

`prop_masque` checks round trips: datagram context-id codec, URI template expand/match for hostnames, and capsule encode/decode. It runs with the `rebar3_proper` plugin from the `test` profile.

## Fixtures and test handlers

| Module | What it is for |
| --- | --- |
| `masque_test_helpers` | certificates (`generate_certs/0`, `cleanup_certs/1`), an h3 listener on port 0 (`start_masque_server/1`, `stop_masque_server/1`), a raw `quic_h3` client (`h3_client_connect/2`, `h3_await_response/2`) |
| `masque_echo_handler` | echoes every UDP packet |
| `masque_report_handler` | echo handler whose `init/2` sends `{masque_session, self()}` to `report_to`; capsule `16#ff00` closes the session; `early_data` queues output before finalize |
| `masque_report_tcp_handler` | `masque_tcp_proxy_handler` that also reports its pid; supports `early_data` |
| `masque_ip_echo_handler` | echoes IP packets; `early_routes` / `early_packet` produce output before finalize |
| `masque_ip_unprompted_handler` | sends an unprompted ADDRESS_ASSIGN (request id 0), for chain tests |
| `masque_crash_bind_handler` | default udp-bind handler that crashes on capsule `16#ff01`; `early_assign` opens a context before finalize |
| `masque_stop_init_handler` | `init/2` always returns `{stop, _}`, to check the client gets a reject and not a 2xx followed by a close |
| `masque_weird_reject_handler` | rejects with a reason `masque_errors` does not know (must map to 502) |
| `masque_mock_transport` | gen_server standing in for `h2` / `quic_h3` in upstream owner tests |
| `masque_racer_fake_session` | fake client session for racer tests, injected through the `racer_transport_mods` option |

## Running tests

```bash
rebar3 eunit                                                  # all EUnit modules
rebar3 eunit --module=masque_uri_tests                        # one module
rebar3 ct                                                     # all suites
rebar3 ct --suite test/masque_lifecycle_SUITE                 # one suite
rebar3 ct --suite test/masque_lifecycle_SUITE \
          --case h3_client_close_stops_server_session         # one case
rebar3 as test proper                                         # all properties
rebar3 as test proper -m prop_masque -p prop_datagram_roundtrip
```

CT logs go to `_build/test/logs/`. Open `_build/test/logs/index.html` and follow the latest `ct_run.*` run to the suite and case; the case log holds `ct:pal/2` output, the failure reason and crash reports. CI uploads the same directory as an artifact when a job fails. Cover is on (`cover_enabled` in `rebar.config`).

### The interop suite

`masque_interop_SUITE` drives an external MASQUE implementation through `os:cmd/1`. Without `MASQUE_GO_BIN` every case is skipped, so `rebar3 ct` stays green on a machine without it.

```bash
MASQUE_GO_BIN=/path/to/masque-go MASQUE_GO_MODE=server \
  rebar3 ct --suite test/masque_interop_SUITE
```

`MASQUE_GO_MODE` is `server` (default, the external binary is the proxy) or `client`.

## Known traps

- **Dial `127.0.0.1`, not `localhost`.** `localhost` resolves to both `::1` and `127.0.0.1`, and under load (a full `rebar3 ct` run) the dual-stack handshake race can stall a dial past its timeout. Every suite dials `127.0.0.1` except `masque_interop_SUITE`, which targets an external peer. Use the IP literal in new code. The generated certificate lists `IP:127.0.0.1` and `IP:::1` as subject alt names, so verification still works if you trust it through `cacerts`.
- **Certificates come from `openssl`.** `masque_test_helpers:generate_certs/0` shells out to `openssl req` and writes into a fresh `/tmp/masque_test_<N>` directory. Without `openssl` the suites skip with `cert_generation_failed`. The map it returns has DER `cert` / `key` for h3 listeners and PEM paths `cert_file` / `key_file` for h2 and h1 listeners.
- **Clients verify by default.** A client connecting to a test listener needs `verify => verify_none`, or `cacerts` holding a CA that signed the listener certificate (OTP `ssl` refuses a self-signed leaf even in `cacerts`; see `masque_client_errors_SUITE`).
- **Listen sockets belong to their opener.** A listener or target socket opened in `init_per_suite` dies with that process. Open per test case, or hand the socket to a keeper process (see `masque_h1_race_SUITE`).
- **`report_to => self()` in `init_per_testcase`.** CT runs `init_per_testcase/2` and the case in the same process, so a handler that reports to `self()` from there reaches the case.
- **Timetraps are 30 s** in most suites (`suite() -> [{timetrap, {seconds, 30}}]`). A case that waits on a default handshake timeout (5 s) several times can hit it.

## Writing a lifecycle regression test

Use this when you change how a session starts or ends. The pattern: start a listener whose handler reports the server session pid, open a tunnel, monitor that pid, trigger the event, assert the `'DOWN'`.

The simplest place is `masque_lifecycle_SUITE`, which already starts h3 and h2 listeners with `masque_report_handler` in `init_per_testcase/2`. Add the case name to the export list and to `all/0`, then:

```erlang
h3_client_close_ends_server_session(Config) ->
    Sess = connect(Config, h3),            %% masque:connect/3 against the h3 listener
    Pid = await_session(),                 %% {masque_session, Pid} from the handler's init/2
    MRef = erlang:monitor(process, Pid),
    ok = masque:close(Sess),
    await_down(MRef, Pid).                 %% fails the case after 5 s
```

For h2 and h1 also check that the session supervisor went back to its baseline, so a leaked child is caught:

```erlang
h2_client_close_releases_child(Config) ->
    Baseline = session_count(masque_h2_session_sup),
    Sess = connect(Config, h2),
    Pid = await_session(),
    MRef = erlang:monitor(process, Pid),
    ok = masque:close(Sess),
    await_down(MRef, Pid),
    ok = wait_count(masque_h2_session_sup, Baseline, 50).
```

If you need a listener option for one case only, add a clause to `extra_opts/1` in the suite.

In a new suite, the setup is:

```erlang
init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(masque),
    case masque_test_helpers:generate_certs() of
        {ok, Certs} -> [{certs, Certs} | Config];
        {error, R} -> {skip, {cert_generation_failed, R}}
    end.

end_per_suite(Config) ->
    masque_test_helpers:cleanup_certs(?config(certs, Config)).

init_per_testcase(_Case, Config) ->
    Opts = #{
        handler => masque_report_handler,
        handler_opts => #{report_to => self()}
    },
    {ok, H3} = masque_test_helpers:start_masque_server(
        maps:merge(?config(certs, Config), Opts)
    ),
    [{h3, H3} | Config].

end_per_testcase(_Case, Config) ->
    masque_test_helpers:stop_masque_server(?config(h3, Config)).
```

and the client side dials `https://127.0.0.1:Port` with `#{verify => verify_none, transports => [h3]}`.

Next: [debugging](debugging.md) to inspect a tunnel that does not behave, or [how-to](how-to.md) for the tests each kind of change needs.
