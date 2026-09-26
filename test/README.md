# Tests

This directory holds every test for masque. Use this page to find the suite a change belongs in; the full guide, with fixtures, run commands, known traps and a lifecycle test template, is [docs/3-change/testing.md](../docs/3-change/testing.md).

| Kind | Files | Run with |
| --- | --- | --- |
| Codec and parser unit tests | `masque_datagram_tests`, `masque_ip_datagram_tests`, `masque_capsule_tests`, `masque_ip_capsule_tests`, `masque_compression_capsule_tests`, `masque_compression_table_tests`, `masque_udp_bind_payload_tests`, `masque_icmp_tests`, `masque_ip_packet_tests`, `masque_ip_tests`, `masque_uri*_tests` | `rebar3 eunit` |
| Component unit tests | `masque_facade_tests`, `masque_tls_tests`, `masque_h1_client_session_tests`, `masque_h2_server_tests`, `masque_racer_tests`, `masque_upstream_owner_tests`, `masque_upstream_pool_tests`, `masque_chain_handler_tests`, `masque_ip_proxy_handler_tests`, `masque_ip_session_registry_tests`, `masque_udp_bind_proxy_handler_tests` | `rebar3 eunit` |
| Compliance suites | `masque_compliance_SUITE`, `masque_ip_compliance_SUITE`, `masque_ip_compliance_h1_SUITE`, `masque_udp_bind_compliance_SUITE` | `rebar3 ct` |
| Per-transport suites | `masque_h1_SUITE`, `masque_h1_race_SUITE`, `masque_tcp_h1_SUITE`, `masque_ip_h1_SUITE`, `masque_ip_h2_SUITE`, `masque_ip_h3_SUITE` | `rebar3 ct` |
| Lifecycle and robustness | `masque_lifecycle_SUITE`, `masque_backpressure_SUITE`, `masque_client_errors_SUITE`, `masque_client_rx_SUITE` | `rebar3 ct` |
| Features | `masque_auth_challenge_SUITE`, `masque_chain_listener_SUITE`, `masque_chain_ip_SUITE`, `masque_upstream_pool_SUITE`, `masque_two_hop_example_SUITE`, `masque_interop_SUITE` (skipped unless `MASQUE_GO_BIN` is set) | `rebar3 ct` |
| Properties | `prop_masque` | `rebar3 as test proper` |
| Fixtures | `masque_test_helpers`, `masque_echo_handler`, `masque_report_handler`, `masque_report_tcp_handler`, `masque_ip_echo_handler`, `masque_ip_unprompted_handler`, `masque_crash_bind_handler`, `masque_stop_init_handler`, `masque_weird_reject_handler`, `masque_mock_transport`, `masque_racer_fake_session` | used by the above |

One suite: `rebar3 ct --suite test/masque_lifecycle_SUITE`. One case: add `--case <name>`. Logs: `_build/test/logs/index.html`. Suites need `openssl` to generate a test certificate and should dial `127.0.0.1`, not `localhost`.

Next: [docs/3-change/testing.md](../docs/3-change/testing.md).
