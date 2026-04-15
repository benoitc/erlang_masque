# Changelog

All notable changes to `masque` are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - unreleased

### Added
- RFC 9298 CONNECT-UDP server with Extended CONNECT handshake,
  URI template matching, and HTTP status mapping for failure modes.
- Client API (`masque:connect/3`, `send_packet`, `recv_packet`,
  `send_capsule`) with both message-mode and blocking queue-mode
  delivery.
- Built-in `masque_udp_proxy_handler` relaying tunnels to real UDP
  targets with pluggable `allow` / `resolver` hooks.
- Capsule-protocol dispatch on both client and server
  (`handle_capsule/3` callback, `{send_capsule, _, _}` action,
  `{masque_capsule, Sess, Type, Value}` delivery message).
- Per-connection router (`masque_server_connection`) demuxing HTTP/3
  datagrams and stream bytes to per-tunnel session processes.
- Graceful close, stream-reset handling, and oversize-datagram
  protection on both sides.
- Compliance common_test suite (17 cases) covering handshake errors,
  datagram echo, UDP round-trip through the proxy, capsules,
  concurrency, load, and boundary conditions.
- Skippable external-peer interop suite driven by `MASQUE_GO_BIN`.
- Runnable examples: `udp_echo_proxy`, `udp_dig_client`.
