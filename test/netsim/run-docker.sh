#!/bin/sh
# Run masque_netsim_SUITE on a machine without Linux namespaces, in a
# privileged Linux container. Usage: test/netsim/run-docker.sh
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# CT logs land in _build/netsim-logs.
mkdir -p "$ROOT/_build/netsim-logs"
exec docker run --rm --privileged -e LTE_MTU -e NETEM_OFF -e CT_CASE -e WIFI_NETEM -e LTE_NETEM -v "$ROOT:/src:ro" -v "$ROOT/_build/netsim-logs:/logs" erlang:29 sh -c '
    set -e
    apt-get update -qq >/dev/null
    apt-get install -y -qq iproute2 iptables conntrack cmake iputils-ping >/dev/null
    cp -r /src /work && rm -rf /work/_build && cd /work
    rebar3 as test compile >/dev/null
    sh test/netsim/setup.sh
    status=0
    if [ -n "${NETEM_OFF:-}" ]; then
        for d in mq_cli:wifi0 mq_wifi:w_in mq_cli:lte0 mq_lte:l_in; do
            ip netns exec "${d%%:*}" tc qdisc del dev "${d##*:}" root
        done
    fi
    MASQUE_NETSIM=1 ip netns exec mq_cli rebar3 ct --suite test/masque_netsim_SUITE ${CT_CASE:+--case $CT_CASE} || status=$?
    cp -r _build/test/logs/. /logs/
    exit $status
'
