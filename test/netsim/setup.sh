#!/bin/sh
# Build the simulated networks for masque_netsim_SUITE. Linux, as root.
#
#   mq_cli --wifi0-- mq_wifi (NAT) --\
#                                     mq_srv  (proxy 203.0.113.1, targets)
#   mq_cli --lte0--- mq_lte  (NAT) --/
#
# The client prefers Wi-Fi (route metric 100) over mobile (200). Taking
# wifi0 down moves traffic to mobile, as an OS does. The mobile path has
# more delay and loss and a smaller MTU.
set -eu

LTE_MTU=${LTE_MTU:-1380}

for ns in mq_cli mq_wifi mq_lte mq_srv; do
    ip netns del "$ns" 2>/dev/null || true
    ip netns add "$ns"
    ip -n "$ns" link set lo up
done

link() { # ns1 if1 ns2 if2
    ip link add "$2" type veth peer name "$4"
    ip link set "$2" netns "$1"
    ip link set "$4" netns "$3"
    ip -n "$1" link set "$2" up
    ip -n "$3" link set "$4" up
}

# Client side.
link mq_cli wifi0 mq_wifi w_in
link mq_cli lte0 mq_lte l_in
ip -n mq_cli addr add 10.10.1.2/24 dev wifi0
ip -n mq_wifi addr add 10.10.1.1/24 dev w_in
ip -n mq_cli addr add 10.10.2.2/24 dev lte0
ip -n mq_lte addr add 10.10.2.1/24 dev l_in
ip -n mq_cli link set lte0 mtu "$LTE_MTU"
ip -n mq_lte link set l_in mtu "$LTE_MTU"
ip netns exec mq_cli sysctl -qw net.ipv4.conf.all.ignore_routes_with_linkdown=1
ip netns exec mq_cli sysctl -qw net.ipv4.conf.default.ignore_routes_with_linkdown=1
ip -n mq_cli route add default via 10.10.1.1 dev wifi0 metric 100
ip -n mq_cli route add default via 10.10.2.1 dev lte0 metric 200

# Uplinks to the proxy's network.
link mq_wifi w_up mq_srv s_w
link mq_lte l_up mq_srv s_l
ip -n mq_wifi addr add 192.168.100.2/30 dev w_up
ip -n mq_srv addr add 192.168.100.1/30 dev s_w
ip -n mq_lte addr add 192.168.100.6/30 dev l_up
ip -n mq_srv addr add 192.168.100.5/30 dev s_l
ip -n mq_srv addr add 203.0.113.1/32 dev lo
# The proxy has one public address: replies must come from it, whichever
# uplink they leave by, or the NATs drop them.
ip -n mq_srv route replace 192.168.100.0/30 dev s_w src 203.0.113.1
ip -n mq_srv route replace 192.168.100.4/30 dev s_l src 203.0.113.1
ip -n mq_wifi route add 203.0.113.1/32 via 192.168.100.1
ip -n mq_lte route add 203.0.113.1/32 via 192.168.100.5

# Each access network is a NAT, as home routers and carriers are.
for r in wifi:w_up lte:l_up; do
    ns="mq_${r%%:*}"
    ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
    ip netns exec "$ns" iptables -t nat -A POSTROUTING -o "${r##*:}" -j MASQUERADE
done

# Path conditions, both directions.
WIFI_NETEM=${WIFI_NETEM:-delay 10ms loss 0.1%}
# No jitter by default: netem jitter reorders far more than real networks
# do. masque_netsim_SUITE turns it on in its own reordering case.
LTE_NETEM=${LTE_NETEM:-delay 40ms loss 0.5%}
ip netns exec mq_cli tc qdisc add dev wifi0 root netem $WIFI_NETEM
ip netns exec mq_wifi tc qdisc add dev w_in root netem $WIFI_NETEM
ip netns exec mq_cli tc qdisc add dev lte0 root netem $LTE_NETEM
ip netns exec mq_lte tc qdisc add dev l_in root netem $LTE_NETEM

ip netns exec mq_cli ping -c1 -W2 203.0.113.1 >/dev/null
echo "netsim ready"
