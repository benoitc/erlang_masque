#!/bin/sh
# Remove the namespaces made by setup.sh.
for ns in mq_cli mq_wifi mq_lte mq_srv; do
    ip netns del "$ns" 2>/dev/null || true
done
