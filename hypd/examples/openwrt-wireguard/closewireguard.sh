#!/bin/sh

if [ $# -lt 1 ]; then
    echo "Usage: $0 <srcip>"
    exit 1
fi

# Can't use dots in rule name, so swap for underscores
rulename="hypd_${1//./_}_wireguard"

# Configure the rule in OpenWRT's uci interface
uci delete firewall.$rulename
uci commit firewall
service firewall restart