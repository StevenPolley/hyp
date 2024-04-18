#!/bin/sh

if [ $# -lt 1 ]; then
    echo "Usage: $0 <srcip>"
    exit 1
fi

# Can't use dots in rule name, so swap for underscores
# example: 10.69.69.100 changes to hypd_10_69_69_100_wireguard
rulename="hypd_${1//./_}_wireguard"

# Configure the rule in OpenWRT's uci interface
uci set firewall.$rulename=redirect
uci set firewall.$rulename.dest=lan
uci set firewall.$rulename.target=DNAT
uci set firewall.$rulename.name=$rulename
uci set firewall.$rulename.src=wan
uci set firewall.$rulename.src_dport=51820
uci set firewall.$rulename.dest_ip=10.0.100.1
uci set firewall.$rulename.dest_port=51820
uci set firewall.$rulename.src_ip=$1
uci add_list firewall.$rulename.proto=udp
uci commit firewall
service firewall restart