#!/bin/bash

# Make sure you have environment variables set for FORTIGATE_MGMT_URL, FORTIGATE_API_TOKEN and FORTIGATE_ADDRESS_OBJECT_GROUP
# Examples:
export FORTIGATE_MGMT_URL="https://69.4.20.10:8443" 
export FORTIGATE_API_KEY="5fkwkkzgQ4s31bdH60qsxxfN093zgt"
export FORTIGATE_ADDRESS_OBJECT_GROUP="hyp-allowed-clients"


if [ $# -lt 1 ]; then
    echo "Usage: $0 <srcip>"
    exit 1
fi

echo $FORTIGATE_MGMT_URL
echo $1

# Create the address object
curl "$FORTIGATE_MGMT_URL/api/v2/cmdb/firewall/address?datasource=1" \
    -X "POST" \
    -H "Authorization: Bearer $FORTIGATE_API_KEY" \
    -H "Content-Type: application/json" \
    --data-raw "{\"name\":\"hyp_$1\",\"subnet\":\"$1/32\",\"color\":\"0\"}" \
    --insecure # LOL - remove this if you want, but I want this to be easy for noobs


# Add to address object group
curl "$FORTIGATE_MGMT_URL/api/v2/cmdb/firewall/addrgrp/$FORTIGATE_ADDRESS_OBJECT_GROUP/member" \
    -X "POST" \
    -H "Authorization: Bearer $FORTIGATE_API_KEY" \
    -H "Content-Type: application/json" \
    --data-raw "{\"name\":\"hyp_$1\"}" \
    --insecure # And here too