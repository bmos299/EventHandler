#!/bin/sh
# argv[1] = model_asset_file

ASSET_UUID=$1
DEST_FILE=$2

IBP_ENDPOINT="http://aitrust2-1abd866a65a6a73350903823fc77cd5f-0000.us-south.containers.appdomain.cloud/AITrustAssets"

# fetch the descriptor for source Asset from blockchain
curl -X GET "$IBP_ENDPOINT/$ASSET_UUID" \
    -H "accept: application/json" \
    -H "x-org-name: Org1" | jq -r '.' > $DEST_FILE
