#!/bin/sh
# argv[1] - path to the descriptor file
# argv[2] - path to schema file
# argv[3] - comment
# argv[4] - path to save the response (Blockchain Asset)

DHANDLE_FILE=$1
SCHEMA_FILE=$2
COMMENT="$3"
DEST_ASSET_FILE=$4
IBP_ENDPOINT="http://aitrust2-1abd866a65a6a73350903823fc77cd5f-0000.us-south.containers.appdomain.cloud/AITrustAssets"

# get file contents
ASSET_HASH=`cat $DHANDLE_FILE`
SCHEMA=`cat $SCHEMA_FILE`

set -x
# replace the variables in the template json
jq --arg a "${ASSET_HASH}" --arg b "${SCHEMA}" \
    --arg c "${COMMENT}" \
    '.propertyHashes.assetHash=$a | .propertyValues.assetSchema=$b | .transformationInfo.description=$c' ../asset-templates/data_asset_template.json > /tmp/data_asset.json
 
# submit the asset to blockchain
curl -X POST "${IBP_ENDPOINT}" \
    -H "accept: application/json" \
    -H "x-org-name: Org1" \
    -H "Content-Type: application/json" \
    -d @/tmp/data_asset.json | jq -r '.' > $DEST_ASSET_FILE
