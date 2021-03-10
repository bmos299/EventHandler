#!/bin/sh
# argv[1] - path to the file containing batch for scoring
# argv[2] - path to schema file
# argv[3] - model uuid
# argv[4] - path to save the response (Blockchain Asset)
# argv[5] - Comment
DATA_FILE=$1
SCHEMA_FILE=$2
MODEL_UUID=$3
COMMENT="$5"
DEST_ASSET_FILE=$4
IBP_ENDPOINT="http://aitrust2-1abd866a65a6a73350903823fc77cd5f-0000.us-south.containers.appdomain.cloud/AITrustAssets"

# get file contents
PLAINTEXT=`cat $DATA_FILE`
SCHEMA=`cat $SCHEMA_FILE`

set -x
# replace the variables in the template json
jq --arg a "${PLAINTEXT}" --arg b "${SCHEMA}" \
    --arg c "${MODEL_UUID}" --arg d "${COMMENT}" \
    '.propertyValues.assetPlainText=$a | .propertyValues.assetSchema=$b | .propertyValues.requestedModel=$c | .transformationInfo.description=$d' ../asset-templates/batch_asset_template.json > /tmp/batch_asset.json
 
# submit the asset to blockchain
curl -X POST "${IBP_ENDPOINT}" \
    -H "accept: application/json" \
    -H "x-org-name: Org1" \
    -H "Content-Type: application/json" \
    -d @/tmp/batch_asset.json | jq -r '.' > $DEST_ASSET_FILE
