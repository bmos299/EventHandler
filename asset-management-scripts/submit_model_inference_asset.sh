#!/bin/sh
# argv[1] -- predictions file (contains the model hash and proof too).
# argv[2] -- model asset file
# argv[3] -- source data asset file
# argv[4] -- receiving file for the blockchain asset
# argv[5] -- comment
PREDICTIONS_FILE=$1
SOURCE_MODEL_ASSET_FILE=$2
SOURCE_DATA_ASSET_FILE=$3
DEST_ASSET_FILE=$4
COMMENT="$5"
IBP_ENDPOINT="http://aitrust2-1abd866a65a6a73350903823fc77cd5f-0000.us-south.containers.appdomain.cloud/AITrustAssets"

PREDICTIONS=`yq -r '.Predictions' ${PREDICTIONS_FILE} | jq -c '.[]'`
SOURCE_ASSET_MODEL=`yq -r '.assetUUID' ${SOURCE_MODEL_ASSET_FILE}`
SOURCE_ASSET_DATA=`yq  -r '.assetUUID' ${SOURCE_DATA_ASSET_FILE}`
ZK_PROOF=`yq -r '.Proof' ${PREDICTIONS_FILE}`

# build the asset from the template
jq --arg a "${PREDICTIONS}" --arg b "${SOURCE_ASSET_MODEL}" \
     --arg c "${SOURCE_ASSET_DATA}" --arg d "${COMMENT}" \
     --arg e "${ZK_PROOF}" \
    ' .propertyValues.assetPlainText=$a | .sourceAssets[0]=$b | .sourceAssets[1]=$c | .transformationInfo.description=$d | .otherInfo[0]=$e' ../asset-templates/model_inference_asset_template.json > /tmp/model_inference_asset.json

# submit the asset to blockchain
curl -X POST "${IBP_ENDPOINT}" \
    -H "accept: application/json" \
    -H "x-org-name: Org1" \
    -H "Content-Type: application/json" \
    -d @/tmp/model_inference_asset.json | jq -r '.' > $DEST_ASSET_FILE
