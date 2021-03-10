#!/bin/sh
# argv[1] -- model_hash file
# argv[2] -- source asset file
# argv[3] -- performance proof file
# argv[4] -- receiving file for the blockchain asset
# argv[5] -- comment
MODEL_HASH_FILE=$1
SOURCE_ASSET_FILE=$2
PROOF_FILE=$3
DEST_ASSET_FILE=$4
COMMENT="$5"
IBP_ENDPOINT="http://aitrust2-1abd866a65a6a73350903823fc77cd5f-0000.us-south.containers.appdomain.cloud/AITrustAssets"

ASSET_HASH=`cat $MODEL_HASH_FILE`
SOURCE_ASSET_UUID=`jq -r '.assetUUID' ${SOURCE_ASSET_FILE}`
ZK_PROOF=`yq -r '.Proof' $PROOF_FILE`
PERFORMANCE=`yq -r '.R2' $PROOF_FILE`

# build the asset from the template
jq --arg a "${ASSET_HASH}" --arg b "${SOURCE_ASSET_UUID}" \
     --arg c "${COMMENT}" --arg d "${PERFORMANCE}" \
     --arg e "${ZK_PROOF}" \
    ' .propertyHashes.assetHash=$a | .sourceAssets[0]=$b | .transformationInfo.description=$c | .transformationInfo.MetricR2=$d | .otherInfo[0]=$e' ../asset-templates/linear_model_asset_template.json > /tmp/linear_model_asset.json

# submit the asset to blockchain
curl -X POST "${IBP_ENDPOINT}" \
    -H "accept: application/json" \
    -H "x-org-name: Org1" \
    -H "Content-Type: application/json" \
    -d @/tmp/linear_model_asset.json | jq -r '.' > $DEST_ASSET_FILE


