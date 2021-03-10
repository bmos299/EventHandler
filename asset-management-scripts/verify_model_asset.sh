#!/bin/sh
# argv[1] = model_asset_file

MODEL_ASSET_FILE=$1
IBP_ENDPOINT="http://aitrust2-1abd866a65a6a73350903823fc77cd5f-0000.us-south.containers.appdomain.cloud/AITrustAssets"

# parameters: model_hash, source_asset, performance, zk_proof
MODEL_HASH=`jq -r '.assetHashes.assetHash' $MODEL_ASSET_FILE`
SOURCE_ASSET=`jq -r '.lineageInfo.sourceAssets[0]' $MODEL_ASSET_FILE`
PERFORMANCE=`jq -r '.lineageInfo.transformationInfo.MetricR2' $MODEL_ASSET_FILE`
ZK_PROOF=`jq -r '.otherInfo[0]' $MODEL_ASSET_FILE`

echo "MODEL_HASH:${MODEL_HASH}"
echo "SOURCE_ASSET:${SOURCE_ASSET}"
echo "PERFORMANCE:${PERFORMANCE}"
echo "ZK_PROOF:${ZK_PROOF}"

# fetch the descriptor for source Asset from blockchain
curl -X GET "$IBP_ENDPOINT/$SOURCE_ASSET" \
    -H "accept: application/json" \
    -H "x-org-name: Org1" | jq -r '.assetHashes.assetHash' > /tmp/datahandle.yaml

if [ $? -eq 0 ] 
then
    echo "Successfully pulled data handle for source from blockchain"
else
    echo "Failed to pull source data handle. Aborting"
    exit 1
fi
 
# store the proof in a temporary file
echo $ZK_PROOF > /tmp/proof.dat

# run the verification
export TRUSTED_AI_CRYPTO_CONFIG_DIR=../crypto-config/
./bin/trusted_ai_zkp_interface --verify-performance --data-handle /tmp/datahandle.yaml --model-hash "$MODEL_HASH" --r2 "$PERFORMANCE" --proof /tmp/proof.dat
rm -f /tmp/datahandle.yaml /tmp/proof.dat
