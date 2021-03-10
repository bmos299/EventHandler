#!/bin/sh
# argv[1] = model_inference_asset_file

MODEL_INFERENCE_ASSET_FILE=$1
IBP_ENDPOINT="http://aitrust2-1abd866a65a6a73350903823fc77cd5f-0000.us-south.containers.appdomain.cloud/AITrustAssets"

# parameters: model_hash, source_asset, performance, zk_proof
SOURCE_MODEL_UUID=`jq -r '.lineageInfo.sourceAssets[0]' $MODEL_INFERENCE_ASSET_FILE`
SOURCE_DATA_UUID=`jq -r '.lineageInfo.sourceAssets[1]' $MODEL_INFERENCE_ASSET_FILE`
PREDICTIONS=`jq -r '.plainTextContent.assetPlainText' $MODEL_INFERENCE_ASSET_FILE`
ZK_PROOF=`jq -r '.otherInfo[0]' $MODEL_INFERENCE_ASSET_FILE`

echo "SOURCE_MODEL_UUID:${SOURCE_MODEL_UUID}"
echo "SOURCE_DATA_UUID:${SOURCE_DATA_UUID}"
echo "PREDICTIONS:${PREDICTIONS}"


# fetch the batch data and schema from data asset
curl -X GET "$IBP_ENDPOINT/$SOURCE_DATA_UUID" \
    -H "accept: application/json" \
    -H "x-org-name: Org1" > /tmp/source_data_asset.json
jq -r '.plainTextContent.assetPlainText' /tmp/source_data_asset.json > /tmp/batchdata.csv
jq -r '.plainTextContent.assetSchema' /tmp/source_data_asset.json > /tmp/batchschema.yaml

# fetch the model asset from the blockchain
curl -X GET "$IBP_ENDPOINT/$SOURCE_MODEL_UUID" \
    -H "accept: application/json" \
    -H "x-org-name: Org1" > /tmp/source_model_asset.json
MODEL_HASH=`jq -r '.assetHashes.assetHash' /tmp/source_model_asset.json`
 
# store the proof in a temporary file
echo $ZK_PROOF > /tmp/proof.dat

# store predictions in a temporary file
echo "Predictions" > /tmp/predictions.csv
echo "${PREDICTIONS}" >> /tmp/predictions.csv

# run the verification
export TRUSTED_AI_CRYPTO_CONFIG_DIR=../crypto-config/
./bin/trusted_ai_zkp_interface --verify-inference --data-schema /tmp/batchschema.yaml --data-file /tmp/batchdata.csv --model-hash "$MODEL_HASH" --predictions /tmp/predictions.csv --proof /tmp/proof.dat
#rm -f /tmp/datahandle.yaml /tmp/proof.dat
