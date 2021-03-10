#/bin/bash
mkdir -p ./build
pushd ./build
cmake .. && make trusted_ai_zkp_interface
popd
mkdir -p ./asset-management-scripts/bin
cp ./build/zkdoc/trusted_ai_zkp_interface ./asset-management-scripts/bin


