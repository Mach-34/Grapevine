#!/bin/bash

# if artifacts does not exist, make it
if [ ! -d "./artifacts" ]; then
    mkdir -p ./artifacts
fi

# install dependencies
yarn

# compile circuit

circom grapevine.circom \
    --r1cs \
    --wasm \
    --prime bn128 \
    --output ./artifacts

# cleanup
mv ./artifacts/grapevine_js/grapevine.wasm ./artifacts
rm -rf ./artifacts/grapevine_js
