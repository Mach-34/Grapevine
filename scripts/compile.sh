#!/bin/bash

if [ ! -d "./crates/grapevine_circuits/circom/artifacts" ]; then
  mkdir ./crates/grapevine_circuits/circom/artifacts
fi

cd ./crates/grapevine_circuits/circom
yarn
cd -

circom ./crates/grapevine_circuits/circom/grapevine.circom \
  --r1cs --sym --wasm \
  --output ./crates/grapevine_circuits/circom/artifacts --prime bn128

# # cargo install --path ./crates/grapevine_cli
# grapevine params ./crates/grapevine_circuits/circom/artifacts/grapevine.r1cs ./crates/grapevine_circuits/circom/artifacts

# cp ./crates/grapevine_circuits/circom/artifacts/public_params.json ./crates/grapevine_server/static
# cp ./crates/grapevine_circuits/circom/artifacts/grapevine_js/grapevine.wasm ./crates/grapevine_server/static
# cp ./crates/grapevine_circuits/circom/artifacts/grapevine.r1cs ./crates/grapevine_server/static