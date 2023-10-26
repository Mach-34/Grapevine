#!/bin/bash

if [ ! -d "./crates/phrasedos_nova/circom/artifacts" ]; then
  mkdir ./crates/phrasedos_nova/circom/artifacts
fi

circom ./crates/phrasedos_nova/circom/folded.circom --r1cs --sym --wasm --output ./crates/phrasedos_nova/circom/artifacts --prime bn128

cargo install --path ./crates/phrasedos_cli
phrasedos params ./crates/phrasedos_nova/circom/artifacts/folded.r1cs ./crates/phrasedos_nova/circom/artifacts

cp ./crates/phrasedos_nova/circom/artifacts/public_params.json ./crates/phrasedos_server/static
cp ./crates/phrasedos_nova/circom/artifacts/folded_js/folded.wasm ./crates/phrasedos_server/static
cp ./crates/phrasedos_nova/circom/artifacts/folded.r1cs ./crates/phrasedos_server/static