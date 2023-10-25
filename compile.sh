#!/bin/bash

if [ ! -d "./crates/phrasedos_nova/circom/artifacts" ]; then
  mkdir ./crates/phrasedos_nova/circom/artifacts
fi

circom ./crates/phrasedos_nova/circom/folded.circom --r1cs --sym --wasm --output ./crates/phrasedos_nova/circom/artifacts --prime bn128
# cd circuits/artifacts/folded_cpp
# make
# cd 

cargo install --path ./crates/phrasedos_cli
phrasedos params ./crates/phrasedos_nova/circom/artifacts/folded.r1cs ./crates/phrasedos_nova/circom/artifacts