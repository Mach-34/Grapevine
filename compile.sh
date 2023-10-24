#!/bin/bash

if [ ! -d "./circuits/artifacts" ]; then
  mkdir ./circuits/artifacts
fi

circom ./circuits/folded.circom --r1cs --sym --wasm --output ./circuits/artifacts --prime bn128
# cd circuits/artifacts/folded_cpp
# make
# cd -