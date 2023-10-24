#!/bin/bash

if [ ! -d "./circuits/artifacts" ]; then
  mkdir ./circuits/artifacts
fi

circom ./circuits/folded.circom --r1cs --sym --c --output ./circuits/artifacts --prime bn128
cd circuits
make
cd ..