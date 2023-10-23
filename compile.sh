#!/bin/bash

circom ./circuits/main.circom --r1cs --sym --c --output ./circuits --prime bn128
cd circuits
make
cd ..