#!/bin/bash

## NOTE: this test is pretty disgusting but c'est la vie for today

## if grapevine.key exists, move it to real.key
cd ~/.grapevine
if [ -f grapevine.key ]; then
  mv grapevine.key real.key
fi

## make alice account
grapevine register-account alice
## move to alice.key
mv grapevine.key alice.key

## make bob account
grapevine register-account bob
## move to bob.key
mv grapevine.key bob.key

## make charlie account
grapevine register-account charlie
## share key charlie key to alice
grapevine add-connection alice


## CLEANUP
rm alice.key bob.key
if [ -f real.key ]; then
  mv real.key grapevine.key
fi