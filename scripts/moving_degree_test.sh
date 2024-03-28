#!/bin/bash

## NOTE: this test is pretty disgusting but c'est la vie for today

## if ~/.grapevine does not exist, make the folder
if [ ! -f ~/.grapevine ]; then
  mkdir ~/.grapevine
fi

## move to ~/.grapevine
cd ~/.grapevine

## if grapevine.key exists, move it to real.key
if [ -f grapevine.key ]; then
  mv grapevine.key real.key
fi

### 1.
### alice <---- bob <---- charlie <---- the_user
### 
### 2.
### alice <---- bob <---- the_user 
###
### 3. 
### alice <---- the_user

# make user account (POV for the test)
grapevine account register the_user
printf "\n"
echo $(pwd)
echo $(ls)
mv grapevine.key the_user.key

## make charlie account
grapevine account register charlie
## add relationship to the_user
grapevine relationship add the_user
printf "\n"
mv grapevine.key charlie.key

## make bob account
grapevine account register bob
## add relationship to charlie
grapevine relationship add charlie
printf "\n"
mv grapevine.key bob.key

## make alice account
grapevine account register alice
## add relationship to bob
grapevine relationship add bob
printf "\n"
## create degree 1 proof (phrase proof)
grapevine phrase prove "It was cryptography all along" "The very first phrase of the word!"
printf "\n"
mv grapevine.key alice.key

## Note: though you can prove a single proof, there is not an easy way to get the necessary object ID to target a specific proof. so just use prove-new-degrees since it picks it uj
## Prove degree 2 relationshpi to alice's phrase as bob 
mv bob.key grapevine.key
grapevine phrase sync
printf "\n"
mv grapevine.key bob.key

# ## Prove degree 3 relationship to allice's phrase as charlie through bob
mv charlie.key grapevine.key
grapevine phrase sync
printf "\n"
mv grapevine.key charlie.key

## Prove degree 4 relationship to alice's phrase as the_user through charlie
mv the_user.key grapevine.key
grapevine phrase sync
## Get all proofs as the user (show degree 4)
printf "\n"
grapevine phrase degrees
printf "\n"
mv grapevine.key the_user.key

## Make connection to bob
mv bob.key grapevine.key
grapevine relationship add the_user
printf "\n"
mv grapevine.key bob.key

## Prove degree 3 relationship to alice's phrase as the_user through bob
mv the_user.key grapevine.key
grapevine phrase sync
printf "\n"
## Get all proofs as the user (show degree 3 and old proof removed)
grapevine phrase degrees
printf "\n"
mv grapevine.key the_user.key


## Make connection to alice
mv alice.key grapevine.key
grapevine relationship add the_user
printf "\n"
mv grapevine.key alice.key

## Prove degree 2 relationship to alice
mv the_user.key grapevine.key
grapevine phrase sync
printf "\n"
## Get all proofs as the user (show degree 3 and old proof removed)
grapevine phrase degrees
printf "\n"
mv grapevine.key the_user.key

## CLEANUP
# rm alice.key bob.key
if [ -f real.key ]; then
  mv real.key grapevine.key
fi