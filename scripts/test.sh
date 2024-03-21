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

# make user account (POV for the test)
grapevine register-account the_user
mv grapevine.key the_user.key

grapevine register-account charlie
grapevine add-relationship the_user
printf "\n"
mv grapevine.key charlie.key

grapevine register-account bob
grapevine add-relationship charlie
printf "\n"
mv grapevine.key bob.key

grapevine register-account alice
grapevine add-relationship bob
printf "\n"


## create degree 1 proof (phrase proof)
output=$(grapevine create-phrase "It was cryptography all along" "The very first phrase of the word!")
echo "$output"
phrase_id=$(echo "$output" | grep -oP 'Created new phrase #\K[^!]+')
grapevine prove-phrase $phrase_id "It was cryptography all along"
printf "\n"
mv grapevine.key alice.key

## Note: though you can prove a single proof, there is not an easy way to get the necessary object ID to target a specific proof. so just use prove-new-degrees since it picks it uj
## Prove degree 2 relationshpi to alice's phrase as bob 
mv bob.key grapevine.key
grapevine prove-new-degrees
printf "\n"
mv grapevine.key bob.key

# ## Prove degree 3 relationship to allice's phrase as charlie through bob
mv charlie.key grapevine.key
grapevine prove-new-degrees
printf "\n"
mv grapevine.key charlie.key

## Prove degree 4 relationship to alice's phrase as the_user through charlie
mv the_user.key grapevine.key
grapevine prove-new-degrees
## Get all proofs as the user (show degree 4)
printf "\n"
grapevine get-degrees
printf "\n"
mv grapevine.key the_user.key

## Make connection to bob
mv bob.key grapevine.key
grapevine add-relationship the_user
printf "\n"
mv grapevine.key bob.key

## Prove degree 3 relationship to alice's phrase as the_user through bob
mv the_user.key grapevine.key
grapevine prove-new-degrees
printf "\n"
## Get all proofs as the user (show degree 3 and old proof removed)
grapevine get-degrees
printf "\n"
mv grapevine.key the_user.key


## Make connection to alice
mv alice.key grapevine.key
grapevine add-relationship the_user
printf "\n"
mv grapevine.key alice.key

## Prove degree 2 relationship to alice
mv the_user.key grapevine.key
grapevine prove-new-degrees
printf "\n"
## Get all proofs as the user (show degree 3 and old proof removed)
grapevine get-degrees
printf "\n"
mv grapevine.key the_user.key

## CLEANUP
# rm alice.key bob.key
if [ -f real.key ]; then
  mv real.key grapevine.key
fi