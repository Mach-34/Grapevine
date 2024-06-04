pragma circom 2.1.6;


include "node_modules/circomlib/circuits/eddsaposeidon.circom";
include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/mux1.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/gates.circom";
include "./templates/chaff.circom";


template grapevine(num_felts) { 


   // in_out schema
   // 0: degrees of separation
   // 1: x value of pubkey from previous step
   // 2: y value of pubkey from previous step
   // 3: secret hash from previous step
   // 4: chaff


   signal input step_in[5];
   signal output step_out[5];


   // private inputs
   signal input phrase[num_felts]; // secret phrase, if first iteration
   signal input pubkey[2]; // pubkey of current user (x and y point)
   signal input auth_signature[3]; // prev degree's user signature


   // name inputs from step_in
   signal degrees_of_separation <== step_in[0];
   signal prev_pubkey_x <== step_in[1];
   signal prev_pubkey_y <== step_in[2];
   signal given_phrase_hash <== step_in[3];
   signal is_chaff_step <== step_in[4];


   // determine whether degrees of separation from secret is zero
   component is_degree_zero = IsZero();
   is_degree_zero.in <== degrees_of_separation;


   // check that step is neither chaff step nor degree zero
   component degree_zero_or_chaff = NOR();
   degree_zero_or_chaff.a <== is_chaff_step;
   degree_zero_or_chaff.b <== is_degree_zero.out;


   // compute poseidon hash of secret
   // same as the word essentially
   component phrase_hasher = Poseidon(num_felts);
   phrase_hasher.inputs <== phrase;


   // produce signature message which is hash of current user's pubkey
   component pubkey_hasher = Poseidon(2);
   pubkey_hasher.inputs[0] <== pubkey[0];
   pubkey_hasher.inputs[1] <== pubkey[1];


   // verify auth signature
   component poseidon_verifier = EdDSAPoseidonVerifier();
   poseidon_verifier.Ax <== prev_pubkey_x;
   poseidon_verifier.Ay <== prev_pubkey_y;
   poseidon_verifier.enabled <== degree_zero_or_chaff.out;
   poseidon_verifier.M <== pubkey_hasher.out;
   poseidon_verifier.R8x <== auth_signature[0];
   poseidon_verifier.R8y <== auth_signature[1];
   poseidon_verifier.S <== auth_signature[2];
  
   // mux between computed hash and previous iteration's hash to get phrase hash to use
   // if degrees of separation = 0 use computed hash, else use hash from previous step
   component phrase_mux = Mux1();
   phrase_mux.c[0] <== given_phrase_hash;
   phrase_mux.c[1] <== phrase_hasher.out;
   phrase_mux.s <== is_degree_zero.out;


   // mux step_out signal according to whether or not this is a chaff step
   component chaff_mux = ChaffMux();
   chaff_mux.degrees_of_separation <== degrees_of_separation;
   chaff_mux.given_phrase_hash <== given_phrase_hash;
   chaff_mux.is_chaff_step <== is_chaff_step;
   chaff_mux.computed_phrase_hash <== phrase_mux.out;
   chaff_mux.prev_pubkey_x <== prev_pubkey_x;
   chaff_mux.prev_pubkey_y <== prev_pubkey_y;
   chaff_mux.pubkey_x <== pubkey[0];
   chaff_mux.pubkey_y <== pubkey[1];


   // wire output signals
   step_out <== chaff_mux.out;
}


component main { public [step_in] } = grapevine(6);