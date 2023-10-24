pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/mux1.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/gates.circom";
include "./templates/chaff.circom";

template phrase_folding(num_felts) {  

    // in_out schema
    // 0: degrees of separation
    // 1: secret hash from previous step
    // 2: hash of username + secret hash from previous step
    // 3: chaff

    signal input step_in[4];
    signal output step_out[4];

    // private inputs
    signal input secret[num_felts];
    signal input usernames[2]; // prev username, current username

    // name inputs from step_in
    signal degrees_of_separation <== step_in[0];
    signal given_secret_hash <== step_in[1];
    signal given_username_hash <== step_in[2];
    signal is_chaff_step <== step_in[3];

    // determine whether degrees of separation from secret is zero
    component is_degree_zero = IsZero();
    is_degree_zero.in <== degrees_of_separation;

    // compute poseidon hash of secret
    // same as the word essentially
    component secret_hasher = Poseidon(num_felts);
    secret_hasher.inputs <== secret;
    
    // mux between computed hash and non hash
    // if degrees of separation = 0 use computed hash, else use hash from previous step
    component secret_mux = Mux1();
    secret_mux.c[0] <== given_secret_hash;
    secret_mux.c[1] <== secret_hasher.out;
    secret_mux.s <== is_degree_zero.out;

    // compute prev username secret
    component prev_username_hasher = Poseidon(2);
    prev_username_hasher.inputs[0] <== usernames[0];
    prev_username_hasher.inputs[1] <== secret_mux.out;

    // compare computed hash (secet, username) to prev username hash
    component username_hash_comparator = IsEqual();
    username_hash_comparator.in[0] <== prev_username_hasher.out;
    username_hash_comparator.in[1] <== given_username_hash;

    component username_comparator_or_chaff = OR();
    username_comparator_or_chaff.a <== username_hash_comparator.out;
    username_comparator_or_chaff.b <== is_chaff_step;

    // mux between computed username hash and constant true value
    // if degress of separation = 0 always return true
    component prev_username_mux = Mux1();
    prev_username_mux.c[0] <== username_comparator_or_chaff.out;
    prev_username_mux.c[1] <== 1;
    prev_username_mux.s <== is_degree_zero.out;

    // constrain prev username mux to be true
    prev_username_mux.out === 1;

    // compute the next username hash
    component username_hasher = Poseidon(2);
    username_hasher.inputs[0] <== usernames[1];
    username_hasher.inputs[1] <== secret_mux.out;

    // mux step_out signal according to whether or not this is a chaff step
    component chaff_mux = ChaffMux();
    chaff_mux.degrees_of_separation <== degrees_of_separation;
    chaff_mux.given_secret_hash <== given_secret_hash;
    chaff_mux.given_username_hash <== given_username_hash;
    chaff_mux.is_chaff_step <== is_chaff_step;
    chaff_mux.computed_secret_hash <== secret_mux.out;
    chaff_mux.computed_username_hash <== username_hasher.out;

    // wire output signals
    step_out <== chaff_mux.out;
}

component main { public [step_in] } = phrase_folding(6);