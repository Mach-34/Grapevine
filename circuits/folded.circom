pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/mux1.circom";
include "node_modules/circomlib/circuits/comparators.circom";


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
    for (var i = 0; i < num_felts; i++) {
        secret_hasher.inputs[i] <== secret[i];
    }
    
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


    // mux between computed username hash and constant true value
    // if degress of separation = 0 always return true
    component prev_username_mux = Mux1();
    prev_username_mux.c[0] <== username_hash_comparator.out;
    prev_username_mux.c[1] <== 1;
    prev_username_mux.s <== is_degree_zero.out;

    // constrain prev username mux to be true
    prev_username_mux.out === 1;

    // compute the next username hash
    component username_hasher = Poseidon(2);
    username_hasher.inputs[0] <== usernames[1];
    username_hasher.inputs[1] <== secret_mux.out;

    /// CHAFF MUX /// 
    component chaff_mux[3];
    // mux the degree of separation
    // if ! chaff step, increment degree of separation
    chaff_mux[0] = Mux1();
    chaff_mux[0].c[0] <== degrees_of_separation + 1;
    chaff_mux[0].c[1] <== degrees_of_separation;
    chaff_mux[0].s <== is_chaff_step;
    // mux the secret hash
    // if ! chaff step, grab muxed hash output
    chaff_mux[1] = Mux1();
    chaff_mux[1].c[0] <== secret_mux.out;
    chaff_mux[1].c[1] <== given_secret_hash;
    chaff_mux[1].s <== is_chaff_step;
    // mux the username hash
    // if ! chaff step, grab the computed current username hash
    chaff_mux[2] = Mux1();
    chaff_mux[2].c[0] <== username_hasher.out;
    chaff_mux[2].c[1] <== given_username_hash;
    chaff_mux[2].s <== is_chaff_step;

    // flip chaff step
    signal new_chaff_step <-- !is_chaff_step;

    // set step output
    step_out[0] <== chaff_mux[0].out;
    step_out[1] <== chaff_mux[1].out;
    step_out[2] <== chaff_mux[2].out;
    step_out[3] <== new_chaff_step;
}

component main { public [step_in] } = phrase_folding(6);