pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/mux1.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/gates.circom";
include "./templates/chaff.circom";

template grapevine(num_felts) {  

    // in_out schema
    // 0: degrees of separation
    // 1: secret hash from previous step
    // 2: hash of username + secret hash from previous step
    // 3: chaff

    signal input ivc_input[4];
    signal output ivc_output[4];

    // private inputs
    signal input phrase[num_felts]; // secret phrase, if first iteration
    signal input usernames[2]; // prev username, current username
    signal input auth_secrets[2]; // prev degree's user secret, current degree's user secret

    // name inputs from step_in
    signal degrees_of_separation <== ivc_input[0];
    signal given_phrase_hash <== ivc_input[1];
    signal given_degree_secret_hash <== ivc_input[2];
    signal is_chaff_step <== ivc_input[3];

    // determine whether degrees of separation from secret is zero
    component is_degree_zero = IsZero();
    is_degree_zero.in <== degrees_of_separation;

    // compute poseidon hash of secret
    // same as the word essentially
    component phrase_hasher = Poseidon(num_felts);
    phrase_hasher.inputs <== phrase;
    
    // mux between computed hash and previous iteration's hash to get phrase hash to use
    // if degrees of separation = 0 use computed hash, else use hash from previous step
    component phrase_mux = Mux1();
    phrase_mux.c[0] <== given_phrase_hash;
    phrase_mux.c[1] <== phrase_hasher.out;
    phrase_mux.s <== is_degree_zero.out;

    // compute hash of given degree secret
    // H(H(preimage), username, auth_secret[0])
    // where preimage is muxed depending on whether degree N is 1 or > 1
    component degree_secret_hasher = Poseidon(3);
    degree_secret_hasher.inputs[0] <== phrase_mux.out;
    degree_secret_hasher.inputs[1] <== usernames[0];
    degree_secret_hasher.inputs[2] <== auth_secrets[0];

    // compare computed degree secret hash to prev degree secret hash
    component degree_secret_hash_match = IsEqual();
    degree_secret_hash_match.in[0] <== degree_secret_hasher.out;
    degree_secret_hash_match.in[1] <== given_degree_secret_hash;

    // create boolean that is true if either is true:
    //  - given degree secret hash matches computed hash
    //  - is a chaff step
    component degree_secret_match_or_chaff = OR();
    degree_secret_match_or_chaff.a <== degree_secret_hash_match.out;
    degree_secret_match_or_chaff.b <== is_chaff_step;

    // create boolean that is muxes according to:
    //  - if degrees of separation = 0, always true (no check needed)
    //  - if degree of separation > 0, return output of degree_secret_match_or_chaff
    component degree_secret_satisfied_mux = Mux1();
    degree_secret_satisfied_mux.c[0] <== degree_secret_match_or_chaff.out;
    degree_secret_satisfied_mux.c[1] <== 1;
    degree_secret_satisfied_mux.s <== is_degree_zero.out;

    // constrain degree_secret_satisfied_mux to be true
    degree_secret_satisfied_mux.out === 1;

    // compute the next username hash
    component next_degree_secret_hash = Poseidon(3);
    next_degree_secret_hash.inputs[0] <== phrase_mux.out;
    next_degree_secret_hash.inputs[1] <== usernames[1];
    next_degree_secret_hash.inputs[2] <== auth_secrets[1];

    // mux step_out signal according to whether or not this is a chaff step
    component chaff_mux = ChaffMux();
    chaff_mux.degrees_of_separation <== degrees_of_separation;
    chaff_mux.given_phrase_hash <== given_phrase_hash;
    chaff_mux.given_degree_secret_hash <== given_degree_secret_hash;
    chaff_mux.is_chaff_step <== is_chaff_step;
    chaff_mux.computed_phrase_hash <== phrase_mux.out;
    chaff_mux.computed_degree_secret_hash <== next_degree_secret_hash.out;

    // wire output signals
    ivc_output <== chaff_mux.out;
}

component main { public [ivc_input] } = grapevine(6);